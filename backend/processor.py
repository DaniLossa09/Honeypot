import json
from datetime import datetime, timezone
from typing import Dict, List

from .classifier import classify_attack, classify_signal
from .config import EVENTS_EXPORT_PATH, LOG_PATHS, OFFSETS_PATH
from .db import fetch_events, init_db, insert_event, reconcile_events
from .explainer import explain_attack
from .geolocation import GeoResolver
from .parsers import read_incremental
from .utils import sha256_text


class Processor:
    CREDENTIAL_THRESHOLD = 3
    CREDENTIAL_WINDOW_SECONDS = 600
    INCIDENT_BUCKET_SECONDS = 900

    def __init__(self):
        init_db()
        self.signal_history: Dict[str, List[float]] = {}
        reconcile_events(classify_attack, explain_attack, self._event_hash)
        self.geo = GeoResolver()
        self.offsets = self._load_offsets()

    def _load_offsets(self) -> Dict[str, int]:
        if not OFFSETS_PATH.exists():
            return {name: 0 for name in LOG_PATHS}
        try:
            saved = json.loads(OFFSETS_PATH.read_text(encoding='utf-8'))
        except Exception:
            saved = {}
        return {name: int(saved.get(name, 0)) for name in LOG_PATHS}

    def _save_offsets(self) -> None:
        OFFSETS_PATH.parent.mkdir(parents=True, exist_ok=True)
        OFFSETS_PATH.write_text(json.dumps(self.offsets, indent=2), encoding='utf-8')

    def _event_ts(self, event: Dict) -> float:
        value = event.get('timestamp')
        if not value:
            return datetime.now(tz=timezone.utc).timestamp()
        try:
            return datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
        except ValueError:
            return datetime.now(tz=timezone.utc).timestamp()

    def _incident_key(self, event: Dict) -> str:
        raw_event = event.get('raw_event') if isinstance(event.get('raw_event'), dict) else {}
        attack_type = str(event.get('attack_type', ''))
        source = str(event.get('source', ''))
        ip = str(event.get('ip') or 'unknown')
        service = str(event.get('service') or '')
        ts_bucket = int(self._event_ts(event) // self.INCIDENT_BUCKET_SECONDS)

        if attack_type == 'Post-Login Activity' and raw_event.get('session'):
            return '|'.join([source, ip, service, attack_type, str(raw_event.get('session'))])
        return '|'.join([source, ip, service, attack_type, str(ts_bucket)])

    def _signal_key(self, record: Dict, attack_type: str) -> str:
        username = str(record.get('username') or '')
        return '|'.join([
            str(record.get('source') or ''),
            str(record.get('ip') or 'unknown'),
            str(record.get('service') or ''),
            attack_type,
            username,
        ])

    def _signal_threshold_met(self, record: Dict, attack_type: str) -> bool:
        key = self._signal_key(record, attack_type)
        now = self._event_ts(record)
        cutoff = now - self.CREDENTIAL_WINDOW_SECONDS
        history = [ts for ts in self.signal_history.get(key, []) if ts >= cutoff]
        history.append(now)
        self.signal_history[key] = history
        return len(history) >= self.CREDENTIAL_THRESHOLD

    def _event_hash(self, event: Dict) -> str:
        raw = '|'.join([
            self._incident_key(event),
        ])
        return sha256_text(raw)

    def process_once(self) -> int:
        inserted_count = 0
        for source, path in LOG_PATHS.items():
            current_offset = self.offsets.get(source, 0)
            records, new_offset = read_incremental(source, path, current_offset)
            self.offsets[source] = new_offset
            for record in records:
                attack_type = classify_attack(record)
                if not attack_type:
                    signal_type = classify_signal(record)
                    if signal_type and self._signal_threshold_met(record, signal_type):
                        attack_type = signal_type
                if not attack_type:
                    continue
                record['attack_type'] = attack_type
                record.update(explain_attack(record['attack_type']))
                record.update(self.geo.resolve(record.get('ip')))
                record['event_hash'] = self._event_hash(record)
                if insert_event(record):
                    inserted_count += 1
        self._save_offsets()
        self.export_events_json()
        return inserted_count

    def export_events_json(self, limit: int = 500) -> None:
        events = fetch_events(limit=limit)
        EVENTS_EXPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        EVENTS_EXPORT_PATH.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding='utf-8')
