import json
from pathlib import Path
from typing import Dict, List

from .classifier import classify_attack
from .config import EVENTS_EXPORT_PATH, LOG_PATHS, OFFSETS_PATH
from .db import fetch_events, init_db, insert_event
from .explainer import explain_attack
from .geolocation import GeoResolver
from .parsers import read_incremental
from .utils import sha256_text


class Processor:
    def __init__(self):
        init_db()
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

    def _event_hash(self, event: Dict) -> str:
        raw = '|'.join([
            str(event.get('timestamp', '')), str(event.get('source', '')), str(event.get('ip', '')),
            str(event.get('port', '')), str(event.get('service', '')), str(event.get('raw_payload', '')),
        ])
        return sha256_text(raw)

    def process_once(self) -> int:
        inserted_count = 0
        for source, path in LOG_PATHS.items():
            current_offset = self.offsets.get(source, 0)
            records, new_offset = read_incremental(source, path, current_offset)
            self.offsets[source] = new_offset
            for record in records:
                record['attack_type'] = classify_attack(record)
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
