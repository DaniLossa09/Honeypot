import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from .ai_analyst import analyze_event
from .classifier import classify_attack, classify_signal
from .config import ATTACK_SETTINGS_PATH, EVENTS_EXPORT_PATH, LOG_PATHS, OFFSETS_PATH
from .db import fetch_events, get_conn, init_db, insert_event, insert_raw_event, reconcile_events, reset_events
from .explainer import explain_attack
from .geolocation import GeoResolver
from .mitre import map_attack_to_mitre
from .parsers import read_incremental
from .settings import load_attack_settings
from .utils import sha256_text


class Processor:
    CREDENTIAL_THRESHOLD = 3
    CREDENTIAL_WINDOW_SECONDS = 600
    INCIDENT_BUCKET_SECONDS = 900

    def __init__(self):
        init_db()
        self.signal_history: Dict[str, List[float]] = {}
        # Timestamp evento piu recente visto dai segnali: base tempi per il
        # pruning (i log possono avere timestamp storici, il wall clock no).
        self._last_signal_ts = 0.0
        self.attack_settings = load_attack_settings()
        self._settings_mtime = self._settings_file_mtime()
        reconcile_events(self._reconcile_attack_type, explain_attack, self._event_hash)
        self.geo = GeoResolver()
        self.offsets = self._load_offsets()

    def reload_attack_settings(self) -> Dict:
        self.attack_settings = load_attack_settings()
        self._settings_mtime = self._settings_file_mtime()
        return self.attack_settings

    @staticmethod
    def _settings_file_mtime() -> float | None:
        try:
            return ATTACK_SETTINGS_PATH.stat().st_mtime
        except OSError:
            return None

    def _reload_settings_if_changed(self) -> None:
        # Rilettura solo se il file e cambiato (mtime): evita parse+validazione
        # JSON a ogni ciclo di polling. PUT /settings chiama reload esplicito.
        if self._settings_file_mtime() != self._settings_mtime:
            self.reload_attack_settings()

    def _reconcile_attack_type(self, record: Dict) -> str | None:
        attack_type = classify_attack(record)
        if attack_type:
            return attack_type
        if record.get('attack_type') == 'Credential Attack':
            return 'Credential Attack'
        return None

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
        bucket_seconds = int(self.attack_settings.get('incident_bucket_seconds') or self.INCIDENT_BUCKET_SECONDS)
        ts_bucket = int(self._event_ts(event) // bucket_seconds)

        if (
            attack_type == 'Post-Login Activity'
            and raw_event.get('session')
            and self.attack_settings.get('post_login_dedupe_by_session', True)
        ):
            return '|'.join([source, ip, service, attack_type, str(raw_event.get('session'))])
        return '|'.join([source, ip, service, attack_type, str(ts_bucket)])

    def _signal_key(self, record: Dict, attack_type: str) -> str:
        return '|'.join([
            str(record.get('source') or ''),
            str(record.get('ip') or 'unknown'),
            str(record.get('service') or ''),
            attack_type,
        ])

    def _signal_threshold_met(self, record: Dict, attack_type: str) -> bool:
        key = self._signal_key(record, attack_type)
        now = self._event_ts(record)
        threshold = int(self.attack_settings.get('credential_threshold') or self.CREDENTIAL_THRESHOLD)
        window_seconds = int(self.attack_settings.get('credential_window_seconds') or self.CREDENTIAL_WINDOW_SECONDS)
        cutoff = now - window_seconds
        history = [ts for ts in self.signal_history.get(key, []) if ts >= cutoff]
        history.append(now)
        self.signal_history[key] = history
        self._last_signal_ts = max(self._last_signal_ts, now)
        return len(history) >= threshold

    def _prune_signal_history(self) -> None:
        """Rimuove le chiavi con soli timestamp fuori finestra.

        Senza pruning gli IP mai piu rivisti restano in memoria per sempre.
        Il cutoff usa l'ultimo timestamp evento visto (non il wall clock):
        i log riprocessati possono avere date storiche.
        """
        if not self._last_signal_ts:
            return
        window_seconds = int(self.attack_settings.get('credential_window_seconds') or self.CREDENTIAL_WINDOW_SECONDS)
        cutoff = self._last_signal_ts - window_seconds
        for key in list(self.signal_history):
            kept = [ts for ts in self.signal_history[key] if ts >= cutoff]
            if kept:
                self.signal_history[key] = kept
            else:
                del self.signal_history[key]

    def _source_enabled(self, source: str) -> bool:
        enabled_sources = self.attack_settings.get('enabled_sources') or {}
        return bool(enabled_sources.get(source, True))

    def _attack_enabled(self, attack_type: str) -> bool:
        key_map = {
            'Unauthorized Login': 'unauthorized_login',
            'Post-Login Activity': 'post_login_activity',
            'SQL Injection': 'sql_injection',
            'XSS Attack': 'xss',
            'IDOR Attempt': 'idor',
            'Command Injection': 'command_injection',
            'Malware Upload': 'malware_upload',
            'Web Crawl / Recon': 'web_recon',
            'FTP Attack': 'ftp_transfer',
            'Database Attack': 'database_attack',
            'SCADA Attack': 'scada_attack',
        }
        key = key_map.get(attack_type)
        if not key:
            return True
        enabled_attacks = self.attack_settings.get('enabled_direct_attacks') or {}
        return bool(enabled_attacks.get(key, True))

    def _event_hash(self, event: Dict) -> str:
        raw = '|'.join([
            self._incident_key(event),
        ])
        return sha256_text(raw)

    def process_once(self) -> int:
        self._reload_settings_if_changed()
        inserted_count = 0
        offsets_changed = False
        for source, path in LOG_PATHS.items():
            if not self._source_enabled(source):
                continue
            current_offset = self.offsets.get(source, 0)
            records, new_offset = read_incremental(source, path, current_offset)

            # Fase 1 - raw + classificazione: una sola transazione per blocco
            # (un commit = un fsync, non uno per riga: conta molto su SD).
            candidates: List[Dict] = []
            with get_conn() as conn:
                for record in records:
                    insert_raw_event(record, conn=conn)
                    attack_type = classify_attack(record)
                    if attack_type and not self._attack_enabled(attack_type):
                        attack_type = None
                    if not attack_type:
                        signal_type = classify_signal(record)
                        if signal_type and self._signal_threshold_met(record, signal_type):
                            attack_type = signal_type
                    if not attack_type:
                        continue
                    record['attack_type'] = attack_type
                    candidates.append(record)
                conn.commit()

            # Fase 2 - arricchimento (geo/AI = rete, anche lenti): fuori da
            # qualsiasi transazione per non tenere lock sul DB.
            for record in candidates:
                record.update(explain_attack(record['attack_type']))
                record.update(map_attack_to_mitre(record['attack_type'], record))
                record.update(self.geo.resolve(record.get('ip')))
                record.update(analyze_event(record))
                record['event_hash'] = self._event_hash(record)

            # Fase 3 - insert incidenti, una transazione per blocco.
            if candidates:
                with get_conn() as conn:
                    for record in candidates:
                        if insert_event(record, conn=conn):
                            inserted_count += 1
                    conn.commit()

            # Avanza l'offset solo dopo aver processato l'intero blocco: se una
            # fase lancia (geo/AI/insert), l'offset resta indietro e le righe
            # non inserite vengono riprocessate al giro dopo. Gli insert sono
            # idempotenti (event_hash / raw_hash), il replay non crea duplicati.
            if new_offset != current_offset:
                offsets_changed = True
            self.offsets[source] = new_offset

        self._prune_signal_history()
        # Niente righe nuove = niente scritture: offsets.json e l'export JSON
        # venivano riscritti a ogni polling anche a vuoto (usura SD inutile).
        if offsets_changed or inserted_count:
            self._save_offsets()
            self.export_events_json()
        return inserted_count

    def reset_attacks(self) -> Dict[str, int]:
        self.signal_history.clear()
        result = reset_events()
        # Avanza gli offset a fine file: "reset" = pulisci la vista e ignora tutto
        # cio che e gia nei log, cosi gli incidenti cancellati NON ricompaiono al
        # ciclo successivo. Solo le righe di log nuove generano nuovi incidenti.
        # (Per riprocessare i log da zero: azzerare data/state/offsets.json.)
        self.offsets = {name: self._log_size(path) for name, path in LOG_PATHS.items()}
        self._save_offsets()
        self.export_events_json()
        return result

    @staticmethod
    def _log_size(path_str: str) -> int:
        try:
            return Path(path_str).stat().st_size
        except OSError:
            return 0

    def export_events_json(self, limit: int = 500) -> None:
        events = fetch_events(limit=limit)
        EVENTS_EXPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        EVENTS_EXPORT_PATH.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding='utf-8')
