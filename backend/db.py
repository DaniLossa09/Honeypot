import os
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterable, List, Optional

from .config import DB_PATH, EVENTS_EXPORT_PATH
from .mitre import aggregate_discovery, map_attack_to_mitre, resolve_mitre
from .utils import sha256_text

SCHEMA = '''
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_hash TEXT NOT NULL UNIQUE,
    timestamp TEXT,
    source TEXT,
    ip TEXT,
    port INTEGER,
    service TEXT,
    raw_payload TEXT,
    attack_type TEXT,
    country TEXT,
    city TEXT,
    lat REAL,
    lon REAL,
    danger_level TEXT,
    explanation_it TEXT,
    advice TEXT,
    mitre_tactic TEXT,
    mitre_technique TEXT,
    mitre_subtechnique TEXT,
    mitre_confidence TEXT,
    raw_event_json TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_attack_type ON events(attack_type);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);

CREATE TABLE IF NOT EXISTS raw_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_hash TEXT NOT NULL UNIQUE,
    timestamp TEXT,
    source TEXT,
    ip TEXT,
    port INTEGER,
    service TEXT,
    eventid TEXT,
    event_type TEXT,
    username TEXT,
    password TEXT,
    command TEXT,
    argument TEXT,
    path TEXT,
    uri TEXT,
    user_agent TEXT,
    session TEXT,
    raw_payload TEXT,
    raw_event_json TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_raw_events_source_ip ON raw_events(source, ip, service);
CREATE INDEX IF NOT EXISTS idx_raw_events_timestamp ON raw_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_raw_events_session ON raw_events(session);
'''

def reset_events() -> Dict[str, int]:
    """Cancella incidenti e dettagli raw gia importati, senza toccare i log sorgente."""
    with get_conn() as conn:
        events_count = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        raw_count = conn.execute('SELECT COUNT(*) FROM raw_events').fetchone()[0]
        conn.execute('DELETE FROM events')
        conn.execute('DELETE FROM raw_events')
        conn.commit()

    EVENTS_EXPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVENTS_EXPORT_PATH.write_text('[]', encoding='utf-8')

    return {'events_deleted': events_count, 'raw_events_deleted': raw_count}


# Colonne aggiunte dopo la prima release: vanno create con ALTER TABLE sui DB
# esistenti (CREATE TABLE IF NOT EXISTS non aggiunge colonne a tabelle gia presenti).
_EVENT_MIGRATIONS = {
    'mitre_tactic': 'TEXT',
    'mitre_technique': 'TEXT',
    'mitre_subtechnique': 'TEXT',
    'mitre_confidence': 'TEXT',
    'ai_explanation': 'TEXT',
    'ai_attacker_profile': 'TEXT',
    'ai_defense': 'TEXT',
}


def _migrate_events(conn: sqlite3.Connection) -> None:
    existing = {row[1] for row in conn.execute('PRAGMA table_info(events)').fetchall()}
    for column, coltype in _EVENT_MIGRATIONS.items():
        if column not in existing:
            conn.execute(f'ALTER TABLE events ADD COLUMN {column} {coltype}')


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA)
        _migrate_events(conn)
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def insert_event(event: Dict[str, Any]) -> bool:
    sql = '''
    INSERT OR IGNORE INTO events (
        event_hash, timestamp, source, ip, port, service, raw_payload,
        attack_type, country, city, lat, lon, danger_level,
        explanation_it, advice, mitre_tactic, mitre_technique,
        mitre_subtechnique, mitre_confidence,
        ai_explanation, ai_attacker_profile, ai_defense,
        raw_event_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    '''
    values = (
        event['event_hash'], event.get('timestamp'), event.get('source'), event.get('ip'),
        event.get('port'), event.get('service'), event.get('raw_payload'),
        event.get('attack_type'), event.get('country'), event.get('city'),
        event.get('lat'), event.get('lon'), event.get('danger_level'),
        event.get('explanation_it'), event.get('advice'),
        event.get('mitre_tactic'), event.get('mitre_technique'),
        event.get('mitre_subtechnique'), event.get('mitre_confidence'),
        event.get('ai_explanation'), event.get('ai_attacker_profile'), event.get('ai_defense'),
        json.dumps(event.get('raw_event', {}), ensure_ascii=False),
    )
    with get_conn() as conn:
        cur = conn.execute(sql, values)
        conn.commit()
        return cur.rowcount > 0


def _raw_dict(record: Dict[str, Any]) -> Dict[str, Any]:
    raw_event = record.get('raw_event')
    return raw_event if isinstance(raw_event, dict) else {}


def _raw_session(raw_event: Dict[str, Any]) -> Optional[str]:
    value = raw_event.get('session')
    return str(value) if value else None


def _raw_hash(record: Dict[str, Any]) -> str:
    raw = '|'.join([
        str(record.get('source') or ''),
        str(record.get('timestamp') or ''),
        str(record.get('ip') or ''),
        str(record.get('port') or ''),
        str(record.get('raw_payload') or ''),
    ])
    return sha256_text(raw)


def insert_raw_event(record: Dict[str, Any]) -> bool:
    raw_event = _raw_dict(record)
    sql = '''
    INSERT OR IGNORE INTO raw_events (
        raw_hash, timestamp, source, ip, port, service, eventid, event_type,
        username, password, command, argument, path, uri, user_agent, session,
        raw_payload, raw_event_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    '''
    values = (
        _raw_hash(record), record.get('timestamp'), record.get('source'), record.get('ip'),
        record.get('port'), record.get('service'), record.get('eventid'), record.get('event_type'),
        record.get('username'), record.get('password'), record.get('command'), record.get('argument'),
        record.get('path'), record.get('uri'), record.get('user_agent'), _raw_session(raw_event),
        record.get('raw_payload'), json.dumps(raw_event, ensure_ascii=False),
    )
    with get_conn() as conn:
        cur = conn.execute(sql, values)
        conn.commit()
        return cur.rowcount > 0


def _record_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    try:
        raw_event = json.loads(row['raw_event_json'] or '{}')
    except Exception:
        raw_event = {}

    logdata = raw_event.get('logdata', {}) if isinstance(raw_event.get('logdata'), dict) else {}
    command = raw_event.get('command') or raw_event.get('action') or raw_event.get('input')
    argument = raw_event.get('argument') or raw_event.get('arg') or ''

    return {
        'timestamp': row['timestamp'],
        'source': row['source'],
        'ip': row['ip'],
        'port': row['port'],
        'service': row['service'],
        'message': raw_event.get('message') or raw_event.get('logtype') or command or row['raw_payload'] or '',
        'eventid': raw_event.get('eventid'),
        'event_type': raw_event.get('logtype'),
        'username': raw_event.get('username') or raw_event.get('user') or logdata.get('USERNAME') or (argument if command == 'USER' else None),
        'password': raw_event.get('password') or logdata.get('PASSWORD') or (argument if command == 'PASS' else None),
        'command': command,
        'argument': argument,
        'uri': logdata.get('REQUEST') or logdata.get('PATH') or '',
        'path': logdata.get('PATH') or '',
        'user_agent': logdata.get('USERAGENT') or logdata.get('User-Agent'),
        'protocol': raw_event.get('protocol'),
        'raw_payload': row['raw_payload'],
        'raw_event': raw_event,
        'attack_type': row['attack_type'],
    }


def reconcile_events(
    classifier: Callable[[Dict[str, Any]], Optional[str]],
    explainer: Callable[[str], Dict[str, str]],
    event_hasher: Optional[Callable[[Dict[str, Any]], str]] = None,
) -> Dict[str, int]:
    removed = 0
    updated = 0
    seen_hashes = set()

    with get_conn() as conn:
        rows = conn.execute('SELECT * FROM events').fetchall()
        for row in rows:
            record = _record_from_row(row)
            attack_type = classifier(record)
            if not attack_type:
                conn.execute('DELETE FROM events WHERE id = ?', (row['id'],))
                removed += 1
                continue

            record['attack_type'] = attack_type
            new_hash = event_hasher(record) if event_hasher else row['event_hash']
            if new_hash in seen_hashes:
                conn.execute('DELETE FROM events WHERE id = ?', (row['id'],))
                removed += 1
                continue
            seen_hashes.add(new_hash)

            explanation = explainer(attack_type)
            mitre = map_attack_to_mitre(attack_type, record)
            row_keys = row.keys()
            if (
                row['event_hash'] != new_hash
                or row['attack_type'] != attack_type
                or row['danger_level'] != explanation.get('danger_level')
                or row['explanation_it'] != explanation.get('explanation_it')
                or row['advice'] != explanation.get('advice')
                or ('mitre_technique' in row_keys and row['mitre_technique'] != mitre.get('mitre_technique'))
                or ('mitre_subtechnique' in row_keys and row['mitre_subtechnique'] != mitre.get('mitre_subtechnique'))
                or ('mitre_confidence' in row_keys and row['mitre_confidence'] != mitre.get('mitre_confidence'))
            ):
                conn.execute(
                    '''
                    UPDATE events
                    SET event_hash = ?, attack_type = ?, danger_level = ?, explanation_it = ?, advice = ?,
                        mitre_tactic = ?, mitre_technique = ?, mitre_subtechnique = ?, mitre_confidence = ?
                    WHERE id = ?
                    ''',
                    (
                        new_hash,
                        attack_type,
                        explanation.get('danger_level'),
                        explanation.get('explanation_it'),
                        explanation.get('advice'),
                        mitre.get('mitre_tactic'),
                        mitre.get('mitre_technique'),
                        mitre.get('mitre_subtechnique'),
                        mitre.get('mitre_confidence'),
                        row['id'],
                    ),
                )
                updated += 1
        conn.commit()

    return {'removed': removed, 'updated': updated}


def _risk_band(score: int) -> str:
    if score >= 80:
        return 'Critico'
    if score >= 60:
        return 'Alto'
    if score >= 35:
        return 'Medio'
    return 'Basso'


def _event_risk_score(event: Dict[str, Any], raw_events: Optional[List[Dict[str, Any]]] = None) -> int:
    attack_type = event.get('attack_type') or 'Unknown'
    danger = event.get('danger_level') or 'Basso'
    raw_events = raw_events or []

    score = {
        'Web Crawl / Recon': 22,
        'Port Scan': 24,
        'Credential Attack': 42,
        'FTP Attack': 50,
        'Post-Login Activity': 58,
        'XSS Attack': 60,
        'IDOR Attempt': 62,
        'Unauthorized Login': 75,
        'SQL Injection': 78,
        'Database Attack': 72,
        'Command Injection': 86,
        'Malware Upload': 90,
        'SMB Attack': 82,
        'SCADA Attack': 88,
    }.get(attack_type, 35)

    score += {'Alto': 8, 'Medio': 4, 'Basso': 0}.get(danger, 0)

    credential_attempts = len([
        item for item in raw_events
        if item.get('username') is not None or item.get('password') is not None
    ])
    commands = {str(item.get('command') or '').strip().lower() for item in raw_events if item.get('command')}
    paths = {str(item.get('path') or item.get('uri') or '').strip() for item in raw_events if item.get('path') or item.get('uri')}
    sessions = {str(item.get('session') or '').strip() for item in raw_events if item.get('session')}

    if credential_attempts >= 3:
        score += min(18, credential_attempts * 3)
    if commands:
        score += min(16, len(commands) * 4)
    if commands & {'wget', 'curl', 'chmod', 'bash', 'sh', 'nc', 'netcat'}:
        score += 12
    if len(paths) >= 5:
        score += 8
    if len(sessions) > 1:
        score += 6

    return max(0, min(score, 100))


def _enrich_event_risk(event: Dict[str, Any], raw_events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    enriched = dict(event)
    score = _event_risk_score(enriched, raw_events=raw_events)
    enriched['risk_score'] = score
    enriched['risk_level'] = _risk_band(score)
    # Espande gli ID MITRE salvati in nomi ufficiali + URL (read-time).
    enriched.update(resolve_mitre(
        enriched.get('mitre_tactic'),
        enriched.get('mitre_technique'),
        enriched.get('mitre_subtechnique'),
        enriched.get('mitre_confidence'),
    ))
    return enriched


def fetch_events(limit: int = 200) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            'SELECT * FROM events ORDER BY datetime(timestamp) DESC, id DESC LIMIT ?',
            (limit,)
        ).fetchall()
    return [_enrich_event_risk(dict(r)) for r in rows]


def fetch_event_by_id(event_id: int) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        row = conn.execute('SELECT * FROM events WHERE id = ?', (event_id,)).fetchone()
    return _enrich_event_risk(dict(row)) if row else None


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _row_dict(row: sqlite3.Row) -> Dict[str, Any]:
    result = dict(row)
    try:
        result['raw_event'] = json.loads(result.pop('raw_event_json') or '{}')
    except Exception:
        result['raw_event'] = {}
    return result


def _compact_raw_event(row: Dict[str, Any]) -> Dict[str, Any]:
    details = []
    if row.get('username') is not None:
        details.append(f"username={row.get('username')}")
    if row.get('password') is not None:
        details.append(f"password={row.get('password')}")
    if row.get('command'):
        details.append(f"command={row.get('command')}")
    if row.get('argument'):
        details.append(f"argument={row.get('argument')}")
    if row.get('path') or row.get('uri'):
        details.append(f"path={row.get('path') or row.get('uri')}")
    if row.get('eventid') or row.get('event_type'):
        details.append(f"event={row.get('eventid') or row.get('event_type')}")

    row['summary'] = ' | '.join(details) or row.get('raw_payload') or ''
    return row


def fetch_event_context(event_id: int, limit: int = 80) -> Optional[Dict[str, Any]]:
    event = fetch_event_by_id(event_id)
    if not event:
        return None

    raw_event = _parse_raw_event(event)
    session = raw_event.get('session')
    event_ts = _parse_timestamp(event.get('timestamp'))
    window_start = event_ts - timedelta(minutes=10) if event_ts else None
    window_end = event_ts + timedelta(minutes=2) if event_ts else None

    with get_conn() as conn:
        if session:
            rows = conn.execute(
                '''
                SELECT * FROM raw_events
                WHERE source = ? AND ip = ? AND service = ? AND session = ?
                ORDER BY datetime(timestamp) ASC, id ASC
                LIMIT ?
                ''',
                (event.get('source'), event.get('ip'), event.get('service'), str(session), limit),
            ).fetchall()
        else:
            rows = conn.execute(
                '''
                SELECT * FROM raw_events
                WHERE source = ? AND ip = ? AND service = ?
                ORDER BY datetime(timestamp) ASC, id ASC
                LIMIT ?
                ''',
                (event.get('source'), event.get('ip'), event.get('service'), max(limit * 4, limit)),
            ).fetchall()

    raw_events = []
    for row in rows:
        item = _row_dict(row)
        item_ts = _parse_timestamp(item.get('timestamp'))
        if window_start and window_end and item_ts and not (window_start <= item_ts <= window_end):
            continue
        raw_events.append(_compact_raw_event(item))
        if len(raw_events) >= limit:
            break

    if not raw_events and event.get('raw_event_json'):
        raw_events.append(_compact_raw_event({
            'id': None,
            'timestamp': event.get('timestamp'),
            'source': event.get('source'),
            'ip': event.get('ip'),
            'port': event.get('port'),
            'service': event.get('service'),
            'eventid': raw_event.get('eventid'),
            'event_type': raw_event.get('logtype'),
            'username': raw_event.get('username') or raw_event.get('user'),
            'password': raw_event.get('password'),
            'command': raw_event.get('input') or raw_event.get('command') or raw_event.get('action'),
            'argument': raw_event.get('argument') or raw_event.get('arg'),
            'path': raw_event.get('path'),
            'uri': raw_event.get('uri'),
            'user_agent': raw_event.get('user_agent'),
            'session': session,
            'raw_payload': event.get('raw_payload'),
            'raw_event': raw_event,
        }))

    return {'event': _enrich_event_risk(event, raw_events=raw_events), 'raw_events': raw_events}


def _unique_values(rows: Iterable[Dict[str, Any]], field: str, limit: int = 12) -> List[str]:
    values = []
    seen = set()
    for row in rows:
        value = str(row.get(field) or '').strip()
        if not value or value in seen:
            continue
        seen.add(value)
        values.append(value)
        if len(values) >= limit:
            break
    return values


def _incident_reason(event: Dict[str, Any], raw_events: List[Dict[str, Any]]) -> str:
    attack_type = event.get('attack_type') or 'Unknown'
    service = str(event.get('service') or '').upper()
    raw_event = _parse_raw_event(event)
    eventid = raw_event.get('eventid') or event.get('eventid')
    session = raw_event.get('session')

    if attack_type == 'Credential Attack':
        attempts = len([
            item for item in raw_events
            if item.get('username') is not None or item.get('password') is not None
        ])
        return (
            f"Segnalato perche lo stesso IP ha inviato credenziali verso {service or 'il servizio'} "
            f"piu volte nella finestra di correlazione. Tentativi correlati: {attempts or len(raw_events)}."
        )
    if attack_type == 'Unauthorized Login':
        username = raw_event.get('username') or event.get('username')
        return (
            f"Segnalato perche Cowrie ha registrato un login riuscito"
            f"{f' con utente {username}' if username else ''}. In produzione sarebbe accesso non autorizzato riuscito."
        )
    if attack_type == 'Post-Login Activity':
        commands = _unique_values(raw_events, 'command', limit=5)
        suffix = f" Comandi osservati: {', '.join(commands)}." if commands else ''
        return (
            f"Segnalato perche dopo il login sono stati eseguiti comandi nella sessione"
            f"{f' {session}' if session else ''}.{suffix}"
        )
    if attack_type in {'SQL Injection', 'XSS Attack', 'IDOR Attempt', 'Command Injection'}:
        paths = _unique_values(raw_events, 'path', limit=3) or _unique_values(raw_events, 'uri', limit=3)
        suffix = f" Endpoint coinvolti: {', '.join(paths)}." if paths else ''
        return f"Segnalato perche il payload contiene pattern compatibili con {attack_type}.{suffix}"
    if attack_type == 'FTP Attack':
        commands = _unique_values(raw_events, 'command', limit=5)
        suffix = f" Comandi FTP osservati: {', '.join(commands)}." if commands else ''
        return f"Segnalato perche l'IP ha usato comandi FTP operativi o di trasferimento file.{suffix}"
    if attack_type == 'Web Crawl / Recon':
        paths = _unique_values(raw_events, 'path', limit=5) or _unique_values(raw_events, 'uri', limit=5)
        suffix = f" Path osservati: {', '.join(paths)}." if paths else ''
        return f"Segnalato perche sono stati richiesti path o user-agent tipici di scansione/ricognizione.{suffix}"
    if eventid:
        return f"Segnalato perche l'evento sorgente {eventid} e stato classificato come {attack_type}."
    return f"Segnalato perche il comportamento osservato e stato classificato come {attack_type}."


def fetch_incident_detail(event_id: int, limit: int = 120) -> Optional[Dict[str, Any]]:
    context = fetch_event_context(event_id, limit=limit)
    if not context:
        return None

    event = _enrich_event_risk(context['event'], raw_events=context['raw_events'])
    raw_events = context['raw_events']
    timeline = []
    for item in raw_events:
        timeline.append({
            'kind': 'raw',
            'timestamp': item.get('timestamp'),
            'service': item.get('service'),
            'event_type': item.get('eventid') or item.get('event_type') or 'Raw Event',
            'summary': item.get('summary') or '',
        })
    timeline.append({
        'kind': 'incident',
        'timestamp': event.get('timestamp'),
        'service': event.get('service'),
        'event_type': event.get('attack_type'),
        'summary': event.get('explanation_it') or event.get('attack_type') or '',
    })
    timeline = sorted(
        timeline,
        key=lambda item: (item.get('timestamp') or '', 0 if item.get('kind') == 'raw' else 1),
    )

    return {
        'event': event,
        'raw_events': raw_events,
        'technical_reason': _incident_reason(event, raw_events),
        'evidence': {
            'usernames': _top_counts(item.get('username') for item in raw_events),
            'passwords': _top_counts(item.get('password') for item in raw_events),
            'commands': _top_counts(item.get('command') for item in raw_events),
            'paths': _top_counts((item.get('path') or item.get('uri')) for item in raw_events),
            'user_agents': _top_counts(item.get('user_agent') for item in raw_events),
            'sessions': _top_counts(item.get('session') for item in raw_events),
        },
        'discovery': aggregate_discovery(item.get('command') for item in raw_events),
        'timeline': timeline[-limit:],
    }


def _danger_score(level: Optional[str]) -> int:
    return {'Alto': 3, 'Medio': 2, 'Basso': 1}.get(level or '', 0)


def _parse_raw_event(row: Dict[str, Any]) -> Dict[str, Any]:
    try:
        raw_event = json.loads(row.get('raw_event_json') or '{}')
        return raw_event if isinstance(raw_event, dict) else {}
    except Exception:
        return {}


def _storyline_day(timestamp: Optional[str]) -> str:
    if not timestamp:
        return 'unknown-day'
    try:
        return datetime.fromisoformat(str(timestamp).replace('Z', '+00:00')).date().isoformat()
    except ValueError:
        return str(timestamp)[:10] or 'unknown-day'


def _storyline_key(row: Dict[str, Any], raw_event: Dict[str, Any]) -> str:
    ip = row.get('ip') or 'unknown'
    session = raw_event.get('session')
    if session:
        return f"{ip}|session|{session}"
    return f"{ip}|day|{_storyline_day(row.get('timestamp'))}"


def _storyline_title(story: Dict[str, Any]) -> str:
    attacks = story['attack_types']
    if 'Unauthorized Login' in attacks and 'Post-Login Activity' in attacks:
        return 'Compromissione interattiva SSH'
    if len(attacks) == 1:
        return attacks[0]
    return 'Sequenza multi-step'


def _min_timestamp(*values: Optional[str]) -> Optional[str]:
    cleaned = [value for value in values if value]
    return min(cleaned) if cleaned else None


def _max_timestamp(*values: Optional[str]) -> Optional[str]:
    cleaned = [value for value in values if value]
    return max(cleaned) if cleaned else None


def _storyline_summary(story: Dict[str, Any]) -> str:
    attacks = ', '.join(story['attack_types'])
    services = ', '.join(service.upper() for service in story['services'])
    return (
        f"{story['event_count']} incidente/i dallo stesso IP"
        f" su {services or 'servizi sconosciuti'}: {attacks}."
    )


def _top_counts(values: Iterable[Any], limit: int = 10) -> List[Dict[str, Any]]:
    counts: Dict[str, int] = {}
    for value in values:
        text = str(value or '').strip()
        if not text:
            continue
        counts[text] = counts.get(text, 0) + 1
    return [
        {'value': value, 'count': count}
        for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


def fetch_storylines(limit: int = 50) -> List[Dict[str, Any]]:
    rows = fetch_events(limit=max(limit * 10, limit))
    stories: Dict[str, Dict[str, Any]] = {}

    for row in sorted(rows, key=lambda item: (item.get('timestamp') or '', item.get('id') or 0)):
        raw_event = _parse_raw_event(row)
        key = _storyline_key(row, raw_event)
        story = stories.setdefault(key, {
            'storyline_id': key,
            'ip': row.get('ip'),
            'country': row.get('country'),
            'city': row.get('city'),
            'session': raw_event.get('session'),
            'first_seen': row.get('timestamp'),
            'last_seen': row.get('timestamp'),
            'event_count': 0,
            'danger_level': row.get('danger_level') or 'Basso',
            'risk_score': row.get('risk_score') or 0,
            'risk_level': row.get('risk_level') or 'Basso',
            'attack_types': [],
            'services': [],
            'events': [],
        })

        attack_type = row.get('attack_type') or 'Unknown'
        service = row.get('service') or 'unknown'
        if attack_type not in story['attack_types']:
            story['attack_types'].append(attack_type)
        if service not in story['services']:
            story['services'].append(service)
        if _danger_score(row.get('danger_level')) > _danger_score(story.get('danger_level')):
            story['danger_level'] = row.get('danger_level') or story['danger_level']
        if int(row.get('risk_score') or 0) > int(story.get('risk_score') or 0):
            story['risk_score'] = int(row.get('risk_score') or 0)
            story['risk_level'] = row.get('risk_level') or _risk_band(story['risk_score'])

        story['event_count'] += 1
        story['first_seen'] = _min_timestamp(story.get('first_seen'), row.get('timestamp'))
        story['last_seen'] = _max_timestamp(story.get('last_seen'), row.get('timestamp'))
        story['events'].append({
            'id': row.get('id'),
            'timestamp': row.get('timestamp'),
            'attack_type': attack_type,
            'service': service,
            'danger_level': row.get('danger_level') or 'Basso',
            'risk_score': row.get('risk_score') or 0,
            'risk_level': row.get('risk_level') or 'Basso',
            'explanation_it': row.get('explanation_it'),
            'advice': row.get('advice'),
        })

    result = []
    for story in stories.values():
        story['title'] = _storyline_title(story)
        story['summary'] = _storyline_summary(story)
        story['events'] = sorted(
            story['events'],
            key=lambda event: (event.get('timestamp') or '', event.get('id') or 0),
        )
        result.append(story)

    return sorted(
        result,
        key=lambda story: (
            _danger_score(story.get('danger_level')),
            story.get('risk_score') or 0,
            story.get('last_seen') or '',
            story.get('event_count') or 0,
        ),
        reverse=True,
    )[:limit]


def fetch_ip_detail(ip: str, limit: int = 200) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        event_rows = conn.execute(
            '''
            SELECT * FROM events
            WHERE ip = ?
            ORDER BY datetime(timestamp) ASC, id ASC
            LIMIT ?
            ''',
            (ip, limit),
        ).fetchall()
        raw_rows = conn.execute(
            '''
            SELECT * FROM raw_events
            WHERE ip = ?
            ORDER BY datetime(timestamp) ASC, id ASC
            LIMIT ?
            ''',
            (ip, max(limit * 3, limit)),
        ).fetchall()

    if not event_rows and not raw_rows:
        return None

    raw_events = [_compact_raw_event(_row_dict(row)) for row in raw_rows]
    events = [_enrich_event_risk(dict(row), raw_events=raw_events) for row in event_rows]
    all_timestamps = [
        item.get('timestamp')
        for item in [*events, *raw_events]
        if item.get('timestamp')
    ]

    services = sorted({str(item.get('service') or 'unknown') for item in [*events, *raw_events]})
    attack_types = sorted({str(item.get('attack_type') or 'Unknown') for item in events})
    countries = [event.get('country') for event in events if event.get('country')]
    cities = [event.get('city') for event in events if event.get('city')]
    danger_levels = [event.get('danger_level') for event in events]
    risk_score = min(
        100,
        max([int(event.get('risk_score') or 0) for event in events] or [0])
        + min(18, max(0, len(events) - 1) * 4)
        + min(12, max(0, len(services) - 1) * 6)
        + min(10, max(0, len(raw_events) - 5)),
    )

    timeline = []
    for event in events:
        timeline.append({
            'kind': 'incident',
            'id': event.get('id'),
            'timestamp': event.get('timestamp'),
            'service': event.get('service'),
            'attack_type': event.get('attack_type'),
            'danger_level': event.get('danger_level') or 'Basso',
            'summary': event.get('explanation_it') or event.get('attack_type') or '',
        })
    for raw in raw_events:
        timeline.append({
            'kind': 'raw',
            'id': raw.get('id'),
            'timestamp': raw.get('timestamp'),
            'service': raw.get('service'),
            'attack_type': raw.get('eventid') or raw.get('event_type') or 'Raw Event',
            'danger_level': None,
            'summary': raw.get('summary') or '',
        })

    timeline = sorted(
        timeline,
        key=lambda item: (item.get('timestamp') or '', 0 if item.get('kind') == 'raw' else 1, item.get('id') or 0),
    )[:limit]

    return {
        'ip': ip,
        'country': countries[-1] if countries else 'Unknown',
        'city': cities[-1] if cities else 'Unknown',
        'first_seen': min(all_timestamps) if all_timestamps else None,
        'last_seen': max(all_timestamps) if all_timestamps else None,
        'event_count': len(events),
        'raw_event_count': len(raw_events),
        'danger_level': max(danger_levels, key=_danger_score) if danger_levels else 'Basso',
        'risk_score': risk_score,
        'risk_level': _risk_band(risk_score),
        'services': services,
        'attack_types': attack_types,
        'top_usernames': _top_counts(raw.get('username') for raw in raw_events),
        'top_passwords': _top_counts(raw.get('password') for raw in raw_events),
        'top_commands': _top_counts(raw.get('command') for raw in raw_events),
        'top_paths': _top_counts((raw.get('path') or raw.get('uri')) for raw in raw_events),
        'top_user_agents': _top_counts((raw.get('user_agent') for raw in raw_events), limit=8),
        'discovery': aggregate_discovery(raw.get('command') for raw in raw_events),
        'events': events[-limit:],
        'raw_events': raw_events[-limit:],
        'timeline': timeline,
    }


def fetch_stats() -> Dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute('''
            SELECT 
              COUNT(*) as total,
              SUM(CASE WHEN danger_level = 'Alto' THEN 1 ELSE 0 END) as high,
              SUM(CASE WHEN danger_level = 'Medio' THEN 1 ELSE 0 END) as medium,
              COUNT(DISTINCT CASE WHEN country NOT IN ('Local', 'Unknown') THEN country END) as countries
            FROM events
        ''').fetchone()
    return {
        'total': row['total'] or 0,
        'high': row['high'] or 0,
        'medium': row['medium'] or 0,
        'countries': row['countries'] or 0,
    }


def fetch_attack_distribution() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute('''
            SELECT attack_type, COUNT(*) AS count
            FROM events
            GROUP BY attack_type
            ORDER BY count DESC, attack_type ASC
        ''').fetchall()
    return [dict(r) for r in rows]


def fetch_map_points() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute('''
            SELECT 
              lat, lon, country, city, attack_type,
              MIN(ip) as sample_ip,
              MIN(service) as sample_service,
              MAX(danger_level) as danger_level,
              COUNT(*) as count
            FROM events
            WHERE lat IS NOT NULL AND lon IS NOT NULL
            GROUP BY lat, lon, country, city, attack_type
            ORDER BY count DESC
        ''').fetchall()
    return [dict(r) for r in rows]
