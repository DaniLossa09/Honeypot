import os
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterable, List, Optional

from .config import DB_PATH
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

def reset_events():
	"""Cancella tutti gli eventi dal database e resetta il file JSON"""
	with get_conn() as conn:
		conn.execute("DELETE FROM events")
		conn.commit()

	data_dir = os.path.dirname(DB_PATH)
	json_path = os.path.join(data_dir, "events.json")
	with open(json_path, "w") as f:
		json.dump([], f)

	print("[DB] Database e events.json azzerati.")


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA)
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
        explanation_it, advice, raw_event_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    '''
    values = (
        event['event_hash'], event.get('timestamp'), event.get('source'), event.get('ip'),
        event.get('port'), event.get('service'), event.get('raw_payload'),
        event.get('attack_type'), event.get('country'), event.get('city'),
        event.get('lat'), event.get('lon'), event.get('danger_level'),
        event.get('explanation_it'), event.get('advice'),
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
            if (
                row['event_hash'] != new_hash
                or row['attack_type'] != attack_type
                or row['danger_level'] != explanation.get('danger_level')
                or row['explanation_it'] != explanation.get('explanation_it')
                or row['advice'] != explanation.get('advice')
            ):
                conn.execute(
                    '''
                    UPDATE events
                    SET event_hash = ?, attack_type = ?, danger_level = ?, explanation_it = ?, advice = ?
                    WHERE id = ?
                    ''',
                    (
                        new_hash,
                        attack_type,
                        explanation.get('danger_level'),
                        explanation.get('explanation_it'),
                        explanation.get('advice'),
                        row['id'],
                    ),
                )
                updated += 1
        conn.commit()

    return {'removed': removed, 'updated': updated}


def fetch_events(limit: int = 200) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            'SELECT * FROM events ORDER BY datetime(timestamp) DESC, id DESC LIMIT ?',
            (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def fetch_event_by_id(event_id: int) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        row = conn.execute('SELECT * FROM events WHERE id = ?', (event_id,)).fetchone()
    return dict(row) if row else None


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

    return {'event': event, 'raw_events': raw_events}


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

        story['event_count'] += 1
        story['first_seen'] = _min_timestamp(story.get('first_seen'), row.get('timestamp'))
        story['last_seen'] = _max_timestamp(story.get('last_seen'), row.get('timestamp'))
        story['events'].append({
            'id': row.get('id'),
            'timestamp': row.get('timestamp'),
            'attack_type': attack_type,
            'service': service,
            'danger_level': row.get('danger_level') or 'Basso',
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
            story.get('last_seen') or '',
            story.get('event_count') or 0,
        ),
        reverse=True,
    )[:limit]


def fetch_stats() -> Dict[str, Any]:
    with get_conn() as conn:
        row = conn.execute('''
            SELECT 
              COUNT(*) as total,
              SUM(CASE WHEN danger_level = 'Alto' THEN 1 ELSE 0 END) as high,
              SUM(CASE WHEN danger_level = 'Medio' THEN 1 ELSE 0 END) as medium,
              COUNT(DISTINCT country) as countries
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
