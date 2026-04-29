import os
import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterable, List, Optional

from .config import DB_PATH

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
