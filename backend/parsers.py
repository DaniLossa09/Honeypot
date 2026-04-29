import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .utils import extract_ip, normalize_timestamp, safe_json_loads


KV_RE = re.compile(r'(\w+)=((?:"[^"]+")|\S+)')


def _coerce_port(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    match = re.search(r'\b(\d{1,5})\b', text)
    if not match:
        return None
    port = int(match.group(1))
    return port if 0 < port <= 65535 else None


def _read_new_lines(path: Path, offset: int) -> tuple[list[str], int]:
    if not path.exists() or not path.is_file():
        return [], 0

    size = path.stat().st_size
    if offset > size:
        offset = 0

    with path.open('r', encoding='utf-8', errors='ignore') as f:
        f.seek(offset)
        lines = f.readlines()
        new_offset = f.tell()
    return lines, new_offset



def _from_text_line(source: str, line: str) -> Dict[str, Any]:
    kv = {k: v.strip('"') for k, v in KV_RE.findall(line)}
    message = line.strip()
    lowered = message.lower()
    ip = extract_ip(
        kv.get('src_host'),
        kv.get('src'),
        kv.get('remote_host'),
        kv.get('client'),
        kv.get('ip'),
        line,
    )
    port = _coerce_port(kv.get('dst_port') or kv.get('port') or kv.get('src_port'))
    service = kv.get('logtype') or kv.get('service') or kv.get('proto') or ('ftp' if 'ftp' in lowered else '')
    record = {
        'timestamp': normalize_timestamp(kv.get('utc_time') or kv.get('timestamp')),
        'source': source,
        'ip': ip,
        'port': port,
        'service': service.lower(),
        'message': message,
        'raw_payload': message,
        'raw_event': {'line': line, 'parsed_kv': kv},
    }
    return record



def parse_cowrie_line(line: str) -> Optional[Dict[str, Any]]:
    obj = safe_json_loads(line)
    if not obj:
        return None
    protocol = str(obj.get('protocol') or '').lower()
    return {
        'timestamp': normalize_timestamp(obj.get('timestamp')),
        'source': 'cowrie',
        'ip': obj.get('src_ip') or extract_ip(obj),
        'port': _coerce_port(obj.get('src_port') or obj.get('dst_port')) or 22,
        'service': protocol if protocol in {'ssh', 'telnet'} else 'ssh',
        'message': obj.get('message') or obj.get('eventid') or '',
        'eventid': obj.get('eventid'),
        'username': obj.get('username'),
        'password': obj.get('password'),
        'command': obj.get('input') or obj.get('command'),
        'protocol': protocol,
        'raw_payload': json.dumps(obj, ensure_ascii=False),
        'raw_event': obj,
    }



def parse_dionaea_line(line: str) -> Optional[Dict[str, Any]]:
    obj = safe_json_loads(line)
    if not obj:
        return None
    connection = obj.get('connection', {}) if isinstance(obj.get('connection'), dict) else {}
    offer = obj.get('offer', {}) if isinstance(obj.get('offer'), dict) else {}
    return {
        'timestamp': normalize_timestamp(obj.get('timestamp') or obj.get('time')),
        'source': 'dionaea',
        'ip': extract_ip(obj.get('src_ip'), connection.get('remote_host'), obj),
        'port': _coerce_port(obj.get('dst_port') or connection.get('local_port') or obj.get('port')),
        'service': str(obj.get('service') or obj.get('protocol') or offer.get('type') or '').lower(),
        'message': obj.get('message') or obj.get('type') or '',
        'protocol': obj.get('protocol'),
        'raw_payload': json.dumps(obj, ensure_ascii=False),
        'raw_event': obj,
    }



def parse_opencanary_line(line: str) -> Optional[Dict[str, Any]]:
    obj = safe_json_loads(line)
    if obj:
        logdata = obj.get('logdata', {}) if isinstance(obj.get('logdata'), dict) else {}
        port = _coerce_port(obj.get('dst_port') or obj.get('src_port') or logdata.get('PORT'))
        request = logdata.get('REQUEST') or logdata.get('PATH') or ''
        service = str(logdata.get('SERVICE_NAME') or '').lower()
        if not service and port in {80, 443}:
            service = 'https' if port == 443 else 'http'
        return {
            'timestamp': normalize_timestamp(obj.get('local_time') or obj.get('utc_time') or obj.get('timestamp')),
            'source': 'opencanary',
            'ip': obj.get('src_host') or logdata.get('REMOTE_ADDR') or extract_ip(obj),
            'port': port,
            'service': service or str(obj.get('logtype') or '').lower(),
            'message': obj.get('logtype') or request or line.strip(),
            'event_type': obj.get('logtype'),
            'uri': request,
            'path': logdata.get('PATH') or request,
            'username': logdata.get('USERNAME'),
            'password': logdata.get('PASSWORD'),
            'user_agent': logdata.get('USERAGENT') or logdata.get('User-Agent'),
            'raw_payload': json.dumps(obj, ensure_ascii=False),
            'raw_event': obj,
        }
    return _from_text_line('opencanary', line)


def parse_ftp_line(line: str) -> Optional[Dict[str, Any]]:
    obj = safe_json_loads(line)
    if obj:
        command = str(obj.get('command') or obj.get('action') or '').upper()
        argument = obj.get('argument') or obj.get('arg') or ''
        message = str(
            obj.get('message')
            or obj.get('msg')
            or obj.get('event')
            or command
            or obj.get('status')
            or ''
        )
        return {
            'timestamp': normalize_timestamp(obj.get('timestamp') or obj.get('time') or obj.get('@timestamp')),
            'source': 'ftp',
            'ip': extract_ip(obj.get('src_ip'), obj.get('remote_ip'), obj.get('client_ip'), obj),
            'port': _coerce_port(obj.get('port') or obj.get('dst_port') or obj.get('remote_port')) or 21,
            'service': str(obj.get('service') or 'ftp').lower(),
            'message': message or line.strip(),
            'username': obj.get('username') or obj.get('user') or (argument if command == 'USER' else None),
            'password': obj.get('password') or (argument if command == 'PASS' else None),
            'command': command,
            'argument': argument,
            'raw_payload': json.dumps(obj, ensure_ascii=False),
            'raw_event': obj,
        }

    record = _from_text_line('ftp', line)
    record['service'] = record.get('service') or 'ftp'
    record['port'] = record.get('port') or 21
    return record


PARSERS = {
    'cowrie': parse_cowrie_line,
    'opencanary': parse_opencanary_line,
    'dionaea': parse_dionaea_line,
    'ftp': parse_ftp_line,
}


def read_incremental(source: str, path_str: str, offset: int) -> tuple[list[dict], int]:
    path = Path(path_str)
    lines, new_offset = _read_new_lines(path, offset)
    parser = PARSERS[source]
    parsed: List[Dict[str, Any]] = []
    for line in lines:
        clean = line.strip()
        if not clean:
            continue
        try:
            rec = parser(clean)
            if rec:
                parsed.append(rec)
        except Exception:
            # scarta solo la riga corrotta, senza bloccare l'intero ciclo
            continue
    return parsed, new_offset
