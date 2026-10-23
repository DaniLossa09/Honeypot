import json
import hashlib
import ipaddress
import logging
import os
from datetime import datetime, timezone
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .utils import extract_ip, normalize_timestamp, safe_json_loads


_log = logging.getLogger(__name__)


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


def _read_new_lines(path: Path, offset: int, state: Optional[dict] = None) -> tuple[list[str], int]:
    if not path.exists() or not path.is_file():
        return [], 0

    with path.open('rb') as f:
        info = os.fstat(f.fileno())
        identity = [info.st_dev, info.st_ino]
        if state and state.get('identity') != identity:
            offset = 0
        if offset > info.st_size or offset < 0:
            offset = 0
        if state and offset and state.get('offset') == offset:
            f.seek(max(0, offset - 128))
            anchor = hashlib.sha256(f.read(min(offset, 128))).hexdigest()
            if state.get('anchor') != anchor:
                offset = 0
        f.seek(offset)
        data = f.read()
        # Metadati e byte provengono dallo stesso file descriptor.
        last_complete = data.rfind(b'\n')
        end = offset + last_complete + 1 if last_complete >= 0 else offset
        if state is not None:
            f.seek(max(0, end - 128))
            state.update(identity=identity, offset=end,
                         anchor=hashlib.sha256(f.read(min(end, 128))).hexdigest())

    last_nl = data.rfind(b'\n')
    if last_nl == -1:
        # nessuna riga completa ancora disponibile: non avanzare l'offset
        return [], offset

    complete = data[:last_nl + 1]
    new_offset = offset + len(complete)
    lines = complete.decode('utf-8', errors='ignore').splitlines()
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



def _validate_hex(value):
    if value is not None and (not isinstance(value, str) or len(value) > 32768 or len(value) % 2 or not re.fullmatch('[0-9a-fA-F]*', value)):
        raise ValueError('Invalid protocol hex payload')


def _validate_scada_data(data):
    if not isinstance(data, dict):
        raise ValueError('SCADA data must be an object')
    for key in ('function', 'function_code', 'pdu_type'):
        if key in data and (not isinstance(data[key], str) or len(data[key]) > 128):
            raise ValueError('Invalid operation')
    for key in ('unit_id', 'transaction_id', 'fc', 'start_address', 'quantity', 'value',
                'write_address', 'write_quantity', 'db_number', 'area', 'word_length', 'result_code', 'exception_code'):
        if key in data and (type(data[key]) is not int or not 0 <= data[key] <= 0xFFFFFF):
            raise ValueError('Invalid operation number')
    for key in ('request_hex', 'response_hex', 'values_hex'):
        _validate_hex(data.get(key))
    if 'values' in data and (not isinstance(data['values'], list) or len(data['values']) > 2000 or
                            any(type(v) not in (bool, int) or not 0 <= v <= 65535 for v in data['values'])):
        raise ValueError('Invalid register values')


def _validated_traffic_object(source: str, obj: dict) -> tuple[str, str]:
    if not isinstance(obj, dict) or not obj:
        raise ValueError('JSON object required')
    value = obj.get('timestamp') or obj.get('time') or obj.get('@timestamp')
    if not isinstance(value, str):
        raise ValueError('Timestamp required')
    timestamp = normalize_timestamp(value)
    if not timestamp:
        raise ValueError('Invalid timestamp')
    dt = datetime.fromisoformat(timestamp)
    timestamp = dt.replace(tzinfo=dt.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat()
    ip = obj.get('src_ip') or obj.get('remote_ip') or obj.get('client_ip') or obj.get('remote_host')
    if not isinstance(ip, str):
        raise ValueError('Source IP required')
    ip = str(ipaddress.ip_address(ip))
    for key in ('src_port', 'dst_port', 'remote_port', 'local_port', 'port'):
        value = obj.get(key)
        if value is not None and (type(value) is not int or not 1 <= value <= 65535):
            raise ValueError('Invalid port')
    for key in ('eventid', 'protocol', 'message', 'username', 'password', 'input',
                'command', 'argument', 'arg', 'session', 'action', 'user', 'service', 'event', 'msg',
                'database', 'query', 'data_type', 'event_id', 'reason', 'outcome'):
        value = obj.get(key)
        if key == 'message' and source == 'cowrie' and obj.get('eventid') == 'cowrie.session.params' and isinstance(value, list):
            if len(value) > 256 or any(not isinstance(item, str) or len(item) > 65536 for item in value):
                raise ValueError('Invalid session parameters message')
            continue
        if value is not None and (not isinstance(value, str) or len(value) > 65536):
            raise ValueError('Invalid text field')
    if source == 'cowrie':
        if not obj.get('eventid') or (obj.get('protocol') or '').lower() not in {'', 'ssh', 'telnet'}:
            raise ValueError('Invalid Cowrie event or protocol')
    elif source == 'ftp':
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}', obj.get('command') or obj.get('action') or ''):
            raise ValueError('Invalid FTP command')
    elif source in {'mysql', 'scada'}:
        if not isinstance(obj.get('event'), str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', obj['event']):
            raise ValueError('Invalid protocol event')
        if obj.get('event_id') is not None and not re.fullmatch(r'[0-9a-f]{32}', obj['event_id']):
            raise ValueError('Invalid event identity')
        for key in ('request_hex', 'response_hex'):
            _validate_hex(obj.get(key))
        if source == 'scada':
            protocol = obj.get('data_type') or obj.get('protocol') or obj.get('session_type')
            if protocol not in {'modbus', 's7comm', 'enip', 'bacnet'}:
                raise ValueError('Invalid SCADA protocol')
            _validate_scada_data(obj.get('data', {}))
    return ip, timestamp


def parse_cowrie_line(line: str) -> Optional[Dict[str, Any]]:
    obj = safe_json_loads(line)
    ip, timestamp = _validated_traffic_object('cowrie', obj)
    protocol = str(obj.get('protocol') or '').lower()
    message = obj.get('message') or obj.get('eventid') or ''
    if isinstance(message, list):
        message = json.dumps(message, ensure_ascii=False)
    return {
        'timestamp': timestamp,
        'source': 'cowrie',
        'ip': ip,
        'port': obj.get('dst_port') or (23 if protocol == 'telnet' else 22),
        'src_port': obj.get('src_port'), 'dst_port': obj.get('dst_port'),
        'service': protocol if protocol in {'ssh', 'telnet'} else 'ssh',
        'message': message,
        'eventid': obj.get('eventid'),
        'username': obj.get('username'),
        'password': obj.get('password'),
        'command': (obj.get('input') or obj.get('command')) if obj.get('eventid') == 'cowrie.command.input' else None,
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
    if not obj:
        raise ValueError('OpenCanary: JSON object required')
    logtype = obj.get('logtype')
    if type(logtype) is not int or logtype <= 0:
        raise ValueError('OpenCanary: invalid logtype')
    logdata = obj.get('logdata', {})
    if not isinstance(logdata, dict):
        raise ValueError('OpenCanary: logdata must be an object')
    for key in ('REQUEST', 'PATH', 'USERNAME', 'PASSWORD', 'USERAGENT',
                'User-Agent', 'REMOTE_ADDR', 'SERVICE_NAME', 'QUERY_STRING'):
        if key in logdata and (not isinstance(logdata[key], str) or len(logdata[key]) > 65536):
            raise ValueError('OpenCanary: invalid text field')
    ip = obj.get('src_host') or logdata.get('REMOTE_ADDR')
    if ip:
        if not isinstance(ip, str):
            raise ValueError('OpenCanary: invalid source IP')
        ip = str(ipaddress.ip_address(ip))
    elif logtype != 1001:
        raise ValueError('OpenCanary: source IP required')
    port = obj.get('dst_port', obj.get('src_port', logdata.get('PORT')))
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        if logtype == 1001 and port == -1:
            port = None
        else:
            raise ValueError('OpenCanary: invalid destination port')
    timestamp = obj.get('utc_time') or obj.get('local_time') or obj.get('timestamp')
    if timestamp is not None and not isinstance(timestamp, str):
        raise ValueError('OpenCanary: invalid timestamp type')
    timestamp = normalize_timestamp(timestamp)
    if timestamp:
        dt = datetime.fromisoformat(timestamp)
        timestamp = dt.replace(tzinfo=dt.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat()
    elif obj.get('utc_time') or obj.get('local_time') or obj.get('timestamp'):
        raise ValueError('OpenCanary: invalid timestamp')
    else:
        raise ValueError('OpenCanary: timestamp required')
    request = logdata.get('REQUEST') or logdata.get('PATH') or ''
    service = str(logdata.get('SERVICE_NAME') or '').lower()
    if not service and port in {80, 443}:
        service = 'https' if port == 443 else 'http'
    if logtype not in {1001, 3000, 3001, 3002, 3003, 5001, 5002, 5003, 5004, 5005}:
        _log.warning('OpenCanary logtype non classificato: %d (conservato nei raw)', logtype)
    return {
        'timestamp': timestamp, 'source': 'opencanary', 'ip': ip,
        'port': port, 'service': service or str(logtype),
        'message': str(logtype), 'event_type': logtype,
        'uri': request, 'path': logdata.get('PATH') or request,
        'username': logdata.get('USERNAME'), 'password': logdata.get('PASSWORD'),
        'user_agent': logdata.get('USERAGENT') or logdata.get('User-Agent'),
        'raw_payload': json.dumps(obj, ensure_ascii=False), 'raw_event': obj,
    }


def validate_opencanary_record(record: Dict[str, Any]) -> None:
    """Contratto comune verificato anche da classifier e scrittura DB."""
    if record.get('source') not in {'opencanary', 'portscan'}:
        return
    for key in ('timestamp', 'source', 'service', 'message', 'uri', 'path', 'raw_payload'):
        if not isinstance(record.get(key), str):
            raise ValueError('OpenCanary: invalid normalized text')
    if type(record.get('event_type')) is not int:
        raise ValueError('OpenCanary: invalid normalized logtype')
    if not isinstance(record.get('raw_event'), dict):
        raise ValueError('OpenCanary: invalid normalized raw event')
    if datetime.fromisoformat(record['timestamp']).tzinfo is None:
        raise ValueError('OpenCanary: timezone required')
    if record.get('ip'):
        ipaddress.ip_address(record['ip'])
    elif record['event_type'] != 1001:
        raise ValueError('OpenCanary: source IP required')
    port = record.get('port')
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError('OpenCanary: invalid normalized port')
    for key in ('username', 'password', 'user_agent'):
        if record.get(key) is not None and not isinstance(record[key], str):
            raise ValueError('OpenCanary: invalid normalized field')


def validate_record(record: Dict[str, Any]) -> None:
    validate_opencanary_record(record)
    source = record.get('source')
    if source not in {'cowrie', 'ftp', 'mysql', 'scada'}:
        return
    ip, timestamp = _validated_traffic_object(source, record.get('raw_event'))
    if record.get('ip') != ip or record.get('timestamp') != timestamp:
        raise ValueError('Inconsistent normalized identity or timestamp')
    for key in ('service', 'message', 'raw_payload'):
        if not isinstance(record.get(key), str):
            raise ValueError('Invalid normalized text')
    for key in ('username', 'password', 'command', 'argument'):
        if record.get(key) is not None and not isinstance(record[key], str):
            raise ValueError('Invalid normalized field')
    for key in ('port', 'src_port', 'dst_port'):
        value = record.get(key)
        if value is not None and (type(value) is not int or not 1 <= value <= 65535):
            raise ValueError('Invalid normalized port')


def parse_ftp_line(line: str) -> Optional[Dict[str, Any]]:
    obj = safe_json_loads(line)
    ip, timestamp = _validated_traffic_object('ftp', obj)
    command = (obj.get('command') or obj.get('action')).upper()
    argument = obj.get('argument') or obj.get('arg') or ''
    return {
        'timestamp': timestamp, 'source': 'ftp', 'ip': ip,
        'port': obj.get('dst_port') or obj.get('port') or 21,
        'src_port': obj.get('src_port') or obj.get('remote_port'),
        'dst_port': obj.get('dst_port'),
        'service': 'ftp', 'message': obj.get('message') or obj.get('msg') or command,
        'username': obj.get('username') or obj.get('user') or (argument if command == 'USER' else None),
        'password': obj.get('password') or (argument if command == 'PASS' else None),
        'command': command, 'argument': argument,
        'raw_payload': json.dumps(obj, ensure_ascii=False), 'raw_event': obj,
    }


def parse_mysql_line(line: str) -> Optional[Dict[str, Any]]:
    obj = safe_json_loads(line)
    ip, timestamp = _validated_traffic_object('mysql', obj)
    event = obj['event']
    return {
        'timestamp': timestamp, 'source': 'mysql', 'ip': ip,
        'port': obj.get('dst_port') or 3306,
        'src_port': obj.get('src_port'), 'dst_port': obj.get('dst_port'),
        'service': 'mysql', 'message': event, 'eventid': event,
        'username': obj.get('username'), 'argument': obj.get('query') or obj.get('database') or '',
        'command': event.upper() if event in {'login_attempt', 'query'} else None,
        'raw_payload': json.dumps(obj, ensure_ascii=False), 'raw_event': obj,
    }


def parse_smb_line(line: str) -> Optional[Dict[str, Any]]:
    obj = safe_json_loads(line)
    if not obj:
        return None
    event = str(obj.get('event') or '').lower()
    username = obj.get('username')
    domain = obj.get('domain') or ''
    full_user = f"{domain}\\{username}" if domain and username else (username or None)
    return {
        'timestamp': normalize_timestamp(obj.get('timestamp')),
        'source': 'smb',
        'ip': extract_ip(obj.get('src_ip'), obj.get('remote_ip'), obj),
        'port': _coerce_port(obj.get('src_port') or obj.get('dst_port')) or 445,
        'service': 'smb',
        'message': event,
        'eventid': event,
        'username': full_user,
        'command': event.upper() if event else None,
        'raw_payload': json.dumps(obj, ensure_ascii=False),
        'raw_event': obj,
    }


def parse_scada_line(line: str) -> Optional[Dict[str, Any]]:
    obj = safe_json_loads(line)
    ip, timestamp = _validated_traffic_object('scada', obj)
    protocol = obj.get('data_type') or obj.get('protocol') or obj.get('session_type')
    port = obj.get('dst_port') or obj.get('local_port')
    data = obj.get('data', {})
    command = data.get('function') or data.get('function_code')
    return {
        'timestamp': timestamp, 'source': 'scada', 'ip': ip,
        'port': port or {'modbus': 502, 's7comm': 102, 'enip': 44818, 'bacnet': 47808}[protocol],
        'src_port': obj.get('src_port') or obj.get('remote_port'), 'dst_port': port,
        'service': protocol, 'message': obj.get('message') or obj['event'], 'eventid': obj['event'],
        'command': command.upper() if command else None,
        'argument': json.dumps(data, ensure_ascii=False) if data else '',
        'raw_payload': json.dumps(obj, ensure_ascii=False), 'raw_event': obj,
    }


def parse_portscan_line(line: str) -> Dict[str, Any]:
    record = parse_opencanary_line(line)
    if record['event_type'] != 5001 or record['service'] != 'portscan':
        raise ValueError('Host sensor: invalid port scan event')
    record['source'] = 'portscan'
    return record


PARSERS = {
    'portscan': parse_portscan_line,
    'cowrie': parse_cowrie_line,
    'opencanary': parse_opencanary_line,
    'dionaea': parse_dionaea_line,
    'ftp': parse_ftp_line,
    'mysql': parse_mysql_line,
    'smb': parse_smb_line,
    'scada': parse_scada_line,
}


def read_incremental(source: str, path_str: str, offset: int, state: Optional[dict] = None) -> tuple[list[dict], int]:
    path = Path(path_str)
    lines, new_offset = _read_new_lines(path, offset, state)
    parser = PARSERS[source]
    parsed: List[Dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        clean = line.strip()
        if not clean:
            continue
        try:
            rec = parser(clean)
            if rec:
                validate_record(rec)
                parsed.append(rec)
        except Exception as exc:
            # Non stampare payload o messaggi di errore controllati dall'attaccante.
            _log.warning('Riga rifiutata: source=%s batch_line=%d error=%s',
                         source, line_number, type(exc).__name__)
            continue
    return parsed, new_offset
