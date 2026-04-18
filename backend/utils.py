import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional


IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8', errors='ignore')).hexdigest()



def normalize_timestamp(value: Any) -> Optional[str]:
    if not value:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    text = str(value).strip()
    text = text.replace('Z', '+00:00')
    try:
        return datetime.fromisoformat(text).isoformat()
    except ValueError:
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%b %d %H:%M:%S',
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(text, fmt)
                if fmt == '%b %d %H:%M:%S':
                    dt = dt.replace(year=datetime.now().year)
                return dt.replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                continue
    return None



def safe_json_loads(line: str) -> Optional[Dict[str, Any]]:
    try:
        obj = json.loads(line)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None



def extract_ip(*values: Any) -> Optional[str]:
    for value in values:
        if value is None:
            continue
        if isinstance(value, dict):
            nested = extract_ip(*value.values())
            if nested:
                return nested
        elif isinstance(value, (list, tuple, set)):
            nested = extract_ip(*value)
            if nested:
                return nested
        else:
            text = str(value)
            for match in IP_REGEX.findall(text):
                try:
                    ipaddress.ip_address(match)
                    return match
                except ValueError:
                    continue
    return None



def is_local_ip(ip: Optional[str]) -> bool:
    if not ip:
        return True
    if ip == 'localhost':
        return True
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved
    except ValueError:
        return True
