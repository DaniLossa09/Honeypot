import re
from typing import Any, Dict, Optional

SQLI_PATTERNS = [
    r"\bunion\s+select\b", r"\bselect\b.+\bfrom\b", r"\bor\s+1=1\b",
    r"information_schema", r"sleep\s*\(", r"benchmark\s*\(", r"'\s*or\s*'1'='1",
]
XSS_PATTERNS = [
    r"<script", r"javascript:", r"onerror=", r"onload=", r"alert\s*\(", r"document\.cookie",
]
IDOR_PATTERNS = [
    r"\b(user|account|customer|client|invoice|order)_?id=\d{1,12}\b",
    r"/(users|accounts|customers|clients|invoices|orders)/\d{1,12}\b",
    r"\b(id|uid)=0\b", r"\b(id|uid)=-1\b",
]
CMD_PATTERNS = [
    r"\bwget\b", r"\bcurl\b", r"/bin/sh", r"/bin/bash", r"\bchmod\b", r"\bchmod\s+\+x\b",
    r"\bnc\b", r"\bnetcat\b", r"\bsh\s+-c\b", r";\s*(wget|curl|cat|bash|sh)",
]
MALWARE_PATTERNS = [r"\.exe\b", r"\.dll\b", r"\.elf\b", r"payload", r"shellcode", r"malware"]
CRAWL_PATTERNS = [r"nikto", r"nmap", r"masscan", r"gobuster", r"dirbuster", r"sqlmap", r"scanner", r"crawler"]
SENSITIVE_WEB_PATHS = [
    r"/wp-", r"/wordpress", r"/phpmyadmin", r"/admin\b", r"/administrator\b",
    r"/\.env\b", r"/config\b", r"/backup\b", r"/boaform/", r"/cgi-bin/",
]

COWRIE_NOISE_EVENTS = {
    'cowrie.session.connect',
    'cowrie.session.closed',
    'cowrie.client.version',
    'cowrie.client.kex',
    'cowrie.client.size',
    'cowrie.client.var',
    'cowrie.session.params',
    'cowrie.log.closed',
    'cowrie.command.failed',
}

FTP_NOISE_COMMANDS = {'CONNECT', 'DISCONNECT', 'OPTS', 'SYST', 'FEAT', 'PWD', 'TYPE', 'QUIT', 'NOOP'}
FTP_TRANSFER_COMMANDS = {'STOR', 'APPE', 'RETR', 'DELE', 'RNFR', 'RNTO', 'SITE'}


def _text(record: Dict[str, Any]) -> str:
    parts = [
        str(record.get('message', '')), str(record.get('raw_payload', '')), str(record.get('service', '')),
        str(record.get('eventid', '')), str(record.get('event_type', '')), str(record.get('command', '')),
        str(record.get('username', '')), str(record.get('password', '')), str(record.get('uri', '')),
        str(record.get('path', '')), str(record.get('user_agent', '')), str(record.get('source', '')),
        str(record.get('protocol', '')), str(record.get('port', '')),
    ]
    return ' '.join(parts).lower()


def _raw(record: Dict[str, Any]) -> Dict[str, Any]:
    raw = record.get('raw_event')
    return raw if isinstance(raw, dict) else {}


def _match_any(patterns, text: str) -> bool:
    return any(re.search(p, text, flags=re.IGNORECASE) for p in patterns)


def _web_text(record: Dict[str, Any]) -> str:
    raw = _raw(record)
    logdata = raw.get('logdata', {}) if isinstance(raw.get('logdata'), dict) else {}
    parts = [
        str(record.get('uri') or ''),
        str(record.get('path') or ''),
        str(logdata.get('REQUEST') or ''),
        str(logdata.get('PATH') or ''),
        str(logdata.get('QUERY_STRING') or ''),
        str(logdata.get('USERNAME') or ''),
        str(logdata.get('PASSWORD') or ''),
    ]
    return ' '.join(parts).lower()


def _has_submitted_credentials(record: Dict[str, Any]) -> bool:
    raw = _raw(record)
    logdata = raw.get('logdata', {}) if isinstance(raw.get('logdata'), dict) else {}
    values = [
        record.get('username'),
        record.get('password'),
        logdata.get('USERNAME'),
        logdata.get('PASSWORD'),
    ]
    return any(str(value or '').strip() for value in values)


def _classify_cowrie(record: Dict[str, Any]) -> Optional[str]:
    eventid = str(record.get('eventid') or '').lower()
    command = str(record.get('command') or '').strip().lower()

    if eventid == 'cowrie.login.success':
        return 'Unauthorized Login'
    if eventid == 'cowrie.command.input':
        if not command or command in {'exit', 'logout'}:
            return None
        if _match_any(CMD_PATTERNS, command) or _match_any(MALWARE_PATTERNS, command):
            return 'Command Injection'
        return 'Post-Login Activity'
    if eventid in COWRIE_NOISE_EVENTS:
        return None
    return None


def _classify_ftp(record: Dict[str, Any]) -> Optional[str]:
    command = str(record.get('command') or '').strip().upper()
    argument = str(record.get('argument') or '').strip()

    if command in FTP_NOISE_COMMANDS:
        return None
    if command in FTP_TRANSFER_COMMANDS:
        return 'FTP Attack'
    if _match_any(CMD_PATTERNS, argument) or _match_any(MALWARE_PATTERNS, argument):
        return 'Command Injection'
    return None


def _classify_web(record: Dict[str, Any]) -> Optional[str]:
    raw = _raw(record)
    logtype = str(raw.get('logtype') or record.get('event_type') or '')
    web_text = _web_text(record)
    user_agent = str(record.get('user_agent') or '').lower()

    if logtype == '1001':
        return None
    if _match_any(SQLI_PATTERNS, web_text):
        return 'SQL Injection'
    if _match_any(XSS_PATTERNS, web_text):
        return 'XSS Attack'
    if _match_any(IDOR_PATTERNS, web_text):
        return 'IDOR Attempt'
    if _match_any(CMD_PATTERNS, web_text):
        return 'Command Injection'
    if _match_any(MALWARE_PATTERNS, web_text):
        return 'Malware Upload'
    if _match_any(CRAWL_PATTERNS, user_agent) or _match_any(CRAWL_PATTERNS, web_text):
        return 'Web Crawl / Recon'
    if _match_any(SENSITIVE_WEB_PATHS, web_text):
        return 'Web Crawl / Recon'
    return None


def classify_attack(record: Dict[str, Any]) -> Optional[str]:
    text = _text(record)
    port = int(record.get('port') or 0)
    service = (record.get('service') or '').lower()
    source = (record.get('source') or '').lower()

    if source == 'cowrie':
        return _classify_cowrie(record)
    if source == 'ftp' or service == 'ftp' or port == 21:
        return _classify_ftp(record)
    if source == 'opencanary' or service in {'http', 'https'} or port in {80, 443}:
        return _classify_web(record)
    if 'smb' in service or port == 445:
        if _match_any(MALWARE_PATTERNS, text) or 'download' in text:
            return 'Malware Upload'
        return 'SMB Attack'
    if re.search(r'\b(portscan|port scan|syn scan|portprobe)\b', text):
        return 'Port Scan'
    return None


def classify_signal(record: Dict[str, Any]) -> Optional[str]:
    source = (record.get('source') or '').lower()
    eventid = str(record.get('eventid') or '').lower()
    command = str(record.get('command') or '').strip().upper()
    raw = _raw(record)
    logtype = str(raw.get('logtype') or record.get('event_type') or '')

    if source == 'cowrie' and eventid == 'cowrie.login.failed':
        return 'Credential Attack'
    if source == 'ftp' and command in {'PASS', 'ACCT'} and str(record.get('argument') or '').strip():
        return 'Credential Attack'
    if source == 'opencanary' and logtype == '3001' and _has_submitted_credentials(record):
        return 'Credential Attack'
    return None
