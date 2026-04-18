import re
from typing import Any, Dict

SQLI_PATTERNS = [
    r"\bunion\s+select\b", r"\bselect\b.+\bfrom\b", r"\bor\s+1=1\b",
    r"information_schema", r"sleep\s*\(", r"benchmark\s*\(", r"'\s*or\s*'1'='1",
]
XSS_PATTERNS = [
    r"<script", r"javascript:", r"onerror=", r"onload=", r"alert\s*\(", r"document\.cookie",
]
CMD_PATTERNS = [
    r"\bwget\b", r"\bcurl\b", r"/bin/sh", r"/bin/bash", r"\bchmod\b", r"\bchmod\s+\+x\b",
    r"\bnc\b", r"\bnetcat\b", r"\bsh\s+-c\b", r";\s*(wget|curl|cat|bash|sh)",
]
MALWARE_PATTERNS = [r"\.exe\b", r"\.dll\b", r"\.elf\b", r"payload", r"shellcode", r"malware"]
CRAWL_PATTERNS = [r"nikto", r"nmap", r"masscan", r"gobuster", r"dirbuster", r"sqlmap", r"scanner", r"crawler"]

BRUTE_WORDS = {'login failed', 'failed password', 'invalid password', 'authentication failed', 'login attempt'}
FTP_WORDS = {'ftp', 'user', 'pass', 'stor', 'retr', 'vsftpd', 'proftpd', 'filezilla'}


def _text(record: Dict[str, Any]) -> str:
    parts = [
        str(record.get('message', '')), str(record.get('raw_payload', '')), str(record.get('service', '')),
        str(record.get('eventid', '')), str(record.get('event_type', '')), str(record.get('command', '')),
        str(record.get('username', '')), str(record.get('password', '')), str(record.get('uri', '')),
        str(record.get('path', '')), str(record.get('user_agent', '')), str(record.get('source', '')),
        str(record.get('protocol', '')), str(record.get('port', '')),
    ]
    return ' '.join(parts).lower()


def _match_any(patterns, text: str) -> bool:
    return any(re.search(p, text, flags=re.IGNORECASE) for p in patterns)


def classify_attack(record: Dict[str, Any]) -> str:
    text = _text(record)
    port = int(record.get('port') or 0)
    service = (record.get('service') or '').lower()

    if any(word in text for word in BRUTE_WORDS) or ('cowrie.login.failed' in text):
        return 'Brute Force'
    if _match_any(SQLI_PATTERNS, text):
        return 'SQL Injection'
    if _match_any(XSS_PATTERNS, text):
        return 'XSS Attack'
    if _match_any(CMD_PATTERNS, text):
        return 'Command Injection'
    if 'smb' in service or port == 445:
        if _match_any(MALWARE_PATTERNS, text) or 'download' in text:
            return 'Malware Upload'
        return 'SMB Attack'
    if 'ftp' in service or port == 21 or any(word in text for word in FTP_WORDS):
        return 'FTP Attack'
    if _match_any(CRAWL_PATTERNS, text) or 'user-agent' in text or '/wp-' in text or '/phpmyadmin' in text:
        return 'Web Crawl / Recon'
    if 'scan' in text or 'syn' in text or 'portprobe' in text:
        return 'Port Scan'
    if _match_any(MALWARE_PATTERNS, text):
        return 'Malware Upload'
    return 'Unknown'
