"""Mapping tra le categorie di attacco interne e il framework MITRE ATT&CK.

Sottoinsieme vendorizzato di ATT&CK Enterprise (solo le entita usate da questo
honeypot: SSH/Telnet, web, FTP, credential access, recon). Nessuna chiamata
esterna: ID e nomi ufficiali sono cablati qui. Solo stdlib.

Principi:
- Il mapping e un livello AGGIUNTIVO: l'attack_type interno resta la categoria
  primaria, MITRE la arricchisce.
- Nessun ID inventato. Dove i log non bastano per una sub-technique affidabile,
  si lascia None ("non determinabile") invece di forzare un ID plausibile.
- `mitre_confidence` ('Alto'|'Medio'|'Basso'): 'Basso' = mapping approssimato
  (la technique non descrive esattamente l'attacco, es. IDOR/XSS/SMB).

Solo gli ID + la confidenza vengono salvati nel DB; nomi ufficiali e URL si
risolvono a read-time con `resolve_mitre` (DB normalizzato).
"""
import re
from typing import Any, Dict, Iterable, List, Optional

# --- Riferimento vendorizzato (ID -> nome ufficiale, in inglese) ------------
TACTICS: Dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0011": "Command and Control",
}

TECHNIQUES: Dict[str, str] = {
    "T1595": "Active Scanning",
    "T1190": "Exploit Public-Facing Application",
    "T1078": "Valid Accounts",
    "T1059": "Command and Scripting Interpreter",
    "T1110": "Brute Force",
    "T1210": "Exploitation of Remote Services",
    "T1105": "Ingress Tool Transfer",
    # Discovery (TA0007)
    "T1082": "System Information Discovery",
    "T1033": "System Owner/User Discovery",
    "T1087": "Account Discovery",
    "T1057": "Process Discovery",
    "T1016": "System Network Configuration Discovery",
    "T1049": "System Network Connections Discovery",
    "T1018": "Remote System Discovery",
    "T1083": "File and Directory Discovery",
    "T1518": "Software Discovery",
    "T1069": "Permission Groups Discovery",
    "T1124": "System Time Discovery",
}

SUBTECHNIQUES: Dict[str, str] = {
    "T1595.001": "Scanning IP Blocks",
    "T1595.002": "Vulnerability Scanning",
    "T1595.003": "Wordlist Scanning",
    "T1078.003": "Local Accounts",
    "T1059.004": "Unix Shell",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1110.004": "Credential Stuffing",
    # Discovery (TA0007)
    "T1087.001": "Local Account",
    "T1069.001": "Local Groups",
}

# Strumenti di scansione -> sub-technique recon (euristica su user-agent / path)
_VULN_SCAN_TOOLS = ("nikto", "nmap", "masscan", "sqlmap")
_WORDLIST_TOOLS = ("gobuster", "dirbuster")


def _entry(
    tactic: Optional[str],
    technique: Optional[str],
    subtechnique: Optional[str],
    confidence: Optional[str],
) -> Dict[str, Optional[str]]:
    return {
        "mitre_tactic": tactic,
        "mitre_technique": technique,
        "mitre_subtechnique": subtechnique,
        "mitre_confidence": confidence,
    }


def _empty() -> Dict[str, Optional[str]]:
    """Evento reale ma non classificabile su ATT&CK con i dati attuali."""
    return _entry(None, None, None, None)


def _record_text(record: Dict[str, Any]) -> str:
    parts = [
        str(record.get("user_agent") or ""),
        str(record.get("uri") or ""),
        str(record.get("path") or ""),
        str(record.get("command") or ""),
    ]
    return " ".join(parts).lower()


def _recon_subtechnique(record: Dict[str, Any]) -> Optional[str]:
    text = _record_text(record)
    if any(tool in text for tool in _VULN_SCAN_TOOLS):
        return "T1595.002"
    if any(tool in text for tool in _WORDLIST_TOOLS):
        return "T1595.003"
    return None


def map_attack_to_mitre(attack_type: Optional[str], record: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Restituisce gli ID MITRE + confidenza per un evento gia classificato.

    Usa `record` per i raffinamenti dipendenti dal contesto (sorgente, comando
    FTP, user-agent di scansione). Non inventa ID: ritorna None dove i dati non
    bastano.
    """
    if not attack_type:
        return _empty()

    source = str(record.get("source") or "").lower()

    if attack_type == "Credential Attack":
        # Brute force online verso un servizio esposto: il default coerente e
        # Password Guessing. Spraying/Stuffing non sono distinguibili dal singolo
        # evento -> confidenza Medio sulla sub.
        return _entry("TA0006", "T1110", "T1110.001", "Alto")

    if attack_type == "Unauthorized Login":
        return _entry("TA0001", "T1078", "T1078.003", "Alto")

    if attack_type == "Post-Login Activity":
        return _entry("TA0002", "T1059", "T1059.004", "Alto")

    if attack_type == "Command Injection":
        # Shell Unix solo se l'esecuzione e su cowrie/ftp; via web la sub non e
        # determinabile con certezza.
        if source in {"cowrie", "ftp"}:
            return _entry("TA0002", "T1059", "T1059.004", "Alto")
        return _entry("TA0002", "T1059", None, "Medio")

    if attack_type == "Malware Upload":
        return _entry("TA0011", "T1105", None, "Alto")

    if attack_type == "SQL Injection":
        # T1190 non ha sub-technique.
        return _entry("TA0001", "T1190", None, "Alto")

    if attack_type == "Web Crawl / Recon":
        sub = _recon_subtechnique(record)
        return _entry("TA0043", "T1595", sub, "Alto" if sub else "Medio")

    if attack_type == "Port Scan":
        # Active Scanning chiaro; nessuna sub ATT&CK descrive il port scan -> None.
        return _entry("TA0043", "T1595", None, "Medio")

    if attack_type == "FTP Attack":
        command = str(record.get("command") or "").strip().upper()
        if command in {"STOR", "APPE"}:
            return _entry("TA0011", "T1105", None, "Medio")
        # RETR/DELE/RNFR/... : direzione/intento ambigui -> non classificato.
        return _empty()

    if attack_type == "Database Attack":
        # Query/comandi verso DB honeypot: exploitation generica di servizio esposto.
        return _entry("TA0001", "T1190", None, "Medio")

    if attack_type == "SCADA Attack":
        # Interazione con protocolli ICS/SCADA. T1210 e' il piu' vicino in
        # ATT&CK Enterprise; i protocolli ICS hanno una matrice separata (ICS ATT&CK)
        # che non e' inclusa qui -> confidenza Basso.
        return _entry("TA0008", "T1210", None, "Basso")

    # --- Mapping approssimati (Basso = "incerto"): nessuna technique ATT&CK
    # descrive esattamente questi attacchi, ma manteniamo un riferimento ----
    if attack_type == "IDOR Attempt":
        return _entry("TA0001", "T1190", None, "Basso")

    if attack_type == "XSS Attack":
        return _entry("TA0001", "T1190", None, "Basso")

    if attack_type == "SMB Attack":
        return _entry("TA0008", "T1210", None, "Basso")

    # Unknown e qualunque altra categoria: non classificato MITRE.
    return _empty()


def attack_url(technique: Optional[str], subtechnique: Optional[str]) -> Optional[str]:
    if subtechnique and "." in subtechnique:
        base, sub = subtechnique.split(".", 1)
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    if technique:
        return f"https://attack.mitre.org/techniques/{technique}/"
    return None


def resolve_mitre(
    tactic: Optional[str],
    technique: Optional[str],
    subtechnique: Optional[str],
    confidence: Optional[str],
) -> Dict[str, Optional[str]]:
    """Espande gli ID salvati nel DB in nomi ufficiali + URL (read-time).

    `mitre_uncertain` segnala i mapping approssimati (confidenza Bassa), cosi la
    dashboard puo mostrare l'etichetta "incerto".
    """
    return {
        "mitre_tactic": tactic,
        "mitre_tactic_name": TACTICS.get(tactic or ""),
        "mitre_technique": technique,
        "mitre_technique_name": TECHNIQUES.get(technique or ""),
        "mitre_subtechnique": subtechnique,
        "mitre_subtechnique_name": SUBTECHNIQUES.get(subtechnique or ""),
        "mitre_confidence": confidence,
        "mitre_uncertain": bool(technique) and confidence == "Basso",
        "mitre_url": attack_url(technique, subtechnique),
    }


# --- Discovery (TA0007): mapping comando -> technique -----------------------
# Estratto a livello di singolo comando shell (Cowrie logga la stringa esatta).
# Ogni comando e evidenza diretta della technique, quindi confidenza Alta; i
# comandi ad alto volume e poco specifici (ls/find) restano a Media.
#
# Chiave = comando base (primo token, senza path). Valore = (technique, sub, conf).
_BASE_CMD_DISCOVERY: Dict[str, tuple] = {
    "whoami": ("T1033", None, "Alto"),
    "id": ("T1033", None, "Alto"),
    "who": ("T1033", None, "Alto"),
    "w": ("T1033", None, "Alto"),
    "last": ("T1033", None, "Alto"),
    "logname": ("T1033", None, "Alto"),
    "users": ("T1033", None, "Alto"),
    "uname": ("T1082", None, "Alto"),
    "hostname": ("T1082", None, "Alto"),
    "hostnamectl": ("T1082", None, "Alto"),
    "lscpu": ("T1082", None, "Alto"),
    "lsb_release": ("T1082", None, "Alto"),
    "nproc": ("T1082", None, "Alto"),
    "dmidecode": ("T1082", None, "Alto"),
    "ps": ("T1057", None, "Alto"),
    "top": ("T1057", None, "Alto"),
    "htop": ("T1057", None, "Alto"),
    "pgrep": ("T1057", None, "Alto"),
    "ifconfig": ("T1016", None, "Alto"),
    "iwconfig": ("T1016", None, "Alto"),
    "ip": ("T1016", None, "Alto"),
    "route": ("T1016", None, "Alto"),
    "arp": ("T1016", None, "Alto"),
    "netstat": ("T1049", None, "Alto"),
    "ss": ("T1049", None, "Alto"),
    "lsof": ("T1049", None, "Alto"),
    "which": ("T1518", None, "Alto"),
    "whereis": ("T1518", None, "Alto"),
    "dpkg": ("T1518", None, "Alto"),
    "rpm": ("T1518", None, "Alto"),
    "groups": ("T1069", "T1069.001", "Alto"),
    "getent": ("T1087", "T1087.001", "Alto"),
    "lastlog": ("T1087", "T1087.001", "Alto"),
    "date": ("T1124", None, "Medio"),
    "uptime": ("T1124", None, "Medio"),
    # Alto volume / poco specifici -> confidenza Media.
    "ls": ("T1083", None, "Medio"),
    "dir": ("T1083", None, "Medio"),
    "find": ("T1083", None, "Medio"),
    "tree": ("T1083", None, "Medio"),
    "du": ("T1083", None, "Medio"),
    "locate": ("T1083", None, "Medio"),
    "stat": ("T1083", None, "Medio"),
}

# Lettura di file sensibili (cat/less/head/...): il path determina la technique.
# /etc/shadow e' volutamente ESCLUSO: e' Credential Access (T1003), altra tattica.
_READ_CMDS = {"cat", "less", "more", "head", "tail", "tac", "strings", "grep", "awk", "nl"}
_FILE_DISCOVERY = [
    ("/etc/passwd", "T1087", "T1087.001", "Alto"),
    ("/etc/group", "T1069", "T1069.001", "Alto"),
    ("/etc/hosts", "T1018", None, "Alto"),
    ("known_hosts", "T1018", None, "Alto"),
    ("/proc/cpuinfo", "T1082", None, "Alto"),
    ("/proc/meminfo", "T1082", None, "Alto"),
    ("/proc/version", "T1082", None, "Alto"),
    ("/etc/os-release", "T1082", None, "Alto"),
    ("/etc/issue", "T1082", None, "Alto"),
    ("/etc/resolv.conf", "T1016", None, "Alto"),
]

_CONFIDENCE_RANK = {"Alto": 3, "Medio": 2, "Basso": 1}
_SEGMENT_SPLIT = re.compile(r"[|;&]+")


def _discovery_entry(technique: str, subtechnique: Optional[str], confidence: str) -> Dict[str, Any]:
    return {
        "tactic": "TA0007",
        "tactic_name": "Discovery",
        "technique": technique,
        "technique_name": TECHNIQUES.get(technique),
        "subtechnique": subtechnique,
        "subtechnique_name": SUBTECHNIQUES.get(subtechnique) if subtechnique else None,
        "id": subtechnique or technique,
        "name": SUBTECHNIQUES.get(subtechnique) if subtechnique else TECHNIQUES.get(technique),
        "confidence": confidence,
        "url": attack_url(technique, subtechnique),
    }


def discovery_techniques(command: Optional[str]) -> List[Dict[str, Any]]:
    """Technique di Discovery estratte da un singolo comando shell.

    Ritorna 0..N entry (di norma 0 o 1). Comandi non riconosciuti o rumore ->
    lista vuota: non si forza nulla.
    """
    if not command:
        return []
    text = str(command).strip().lower()
    if not text:
        return []

    matches: Dict[str, Dict[str, Any]] = {}

    def _add(technique: str, subtechnique: Optional[str], confidence: str) -> None:
        entry = _discovery_entry(technique, subtechnique, confidence)
        key = entry["id"]
        existing = matches.get(key)
        if not existing or _CONFIDENCE_RANK[confidence] > _CONFIDENCE_RANK[existing["confidence"]]:
            matches[key] = entry

    for segment in _SEGMENT_SPLIT.split(text):
        tokens = segment.split()
        if not tokens:
            continue
        base = tokens[0].rsplit("/", 1)[-1]  # /usr/bin/whoami -> whoami
        rule = _BASE_CMD_DISCOVERY.get(base)
        if rule:
            _add(*rule)
        if base in _READ_CMDS:
            for needle, technique, subtechnique, confidence in _FILE_DISCOVERY:
                if needle in segment:
                    _add(technique, subtechnique, confidence)

    return list(matches.values())


def aggregate_discovery(commands: Iterable[Optional[str]]) -> List[Dict[str, Any]]:
    """Aggrega le technique di Discovery viste in una sessione/IP, con conteggi.

    Ordina per frequenza decrescente. Mantiene la confidenza piu alta osservata
    per ciascuna technique.
    """
    agg: Dict[str, Dict[str, Any]] = {}
    for command in commands:
        for entry in discovery_techniques(command):
            key = entry["id"]
            current = agg.get(key)
            if current is None:
                item = dict(entry)
                item["count"] = 1
                agg[key] = item
            else:
                current["count"] += 1
                if _CONFIDENCE_RANK[entry["confidence"]] > _CONFIDENCE_RANK[current["confidence"]]:
                    current["confidence"] = entry["confidence"]
    return sorted(agg.values(), key=lambda item: (-item["count"], item["id"]))
