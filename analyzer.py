"""
HoneypotX - Cyber Threat Intelligence Backend
==============================================
Legge log da Cowrie, OpenCanary e Dionaea,
classifica gli attacchi e geolocalizza gli IP.

Autore: GFMarilli 2026 Contest
"""

import json
import sqlite3
import requests
import time
import os
from datetime import datetime
from collections import defaultdict


# ─── CONFIGURAZIONE PERCORSI LOG ────────────────────────────────────────────

LOG_PATHS = {
    "cowrie":     "var/log/cowrie/cowrie.json",       # cambia se necessario
    "opencanary": "var/log/opencanary/opencanary.log", # cambia se necessario
    "dionaea":    "var/log/dionaea/dionaea.json",      # cambia se necessario
}

DB_PATH = "honeypot_data.db"


# ─── DATABASE ────────────────────────────────────────────────────────────────

def init_db():
    """Crea il database SQLite con la tabella degli eventi."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            source      TEXT,    -- cowrie / opencanary / dionaea
            ip          TEXT,
            port        INTEGER,
            service     TEXT,
            attack_type TEXT,
            detail      TEXT,
            country     TEXT,
            city        TEXT,
            lat         REAL,
            lon         REAL,
            confidence  TEXT     -- high / medium / low
        )
    """)
    conn.commit()
    conn.close()
    print("[DB] Database inizializzato.")


def save_event(event: dict):
    """Salva un evento analizzato nel database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO events
        (timestamp, source, ip, port, service, attack_type, detail,
         country, city, lat, lon, confidence)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        event.get("timestamp"),
        event.get("source"),
        event.get("ip"),
        event.get("port"),
        event.get("service"),
        event.get("attack_type"),
        event.get("detail"),
        event.get("country"),
        event.get("city"),
        event.get("lat"),
        event.get("lon"),
        event.get("confidence"),
    ))
    conn.commit()
    conn.close()


# ─── GEOLOCALIZZAZIONE IP ─────────────────────────────────────────────────

# Cache per evitare richieste ripetute sullo stesso IP
_geo_cache = {}

def geolocate_ip(ip: str) -> dict:
    """
    Geolocalizza un IP usando ip-api.com (gratuito, 45 req/min).
    Ritorna dict con country, city, lat, lon.
    """
    # IP privati / locali → non geolocalizzare
    if ip.startswith(("192.168.", "10.", "172.", "127.", "::1")):
        return {"country": "Local", "city": "Local", "lat": 0.0, "lon": 0.0}

    if ip in _geo_cache:
        return _geo_cache[ip]

    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            result = {
                "country": data.get("country", "Unknown"),
                "city":    data.get("city", "Unknown"),
                "lat":     data.get("lat", 0.0),
                "lon":     data.get("lon", 0.0),
            }
        else:
            result = {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0}
    except Exception as e:
        print(f"[GEO] Errore per IP {ip}: {e}")
        result = {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0}

    _geo_cache[ip] = result
    time.sleep(0.1)  # rispetta rate limit ip-api.com
    return result


# ─── CLASSIFICAZIONE ATTACCHI ────────────────────────────────────────────────

# Contatore tentativi per IP (per brute force ad alta confidenza)
_ip_attempts = defaultdict(int)

def classify_attack(source: str, data: str, port: int, service: str, ip: str) -> tuple:
    """
    Classifica il tipo di attacco.
    Ritorna (attack_type: str, confidence: str).

    Tipi supportati:
    - Brute Force
    - Port Scan
    - SQL Injection
    - XSS Attack
    - Command Injection
    - Malware Upload
    - FTP Attack
    - SMB Attack
    - Web Crawl
    - Unknown
    """
    data_lower = data.lower() if data else ""
    _ip_attempts[ip] += 1
    attempts = _ip_attempts[ip]

    # ── Brute Force ──────────────────────────────────────────────────────────
    brute_keywords = ["login attempt", "authentication failed", "invalid password",
                      "failed password", "login failed", "auth attempt"]
    if any(k in data_lower for k in brute_keywords) or service in ("ssh", "telnet", "ftp"):
        if attempts >= 10:
            return "Brute Force", "high"
        return "Brute Force", "medium"

    # ── SQL Injection ─────────────────────────────────────────────────────────
    sqli_keywords = ["select ", "union ", "drop ", "insert ", "' or ", "\" or ",
                     "1=1", "or 1=1", "--", "/*", "xp_cmdshell", "information_schema"]
    if any(k in data_lower for k in sqli_keywords):
        return "SQL Injection", "high"

    # ── XSS ──────────────────────────────────────────────────────────────────
    xss_keywords = ["<script", "javascript:", "onerror=", "onload=", "alert(", "document.cookie"]
    if any(k in data_lower for k in xss_keywords):
        return "XSS Attack", "high"

    # ── Command Injection ─────────────────────────────────────────────────────
    cmd_keywords = ["; ls", "; cat", "; wget", "; curl", "| bash", "| sh",
                    "/etc/passwd", "/bin/sh", "$(", "`"]
    if any(k in data_lower for k in cmd_keywords):
        return "Command Injection", "high"

    # ── Malware Upload (Dionaea) ───────────────────────────────────────────────
    if source == "dionaea" or "download" in data_lower or "upload" in data_lower:
        if port in (445, 4444, 1433):
            return "Malware Upload", "high"
        return "Malware Upload", "medium"

    # ── SMB Attack ────────────────────────────────────────────────────────────
    if port == 445 or "smb" in data_lower or service == "smb":
        return "SMB Attack", "high"

    # ── FTP Attack ────────────────────────────────────────────────────────────
    if port == 21 or service == "ftp":
        return "FTP Attack", "medium"

    # ── Port Scan ────────────────────────────────────────────────────────────
    scan_keywords = ["connection attempt", "port scan", "syn scan", "connect"]
    if any(k in data_lower for k in scan_keywords) or service == "portscan":
        return "Port Scan", "medium"

    # ── Web Crawl / Recon ─────────────────────────────────────────────────────
    if service in ("http", "https") and port in (80, 443, 8080, 8443):
        crawler_agents = ["nmap", "masscan", "zgrab", "nikto", "sqlmap", "python-requests"]
        if any(a in data_lower for a in crawler_agents):
            return "Web Crawl / Recon", "high"
        return "Web Crawl / Recon", "low"

    return "Unknown", "low"


# ─── PARSER PER OGNI HONEYPOT ─────────────────────────────────────────────

def parse_cowrie_log(path: str) -> list:
    """
    Legge cowrie.json (formato: una riga JSON per evento).
    Estrae: ip, timestamp, porta, servizio, payload.
    """
    events = []
    if not os.path.exists(path):
        print(f"[COWRIE] File non trovato: {path}")
        return events

    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip      = raw.get("src_ip", "")
            ts      = raw.get("timestamp", "")
            port    = int(raw.get("dst_port", 22))
            service = "ssh" if port == 22 else "telnet"

            # costruisci stringa dettaglio per la classificazione
            detail_parts = []
            if raw.get("eventid"):
                detail_parts.append(raw["eventid"])
            if raw.get("input"):              # comando digitato dall'attaccante
                detail_parts.append(raw["input"])
            if raw.get("username"):
                detail_parts.append(f"login attempt {raw.get('username')}:{raw.get('password','')}")
            detail = " | ".join(detail_parts)

            events.append({
                "source":    "cowrie",
                "ip":        ip,
                "timestamp": ts,
                "port":      port,
                "service":   service,
                "detail":    detail,
            })

    print(f"[COWRIE] Letti {len(events)} eventi.")
    return events


def parse_opencanary_log(path: str) -> list:
    """
    Legge opencanary.log (formato: una riga JSON per evento).
    Estrae: ip, timestamp, porta, servizio, payload.
    """
    events = []
    if not os.path.exists(path):
        print(f"[OPENCANARY] File non trovato: {path}")
        return events

    # Mappa codici servizio OpenCanary → nome leggibile
    service_map = {
        1:  "ftp",   2:  "http",  3:  "ssh",  4:  "telnet",
        5:  "smb",   6:  "vnc",   7:  "mssql",8:  "mysql",
        9:  "rdp",  10:  "snmp", 11:  "sip",  12: "git",
        13: "redis", 14: "tftp", 15: "ntp",
    }

    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip      = raw.get("src_host", "")
            ts      = raw.get("utc_time", datetime.utcnow().isoformat())
            port    = int(raw.get("dst_port", 0))
            svc_id  = raw.get("logtype", 0)
            service = service_map.get(svc_id, f"port_{port}")

            logdata = raw.get("logdata", {})
            detail  = json.dumps(logdata) if logdata else raw.get("msg", "")

            events.append({
                "source":    "opencanary",
                "ip":        ip,
                "timestamp": ts,
                "port":      port,
                "service":   service,
                "detail":    detail,
            })

    print(f"[OPENCANARY] Letti {len(events)} eventi.")
    return events


def parse_dionaea_log(path: str) -> list:
    """
    Legge dionaea.json.
    Estrae: ip, timestamp, porta, servizio, payload.
    """
    events = []
    if not os.path.exists(path):
        print(f"[DIONAEA] File non trovato: {path}")
        return events

    # Dionaea può avere log in formato JSON lines o array
    with open(path, "r", errors="ignore") as f:
        content = f.read().strip()

    # Prova prima come array JSON
    try:
        raw_list = json.loads(content)
        if isinstance(raw_list, dict):
            raw_list = [raw_list]
    except json.JSONDecodeError:
        # Altrimenti JSON lines
        raw_list = []
        for line in content.splitlines():
            line = line.strip()
            if line:
                try:
                    raw_list.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    port_service = {
        21: "ftp", 22: "ssh", 80: "http", 443: "https",
        445: "smb", 1433: "mssql", 3306: "mysql", 4444: "shell",
    }

    for raw in raw_list:
        ip      = raw.get("src_ip", raw.get("remote_host", ""))
        ts      = raw.get("timestamp", datetime.utcnow().isoformat())
        port    = int(raw.get("dst_port", raw.get("local_port", 0)))
        service = port_service.get(port, raw.get("protocol", "unknown"))
        detail  = raw.get("payload", raw.get("download_md5_hash", ""))

        events.append({
            "source":    "dionaea",
            "ip":        ip,
            "timestamp": ts,
            "port":      port,
            "service":   service,
            "detail":    str(detail),
        })

    print(f"[DIONAEA] Letti {len(events)} eventi.")
    return events


# ─── PIPELINE PRINCIPALE ──────────────────────────────────────────────────

def analyze_all():
    """
    Esegue la pipeline completa:
    1. Legge log da tutti e tre gli honeypot
    2. Classifica ogni attacco
    3. Geolocalizza ogni IP
    4. Salva tutto nel DB
    """
    init_db()

    # 1. Leggi tutti i log
    all_events = []
    all_events.extend(parse_cowrie_log(LOG_PATHS["cowrie"]))
    all_events.extend(parse_opencanary_log(LOG_PATHS["opencanary"]))
    all_events.extend(parse_dionaea_log(LOG_PATHS["dionaea"]))

    print(f"\n[ANALYZER] Totale eventi da processare: {len(all_events)}")

    # 2. Classifica + Geolocalizza + Salva
    for i, ev in enumerate(all_events):
        ip      = ev["ip"]
        detail  = ev.get("detail", "")
        port    = ev.get("port", 0)
        service = ev.get("service", "")
        source  = ev.get("source", "")

        # Classificazione
        attack_type, confidence = classify_attack(source, detail, port, service, ip)

        # Geolocalizzazione
        geo = geolocate_ip(ip)

        # Evento arricchito
        enriched = {
            **ev,
            "attack_type": attack_type,
            "confidence":  confidence,
            "country":     geo["country"],
            "city":        geo["city"],
            "lat":         geo["lat"],
            "lon":         geo["lon"],
        }

        save_event(enriched)

        # Progress ogni 50 eventi
        if (i + 1) % 50 == 0:
            print(f"[ANALYZER] Processati {i+1}/{len(all_events)} eventi...")

    print(f"\n[ANALYZER] ✅ Completato! {len(all_events)} eventi salvati in '{DB_PATH}'")


# ─── STATISTICHE RAPIDE ──────────────────────────────────────────────────

def print_stats():
    """Stampa un riepilogo degli attacchi dal database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    print("\n" + "="*50)
    print("  📊 STATISTICHE ATTACCHI")
    print("="*50)

    # Totale eventi
    c.execute("SELECT COUNT(*) FROM events")
    total = c.fetchone()[0]
    print(f"\n  Totale eventi rilevati: {total}")

    # Per tipo di attacco
    print("\n  🔥 Attacchi per tipo:")
    c.execute("""
        SELECT attack_type, COUNT(*) as n
        FROM events
        GROUP BY attack_type
        ORDER BY n DESC
    """)
    for row in c.fetchall():
        print(f"     {row[0]:<25} → {row[1]}")

    # Per paese
    print("\n  🌍 Top 5 paesi attaccanti:")
    c.execute("""
        SELECT country, COUNT(*) as n
        FROM events
        WHERE country != 'Local'
        GROUP BY country
        ORDER BY n DESC
        LIMIT 5
    """)
    for row in c.fetchall():
        print(f"     {row[0]:<25} → {row[1]}")

    # IP più attivi
    print("\n  🔴 Top 5 IP attaccanti:")
    c.execute("""
        SELECT ip, COUNT(*) as n, attack_type, country
        FROM events
        GROUP BY ip
        ORDER BY n DESC
        LIMIT 5
    """)
    for row in c.fetchall():
        print(f"     {row[0]:<20} ({row[3]}) → {row[1]} attacchi | tipo: {row[2]}")

    # Per honeypot sorgente
    print("\n  🪤 Attacchi per honeypot:")
    c.execute("""
        SELECT source, COUNT(*) as n
        FROM events
        GROUP BY source
        ORDER BY n DESC
    """)
    for row in c.fetchall():
        print(f"     {row[0]:<15} → {row[1]}")

    print("\n" + "="*50)
    conn.close()


def export_json(output_path: str = "events_export.json"):
    """Esporta tutti gli eventi in JSON (utile per la dashboard)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM events ORDER BY timestamp DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()

    with open(output_path, "w") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)

    print(f"[EXPORT] ✅ {len(rows)} eventi esportati in '{output_path}'")


# ─── ENTRY POINT ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("╔══════════════════════════════════════╗")
    print("║   HoneypotX — Threat Analyzer v1.0  ║")
    print("╚══════════════════════════════════════╝\n")

    analyze_all()
    print_stats()
    export_json()
