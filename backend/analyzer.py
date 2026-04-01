"""
HoneypotX - Cyber Threat Intelligence Backend
==============================================
Legge log, classifica gli attacchi e geolocalizza.
"""

import json
import sqlite3
import requests
import time
import os
from datetime import datetime
from collections import defaultdict

# ── PATH ASSOLUTI E AMBIENTE ─────────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
LOGS_DIR = os.path.join(BASE_DIR, 'honeypots', 'logs')
DATA_DIR = os.path.join(BASE_DIR, 'data')

LOG_PATHS = {
    "cowrie":     os.path.join(LOGS_DIR, "cowrie", "cowrie.json"),
    "opencanary": os.path.join(LOGS_DIR, "opencanary", "opencanary.log"),
    "dionaea":    os.path.join(LOGS_DIR, "dionaea", "dionaea.json"),
}

DB_PATH = os.path.join(DATA_DIR, "honeypot_data.db")

# ── DATABASE ─────────────────────────────────────────────────────────────────
def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            source      TEXT,
            ip          TEXT,
            port        INTEGER,
            service     TEXT,
            attack_type TEXT,
            detail      TEXT,
            country     TEXT,
            city        TEXT,
            lat         REAL,
            lon         REAL,
            confidence  TEXT
        )
    """)
    conn.commit()
    conn.close()
    print("[DB] Database analizzatore inizializzato.")

def save_event(event: dict):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO events
        (timestamp, source, ip, port, service, attack_type, detail, country, city, lat, lon, confidence)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        event.get("timestamp"), event.get("source"), event.get("ip"), event.get("port"),
        event.get("service"), event.get("attack_type"), event.get("detail"),
        event.get("country"), event.get("city"), event.get("lat"), event.get("lon"), event.get("confidence"),
    ))
    conn.commit()
    conn.close()

# ── GEOLOCALIZZAZIONE E CLASSIFICAZIONE ────────────────────────────────────
_geo_cache = {}

def geolocate_ip(ip: str) -> dict:
    if ip.startswith(("192.168.", "10.", "172.", "127.", "::1")):
        return {"country": "Local", "city": "Local", "lat": 0.0, "lon": 0.0}
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            result = {"country": data.get("country", "Unknown"), "city": data.get("city", "Unknown"), "lat": data.get("lat", 0.0), "lon": data.get("lon", 0.0)}
        else:
            result = {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0}
    except Exception as e:
        result = {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0}
    _geo_cache[ip] = result
    time.sleep(0.1)
    return result

_ip_attempts = defaultdict(int)

def classify_attack(source: str, data: str, port: int, service: str, ip: str) -> tuple:
    data_lower = data.lower() if data else ""
    _ip_attempts[ip] += 1
    attempts = _ip_attempts[ip]

    if any(k in data_lower for k in ["login attempt", "failed"]) or service in ("ssh", "telnet"):
        return ("Brute Force", "high") if attempts >= 10 else ("Brute Force", "medium")
    if any(k in data_lower for k in ["select ", "union ", "1=1"]): return "SQL Injection", "high"
    if any(k in data_lower for k in ["<script", "alert("]): return "XSS Attack", "high"
    if any(k in data_lower for k in ["; ls", "wget", "/etc/passwd"]): return "Command Injection", "high"
    if source == "dionaea" or "download" in data_lower: return "Malware Upload", "high" if port in (445, 4444) else "medium"
    if port == 445 or "smb" in data_lower: return "SMB Attack", "high"
    if port == 21 or service == "ftp": return "FTP Attack", "medium"
    if "scan" in data_lower or service == "portscan": return "Port Scan", "medium"
    if service in ("http", "https") and any(a in data_lower for a in ["nmap", "sqlmap"]): return "Web Crawl / Recon", "high"
    return "Unknown", "low"

# ── PARSERS E PIPELINE ───────────────────────────────────────────────────────
def parse_cowrie_log(path: str) -> list:
    events = []
    if not os.path.exists(path): return events
    with open(path, "r", errors="ignore") as f:
        for line in f:
            if not line.strip(): continue
            try: raw = json.loads(line.strip())
            except json.JSONDecodeError: continue
            ip = raw.get("src_ip", "")
            events.append({"source": "cowrie", "ip": ip, "timestamp": raw.get("timestamp", ""), "port": int(raw.get("dst_port", 22)), "service": "ssh" if int(raw.get("dst_port", 22)) == 22 else "telnet", "detail": str(raw.get("input", ""))})
    return events

def parse_opencanary_log(path: str) -> list:
    events = []
    if not os.path.exists(path): return events
    with open(path, "r", errors="ignore") as f:
        for line in f:
            if not line.strip(): continue
            try: raw = json.loads(line.strip())
            except json.JSONDecodeError: continue
            events.append({"source": "opencanary", "ip": raw.get("src_host", ""), "timestamp": raw.get("utc_time", datetime.utcnow().isoformat()), "port": int(raw.get("dst_port", 0)), "service": f"port_{raw.get('dst_port')}", "detail": raw.get("msg", "")})
    return events

def parse_dionaea_log(path: str) -> list:
    events = []
    if not os.path.exists(path): return events
    with open(path, "r", errors="ignore") as f:
        content = f.read().strip()
    try:
        raw_list = json.loads(content)
        if isinstance(raw_list, dict): raw_list = [raw_list]
    except: raw_list = [json.loads(l) for l in content.splitlines() if l.strip()]
    
    for raw in raw_list:
        events.append({"source": "dionaea", "ip": raw.get("src_ip", ""), "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()), "port": int(raw.get("dst_port", 0)), "service": raw.get("protocol", "unknown"), "detail": raw.get("payload", "")})
    return events

def analyze_all():
    init_db()
    all_events = parse_cowrie_log(LOG_PATHS["cowrie"]) + parse_opencanary_log(LOG_PATHS["opencanary"]) + parse_dionaea_log(LOG_PATHS["dionaea"])
    print(f"\n[ANALYZER] Totale eventi da processare: {len(all_events)}")
    for i, ev in enumerate(all_events):
        attack_type, confidence = classify_attack(ev["source"], ev["detail"], ev["port"], ev["service"], ev["ip"])
        geo = geolocate_ip(ev["ip"])
        save_event({**ev, "attack_type": attack_type, "confidence": confidence, "country": geo["country"], "city": geo["city"], "lat": geo["lat"], "lon": geo["lon"]})
    print(f"\n[ANALYZER] ✅ Completato! Eventi salvati.")

def print_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM events")
    print(f"\n📊 STATISTICHE: Totale eventi rilevati: {c.fetchone()[0]}")
    conn.close()

def export_json():
    output_path = os.path.join(DATA_DIR, "events_export.json")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.cursor().execute("SELECT * FROM events ORDER BY timestamp DESC").fetchall()]
    conn.close()
    with open(output_path, "w") as f: json.dump(rows, f, indent=2, ensure_ascii=False)
    print(f"[EXPORT] ✅ Esportati in '{output_path}'")

if __name__ == "__main__":
    analyze_all()
    print_stats()
    export_json()