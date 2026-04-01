"""
test_analyzer.py
================
Genera log FINTI e lancia l'analyzer.
Ora usa i percorsi relativi alla nuova architettura.
"""

import json
import os
import sys

# Per importare il backend, aggiungiamo la root del progetto al PYTHONPATH
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, BASE_DIR)

from backend.analyzer import analyze_all, print_stats, export_json

LOGS_DIR = os.path.join(BASE_DIR, 'honeypots', 'logs')
DATA_DIR = os.path.join(BASE_DIR, 'data')

os.makedirs(os.path.join(LOGS_DIR, "cowrie"), exist_ok=True)
os.makedirs(os.path.join(LOGS_DIR, "opencanary"), exist_ok=True)
os.makedirs(os.path.join(LOGS_DIR, "dionaea"), exist_ok=True)

cowrie_events = [
    {"src_ip": "185.234.219.12", "timestamp": "2026-03-31T10:00:00", "dst_port": 22, "eventid": "cowrie.login.failed", "username": "root", "password": "123"},
]
with open(os.path.join(LOGS_DIR, "cowrie", "cowrie.json"), "w") as f:
    for e in cowrie_events: f.write(json.dumps(e) + "\n")

print("[TEST] Log fittizi creati in /honeypots/logs/")
print("\n[TEST] Avvio analyzer...\n")

db_path = os.path.join(DATA_DIR, "honeypot_data.db")
if os.path.exists(db_path):
    os.remove(db_path)

analyze_all()
print_stats()
export_json()

print("\n[TEST] ✅ Tutto ok! I dati sono nella cartella /data/")