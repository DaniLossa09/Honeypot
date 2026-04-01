"""
ai_explainer.py
===============
Modulo AI che spiega gli attacchi usando Claude/Llama3 via Groq.
Modificato per la sicurezza (uso di dotenv) e path assoluti.
"""

import json
import sqlite3
import requests
import time
import os
from datetime import datetime
from dotenv import load_dotenv

# ── PATH ASSOLUTI E AMBIENTE ─────────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA_DIR = os.path.join(BASE_DIR, 'data')

load_dotenv(os.path.join(BASE_DIR, '.env'))

DB_PATH          = os.path.join(DATA_DIR, "honeypot_data.db")
EXPLANATIONS_DB  = os.path.join(DATA_DIR, "explanations.db")
API_URL          = "https://api.groq.com/openai/v1/chat/completions"
API_KEY          = os.environ.get("GROQ_API_KEY", "") 
MODEL            = "llama-3.3-70b-versatile"
MAX_EVENTS_TO_EXPLAIN = 20

# ── DATABASE SPIEGAZIONI ────────────────────────────────────────────────────
def init_explanations_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(EXPLANATIONS_DB)
    conn.cursor().execute("""
        CREATE TABLE IF NOT EXISTS explanations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER UNIQUE,
            attack_type TEXT, ip TEXT, country TEXT, service TEXT, confidence TEXT,
            explanation_it TEXT, danger_level TEXT, advice TEXT, generated_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_explanation(event_id, attack_type, ip, country, service, confidence, explanation, danger, advice):
    conn = sqlite3.connect(EXPLANATIONS_DB)
    conn.cursor().execute("""
        INSERT OR REPLACE INTO explanations
        (event_id, attack_type, ip, country, service, confidence, explanation_it, danger_level, advice, generated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (event_id, attack_type, ip, country, service, confidence, explanation, danger, advice, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def already_explained(event_id: int) -> bool:
    conn = sqlite3.connect(EXPLANATIONS_DB)
    res = conn.cursor().execute("SELECT id FROM explanations WHERE event_id = ?", (event_id,)).fetchone()
    conn.close()
    return res is not None

# ── PROMPT E API ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = "Sei un esperto di cybersecurity. Spiega attacchi in modo semplice per non-tecnici in italiano."

def call_claude_api(prompt: str) -> dict | None:
    if not API_KEY:
        print("  [AI] ❌ ERRORE: Chiave API mancante. Configura il file .env!")
        return None
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}"}
    body = {"model": MODEL, "max_tokens": 1024, "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]}
    try:
        resp = requests.post(API_URL, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        raw_text = resp.json()["choices"][0]["message"]["content"].strip()
        import re; match = re.search(r'\{.*\}', raw_text, re.DOTALL)
        if match: raw_text = match.group(0)
        return json.loads(raw_text)
    except Exception as e:
        print(f"  [AI] Errore API: {e}")
        return None

def explain_all_attacks():
    init_explanations_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    events = [dict(r) for r in conn.cursor().execute("SELECT id, attack_type, ip, country, city, service, confidence, detail FROM events WHERE attack_type != 'Unknown' LIMIT ?", (MAX_EVENTS_TO_EXPLAIN,)).fetchall()]
    conn.close()

    for ev in events:
        if already_explained(ev["id"]): continue
        print(f"  → Spiegazione per Evento #{ev['id']} | {ev['attack_type']}")
        prompt = f"Attacco: {ev['attack_type']}, IP: {ev['ip']}, Paese: {ev['country']}, Servizio: {ev['service']}. Dammi un JSON con 'spiegazione', 'livello_pericolo' (Basso/Medio/Alto), 'consiglio'."
        ai_resp = call_claude_api(prompt)
        if ai_resp:
            save_explanation(ev["id"], ev["attack_type"], ev["ip"], ev["country"], ev["service"], ev.get("confidence"), ai_resp.get("spiegazione"), ai_resp.get("livello_pericolo"), ai_resp.get("consiglio"))
            print("    ✅ Spiegato!")
        time.sleep(0.5)

def print_explanations_report():
    print("\n  🧠 REPORT EDUCATIVO GENERATO")

def export_explanations_json():
    output_path = os.path.join(DATA_DIR, "explanations_export.json")
    conn = sqlite3.connect(EXPLANATIONS_DB)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.cursor().execute("SELECT * FROM explanations").fetchall()]
    conn.close()
    with open(output_path, "w", encoding="utf-8") as f: json.dump(rows, f, indent=2, ensure_ascii=False)
    print(f"[EXPORT] ✅ Spiegazioni in '{output_path}'")

if __name__ == "__main__":
    explain_all_attacks()
    print_explanations_report()
    export_explanations_json()