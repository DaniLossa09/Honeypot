"""
ai_explainer.py
===============
Modulo AI di HoneypotX — spiega ogni attacco in linguaggio semplice,
educativo e comprensibile anche per chi non sa nulla di informatica.

Usa l'API di Claude (Anthropic) per generare spiegazioni personalizzate
basate sul tipo di attacco, paese di origine e servizio colpito.

Autore: GFMarilli 2026 Contest
"""

import json
import sqlite3
import requests
import time
from datetime import datetime


# ─── CONFIGURAZIONE ──────────────────────────────────────────────────────────

DB_PATH          = "honeypot_data.db"
EXPLANATIONS_DB  = "explanations.db"
API_URL          = "https://api.groq.com/openai/v1/chat/completions"
API_KEY          = "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"
MODEL            = "llama-3.3-70b-versatile"

# Quanti eventi spiegare in una singola esecuzione
# (metti None per spiegarli tutti, ma attenzione ai tempi)
MAX_EVENTS_TO_EXPLAIN = 20


# ─── DATABASE SPIEGAZIONI ────────────────────────────────────────────────────

def init_explanations_db():
    """Crea il DB dove salviamo le spiegazioni AI."""
    conn = sqlite3.connect(EXPLANATIONS_DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS explanations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id        INTEGER UNIQUE,   -- collegato a events.id
            attack_type     TEXT,
            ip              TEXT,
            country         TEXT,
            service         TEXT,
            confidence      TEXT,
            explanation_it  TEXT,             -- spiegazione in italiano
            danger_level    TEXT,             -- Basso / Medio / Alto
            advice          TEXT,             -- consiglio pratico
            generated_at    TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_explanation(event_id: int, attack_type: str, ip: str,
                     country: str, service: str, confidence: str,
                     explanation: str, danger: str, advice: str):
    """Salva una spiegazione nel DB."""
    conn = sqlite3.connect(EXPLANATIONS_DB)
    c = conn.cursor()
    c.execute("""
        INSERT OR REPLACE INTO explanations
        (event_id, attack_type, ip, country, service, confidence,
         explanation_it, danger_level, advice, generated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        event_id, attack_type, ip, country, service, confidence,
        explanation, danger, advice,
        datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()


def already_explained(event_id: int) -> bool:
    """Controlla se un evento è già stato spiegato (evita doppioni)."""
    conn = sqlite3.connect(EXPLANATIONS_DB)
    c = conn.cursor()
    c.execute("SELECT id FROM explanations WHERE event_id = ?", (event_id,))
    result = c.fetchone()
    conn.close()
    return result is not None


# ─── PROMPT BUILDER ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """Sei un esperto di cybersecurity con una missione speciale:
spiegare gli attacchi informatici in modo che li capisca CHIUNQUE,
anche una persona che non ha mai usato un computer in modo tecnico.

Il tuo stile deve essere:
- Chiaro e diretto, senza gergo tecnico
- Usa analogie del mondo reale quando possibile
- Tono educativo ma mai noioso
- Scrivi sempre in italiano
- Non usare elenchi puntati, scrivi in modo narrativo e coinvolgente

Quando spieghi un attacco, immagina di parlare a un insegnante di liceo
che vuole capire cosa sta succedendo alla rete della sua scuola."""


def build_prompt(attack_type: str, ip: str, country: str,
                 service: str, confidence: str, detail: str) -> str:
    """Costruisce il prompt per Claude basato sui dati dell'attacco."""

    # Mappa livelli di confidenza in italiano
    conf_map = {"high": "alta", "medium": "media", "low": "bassa"}
    conf_it = conf_map.get(confidence, "media")

    # Dettaglio opzionale (tronca se troppo lungo)
    detail_str = ""
    if detail and len(detail) > 10:
        detail_trunc = detail[:300] + ("..." if len(detail) > 300 else "")
        detail_str = f"\nDettaglio tecnico del payload: {detail_trunc}"

    return f"""Ho rilevato il seguente attacco informatico sul mio honeypot:

- Tipo di attacco: {attack_type}
- Indirizzo IP dell'attaccante: {ip}
- Paese di provenienza: {country}
- Servizio/porta colpita: {service}
- Livello di confidenza del rilevamento: {conf_it}{detail_str}

Rispondimi SOLO con un oggetto JSON valido (nessun testo prima o dopo), con questa struttura esatta:

{{
  "spiegazione": "...",
  "livello_pericolo": "Basso" | "Medio" | "Alto",
  "consiglio": "..."
}}

Dove:
- "spiegazione": 3-4 frasi in italiano semplice che spiegano cos'è questo attacco,
  come funziona (con un'analogia del mondo reale), e perché qualcuno lo farebbe.
  Scrivi in modo narrativo, non usare elenchi.
- "livello_pericolo": una sola parola tra Basso, Medio o Alto.
- "consiglio": 1-2 frasi su come difendersi o cosa fare, in modo pratico e comprensibile."""


# ─── CHIAMATA ALL'API AI ─────────────────────────────────────────────────────
def call_claude_api(prompt: str) -> dict | None:
    """
    Chiama Groq API e ritorna il JSON con la spiegazione.
    """
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
    }

    body = {
        "model": MODEL,
        "max_tokens": 1024,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt + "\n\nRispondi SOLO con il JSON, niente altro testo."}
        ]
    }

    try:
        resp = requests.post(API_URL, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        raw_text = data["choices"][0]["message"]["content"].strip()

        # Estrai JSON anche se c'è testo intorno
        import re
        match = re.search(r'\{.*\}', raw_text, re.DOTALL)
        if match:
            raw_text = match.group(0)

        parsed = json.loads(raw_text)
        return parsed

    except requests.exceptions.RequestException as e:
        print(f"  [AI] Errore di rete: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"  [AI] Risposta non JSON valida: {e}")
        return None
# ─── PIPELINE PRINCIPALE ─────────────────────────────────────────────────────

def explain_all_attacks():
    """
    Legge gli eventi dal DB dell'analyzer,
    chiede a Claude di spiegarli,
    e salva le spiegazioni nel DB delle explanations.
    """
    init_explanations_db()

    # Leggi eventi dal DB principale
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Prendi eventi non ancora spiegati, ordinati per confidenza alta prima
    c.execute("""
        SELECT id, attack_type, ip, country, city, service, confidence, detail
        FROM events
        WHERE attack_type != 'Unknown'
        ORDER BY
            CASE confidence WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
            id DESC
        LIMIT ?
    """, (MAX_EVENTS_TO_EXPLAIN,))

    events = [dict(r) for r in c.fetchall()]
    conn.close()

    if not events:
        print("[AI] Nessun evento nel database. Hai già eseguito analyzer.py?")
        return

    print(f"[AI] {len(events)} eventi da spiegare...\n")

    explained = 0
    skipped   = 0

    for ev in events:
        eid = ev["id"]

        if already_explained(eid):
            skipped += 1
            continue

        attack  = ev["attack_type"]
        ip      = ev["ip"]
        country = ev.get("country", "Unknown")
        service = ev.get("service", "unknown")
        conf    = ev.get("confidence", "medium")
        detail  = ev.get("detail", "")

        print(f"  → Evento #{eid} | {attack} | {ip} ({country}) | {service}")

        prompt   = build_prompt(attack, ip, country, service, conf, detail)
        ai_resp  = call_claude_api(prompt)

        if ai_resp:
            save_explanation(
                event_id    = eid,
                attack_type = attack,
                ip          = ip,
                country     = country,
                service     = service,
                confidence  = conf,
                explanation = ai_resp.get("spiegazione", ""),
                danger      = ai_resp.get("livello_pericolo", "Medio"),
                advice      = ai_resp.get("consiglio", ""),
            )
            explained += 1
            print(f"     ✅ Spiegato! Pericolo: {ai_resp.get('livello_pericolo')}")
        else:
            print(f"     ⚠️  Saltato (errore API)")

        time.sleep(0.5)  # pausa tra chiamate

    print(f"\n[AI] ✅ Completato: {explained} spiegati, {skipped} già presenti.")


# ─── LETTURA REPORT LEGGIBILE ────────────────────────────────────────────────

def print_explanations_report():
    """Stampa un report leggibile con tutte le spiegazioni generate."""
    conn = sqlite3.connect(EXPLANATIONS_DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT * FROM explanations
        ORDER BY
            CASE danger_level WHEN 'Alto' THEN 1 WHEN 'Medio' THEN 2 ELSE 3 END,
            generated_at DESC
    """)
    rows = c.fetchall()
    conn.close()

    if not rows:
        print("[REPORT] Nessuna spiegazione ancora generata.")
        return

    print("\n" + "="*60)
    print("  🧠 REPORT EDUCATIVO ATTACCHI — HoneypotX")
    print("="*60)

    for r in rows:
        danger_emoji = {"Alto": "🔴", "Medio": "🟡", "Basso": "🟢"}.get(r["danger_level"], "⚪")
        print(f"""
{danger_emoji} [{r['danger_level'].upper()}] {r['attack_type']}
   IP: {r['ip']} ({r['country']}) — Servizio: {r['service']}
   ─────────────────────────────────────────────────────
   📖 {r['explanation_it']}
   💡 CONSIGLIO: {r['advice']}
""")

    print("="*60)


def export_explanations_json(output_path: str = "explanations_export.json"):
    """Esporta spiegazioni in JSON (per la futura dashboard)."""
    conn = sqlite3.connect(EXPLANATIONS_DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM explanations ORDER BY generated_at DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)

    print(f"[EXPORT] ✅ {len(rows)} spiegazioni esportate in '{output_path}'")


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("╔══════════════════════════════════════════╗")
    print("║   HoneypotX — AI Explainer v1.0         ║")
    print("║   Spiego gli attacchi a tutti 🧠         ║")
    print("╚══════════════════════════════════════════╝\n")

    explain_all_attacks()
    print_explanations_report()
    export_explanations_json()
