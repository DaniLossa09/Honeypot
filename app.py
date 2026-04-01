"""
app.py — HoneypotX Web Server
==============================
Backend Flask con:
- Sistema login con database SQLite
- Sessioni per utente
- API JSON per dashboard personalizzata per organizzazione
- Ogni org vede solo i propri dati

Avvia con:
    pip install flask flask-login werkzeug
    python app.py
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import json
import os
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = "honeypotx-secret-key-cambia-in-produzione"

# ── DATABASE ─────────────────────────────────────────────────────────────────

USERS_DB  = "users.db"
DATA_DB   = "honeypot_data.db"
EXPL_DB   = "explanations.db"


def init_users_db():
    """Crea DB utenti e inserisce utenti demo."""
    conn = sqlite3.connect(USERS_DB)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS organizations (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT UNIQUE NOT NULL,
            org_type  TEXT,       -- school / company / municipality
            created_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            org_id      INTEGER,
            role        TEXT DEFAULT 'viewer',  -- admin / viewer
            created_at  TEXT,
            FOREIGN KEY (org_id) REFERENCES organizations(id)
        )
    """)

    # Inserisci organizzazioni demo se non esistono
    orgs = [
        ("Scuola Rossi - Milano",  "school"),
        ("Azienda TechCorp",       "company"),
    ]
    for name, otype in orgs:
        c.execute("INSERT OR IGNORE INTO organizations (name, org_type, created_at) VALUES (?,?,?)",
                  (name, otype, datetime.utcnow().isoformat()))

    conn.commit()

    # Recupera ID organizzazioni
    c.execute("SELECT id FROM organizations WHERE name='Scuola Rossi - Milano'")
    school_id = c.fetchone()[0]
    c.execute("SELECT id FROM organizations WHERE name='Azienda TechCorp'")
    company_id = c.fetchone()[0]

    # Inserisci utenti demo
    demo_users = [
        ("admin_scuola",  "scuola123",   school_id,  "admin"),
        ("admin_tech",    "techcorp123", company_id, "admin"),
        ("viewer_scuola", "viewer123",   school_id,  "viewer"),
    ]
    for uname, pwd, org_id, role in demo_users:
        c.execute("SELECT id FROM users WHERE username=?", (uname,))
        if not c.fetchone():
            c.execute("""
                INSERT INTO users (username, password, org_id, role, created_at)
                VALUES (?,?,?,?,?)
            """, (uname, generate_password_hash(pwd), org_id, role,
                  datetime.utcnow().isoformat()))

    conn.commit()
    conn.close()
    print("[DB] Database utenti inizializzato.")


def get_user(username):
    conn = sqlite3.connect(USERS_DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT u.*, o.name as org_name, o.org_type
        FROM users u
        JOIN organizations o ON u.org_id = o.id
        WHERE u.username = ?
    """, (username,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


# ── AUTH DECORATOR ────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated


# ── ROUTES HTML ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard_page'))
    return redirect(url_for('login_page'))


@app.route('/login')
def login_page():
    return send_from_directory('templates', 'login.html')


@app.route('/dashboard')
@login_required
def dashboard_page():
    return send_from_directory('templates', 'dashboard.html')


# ── API AUTH ──────────────────────────────────────────────────────────────────

@app.route('/api/login', methods=['POST'])
def api_login():
    data     = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    user = get_user(username)
    if not user or not check_password_hash(user['password'], password):
        return jsonify({"error": "Credenziali non valide"}), 401

    session['user_id']  = user['id']
    session['username'] = user['username']
    session['org_id']   = user['org_id']
    session['org_name'] = user['org_name']
    session['org_type'] = user['org_type']
    session['role']     = user['role']

    return jsonify({
        "ok":       True,
        "username": user['username'],
        "org_name": user['org_name'],
        "org_type": user['org_type'],
        "role":     user['role'],
    })


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route('/api/me')
@login_required
def api_me():
    return jsonify({
        "username": session['username'],
        "org_name": session['org_name'],
        "org_type": session['org_type'],
        "role":     session['role'],
    })


# ── API DATI (filtrati per organizzazione) ────────────────────────────────────

def get_events_for_org(org_id: int) -> list:
    """
    Ritorna gli eventi dell'organizzazione.
    In produzione ogni evento ha un org_id.
    Per la demo assegniamo gli eventi in modo alternato tra le due org.
    """
    # Dati demo — in produzione leggi da honeypot_data.db con WHERE org_id=?
    ALL_EVENTS = [
        {"id":91,  "timestamp":"2026-03-31T10:00:00","source":"cowrie",    "ip":"185.234.219.12","port":22,  "service":"ssh",   "attack_type":"Brute Force",      "country":"Austria",       "city":"Vienna",   "lat":48.2, "lon":16.3,   "confidence":"high"},
        {"id":92,  "timestamp":"2026-03-31T11:00:00","source":"opencanary","ip":"45.33.32.156",  "port":80,  "service":"http",  "attack_type":"SQL Injection",    "country":"United States", "city":"Fremont",  "lat":37.5, "lon":-121.9, "confidence":"high"},
        {"id":94,  "timestamp":"2026-03-31T11:10:00","source":"opencanary","ip":"104.21.56.89",  "port":80,  "service":"http",  "attack_type":"XSS Attack",       "country":"Canada",        "city":"Toronto",  "lat":43.7, "lon":-79.4,  "confidence":"medium"},
        {"id":95,  "timestamp":"2026-03-31T12:00:00","source":"dionaea",   "ip":"77.88.55.60",   "port":445, "service":"smb",   "attack_type":"Malware Upload",   "country":"Russia",        "city":"Moscow",   "lat":55.7, "lon":37.6,   "confidence":"high"},
        {"id":96,  "timestamp":"2026-03-31T12:05:00","source":"dionaea",   "ip":"1.2.3.4",       "port":4444,"service":"shell", "attack_type":"Malware Upload",   "country":"Australia",     "city":"Sydney",   "lat":-33.8,"lon":151.2,  "confidence":"high"},
        {"id":97,  "timestamp":"2026-03-31T10:05:00","source":"cowrie",    "ip":"91.108.4.3",    "port":22,  "service":"ssh",   "attack_type":"Command Injection", "country":"Germany",      "city":"Berlin",   "lat":52.5, "lon":13.4,   "confidence":"high"},
        {"id":98,  "timestamp":"2026-03-31T13:00:00","source":"opencanary","ip":"198.51.100.7",  "port":21,  "service":"ftp",   "attack_type":"FTP Attack",       "country":"Brazil",        "city":"São Paulo","lat":-23.5,"lon":-46.6,  "confidence":"medium"},
        {"id":99,  "timestamp":"2026-03-31T13:30:00","source":"cowrie",    "ip":"185.234.219.12","port":22,  "service":"ssh",   "attack_type":"Brute Force",      "country":"Austria",       "city":"Vienna",   "lat":48.2, "lon":16.3,   "confidence":"high"},
        {"id":100, "timestamp":"2026-03-31T14:00:00","source":"dionaea",   "ip":"5.188.206.14",  "port":445, "service":"smb",   "attack_type":"SMB Attack",       "country":"China",         "city":"Shanghai", "lat":31.2, "lon":121.5,  "confidence":"high"},
        {"id":101, "timestamp":"2026-03-31T14:30:00","source":"opencanary","ip":"212.58.246.90", "port":80,  "service":"http",  "attack_type":"Web Crawl / Recon","country":"United Kingdom","city":"London",   "lat":51.5, "lon":-0.1,   "confidence":"low"},
    ]

    # Assegna org 1 (scuola) agli eventi pari, org 2 (azienda) agli eventi dispari
    # In produzione ogni evento avrà il suo org_id reale
    return [e for i, e in enumerate(ALL_EVENTS) if (i % 2 == 0) == (org_id == 1)]


def get_explanations_for_events(event_ids: list) -> dict:
    """Ritorna le spiegazioni AI per una lista di event_id."""
    ALL_EXPLANATIONS = {
        91:  {"danger_level":"Alto",  "explanation_it":"Immagina un ladro che prova migliaia di chiavi diverse sulla porta di casa tua, una dopo l'altra, sperando che una apra. Questo è esattamente ciò che sta accadendo: qualcuno in Austria sta provando combinazioni di nome utente e password sul sistema SSH, cercando di entrare automaticamente con centinaia di tentativi al minuto.", "advice":"Utilizza password lunghe e complesse. Attiva l'autenticazione a due fattori: anche se l'attaccante indovinasse la password, non potrebbe comunque entrare."},
        92:  {"danger_level":"Alto",  "explanation_it":"Pensa a un modulo di ricerca su un sito web come a un cassetto chiuso. Un attacco SQL Injection è come qualcuno che inserisce una combinazione magica di parole che fa aprire tutti i cassetti del magazzino. L'attaccante cerca di ingannare il database per farsi dare informazioni riservate.", "advice":"Non fidarti mai dei dati inseriti dagli utenti senza controllarli. Usa query preparate nel codice e mantieni il software sempre aggiornato."},
        94:  {"danger_level":"Medio", "explanation_it":"Un attacco XSS è come lasciare un biglietto trappola sul tavolo di qualcun altro. L'attaccante inserisce codice malevolo in una pagina web sperando che altri utenti lo eseguano. Il codice può rubare credenziali o cookie di sessione.", "advice":"Filtra sempre i contenuti inseriti dagli utenti prima di mostrarli. I moderni framework web hanno protezioni integrate: usale."},
        95:  {"danger_level":"Alto",  "explanation_it":"Immagina qualcuno che bussa alla porta di servizio di un magazzino fingendo di essere un corriere, per poi lasciare un pacco pericoloso. Questo attacco sfrutta il protocollo SMB per tentare di installare software malevolo. È la stessa tecnica usata da ransomware famosi come WannaCry.", "advice":"Blocca la porta 445 nel firewall se non è necessaria. Aggiorna sempre il sistema operativo per chiudere le vulnerabilità note."},
        96:  {"danger_level":"Alto",  "explanation_it":"Una shell backdoor è come una porta segreta installata in casa tua a tua insaputa. L'attaccante cerca di creare un canale segreto attraverso cui potrà entrare nel sistema quando vuole, senza bisogno di credenziali.", "advice":"Monitora le connessioni di rete insolite. Usa un firewall che blocchi connessioni in uscita non autorizzate."},
        97:  {"danger_level":"Alto",  "explanation_it":"L'attaccante sta cercando di inserire comandi di sistema direttamente, tentando di scaricare ed eseguire programmi malevoli. Il comando wget indica il tentativo di scaricare qualcosa da internet senza autorizzazione.", "advice":"Limita i comandi eseguibili. Usa il principio del minimo privilegio: ogni servizio dovrebbe avere solo i permessi strettamente necessari."},
        98:  {"danger_level":"Medio", "explanation_it":"Il protocollo FTP è come una vecchia cassetta postale senza serratura. L'attaccante prova ad accedere al servizio di trasferimento file con credenziali anonime, cercando di leggere o caricare file senza autorizzazione.", "advice":"Sostituisci FTP con SFTP che cifra la comunicazione. Se FTP è necessario, disabilita l'accesso anonimo."},
        99:  {"danger_level":"Alto",  "explanation_it":"Lo stesso attaccante dell'Austria continua a provare con strumenti automatici. I bot moderni possono fare migliaia di tentativi all'ora, provando liste di password comuni scaricabili da internet.", "advice":"Implementa un sistema di blocco automatico dopo N tentativi falliti (fail2ban). Cambia la porta SSH predefinita."},
        100: {"danger_level":"Alto",  "explanation_it":"SMB è il linguaggio che i computer Windows usano per condividere file. Questo attacco dalla Cina sfrutta vulnerabilità in questo protocollo. È lo stesso vettore usato da malware devastanti che hanno bloccato ospedali e aziende in tutto il mondo.", "advice":"Aggiorna Windows immediatamente. Disabilita SMBv1 che è obsoleto e vulnerabile."},
        101: {"danger_level":"Basso", "explanation_it":"Come qualcuno che cammina per il quartiere guardando ogni casa e annotando dove sono le telecamere. Questo attacco di ricognizione raccoglie informazioni per pianificare attacchi futuri più mirati.", "advice":"Nascondi le informazioni sulla versione del software nei banner HTTP. Meno informazioni dai, meno vulnerabilità possono sfruttare."},
    }
    return {eid: ALL_EXPLANATIONS[eid] for eid in event_ids if eid in ALL_EXPLANATIONS}


@app.route('/api/events')
@login_required
def api_events():
    org_id = session['org_id']
    events = get_events_for_org(org_id)
    return jsonify(events)


@app.route('/api/explanations')
@login_required
def api_explanations():
    org_id   = session['org_id']
    events   = get_events_for_org(org_id)
    ids      = [e['id'] for e in events]
    explanations = get_explanations_for_events(ids)
    return jsonify(explanations)


@app.route('/api/stats')
@login_required
def api_stats():
    org_id   = session['org_id']
    events   = get_events_for_org(org_id)
    ids      = [e['id'] for e in events]
    explanations = get_explanations_for_events(ids)

    total     = len(events)
    high      = sum(1 for e in explanations.values() if e['danger_level'] == 'Alto')
    medium    = sum(1 for e in explanations.values() if e['danger_level'] == 'Medio')
    countries = len(set(e['country'] for e in events))

    attack_counts = {}
    for e in events:
        attack_counts[e['attack_type']] = attack_counts.get(e['attack_type'], 0) + 1

    return jsonify({
        "total":         total,
        "high":          high,
        "medium":        medium,
        "countries":     countries,
        "attack_counts": attack_counts,
        "org_name":      session['org_name'],
    })


# ── AVVIO ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_users_db()
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static',    exist_ok=True)
    print("\n╔══════════════════════════════════════════╗")
    print("║   HoneypotX — Web Server v1.0           ║")
    print("╚══════════════════════════════════════════╝")
    print("\n  Apri il browser su: http://localhost:5000")
    print("\n  Credenziali demo:")
    print("  → Scuola:  admin_scuola  / scuola123")
    print("  → Azienda: admin_tech    / techcorp123\n")
    app.run(debug=True, port=5000)
