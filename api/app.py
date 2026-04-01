"""
app.py — HoneypotX Web Server
==============================
Backend Flask con sistema login e dashboard.
Modificato con percorsi assoluti e dotenv per la sicurezza.
"""

from flask import Flask, request, jsonify, session, redirect, url_for, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import json
import os
from datetime import datetime
from functools import wraps
from dotenv import load_dotenv

# ── PATH ASSOLUTI E AMBIENTE ─────────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA_DIR = os.path.join(BASE_DIR, 'data')
FRONTEND_DIR = os.path.join(BASE_DIR, 'frontend')

load_dotenv(os.path.join(BASE_DIR, '.env'))

app = Flask(__name__, 
            static_folder=os.path.join(FRONTEND_DIR, 'static'), 
            template_folder=os.path.join(FRONTEND_DIR, 'templates'))
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "chiave-di-emergenza-dev")

# ── DATABASE ─────────────────────────────────────────────────────────────────
USERS_DB  = os.path.join(DATA_DIR, "users.db")
DATA_DB   = os.path.join(DATA_DIR, "honeypot_data.db")
EXPL_DB   = os.path.join(DATA_DIR, "explanations.db")

def init_users_db():
    """Crea DB utenti e inserisce utenti demo."""
    os.makedirs(DATA_DIR, exist_ok=True)
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

    orgs = [
        ("Scuola Rossi - Milano",  "school"),
        ("Azienda TechCorp",       "company"),
    ]
    for name, otype in orgs:
        c.execute("INSERT OR IGNORE INTO organizations (name, org_type, created_at) VALUES (?,?,?)",
                  (name, otype, datetime.utcnow().isoformat()))

    conn.commit()

    c.execute("SELECT id FROM organizations WHERE name='Scuola Rossi - Milano'")
    school_id = c.fetchone()[0]
    c.execute("SELECT id FROM organizations WHERE name='Azienda TechCorp'")
    company_id = c.fetchone()[0]

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
    print("[DB] Database utenti inizializzato in:", USERS_DB)

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
    # Per ora uso un file di fallback se login.html non c'è
    return send_from_directory(app.template_folder, 'login.html')

@app.route('/dashboard')
@login_required
def dashboard_page():
    return send_from_directory(app.template_folder, 'dashboard_v2.html')

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

# ── API DATI (Mocked for Demo) ──────────────────────────────────────────────
def get_events_for_org(org_id: int) -> list:
    ALL_EVENTS = [
        {"id":91,  "timestamp":"2026-03-31T10:00:00","source":"cowrie",    "ip":"185.234.219.12","port":22,  "service":"ssh",   "attack_type":"Brute Force",      "country":"Austria",       "city":"Vienna",   "lat":48.2, "lon":16.3,   "confidence":"high"},
        {"id":92,  "timestamp":"2026-03-31T11:00:00","source":"opencanary","ip":"45.33.32.156",  "port":80,  "service":"http",  "attack_type":"SQL Injection",    "country":"United States", "city":"Fremont",  "lat":37.5, "lon":-121.9, "confidence":"high"},
    ]
    return [e for i, e in enumerate(ALL_EVENTS) if (i % 2 == 0) == (org_id == 1)]

def get_explanations_for_events(event_ids: list) -> dict:
    ALL_EXPLANATIONS = {
        91:  {"danger_level":"Alto",  "explanation_it":"Immagina un ladro che prova migliaia di chiavi...", "advice":"Utilizza password lunghe e complesse."},
        92:  {"danger_level":"Alto",  "explanation_it":"Pensa a un modulo di ricerca su un sito come a un cassetto chiuso...", "advice":"Non fidarti mai dei dati inseriti dagli utenti."},
    }
    return {eid: ALL_EXPLANATIONS[eid] for eid in event_ids if eid in ALL_EXPLANATIONS}

@app.route('/api/events')
@login_required
def api_events():
    return jsonify(get_events_for_org(session['org_id']))

@app.route('/api/explanations')
@login_required
def api_explanations():
    events   = get_events_for_org(session['org_id'])
    ids      = [e['id'] for e in events]
    return jsonify(get_explanations_for_events(ids))

@app.route('/api/stats')
@login_required
def api_stats():
    events = get_events_for_org(session['org_id'])
    explanations = get_explanations_for_events([e['id'] for e in events])
    high = sum(1 for e in explanations.values() if e['danger_level'] == 'Alto')
    return jsonify({
        "total": len(events),
        "high": high,
        "org_name": session['org_name'],
    })

# ── AVVIO ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_users_db()
    os.makedirs(app.template_folder, exist_ok=True)
    os.makedirs(app.static_folder,   exist_ok=True)
    print("\n╔══════════════════════════════════════════╗")
    print("║   HoneypotX — Web Server v1.0            ║")
    print("╚══════════════════════════════════════════╝")
    print("\n  Apri il browser su: http://localhost:5000")
    print("\n  Credenziali demo:")
    print("  → Scuola:  admin_scuola  / scuola123")
    print("  → Azienda: admin_tech    / techcorp123\n")
    app.run(debug=True, port=5000)