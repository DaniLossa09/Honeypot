# CLAUDE.md — HoneypotX

Guida tecnica per lavorare su questo progetto. Tenere aggiornato quando l'architettura cambia.

## Cos'è

HoneypotX è una piattaforma honeypot multi-protocollo. **Non** genera traffico: legge i log
prodotti da honeypot esterni (Cowrie, OpenCanary, un FTP honeypot custom), li correla,
classifica gli attacchi reali riducendo il rumore, assegna un *risk score* e li mostra in una
dashboard live protetta da login.

Stack: **FastAPI + SQLite + HTML/JS vanilla**. Nessun framework frontend, nessuna dipendenza
crypto esterna (token e hash password sono implementati a mano con la stdlib).

## Architettura / flusso dati

```
log honeypot (file)  ──►  parsers.py  ──►  classifier.py  ──►  processor.py  ──►  SQLite (db.py)  ──►  api/main.py  ──►  dashboard_live.html
  cowrie.json              normalizza      regole attacco     dedup + geo +        events /            endpoint REST       fetch + render
  opencanary.log           in record       + segnali soglia   risk + explain       raw_events                              (polling)
  ftp.json
```

1. **`backend/parsers.py`** — `read_incremental(source, path, offset)` legge solo le righe nuove
   (tail incrementale via offset salvato in `data/state/offsets.json`). Un parser per sorgente
   (`parse_cowrie_line`, `parse_opencanary_line`, `parse_ftp_line`, `parse_dionaea_line`)
   normalizza ogni riga in un dict comune (`ip`, `port`, `service`, `command`, `username`, …).
2. **`backend/classifier.py`** — due livelli:
   - `classify_attack(record)` → incidente diretto (es. `Unauthorized Login`, `SQL Injection`,
     `FTP Attack`, `Post-Login Activity`). Restituisce `None` per il rumore.
   - `classify_signal(record)` → segnale che diventa incidente solo **sopra soglia** (es.
     `Credential Attack`: serve un numero minimo di tentativi nella finestra temporale).
3. **`backend/processor.py`** — `Processor.process_once()` orchestra: legge i nuovi record,
   li salva in `raw_events`, classifica, applica le soglie (`signal_history` in memoria),
   filtra per impostazioni attive, arricchisce con spiegazione (`explainer.py`) e geo
   (`geolocation.py`), calcola un `event_hash` per la deduplica e inserisce in `events`.
   Gira in loop di background (vedi `api/main.py`) ogni `HPX_POLL_INTERVAL` secondi.
4. **`backend/db.py`** — schema (`events`, `raw_events`), insert idempotenti
   (`INSERT OR IGNORE` sull'hash), e tutte le query di lettura/aggregazione usate dall'API
   (`fetch_events`, `fetch_stats`, `fetch_map_points`, `fetch_storylines`,
   `fetch_incident_detail`, `fetch_ip_detail`). Il **risk score** è calcolato qui
   (`_event_risk_score` / `_risk_band`). Le *storyline* correlano incidenti dello stesso IP
   (per sessione o per giorno).
5. **`api/main.py`** — app FastAPI. Istanzia `processor = Processor()` a livello di modulo e
   avvia il loop di background nel `lifespan`. Tutti gli endpoint dati richiedono auth Bearer
   (`Depends(require_auth)`); aperti solo `/health` e `/auth/login`.
6. **`frontend/dashboard_live.html`** — singolo file (~3k righe): login, polling degli endpoint,
   rendering di tabella eventi, mappa (Leaflet), grafico distribuzione, storyline, modali
   dettaglio incidente/IP, pannello impostazioni, export report. Il token è in `localStorage`.

## Componenti chiave (mappa file)

| File | Ruolo |
|------|-------|
| `api/main.py` | Endpoint REST + lifespan/loop di background |
| `backend/processor.py` | Pipeline di elaborazione (`process_once`, soglie, reset) |
| `backend/classifier.py` | Regole di rilevamento (incidenti + segnali) |
| `backend/parsers.py` | Normalizzazione log per sorgente + tail incrementale |
| `backend/db.py` | Schema SQLite, insert, query, risk score, storyline |
| `backend/explainer.py` | Testo IT (danger_level / spiegazione / consiglio) per tipo attacco |
| `backend/geolocation.py` | Lookup geo via ip-api.com con cache su file |
| `backend/auth.py` | Hash password (pbkdf2_sha256) + token firmato HMAC-SHA256 |
| `backend/settings.py` | Caricamento/validazione `attack_settings.json` (con limiti) |
| `backend/reports.py` | Export report incidente/IP in HTML (escaped) o JSON |
| `backend/config.py` | Path, env (`.env` caricato a mano), costanti runtime |
| `frontend/dashboard_live.html` | Dashboard completa (vanilla JS) |
| `honeypots/dionaea/ftp_honeypot.py` | FTP honeypot standalone che serve `fake_corp/ftp_root` |
| `scripts/set_dashboard_password.py` | Crea/ruota `config/dashboard_auth.json` |
| `scripts/install.sh` | Genera `.env`, init settings, imposta credenziali, healthcheck |

## Configurazione

- **Runtime via env / `.env`** (vedi `.env.example`): `HPX_*` per path log, DB, host/porta API,
  origine frontend, intervallo polling, base API geo. `.env` è caricato a mano da
  `backend/config.py` (niente python-dotenv).
- **`config/dashboard_auth.json`** (gitignored, **non** committato): `username`,
  `password_hash`, `token_secret`, `token_ttl_seconds`. Generato da
  `scripts/set_dashboard_password.py`.
- **`config/attack_settings.json`** (gitignored): soglie credenziali, finestra, bucket
  incidenti, sorgenti e attacchi abilitati. Modificabile a runtime via `PUT /settings/attacks`
  (la dashboard ha un pannello). Validato/clamp in `backend/settings.py`.

## Comandi

```bash
# Test (10/10 verdi dopo il fix permessi)
./scripts/run_tests.sh
# oppure
python3 -m unittest discover -s tests -v

# Avvio API
python3 run_all.py            # usa HPX_API_HOST/PORT
# oppure
uvicorn api.main:app --host 0.0.0.0 --port 8000

# Setup iniziale
./scripts/install.sh

# Dipendenze
pip install -r requirements.txt   # fastapi, uvicorn, requests (il resto è stdlib)
```

La dashboard è il file statico `frontend/dashboard_live.html`: aprirlo nel browser e puntarlo
all'API (parametro `?api=` o `localStorage.honeypotx_api_base`).

## Stato / cose da sapere (verificato il 2026-06-21)

### ⚠️ Permessi & ownership (modello da rispettare)
Due utenti scrivono in questo albero, e confonderli rompe tutto:
- **L'app** gira come `cyferwall` (uid 1000) e **scrive** `data/` (DB, cache, state, exports,
  reports) e `config/`. Questi devono appartenere a `cyferwall`. Se finiscono a root → DB
  `OperationalError: attempt to write a readonly database`, niente attacchi registrati, export
  500.
- **I container honeypot** scrivono i **log** in `honeypots/logs/`: `cowrie` come **uid 999**
  (`user: "999:999"` nel compose), `dionaea`/`opencanary` come root. L'app questi log li **legge
  soltanto**.

Regole pratiche (non rifare gli errori già visti):
- **Mai** avviare app/script con `sudo` (creerebbero file root non scrivibili). `install.sh` e
  `run_all.py` hanno un guard che **rifiuta l'avvio come root**.
- **Mai** includere `honeypots/logs/` in un `chown` verso `cyferwall`: toglie la scrittura al
  container cowrie (uid 999) → SSH smette di loggare. Se serve riassegnare i log usare l'uid del
  container: `chown -R 999:999 honeypots/logs/cowrie` (world-readable per l'app).
- Reset/recupero offset: vedi sotto.

### `RESET ATTACCHI` e offset
`reset_attacks` cancella DB + raw e **avanza gli offset a fine file** (`_log_size`): reset =
"pulisci la vista e ignora ciò che è già nei log", quindi gli incidenti cancellati **non
ricompaiono**; solo le righe di log nuove generano nuovi incidenti. **Per riprocessare i log da
zero** (recupero, es. dopo una finestra di DB non scrivibile): azzerare manualmente
`data/state/offsets.json` — non il bottone reset.

### ✅ Fix applicati il 2026-06-21 (tutti verificati, 10/10 test)
1. **Permessi root su `data/`** (era BLOCCANTE) → `chown` + guard anti-root (vedi sopra).
2. **I/O bloccante async**: `background_processor` usa `asyncio.to_thread(process_once)` (idem la
   chiamata nel `lifespan`); gli endpoint sono `def` → già in threadpool FastAPI.
3. **CORS + binding** (`api/main.py`, `backend/config.py`): niente più wildcard+credenziali —
   con `*` le credenziali CORS sono disattivate (ok con auth Bearer da header, no cookie), con
   origini CSV esplicite sono attive. `HPX_API_HOST` resta `0.0.0.0` perché la dashboard è usata
   in LAN (`0.0.0.0:8080`, API base `http://<hostname>:8000`); restringere con `127.0.0.1` o IP
   LAN + reverse proxy/TLS se serve.
4. **XSS difesa in profondità** (`frontend/dashboard_live.html`): `ip`, `country`, `city`,
   `service`, `attack_type`, `danger` ora escaped in `renderTable`/`modalMeta` (geo da ip-api.com
   = non fidato). I campi attacker-controlled erano già escaped.
5. **FTP honeypot** (`honeypots/dionaea/ftp_honeypot.py`): containment con
   `target.is_relative_to(FAKE_ROOT)`; `datetime.utcnow()` → `datetime.now(timezone.utc)`.
6. **Rilevazione SSH**: Cowrie non scriveva `cowrie.json` (file passato a uid 1000 dal chown del
   fix #1, container uid 999 senza permesso di append). Risolto con `chmod 666` sui log cowrie +
   `docker restart cowrie`; alla rotazione i nuovi file li crea uid 999 → si auto-risolve.
   Verificato end-to-end: `Unauthorized Login` + `Post-Login Activity` + `Command Injection`.

### Bug / miglioramenti noti (non bloccanti, ancora aperti)
- **Tail di riga parziale**: `_read_new_lines` può leggere una riga senza newline finale e
  avanzare l'offset, scartando il resto al ciclo dopo. Raro, comune nei tail.
- **`EXPORT_DIR` non override-abile via env**: i test dei report scrivono nell'albero reale
  (`data/exports/reports/`) invece che in tmp → passano ma sporcano `data/`. Se si toccano i
  report, valutare di rendere `EXPORT_DIR` override-abile via env come gli altri path.

### Cose fatte bene (non rompere)
- Tutte le query SQLite sono **parametrizzate** → niente SQL injection.
- Auth artigianale ma corretta: token firmato HMAC-SHA256, confronto a tempo costante
  (`hmac.compare_digest`), controllo `exp`; password pbkdf2_sha256 a 200k iterazioni.
- Segreti **non** committati (`dashboard_auth.json` / `attack_settings.json` gitignored e non
  tracciati). I log di esempio in `honeypots/logs/cowrie/` sono volutamente versionati.
- Insert idempotenti via `event_hash` / `raw_hash` (`INSERT OR IGNORE`) → niente duplicati.
- Report HTML generati con `html.escape`.
- Parametri `limit` degli endpoint sono clampati lato API.

## Convenzioni

- Codice e identificatori in inglese; testi utente, spiegazioni e commenti in **italiano**.
- Niente dipendenze nuove se la stdlib basta (è la linea seguita per auth/token).
- I test sono `unittest` (non pytest): `python3 -m unittest discover -s tests`.
- Modifiche alle regole di rilevamento → aggiornare/aggiungere casi in
  `tests/test_detection_rules.py`; modifiche alla pipeline → `tests/test_processor_flow.py`.
