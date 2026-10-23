# HoneypotX

Multi-protocol honeypot platform that reads logs from real deception services, correlates
events, filters out noise, scores risk, maps each incident to **MITRE ATT&CK**, generates
**dynamic AI analysis**, and shows everything on a live, authenticated dashboard.

HoneypotX **does not generate traffic**. It only reads logs produced by honeypot services
(Cowrie, OpenCanary, FTP/Dionaea, MySQL, SMB, SCADA) and turns raw noise into readable,
correlated, explained incidents.

---

## What it does

```
honeypot logs ──► parsers ──► classifier ──► processor ─────────────────────► SQLite ──► API ──► dashboard
 (Cowrie, OpenCanary,   normalize     detection rules   dedup + geo + risk score +          events /            REST            live, polling,
  FTP, MySQL, SMB,      into common   + threshold       MITRE ATT&CK mapping + AI analysis   raw events                          maps, storylines
  SCADA)                record        signals                    ▲
                                                                  └── AI analyst (Claude Haiku via HTTP,
                                                                      rate-limited, static fallback)
```

1. **Collect** — an incremental tail reader follows each honeypot's log file (offset-based,
   restart-safe) and normalizes every line into a common record shape.
2. **Classify** — direct incidents (e.g. `Unauthorized Login`, `SQL Injection`, `Command
   Injection`) are flagged immediately; noisy signals (e.g. repeated bad credentials) only
   become an incident once they cross a configurable threshold in a time window.
3. **Enrich** — each incident gets a risk score, a plain-language explanation, a MITRE
   ATT&CK technique (with confidence level — never a guessed ID), IP geolocation, and,
   optionally, a live AI-generated analysis of the attacker's behavior.
4. **Correlate** — incidents from the same IP/session are grouped into storylines (e.g. "login
   → recon → persistence attempt") instead of being shown as disconnected events.
5. **Serve** — a FastAPI backend exposes everything behind token authentication; a single-file
   dashboard (vanilla HTML/JS + Leaflet) polls it for live updates.

---

## Honeypot sources

| Source | Protocol / Port | What it captures |
|---|---|---|
| **Cowrie** | SSH / Telnet | Full interactive session: login attempts, commands typed after login, malware download attempts |
| **OpenCanary** | HTTP/HTTPS + more | Web recon, credential submission, common canary triggers |
| **Dionaea (FTP)** | FTP / 21 | Login and command capture; authentication and data transfers explicitly denied |
| **MySQL honeypot** | 3306 | Real `HandshakeV10` negotiation, captured username/database, `ER_ACCESS_DENIED` |
| **SMB honeypot** | 445 | SMB2 negotiate + NTLM challenge/response, captured username/domain, `STATUS_ACCESS_DENIED` |
| **SCADA honeypot** | Modbus/TCP 502, S7comm 102 | Validated requests, addresses and values; bounded in-memory register/DB1 state, no real PLC |

All custom honeypots (MySQL/SMB/SCADA) are hand-written Python, dependency-free, and speak
just enough of their protocol to complete a believable handshake before logging the attempt
and denying access.

---

## Detection & correlation

- **Direct attack classification**: unauthorized login, post-login command execution, command
  injection, malware upload, SQL injection, XSS, IDOR, web reconnaissance, FTP file transfer
  abuse, database attacks, SCADA protocol abuse.
- **Threshold-based signals**: credential brute force only fires once the same IP crosses a
  configurable number of attempts in a time window — avoids flooding the dashboard with a
  single failed login.
- **Risk scoring**: a 0–100 score combines attack severity, number of credential attempts,
  distinct commands, distinct paths, and multi-session activity from the same IP.
- **MITRE ATT&CK mapping**: every incident gets a tactic/technique/sub-technique with an
  explicit confidence level (`Alto` / `Medio` / `Basso`). If the log data isn't enough to be
  sure, the mapping is left `None` rather than guessed — no invented IDs, ever. Per-command
  **Discovery** techniques (`whoami` → `T1033`, `cat /etc/passwd` → `T1087.001`, etc.) are
  extracted separately and shown in the incident/IP detail view.
- **Storyline correlation**: incidents from the same IP (same session, or same day) are
  grouped into a single narrative — e.g. "interactive SSH compromise" when a login is
  followed by post-login commands.

---

## AI-assisted analysis

Each new incident can be analyzed by **Claude Haiku** (via plain HTTP calls, no SDK) to
produce, in Italian:

- what the attacker likely did and was after,
- a profile of the attacker (bot / scanner / human, sophistication, motivation),
- concrete, incident-specific defense advice.

Rate-limited to one call per hour per `(IP, attack type)` to avoid hammering the API during
high-volume attacks. If no API key is configured, or the call fails, the dashboard silently
falls back to static, rule-based explanations — the AI layer is fully optional.

---

## Dashboard

Single static file (`frontend/dashboard_live.html`), no build step, no framework:

- Live event table with MITRE badges and risk level
- World map of attack origins (Leaflet), including local/LAN traffic shown separately
- Attack type distribution chart
- Storyline view (multi-step attacks from the same actor)
- Incident detail modal: technical reasoning, evidence, timeline, Discovery techniques, AI
  analysis when available
- IP intelligence view: aggregated behavior across all incidents from one address
- Runtime settings panel (thresholds, enabled sources/attacks) — no restart needed
- HTML/JSON incident and IP report export
- Token-based login, no cookies

---

## Stack

FastAPI + SQLite + vanilla HTML/JS. No frontend framework, no external crypto dependency —
password hashing (PBKDF2) and signed tokens (HMAC-SHA256) are implemented by hand with the
standard library. AI calls use `requests`, no Anthropic SDK.

```text
fastapi     web framework / REST API
uvicorn     ASGI server
requests    HTTP client (geolocation + AI calls)
```

Everything else is Python standard library.

---

## Getting started

```bash
git clone <this-repo>
cd honeypotx

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

chmod +x scripts/install.sh
./scripts/install.sh
```

`install.sh` interactively creates `.env`, the runtime folders under `data/`, and the
dashboard credentials in `config/`. It refuses to run as root (the app must own its own data
files — see [Permissions](#permissions--ownership) below).

Per avviare insieme i container (con build), il server della dashboard sulla porta
8080 e il backend usando la `.venv`:

```bash
./start.sh
```

Lo script funziona da qualsiasi directory e va eseguito senza `sudo`. Apri
<http://localhost:8080/dashboard_live.html>. Con `Ctrl+C` si fermano backend e
server dashboard; i container Docker restano accesi. Per fermare anche i container:

```bash
docker compose -f honeypots/docker-compose.yml down
```

Start the API manually:

```bash
python3 run_all.py
# or
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Then open `frontend/dashboard_live.html` in a browser and point it at your API (`?api=`
query param, or it's saved to `localStorage` after the first login).

Bring up the honeypot containers (Cowrie/OpenCanary/Dionaea + the custom MySQL/SMB/SCADA
services) with Docker Compose:

```bash
cd honeypots
docker compose up -d --build
```

Verify everything end-to-end:

```bash
./scripts/healthcheck.sh
```

---

## Configuration

All runtime configuration lives in `.env` (see `.env.example`) and is loaded by
`backend/config.py` — log paths, database/state paths, API host/port, poll interval,
geolocation endpoint, and the optional AI key:

```bash
HPX_ANTHROPIC_API_KEY=sk-ant-...          # leave empty to disable AI analysis
HPX_AI_MODEL=claude-haiku-4-5-20251001
HPX_AI_ENABLED=1
```

Detection thresholds, correlation windows and which sources/attack types are active are
stored in `config/attack_settings.json` (editable at runtime from the dashboard's settings
panel, or via `PUT /settings/attacks`). Dashboard credentials live in
`config/dashboard_auth.json`, generated by:

```bash
python3 scripts/set_dashboard_password.py
```

Neither of these two files, nor `.env`, is committed — see `.gitignore`.

---

## Permissions & ownership

Two different users write into this tree, and mixing them up breaks the app:

- **The app** (FastAPI process) runs as an unprivileged user and owns `data/` (SQLite DB,
  geolocation cache, offsets, exports) and `config/`.
- **The honeypot containers** write their logs into `honeypots/logs/*` — Cowrie typically as
  a non-root container UID, the others as root by default. The app only ever **reads** these.

Never start the app with `sudo`, and never blanket-`chown` `honeypots/logs/` to the app user —
it will take away the honeypot containers' write access to their own logs.

---

## Security notes

- All SQL is parameterized — no string-built queries.
- Passwords: PBKDF2-HMAC-SHA256, 200k iterations. Tokens: HMAC-SHA256 signed, constant-time
  compared, with expiry.
- `/auth/login` is rate-limited per IP to blunt both brute force and CPU-exhaustion attempts
  against the password hashing.
- XSS defense-in-depth: every attacker-controlled and third-party (geolocation) field is
  HTML-escaped before being rendered.
- CORS is never configured as wildcard-with-credentials (an invalid, unsafe combination) —
  wildcard origins disable credentialed requests, explicit origins enable them.
- Destructive dashboard actions (resetting all recorded incidents) require re-entering the
  dashboard password, not just a confirmation dialog.

---

## Tests

```bash
./scripts/run_tests.sh
# or
python3 -m unittest discover -s tests -v
```

Covers parsers, detection rules, the full processing pipeline (thresholds, deduplication,
MITRE backfill, Discovery extraction), auth, and rate limiting.

---

## Project layout

```text
api/main.py                    FastAPI app, REST endpoints, background processing loop
backend/processor.py           Pipeline orchestration (read → classify → enrich → store)
backend/classifier.py          Attack detection rules (direct + threshold-based signals)
backend/parsers.py             Per-source log normalization, incremental tail reading
backend/db.py                  SQLite schema, queries, risk scoring, storyline correlation
backend/mitre.py               MITRE ATT&CK mapping (hand-vendored subset, no invented IDs)
backend/ai_analyst.py          Claude Haiku analysis via HTTP, rate-limited, with fallback
backend/geolocation.py         IP geolocation with file-based cache
backend/auth.py                Password hashing + signed tokens (stdlib only)
backend/ratelimit.py           In-memory login rate limiter
backend/reports.py             HTML/JSON incident & IP report export
frontend/dashboard_live.html   Full dashboard (single file, vanilla JS)
honeypots/                     Docker Compose stack + custom MySQL/SMB/SCADA honeypots
scripts/install.sh             Guided setup (.env, credentials, healthcheck)
scripts/generate_fake_corp.py  Fake corporate scenery generator (honeyfs, FTP root, userdb)
tests/                         unittest suite
```

More detail in `docs/PROJECT_OVERVIEW.md`, `docs/INSTALL.md`, and
`docs/FAKE_CORP_ENVIRONMENT.md`.

---

## License

No license file is currently included — all rights reserved by default. Contact the
repository owner before reusing or redistributing this code.

### Contatori e recupero dei log

La dashboard distingue gli incidenti correlati (totale globale di `/stats`) dai login
OpenCanary acquisiti in `raw_events`. Filtri e grafici operano sulla vista degli ultimi
200 incidenti, il totale globale resta indipendente da questa finestra. I login sotto
soglia restano nei grezzi e non aumentano il numero di incidenti.

Gli offset in byte esistenti restano validi; `_files` aggiunge identità del file e
un'impronta dei byte precedenti all'offset per rilevare sostituzioni e troncamenti.
La prima adozione dei metadati non rilegge lo storico. Se la rotazione rimuove byte
prima che il processor li legga, quei byte non sono recuperabili dal solo file corrente.

La riconciliazione dello storico all'avvio è disattivata per default: può eliminare
incidenti non più classificati o raggruppati. `HPX_RECONCILE_ON_STARTUP=1` la abilita
esplicitamente; usarla solo dopo backup e approvazione delle modifiche allo storico.

### SSH, Telnet e FTP

FTP conserva sessione, username e porte della connessione nei log JSON. Legge i comandi
per righe CRLF (limite 8192 byte), indipendentemente dai pacchetti TCP. L'autenticazione
resta negata; trasferimenti e modalità dati, incluse PASV/EPSV/PORT/EPRT, rispondono 530.
È pubblicata soltanto la porta di controllo 21; non vengono aperte connessioni dati.

I nuovi eventi espongono `src_port` e `dst_port` anche in DB/API, se presenti nel log
sorgente. I campi mancanti restano null; `port` usa la porta destinazione disponibile o
il valore del servizio (22 SSH, 23 Telnet, 21 FTP). Le vecchie righe non vengono riscritte.
Le opzioni di negoziazione Telnet restano nel JSON originale e non sono comandi shell.
Gli incidenti credenziali correlano i segnali dello stesso IP/servizio nella finestra
configurata anche quando provengono da sessioni diverse.

### MySQL, SCADA e isolamento

MySQL conserva il diniego di autenticazione (1045): registra negoziato, login e database
richiesto, senza accettare sessioni query o collegarsi a database reali.
Modbus gestisce FC 1/2/3/4/5/6/15/16/17/23, con 128 registri e 2048 coil per unità.
S7 gestisce COTP, negoziato PDU e letture/scritture BYTE di una variabile per richiesta
nel DB1 (4096 byte). Le operazioni non supportate ricevono errori espliciti. Lo stato
emulato è limitato alla memoria del processo e riparte al riavvio. I log contengono
solo interazioni effettivamente ricevute, timestamp per evento e identificatore univoco.
Le scritture osservate possono ricevere ATT&CK ICS T1692.001 (confidenza Medio);
una connessione o lettura non prova sfruttamento di vulnerabilità.

MySQL/SCADA girano come UID 10001/10002, senza capability, con root filesystem in sola
lettura e healthcheck passivi. Prima del primo avvio preparare i bind mount e installare
il contenimento persistente dall'host:

```bash
sudo python3 scripts/honeypot_isolation.py install
docker compose -f honeypots/docker-compose.yml up -d --build
```

L'installazione richiede una rete `honeypots_honeypot-net` già esistente; su un host
nuovo crearla prima con `docker compose -f honeypots/docker-compose.yml create`, che
prepara i container senza avviarli. Lo script modifica soltanto ownership dei due log,
le proprie tabelle nftables `inet/bridge hpx_isolation` e le proprie unità systemd.
Blocca nuove connessioni verso host/reti e fra honeypot, lasciando le risposte ai client.
Il servizio carica il bridge salvato prima di Docker; il timer aggiorna le regole ogni
30 secondi. Dopo una ricreazione della rete attendere e verificare l'aggiornamento
prima di esporre i servizi. Tutti i servizi usano DNS locale non inoltrato all'esterno.

```bash
systemctl is-active honeypotx-isolation.service honeypotx-isolation-refresh.timer
sudo python3 /usr/local/libexec/honeypotx-isolation.py status
# Rollback delle sole regole/unità HoneypotX, senza cancellare dati:
sudo python3 /usr/local/libexec/honeypotx-isolation.py rollback
```

Le regole coprono IPv4/IPv6; nella rete attuale IPv6 non ha una route utilizzabile.
Il dettaglio del collaudo e dei limiti verificati è in `docs/AUDIT_PHASE4.md`.

### Audit e regressione

Esiti, fix e punti aperti: [report finale](docs/AUDIT_FINAL.md).
Stato verificato: [istantanea JSON](docs/AUDIT_FINAL_STATE.json).
Proposta di collaudo periodico: [piano di regressione](docs/REGRESSION_PLAN.md).
