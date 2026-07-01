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
| **Dionaea (FTP)** | FTP / 21 | Login attempts, file transfer commands, sandboxed fake filesystem |
| **MySQL honeypot** | 3306 | Real `HandshakeV10` negotiation, captured username/database, `ER_ACCESS_DENIED` |
| **SMB honeypot** | 445 | SMB2 negotiate + NTLM challenge/response, captured username/domain, `STATUS_ACCESS_DENIED` |
| **SCADA honeypot** | Modbus/TCP 502, S7comm 102 | Function codes, fake register values — built from scratch (Conpot is amd64-only, this stack targets ARM64) |

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

Start the API:

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
