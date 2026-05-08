# HoneypotX

HoneypotX is a lightweight multi-protocol honeypot platform built to detect and visualize real attack activity while reducing false positives.

The project combines multiple honeypot sources, correlates events, assigns risk scores and provides a protected live dashboard for monitoring incidents.

---

## Features

- SSH/Telnet monitoring via Cowrie
- HTTP/HTTPS monitoring via OpenCanary
- FTP honeypot support
- Smart attack classification
- False positive reduction
- Risk scoring system
- Attack storyline correlation
- Interactive dashboard
- Incident & IP detail views
- HTML/JSON report export
- Runtime configuration panel
- Authentication-protected API and dashboard

---

## Supported Attack Detection

HoneypotX detects:

- Credential brute force
- Successful unauthorized logins
- Post-login command execution
- SQL Injection
- XSS
- Command Injection
- Malware uploads
- Web reconnaissance
- Suspicious FTP activity

The system ignores simple connections and generic noise to focus on meaningful threats.

---

## Stack

- FastAPI
- SQLite
- Cowrie
- OpenCanary
- HTML/JS Dashboard

---

## Installation

```bash
git clone <repository>
cd honeypotx

chmod +x scripts/install.sh
./scripts/install.sh
```

---

## Main Components

```text
api/main.py                  FastAPI backend
backend/processor.py         Event processor
backend/classifier.py        Attack classification
frontend/dashboard_live.html Dashboard
data/honeypotx.db            SQLite database
```

---

## Dashboard Features

- Live attack monitoring
- Global attack map
- Risk analysis
- Storyline correlation
- Advanced filters
- Incident details
- IP intelligence

---

## Run Tests

```bash
./scripts/run_tests.sh
```

---

## Vision

HoneypotX is designed to be more than a simple log collector.

The goal is to provide a lightweight and explainable deception platform capable of identifying real attacker behavior instead of generating alerts for every connection.

---

## License

MIT

