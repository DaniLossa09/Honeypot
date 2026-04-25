# 🛡️ HoneypotX

HoneypotX è un sistema di monitoraggio e analisi degli attacchi informatici basato su honeypot reali containerizzati (Docker) e un backend Python.

Il progetto raccoglie log da servizi esposti (SSH, FTP, HTTP, ecc.), li analizza e li visualizza in una dashboard, distinguendo tra eventi benigni, sospetti e attacchi reali.

---

## 🚀 Funzionalità

- 🔍 Analisi log multi-honeypot (Cowrie, OpenCanary, Dionaea)
- 📊 Dashboard in tempo reale
- 🤖 Classificazione intelligente degli eventi
- 🌍 Geolocalizzazione IP
- ⚡ Riduzione dei falsi positivi
- 🧩 Architettura modulare

---

## 🧠 Sistema di Detection

HoneypotX non considera ogni evento come attacco.

Pipeline:
1. Parsing dei log
2. Normalizzazione eventi
3. Calcolo risk score
4. Correlazione (IP, sessione, tempo)
5. Classificazione finale

Classi:
- ✅ Benigno → connessioni normali, comandi base (`ls`, `pwd`, `GET /`)
- ⚠️ Sospetto → scanning leggero, tentativi ripetuti
- 🚨 Attacco → brute force, exploit, download malware, comandi malevoli

---

## 🏗️ Architettura

Attaccanti → Honeypot (Docker) → Backend Python → API → Dashboard

---

## ⚙️ Installazione

```bash
git clone https://github.com/tuo-username/honeypotx.git
cd honeypotx

mkdir -p logs/cowrie logs/opencanary logs/ftp
chmod -R 777 logs

docker compose up -d --build

cd backend
python3 main.py
```

Dashboard: http://localhost:3000

---

## 📂 Struttura

honeypotx/
├── docker-compose.yml
├── logs/
├── backend/
├── frontend/
└── honeypots/

---

## 🔐 Note

- Utilizzare solo in ambienti controllati
- I log provengono da traffico reale
- Consigliato isolamento tramite firewall

---

## 📄 Licenza

MIT
