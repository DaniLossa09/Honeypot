<div align="center">

<h1>🍯 HoneypotX - Backend Analyzer</h1>

### Intelligent Cybersecurity Log Analyzer & Classifier

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-lightgrey?style=for-the-badge&logo=sqlite)
![Security](https://img.shields.io/badge/Security-Honeypot-red?style=for-the-badge&logo=security)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

</div>

---

## 📖 Informazioni sul Progetto

**HoneypotX** è un potente backend in Python progettato per analizzare i log generati da honeypot popolari come **Cowrie**, **OpenCanary** e **Dionaea**. Il sistema classifica automaticamente le tipologie di attacco e geolocalizza gli IP degli attaccanti, fornendo dati strutturati pronti per essere visualizzati in una dashboard.

### ✨ Funzionalità Principali
* **🔍 Analisi Multi-Honeypot:** Supporto nativo per i log di Cowrie, OpenCanary e Dionaea.
* **🤖 Classificazione Automatica:** Riconoscimento intelligente di pattern di attacco (Brute Force, SQLi, XSS, ecc.).
* **🌍 Geolocalizzazione IP:** Tracciamento della provenienza degli attacchi tramite API esterne.
* **💾 Esportazione Flessibile:** Generazione automatica di database SQLite e file JSON per integrazioni frontend.

---

## 📂 Struttura del Progetto

Il progetto segue un'architettura modulare per garantire scalabilità e ordine.

```text
honeypotX/
├── backend/             # Moduli principali di analisi log e spiegazione AI
├── api/                 # Server web e routing
├── frontend/            # Interfaccia utente (HTML/CSS/JS)
├── data/                # Database generati e log esportati (.db, .json)
├── tests/               # Script di testing con log fittizi
├── run_all.py           # Entry point per avviare l'intero sistema
├── requirements.txt     # Dipendenze
└── README.md            # Documentazione
```

---

## 🚀 Per Iniziare

### 1. Installazione
Clona la repository e installa le dipendenze necessarie:

```bash
git clone https://github.com/tuo-username/honeypotX.git
cd honeypotX
```

### 2. Installazione Dipendenze

```bash
## Linux ##
# Crea ambiente virtuale
python -m venv .venv
# Avvia ambiente virtuale
source .venv/bin/activate

## Windows ##
# Crea ambiente virtuale
python -m venv .venv
# Avvia ambiente virtuale
.venv/Scripts/activate

## Installa dipendenze ##
pip install -r requirements.txt
```

### 3. Test Immediato (Senza honeypot reale)
Puoi testare il sistema generando dei log fittizi per verificare che tutto funzioni correttamente.

```bash
python tests/test_analyzer.py
```
*Questo script creerà log finti, lancerà l'analyzer e mostrerà le statistiche nel terminale, producendo i file di output nella cartella `/data`.*

### 4. Uso con Honeypot Reali
> [!WARNING]
> **Configurazione Percorsi:** Prima di avviare l'analisi reale, assicurati di aggiornare i percorsi dei log. Apri `backend/analyzer.py` e modifica la sezione `LOG_PATHS` per puntare ai log effettivi del tuo server.

```python
LOG_PATHS = {
    "cowrie":     "var/log/cowrie/cowrie.json",
    "opencanary": "var/log/opencanary/opencanary.log",
    "dionaea":    "var/log/dionaea/dionaea.json",
}
```

Esegui l'orchestratore principale:
```bash
python run_all.py
```

---

## 🔍 Tipi di Attacco Riconosciuti

L'analyzer è istruito per riconoscere e classificare le seguenti tipologie di minacce:

| Tipo | Esempio Trigger |
| :--- | :--- |
| 🛡️ **Brute Force** | Login ripetuti su SSH/Telnet/FTP |
| 💉 **SQL Injection** | Payload con `SELECT`, `UNION`, `1=1` |
| 🌐 **XSS Attack** | Payload con `<script>`, `alert(` |
| 💻 **Command Injection** | Payload con `wget`, `bash`, `/etc/passwd` |
| 🦠 **Malware Upload** | Download su porte Dionaea (445, 4444) |
| 📂 **SMB Attack** | Traffico sulla porta 445 |
| 📁 **FTP Attack** | Traffico sulla porta 21 |
| 🕷️ **Web Crawl / Recon** | User-agent nmap, sqlmap, nikto… |
| 🚪 **Port Scan** | Tentativi di connessione generici |
| ❓ **Unknown** | Tutto il resto |

---

## 📊 Output Prodotti

Il sistema genera automaticamente i dati nella cartella `/data`, pronti per essere consumati da un frontend o da tool di BI.

| File | Contenuto |
| :--- | :--- |
| `data/honeypot_data.db` | Database SQLite con lo storico di tutti gli eventi registrati |
| `data/events_export.json` | Esportazione in formato JSON ottimizzata per la dashboard web |

---

## 🌍 Geolocalizzazione & Limiti API

> Il sistema utilizza l'API di `ip-api.com` per la geolocalizzazione (gratuita, limite di **45 richieste al minuto**). 
> Gli IP privati di rete locale (es. `192.168.x.x`, `10.x.x.x`, `127.x.x.x`) vengono automaticamente bypassati dall'API e marcati come `Local` per risparmiare richieste e migliorare le performance.

---

## 🔜 Prossimi Step Consigliati

- **Dashboard Web:** Implementazione frontend in Flask/FastAPI con mappa interattiva Leaflet e grafici Chart.js.
- **Alert Automatici:** Integrazione notifiche Email/Telegram quando un singolo IP supera una soglia *N* di tentativi.
- **Modulo AI:** Integrazione Claude API (o simili) per generare spiegazioni in linguaggio naturale per ogni tipologia di attacco rilevato.