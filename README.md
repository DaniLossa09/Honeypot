# HoneypotX — Backend Analyzer

Backend Python per analizzare i log di **Cowrie**, **OpenCanary** e **Dionaea**,
classificare automaticamente gli attacchi e geolocalizzare gli IP degli attaccanti.

---

## 📁 Struttura file

```
honeypot_analyzer/
│
├── analyzer.py          ← modulo principale (importabile)
├── test_analyzer.py     ← test con log finti (per provare subito)
├── requirements.txt     ← dipendenze Python
└── README.md
```

---

## ⚡ Installazione rapida

```bash
pip install -r requirements.txt
```

---

## 🧪 Test immediato (senza honeypot reale)

```bash
python test_analyzer.py
```

Questo script:
1. Crea log finti di Cowrie, OpenCanary e Dionaea
2. Lancia l'analyzer
3. Mostra statistiche nel terminale
4. Produce `honeypot_data.db` e `events_export.json`

---

## 🚀 Uso con honeypot reali

1. Apri `analyzer.py` e modifica i percorsi nella sezione `LOG_PATHS`:

```python
LOG_PATHS = {
    "cowrie":     "var/log/cowrie/cowrie.json",
    "opencanary": "var/log/opencanary/opencanary.log",
    "dionaea":    "var/log/dionaea/dionaea.json",
}
```

2. Esegui:

```bash
python analyzer.py
```

---

## 📊 Output prodotti

| File                  | Contenuto                                      |
|-----------------------|------------------------------------------------|
| `honeypot_data.db`    | Database SQLite con tutti gli eventi           |
| `events_export.json`  | Esportazione JSON per la dashboard web         |

---

## 🔍 Tipi di attacco riconosciuti

| Tipo               | Esempio trigger                        |
|--------------------|----------------------------------------|
| Brute Force        | Login ripetuti su SSH/Telnet/FTP       |
| SQL Injection       | Payload con `SELECT`, `UNION`, `1=1`   |
| XSS Attack         | Payload con `<script>`, `alert(`       |
| Command Injection  | Payload con `wget`, `bash`, `/etc/passwd` |
| Malware Upload     | Download su porte Dionaea (445, 4444)  |
| SMB Attack         | Traffico sulla porta 445               |
| FTP Attack         | Traffico sulla porta 21                |
| Web Crawl / Recon  | User-agent nmap, sqlmap, nikto…        |
| Port Scan          | Tentativi di connessione generici      |
| Unknown            | Tutto il resto                         |

---

## 🌍 Geolocalizzazione

Usa `ip-api.com` (gratuita, 45 req/min).
Gli IP privati (192.168.x, 10.x, 127.x) vengono marcati come `Local`.

---

## 🔜 Prossimi step consigliati

- **Dashboard web** → Flask/FastAPI + mappa Leaflet + grafici Chart.js
- **Alert automatici** → email/telegram quando un IP supera N tentativi
- **Modulo AI** → Claude API che spiega ogni attacco in linguaggio naturale
