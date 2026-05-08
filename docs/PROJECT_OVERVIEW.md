# HoneypotX - Documentazione completa del progetto

## 1. Descrizione generale

HoneypotX e una piattaforma honeypot pensata per raccogliere, analizzare e visualizzare tentativi di attacco contro servizi esposti. Il progetto integra piu sorgenti honeypot, normalizza i log, riduce i falsi positivi e mostra gli incidenti reali su una dashboard web protetta da login.

L'obiettivo non e contare qualsiasi connessione come attacco, ma segnalare solo comportamenti con rischio concreto: brute force credenziali, login riusciti nel servizio honeypot, comandi post-login, payload web malevoli, trasferimenti FTP sospetti e attivita di ricognizione significativa.

Il progetto e installato nella directory:

```text
/home/cyferwall/honeypot
```

## 2. A chi e rivolto

Il progetto e pensato per:

- piccole e medie aziende che vogliono visibilita sugli attacchi verso servizi esposti;
- team IT/SOC che vogliono distinguere rumore da eventi realmente interessanti;
- ambienti di laboratorio o formazione cybersecurity;
- aziende che vogliono una dashboard semplice per capire cosa sta succedendo senza leggere manualmente log grezzi.

Il valore principale e la riduzione del rumore: un'azienda non deve ricevere allarmi per ogni semplice connessione o login isolato, ma solo quando il comportamento indica un rischio concreto.

## 3. Componenti principali

### Honeypot supportati

Il sistema oggi gestisce tre famiglie di sorgenti:

1. SSH/Telnet tramite Cowrie
   - log principale: `honeypots/logs/cowrie/cowrie.json`
   - rileva login falliti, login riusciti, sessioni e comandi post-login.

2. HTTP/HTTPS tramite OpenCanary
   - log principale: `honeypots/logs/opencanary/opencanary.log`
   - rileva tentativi credenziali ripetuti, SQL injection, XSS, IDOR, command injection, malware upload, web recon.

3. FTP tramite script Python
   - log principale: `honeypots/logs/ftp/ftp.json`
   - rileva tentativi credenziali e comandi operativi/trasferimenti sospetti.

### Backend

Il backend e una API FastAPI in:

```text
api/main.py
```

Funzioni principali:

- espone eventi alla dashboard;
- protegge gli endpoint tramite token di login;
- avvia il processor in background;
- fornisce statistiche, mappe, storyline, dettagli IP, dettagli incidente, export report e configurazione attacchi.

### Processor

Il processor e in:

```text
backend/processor.py
```

Compiti:

- legge incrementalmente i log;
- salva sempre i raw event;
- classifica solo gli eventi rilevanti;
- applica soglie e finestre temporali;
- deduplica incidenti simili;
- arricchisce gli eventi con geolocalizzazione;
- esporta gli eventi in JSON.

### Database

Il database SQLite e configurato di default in:

```text
data/honeypotx.db
```

Tabelle principali:

- `events`: incidenti effettivi mostrati in dashboard;
- `raw_events`: log normalizzati, utili per contesto tecnico, credenziali, comandi e payload.

La logica database e in:

```text
backend/db.py
```

## 4. Logica di rilevamento attacchi

La classificazione si trova in:

```text
backend/classifier.py
```

### SSH/Telnet Cowrie

Non vengono considerati attacchi:

- semplice connessione;
- chiusura sessione;
- banner client;
- key exchange;
- resize terminale;
- comandi vuoti, `exit`, `logout`.

Vengono considerati attacchi:

- login riuscito: `Unauthorized Login`;
- comandi post-login: `Post-Login Activity`;
- comandi pericolosi come `wget`, `curl`, `bash`, `chmod`, `nc`: `Command Injection`;
- login falliti ripetuti oltre soglia: `Credential Attack`.

### OpenCanary HTTP/HTTPS

Non vengono considerati attacchi:

- semplice visita a una pagina;
- singolo login o invio credenziali isolato.

Vengono considerati attacchi:

- credenziali inviate piu volte dallo stesso IP oltre soglia;
- SQL Injection;
- XSS;
- IDOR;
- Command Injection;
- Malware Upload;
- Web Crawl / Recon su path sensibili o user-agent sospetti.

### FTP

Non vengono considerati attacchi:

- comandi normali come `PWD`, `SYST`, `FEAT`, `TYPE`, `QUIT`, `NOOP`.

Vengono considerati attacchi:

- tentativi password ripetuti oltre soglia;
- `STOR`, `APPE`, `RETR`, `DELE`, `RNFR`, `RNTO`, `SITE`;
- argomenti contenenti pattern da command injection o malware.

## 5. Riduzione falsi positivi

Il sistema non crea un incidente per ogni singola riga di log.

Le regole principali sono:

- i tentativi credenziali diventano attacco solo dopo una soglia configurabile;
- la soglia e valutata entro una finestra temporale configurabile;
- comandi multipli nella stessa sessione SSH vengono correlati;
- incidenti uguali vengono deduplicati in bucket temporali;
- semplici visite web o login isolati non generano allarmi.

Questa logica rende il progetto piu realistico per un ambiente aziendale.

## 6. Dashboard

La dashboard e in:

```text
frontend/dashboard_live.html
```

Usa una singola pagina HTML con viste interne:

- Panoramica;
- Mappa / Analisi;
- Storyline;
- Attacchi;
- Configurazione.

La dashboard e protetta da login. Il token viene salvato in `localStorage` e inviato agli endpoint API con header `Authorization: Bearer`.

### Panoramica

Contiene:

- attacchi totali;
- incidenti ad alto rischio;
- incidenti a medio rischio;
- paesi attaccanti;
- mappa globale;
- grafico distribuzione attacchi;
- storyline;
- tabella eventi con filtri.

### Mappa / Analisi

Contiene:

- protocolli piu colpiti;
- tipi di attacco dominanti;
- origini principali;
- mappa dedicata;
- tabella aggregata di distribuzione.

La mappa non si resetta piu a ogni refresh: aggiorna i marker mantenendo centro e zoom scelti dall'utente.

### Storyline

Mostra sequenze di attacco correlate per IP/sessione.

Esempio:

- login riuscito SSH;
- comandi post-login;
- stesso IP;
- stessa sessione.

Questa vista serve a capire il percorso dell'attaccante, non solo il singolo evento.

### Attacchi

Mostra la tabella completa degli incidenti.

Filtri disponibili:

- livello di pericolo;
- ricerca testuale;
- protocollo;
- tipo attacco;
- paese;
- data da/a.

La tabella mostra anche il `Risk Score`.

### Configurazione

Permette di modificare parametri operativi senza editare file Python:

- soglia tentativi credenziali;
- finestra temporale credenziali;
- bucket dedup incidenti;
- sorgenti abilitate;
- dedup post-login per sessione;
- categorie dirette abilitate.

Le impostazioni vengono salvate in:

```text
config/attack_settings.json
```

Il file e ignorato da Git.

## 7. Dettaglio incidente

Cliccando un attacco si apre il dettaglio incidente.

Mostra:

- spiegazione dell'attacco;
- consiglio difensivo;
- motivo tecnico per cui e stato segnalato;
- credenziali provate;
- comandi eseguiti;
- path/URI coinvolti;
- sessioni e user-agent;
- timeline incidente;
- raw event completi.

Endpoint:

```text
GET /incident/{event_id}/detail
```

## 8. Dettaglio IP

Cliccando un IP si apre il dettaglio IP.

Mostra:

- numero incidenti;
- numero raw event;
- risk score;
- servizi/protocolli coinvolti;
- tipi di attacco;
- username provati;
- password provate;
- comandi eseguiti;
- path/URI;
- user-agent;
- timeline completa.

Endpoint:

```text
GET /ip/{ip}/detail
```

## 9. Risk Score

Ogni incidente e ogni IP hanno un punteggio 0-100.

Il punteggio cresce in base a:

- tipo attacco;
- livello di pericolo;
- numero credenziali provate;
- comandi eseguiti;
- comandi pericolosi;
- quantita di path o URI coinvolti;
- piu eventi dallo stesso IP;
- piu protocolli coinvolti.

Esempi:

- Web recon leggero: basso;
- Credential attack: medio;
- login riuscito: alto;
- command injection o malware upload: molto alto.

## 10. Export report

Il sistema puo esportare report:

- HTML leggibile;
- JSON tecnico.

Disponibili per:

- singolo incidente;
- singolo IP.

Endpoint:

```text
GET /incident/{event_id}/export?format=html
GET /incident/{event_id}/export?format=json
GET /ip/{ip}/export?format=html
GET /ip/{ip}/export?format=json
```

I file vengono salvati in:

```text
data/exports/reports/
```

## 11. Reset attacchi

La dashboard ha un pulsante `RESET ATTACCHI`.

Il reset:

- cancella `events`;
- cancella `raw_events`;
- svuota export JSON;
- resetta la memoria dei segnali del processor.

Non cancella:

- log sorgente;
- offset di lettura;
- configurazione;
- credenziali dashboard.

Il reset richiede doppia conferma.

## 12. Autenticazione dashboard

La logica di autenticazione e in:

```text
backend/auth.py
```

Le credenziali vengono salvate in:

```text
config/dashboard_auth.json
```

Il file contiene:

- username;
- password hash PBKDF2;
- secret token;
- durata sessione.

Per cambiare password:

```bash
python3 scripts/set_dashboard_password.py
```

## 13. Configurazione runtime

Il progetto supporta `.env`.

File esempio:

```text
.env.example
```

Variabili principali:

```text
HPX_COWRIE_LOG
HPX_OPENCANARY_LOG
HPX_FTP_LOG
HPX_DB_PATH
HPX_GEO_CACHE_PATH
HPX_OFFSETS_PATH
HPX_EVENTS_EXPORT_PATH
HPX_DASHBOARD_AUTH_PATH
HPX_ATTACK_SETTINGS_PATH
HPX_API_HOST
HPX_API_PORT
HPX_FRONTEND_ORIGIN
HPX_POLL_INTERVAL
HPX_GEO_API_BASE
```

Se `.env` non esiste, il progetto usa i default attuali.

## 14. Installazione

E disponibile un installer guidato:

```bash
./scripts/install.sh
```

Lo script:

- chiede path dei log;
- genera `.env`;
- crea cartelle runtime;
- inizializza configurazione attacchi;
- configura credenziali dashboard;
- esegue healthcheck.

Guida dettagliata:

```text
docs/INSTALL.md
```

## 15. Healthcheck

Script:

```text
scripts/healthcheck.sh
```

Controlla:

- file docker-compose;
- container principali;
- porte esposte;
- path log configurati;
- permessi directory Cowrie;
- mount Cowrie.

## 16. Struttura file principale

```text
api/main.py                     API FastAPI
backend/auth.py                 autenticazione dashboard
backend/classifier.py           classificazione attacchi
backend/config.py               configurazione e .env
backend/db.py                   SQLite, query, storyline, dettagli
backend/explainer.py            spiegazioni e consigli difensivi
backend/geolocation.py          geolocalizzazione IP
backend/parsers.py              parsing log Cowrie/OpenCanary/FTP
backend/processor.py            ciclo lettura log e creazione incidenti
backend/reports.py              export report HTML/JSON
backend/settings.py             configurazione soglie attacchi
frontend/dashboard_live.html    dashboard web
scripts/install.sh              installer guidato
scripts/healthcheck.sh          controlli installazione
scripts/run_tests.sh            test suite
scripts/set_dashboard_password.py cambio password dashboard
docs/INSTALL.md                 guida installazione
```

## 17. Endpoint principali

```text
GET  /health
POST /auth/login
GET  /auth/me
GET  /events
GET  /stats
GET  /attack-distribution
GET  /map-points
GET  /storylines
POST /reset-attacks
GET  /settings/attacks
PUT  /settings/attacks
GET  /event/{event_id}
GET  /event/{event_id}/context
GET  /incident/{event_id}/detail
GET  /incident/{event_id}/export
GET  /ip/{ip}/detail
GET  /ip/{ip}/export
```

Tutti gli endpoint operativi, tranne `/health` e `/auth/login`, richiedono autenticazione.

## 18. Test

I test sono in:

```text
tests/
```

Esecuzione:

```bash
./scripts/run_tests.sh
```

Coprono:

- autenticazione;
- classificazione attacchi;
- riduzione falsi positivi;
- soglie credenziali;
- configurazione custom;
- storyline;
- dettaglio IP;
- dettaglio incidente;
- export report;
- reset.

## 19. Punti di forza attuali

- Multi-protocollo: SSH/Telnet, HTTP/HTTPS, FTP.
- Riduzione falsi positivi.
- Dashboard protetta da login.
- Raw event consultabili.
- Storyline di attacco.
- Dettaglio IP.
- Dettaglio incidente.
- Risk score.
- Export HTML/JSON.
- Configurazione soglie dalla UI.
- Installer guidato.
- Supporto `.env`.
- Test automatici.

## 20. Limiti attuali e possibili evoluzioni

Possibili step futuri:

- Deception Story Builder;
- canary assets;
- MITRE ATT&CK mapping;
- notifiche Telegram/email/webhook;
- pagina attaccanti;
- report PDF;
- integrazione SIEM;
- retention automatica;
- servizio systemd;
- Docker Compose completo per dashboard/API;
- gestione utenti multipli.

## 21. Visione prodotto

HoneypotX non deve essere solo un raccoglitore di log. La direzione migliore e trasformarlo in una piattaforma di deception leggera e spiegabile:

- crea trappole credibili;
- riduce falsi positivi;
- mostra il percorso dell'attaccante;
- assegna priorita;
- suggerisce cosa fare;
- produce report condivisibili.

Questo e il punto che puo differenziarlo da molti honeypot tradizionali: non solo "ho visto una connessione", ma "questo IP ha seguito una catena di azioni con questa intenzione e questo livello di rischio".
