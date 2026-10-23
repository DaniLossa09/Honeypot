# HoneypotX — Report finale dell'audit

Audit del 20 ottobre 2026; stato finale acquisito alle 17:40 UTC (19:40 Europe/Rome).
Repository, README, CLAUDE.md, config e Compose esaminati nelle fasi precedenti.
Nessun AGENTS.md trovato. L'intervento ha seguito le conferme dell'utente fra le fasi.

## Esito e perimetro

La catena log → parser → classifier → SQLite → API → rendering dashboard funziona
per HTTP/HTTPS, SSH/Telnet, FTP, MySQL e Modbus/S7 nei casi collaudati con client reali.
I problemi prioritari di acquisizione/contatori e interoperabilità sono stati corretti.
Non si dichiara una copertura completa di ogni protocollo o di ogni controllo di sicurezza:
le attività aperte sono elencate sotto, distinguendo limiti funzionali e verifiche mancanti.
SMB è in esecuzione e raggiungibile, ma non ha ricevuto un collaudo applicativo NTLM end-to-end
in queste fasi; i suoi due grezzi nel DB non costituiscono prova di tale copertura.

Stato finale verificato, senza generare nuovo traffico honeypot nella fase 5:

- Sei servizi Compose running, zero restart dopo l'ultimo aggiornamento.
- MySQL e SCADA healthy; gli altri quattro non hanno healthcheck configurato.
- `/health` 200, SQLite `PRAGMA quick_check` → `ok`.
- **65 incidenti, 459 eventi grezzi**; `/stats.total` = 65, uguale al conteggio DB
  con triage `true_positive`. **23 login OpenCanary** acquisiti, contati separatamente.
- Tutti e sei gli offset sono a EOF; il dato fotografa il controllo, non garantisce
  assenza di backlog in qualsiasi momento futuro.
- Servizio e timer dell'isolamento persistente entrambi active.

I valori e lo stato dei singoli container sono conservati in [AUDIT_FINAL_STATE.json](AUDIT_FINAL_STATE.json),
privo di credenziali e payload degli attaccanti. Il dettaglio MySQL/SCADA è in
[AUDIT_PHASE4.md](AUDIT_PHASE4.md).

## Problemi, causa radice, prova e trattamento

La severità riguarda il problema iniziale, non una vulnerabilità ancora presente quando
lo stato è indicato come risolto. Le protezioni del tail sono hardening verificato con
casi riproducibili: non sono attribuite senza prova a ogni mancato incremento storico.

| ID / severità | Causa e prova | Fix / stato |
|---|---|---|
| N1 Critico | MySQL e SCADA raggiungevano gateway, IP LAN dell'host e API host. Listener temporaneo: 6 connessioni accettate; `/health` raggiungibile dai container. | Regole nftables dedicate input/forward e bridge, persistenti; DNS non inoltrato. Dopo il fix: 6 rifiuti, zero connessioni accettate; peer OpenCanary irraggiungibile. Risolto nel bridge corrente; limiti di persistenza/ricreazione sotto. |
| O1 Alto | La gestione di offset basata sulla sola dimensione non rilevava sostituzione del file più grande o copytruncate già ricresciuto oltre l'offset. I test riproducono entrambi i casi. | Identità device/inode e impronta dei 128 byte precedenti; offset legacy adottati senza replay. Test rotazione/troncamento/riga parziale superati. |
| O2 Medio | OpenCanary non registrava tutti i percorsi HTTP, e HTTPS usava skin/config non uniformi; richieste 404 assenti dalla normale catena di logging. | Hook per 404, logging redirect/metodi, skin HTTPS coerente; GET reali HTTP/HTTPS su `/` e `/admin` producono 6 eventi inclusi redirect, tutti acquisiti una volta. |
| O3 Medio | I conteggi della vista limitata e gli incidenti correlati non rappresentavano tutti i login acquisiti. Un tentativo sotto soglia non equivale a un incidente nuovo. | Totale globale da `/stats`, contatore login OpenCanary da raw_events; confronto SQL/API coerente. Le soglie restano intenzionali. |
| O4 Medio | Logtype sconosciuti/scarti e validazione non offrivano un contratto sufficiente ai confini. | Schema per OpenCanary/Cowrie/FTP/MySQL/SCADA a parsing, classificazione e insert; eventi sconosciuti OpenCanary conservati/segnalati, portscan classificabile quando emesso. Test tipi invalidi e logtype sconosciuto passati. Copertura SMB da estendere. |
| D1 Alto | Riconciliazione automatica all'avvio poteva eliminare o riaggregare lo storico. | Disabilitata per default; opt-in `HPX_RECONCILE_ON_STARTUP=1`. Riavvii dell'audit senza riconciliazione; storico confrontato e invariato. |
| F1 Alto | FTP trattava i pacchetti TCP come comandi e non applicava un framing CRLF limitato. Credenziali/sessioni/porte incomplete. | Buffer CRLF con limite 8192 byte, UUID sessione e metadati; client reali e casi framing superati. Autenticazione e modalità dati/trasferimenti negati con 530; pubblicata solo 21. |
| C1 Medio | Telnet poteva ricadere su porta 22; opzioni Telnet interpretate come comandi; contesto credenziali limitato alla sessione o da LIMIT prima del filtro temporale. | Porta 23, soli eventi shell come comandi; correlazione credenziali per finestra su più sessioni. Tre sessioni per servizio nei dettagli verificati. |
| C2 Basso | Banner Cowrie richiesto non presente nell'albero montato. | Aggiunto issue.net e aggiornato generatore; sessioni reali SSH/Telnet riuscite. |
| P1 Medio | Schema uniforme avrebbe rifiutato `cowrie.session.params` con message lista, che è un evento legittimo. Individuato durante i nuovi test. | Eccezione strutturata e limitata per quel solo tipo evento; normalizzazione e verifica di nuova ingestione. |
| S1 Alto | COTP/TPKT S7 malformato, lettura socket senza framing e nessuna risposta READ_VAR/WRITE_VAR. Client reale: Invalid TPKT version 0. | Header/framing/limiti e sequence echo corretti; snap7 completa connect/read/write/readback. DR riconosciuta come chiusura, senza falso protocol_error. |
| S2 Alto | Timestamp SCADA congelato per connessione e payload incompleto: due letture distinte con stesso hash; 26 righe delle prove iniziali diventavano 24 grezzi. | Timestamp per emissione, UUID evento/sessione, indirizzi/valori/payload limitati. Ultimo giro: 38 log, 38 hash, 38 righe DB. Replay stessa riga resta idempotente. |
| S3 Alto | Modbus ignorava indirizzi, troncava quantità e confermava scritture senza cambiare stato. | Stato limitato in memoria e validazione; lettura di 10 registri, scritture singole/multiple/coil e FC23 verificate con pymodbus. |
| S4 Medio | MySQL/SCADA usavano porta sorgente come servizio e perdevano evento/funzione/porte normalizzate. | Parser dedicati corretti, campi src_port/dst_port aggiuntivi; JSON integrale e campi DB confrontati con i log. Storico non riscritto. |
| M1 Medio | Mapping T1210/T1190 generico non provato; connessioni SCADA classificate come attacchi e letture potevano nascondere scritture aggregate. | Metadati/setup esclusi; grouping per funzione; mapping ICS solo per scritture osservate, dominio/versione espliciti. Nessuna deduzione di effetto su PLC reali. |
| U1 Medio | MySQL/SCADA root, log dipendenti dall'ownership host, capability e rootfs predefiniti. | UID 10001/10002, proprietà bind mount preparata, cap_drop ALL, no-new-privileges, rootfs read-only; log scrivibili e healthcheck passivi. |
| T1 Medio | Test del processor scrivevano 24 report artificiali nella directory export operativa. | Export dei test isolato con HPX_EXPORT_DIR temporaneo. Solo i 24 file del manifest rimossi dopo approvazione esplicita e verifica path/hash/dimensione. Nessun dato unitario nel DB operativo. |

Le query di inserimento/ricerca esaminate usano parametri; l'audit non ha trovato prova
che la deduplicazione OpenCanary fosse dovuta all'assenza del timestamp nell'hash.
L'hash include timestamp/payload: la collisione riprodotta riguardava SCADA, che emetteva
valori identici per interazioni distinte. Nessuna singola causa viene estesa a tutti i servizi.

## Prove e risultati

| Verifica | Risultato e limiti |
|---|---|
| Suite locale | 84 test passati, inclusi tail/rotazione, schema, classificazione, DB, contesto, framing FTP e protocolli MySQL/SCADA. Fixture isolate in directory/DB temporanei. |
| OpenCanary | Login e richieste reali nelle fasi 2–4; 23 login grezzi al controllo finale. Parser, filtri/soglie, hash, API e contatore verificati; ultimo giro GET: 6/6 eventi. |
| SSH/Telnet | Client reali, tre login falliti per servizio e sessioni riuscite con whoami/uname/pwd/echo/exit; ultimo giro 56 eventi Cowrie acquisiti e campi preservati. |
| FTP | ftplib: login negato e cattura USER/PASS/comandi; trasferimenti negati 530. Ultimo giro 17 eventi nuovi; confronto aggiuntivo di 24 precedenti eventi framing. |
| MySQL | PyMySQL: 3 login negati 1045, database richiesto preservato, 15/15 eventi acquisiti nell'ultimo giro. Nessuna query autenticata inviata. |
| Modbus/S7 | pymodbus e python-snap7 reali: quantità/indirizzi corretti, valori scritti riletti; 23/23 eventi SCADA acquisiti nell'ultimo giro. |
| API/dashboard | Incidenti delle prove presenti in `/events`, dettagli 200, conteggi SQL/API coerenti. Funzioni JS reali renderizzano dati API reali in entrambe le tabelle. Non è un test visuale del browser. |
| Isolamento | Host/gateway/LAN host rifiutati, peer bloccato; porte honeypot e SSH amministrativo 2222 accessibili dall'host. IPv6 senza route: non prova un rifiuto attivo del firewall IPv6. |
| Dati conservati | Snapshot pre-deploy fase 4: 37 incidenti e 286 grezzi identici dopo le modifiche. Anche il precedente riferimento di 17 incidenti/130 grezzi passa il confronto. SQLite quick_check finale ok. |

Porte e mount sono allineati: SSH host22→2222 container, Telnet23→2223, HTTP80,
HTTPS443, FTP21, MySQL3306, SMB445, Modbus502, S7 102. I percorsi host sotto
`honeypots/logs/{cowrie,opencanary,ftp,mysql,smb,scada}` coincidono con LOG_PATHS e i
mount Compose; i file sono leggibili dal backend non privilegiato.

Log recenti per container, conservati durante le prove:

- MySQL: auth_denied/error_code 1045 sono risultati attesi dei login, non crash.
- SCADA: il primo collaudo evidenziava protocol_error alla disconnessione; corretto,
  assente nell'ultimo giro reale. Nessun errore applicativo nell'ultima finestra controllata.
- Cowrie: warning Telnet `state changed and new state returned`; sessioni riuscite.
  `ProcessDone ... exit code 0` e disconnessione SSH del client non sono crash.
- OpenCanary: `Can't use portscan in Docker. Portscan module disabled.` rimane aperto.
- FTP e SMB: nessun warning/errore operativo emerso nella finestra raccolta; per SMB
  ciò non sostituisce un test completo del protocollo.
- Compose: warning container orfano `conpot`, stato Created, conservato senza rimozione.

## Aperto e interventi proposti

| Priorità | Attività / criterio di chiusura |
|---|---|
| Alta, operativa | Collaudare persistenza con riavvio host concordato e verificare regole prima dell'esposizione. Nessun reboot eseguito nell'audit. La ricreazione della rete può lasciare fino a 30s prima del refresh del bridge: prevedere blocco preventivo/ordine di avvio verificato. |
| Media, sicurezza | Estendere UID/capability/rootfs e permessi permanenti a OpenCanary, FTP e SMB (ancora root). Cowrie ha user 999 ma directory log 0777; alcuni file storici sono scrivibili globalmente. Proporre ownership/gruppo/ACL mirati, preservando lettura backend e scrittura container; evitare chmod ricorsivi indiscriminati. |
| Media, funzionale | Portscan OpenCanary dichiarato ma disabilitato in Docker: scegliere acquisizione host dedicata e confinata, oppure documentare esplicitamente la funzione assente. Non abilitare privileged/host network come correzione automatica. |
| Media, copertura | Aggiungere healthcheck passivi a Cowrie/OpenCanary/FTP/SMB e test SMB reale, con schema a tutti i confini. L'attuale audit non certifica la validazione completa di SMB. |
| Media, operativa | Verificare modalità persistente del backend dopo reboot: l'audit lo ha avviato con run_all.py, senza installare un nuovo servizio backend. Il restart unless-stopped dei container non avvia il backend host. |
| Verifica | Browser: login, polling, filtri, contatori, dettaglio e badge ICS. IPv6: collaudo con route disponibile. Test da client LAN esterno: le prove attuali sono dall'host. |
| Limite accettato | MySQL nega autenticazione: query non raggiungibili da client standard. S7 limitato a BYTE/DB1/singola variabile; Modbus e S7 mantengono solo stato volatile, nessun PLC o DB reale. |
| Conservazione | Vecchi mapping/porte mancanti e byte persi prima dell'acquisizione non sono ricostruiti. Non riscrivere lo storico senza backup e decisione esplicita. |
| Bassa | Container conpot orfano e DB legacy honeypots/honeypotx.db conservati. Anche WAL/SHM attivi del DB operativo non vanno cancellati. |

## Regressione proposta

Specifiche in [REGRESSION_PLAN.md](REGRESSION_PLAN.md). Lo script completo multi-servizio è
una proposta, non viene presentato come già implementato. Gli script diagnostici temporanei
delle fasi precedenti restano disponibili in `/tmp`; vanno consolidati prima di uso continuativo.

La suite già implementata si esegue con:

```bash
.venv/bin/python -m unittest discover -s tests
```

## Evidenze, backup e vincoli

Le evidenze integrali di sessione sono sotto `/tmp/hpx-*`, quindi non sono un archivio
permanente. Includono credenziali inviate ai soli honeypot; non sono copiate nel report
pubblico. Conservare privatamente quelle necessarie prima della pulizia automatica di /tmp.
Backup SQLite e offset, non rimossi:

- `/tmp/honeypotx-phase2-20261020T163542Z/`
- `/tmp/hpx-phase3-backup-20261020T165820Z/`
- `/tmp/hpx-phase4-before-deploy-20261020T173410Z/`

Nessun commit/push, docker compose down -v o cancellazione di volumi. Nessun reset del DB
né avanzamento artificiale degli offset. I conteggi operativi includono traffico di collaudo
realmente inviato ai servizi; nessuna riga inventata inserita dal collaudo nel backend/dashboard.
Unica cancellazione: i 24 report unitari identificati e approvati dall'utente.
