# Audit HoneypotX — Fase 4

Diagnosi iniziale del 20 ottobre 2026, precedente ai fix. Solo servizi honeypot locali.
Durante la diagnosi iniziale nessuna modifica al codice operativo, ai container o alle regole di rete.
I fix successivamente autorizzati e applicati sono descritti nella sezione finale. Rimosse esclusivamente
le 24 esportazioni di test già autorizzate, dopo verifica di percorso, dimensione e SHA-256.

## Esito

MySQL completa il negoziato di autenticazione con un client reale e nega l'accesso.
Modbus risponde ma non mantiene una semantica coerente per indirizzi, quantità e scritture.
S7 non completa il handshake con il client reale. L'isolamento dall'host non è presente.
Gli incidenti acquisiti arrivano ad API e rendering dashboard, ma eventi SCADA distinti
si perdono già nella deduplicazione dei grezzi.

## Ambiente e prove riproducibili

Client installati solo in `/tmp/hpx-phase4-clients`: PyMySQL 1.2.3, pymodbus 3.16.1,
python-snap7 3.3.0. Nessuna dipendenza aggiunta all'ambiente o ai requirements del progetto.

Script e risultati integrali della sessione:

- `/tmp/hpx_phase4_clients.py`: login MySQL, letture/scritture Modbus, connessione S7.
- `/tmp/hpx-phase4-client-evidence.json`: marker `HPX-P4-20261020T170943Z`, risultati e log grezzi.
- `/tmp/hpx_phase4_isolation.py` e `/tmp/hpx-phase4-isolation-evidence.json`: listener temporaneo sull'host e sei connessioni accettate dai container.
- `/tmp/hpx_phase4_s7_diagnostic.py` e `/tmp/hpx-phase4-s7-diagnostic.json`: PDU del client S7, inviati dopo il handshake invalido solo per diagnosticare logging e risposte successive.
- `/tmp/hpx_phase4_verify.py`: confronto parser/classifier/hash/DB/API.
- `/tmp/hpx-phase4-dashboard-check.js`: rendering delle funzioni reali della dashboard con risposte API reali, senza browser grafico.

Esecuzione dei client: `/tmp/hpx-phase4-clients/bin/python -u /tmp/hpx_phase4_clients.py`.
Esecuzione del confronto: `PYTHONPATH=. .venv/bin/python /tmp/hpx_phase4_verify.py`.
Ripetere queste prove produce nuovi eventi reali; i numeri sotto si riferiscono a questa sessione.

## Problemi e fix proposti

### Critico — Isolamento di rete assente

Causa: entrambi i servizi usano `honeypots_honeypot-net`, bridge con `Internal: false`,
senza restrizioni di uscita definite nel Compose. La sola configurazione non è stata
considerata prova sufficiente: è stato aperto un listener TCP temporaneo sull'host.

Prova: MySQL e SCADA hanno raggiunto, ciascuno, `172.18.0.1`, `192.168.1.85` e
`192.168.1.84` sulla porta temporanea 43991. Il listener ha accettato sei connessioni.
Dagli stessi container, `http://172.18.0.1:8000/health` restituisce 200 e `{"status":"ok"}`.
`/stats` senza credenziali restituisce 401: l'autenticazione funziona, l'isolamento no.
Non sono stati contattati altri dispositivi LAN: la prova riguarda l'host e le sue interfacce LAN.

Fix: contenimento persistente delle nuove connessioni da honeypot verso host, LAN,
altre reti e altri honeypot, mantenendo soltanto le risposte alle connessioni in ingresso.
Occorrono regole appropriate sia per traffico destinato all'host sia per quello inoltrato;
non basta intervenire sulla sola pubblicazione porte. Preparare un rollback e verificare
l'accesso amministrativo e tutti i protocolli dopo l'applicazione. Nessuna regola applicata
in questa fase.

I due container non sono privileged e montano soltanto le rispettive directory dei log:
non risultano mount del DB applicativo, delle credenziali host o del socket Docker.
I responder sono gli script Python del repository, senza collegamento a MySQL o PLC reali.
Entrambi girano però come root, con filesystem scrivibile e capability Docker predefinite.
Proposta aggiuntiva: UID dedicati, capability ridotte e gestione mirata dei permessi dei log.

### Alto — S7 non interoperabile

Prova con python-snap7: `Invalid TPKT version in response: 0`.
La risposta COTP inizia con `00 16 03 00 ...` ed è lunga 24 byte; il campo versione TPKT
è dunque 0. La costante `_COTP_CC` in `scada_honeypot.py` antepone due byte al vero header.
Lo standard TPKT richiede versione 3.

La diagnosi successiva ha inviato PDU costruiti dalla libreria client nonostante la prima
risposta invalida: il setup riceve una risposta; READ_VAR e WRITE_VAR non ricevono alcuna
risposta. Questo NON costituisce un handshake riuscito con il client standard.
Il server usa inoltre `recv(1024)` come se coincidesse con un PDU, senza seguire il framing TPKT.

Fix: correggere header/lunghezze/riferimenti COTP, leggere i frame completi con limiti,
rispondere alle operazioni supportate e restituire errori di protocollo espliciti alle altre.
Verificare poi connect, lettura e scrittura con python-snap7 senza bypass diagnostici.

### Alto — Perdita di interazioni SCADA nella deduplicazione dei grezzi

Causa: il timestamp è creato una volta nella struttura `base` della connessione e riusato
per tutte le operazioni. Il payload registrato contiene solo parte della richiesta.
`_raw_hash` comprende timestamp e payload, ma questi possono essere identici per operazioni distinte.

Prova Modbus: due letture reali identiche, separate da un secondo, producono due righe con
lo stesso timestamp e lo stesso hash:

`e74e90b4a8618bf1bad7326df853f0c56e7775a6a23c00a3b5ea6b7953a2b163`

Query parametrizzata: `SELECT COUNT(*) FROM raw_events WHERE raw_hash = ?` → **1**, contro due richieste inviate e due righe del log.
Prima prova: 15 righe SCADA, 14 hash distinti, 14 righe DB. Le sei righe MySQL sono tutte presenti.

Prova S7: letture DB1 agli offset 0 e 10 vengono entrambe registrate come `READ_VAR`,
senza indirizzo; cinque eventi diagnostici diventano quattro hash e quattro righe DB.
Complessivamente le due prove hanno prodotto 26 righe MySQL/SCADA e 24 righe grezze distinte.

Fix: timestamp per ogni evento e identificatore univoco dell'evento/connessione;
registrare i campi della richiesta e il payload di protocollo entro limiti espliciti.
Mantenere idempotente il replay dello stesso evento. Non riscrivere lo storico o gli offset.

Anche MySQL riusa il timestamp della connessione per il login: non ha causato collisioni
nei sei eventi osservati, ma non registra il momento effettivo di ogni interazione.

### Alto — Semantica Modbus incoerente

Prove con pymodbus:

| Richiesta | Risposta osservata |
|---|---|
| Read holding, indirizzo 0, quantità 2 | `[100, 50]` |
| Read holding, indirizzo 3, quantità 1 | `[100]`: indirizzo ignorato |
| Read holding, quantità 10 | Solo 8 registri |
| Read coils, quantità 16 | Solo 8 bit |
| Write register 0 = 321 | Confermata; lettura successiva restituisce ancora 100 |
| Write registers 2 = [11, 22] | Confermata; lettura successiva restituisce [100, 50] |
| Write coil 0 = false | Confermata; lettura successiva restituisce true |
| Read/write multiple, FC 0x17 | Eccezione 1 (funzione non supportata), pur essendo elencata tra le funzioni |

Causa: risposte basate su una lista costante, indirizzi ignorati, quantità troncate e
scritture semplicemente riecheggiate. Nei log delle scritture singole il valore è chiamato
`quantity` (es. 321); nelle scritture multiple mancano i valori inviati.

Fix: un piccolo modello di memoria confinato al responder, con validazione di indirizzi,
quantità e payload; scritture coerenti o rifiuto esplicito. Nessun collegamento a PLC reali.
Le risposte emulative non devono diventare eventi inventati: DB e dashboard conserveranno
esclusivamente le interazioni effettivamente ricevute.

### Medio — Parser incompleti e schema non validato ai confini

Esistono parser dedicati per entrambi i servizi. Tuttavia:

- `parse_mysql_line` usa `src_port` come `port`; l'incidente osservato riporta 52568 invece di 3306.
- `parse_scada_line` usa la porta sorgente (es. 52330), calcola `local_port` ma non la usa nel record.
- I nuovi campi DB/API `src_port` e `dst_port` rimangono null per entrambe le sorgenti.
- Il parser SCADA sostituisce l'evento (`connection`, `modbus_request`, `s7_request`) con il protocollo.
- `SETUP_COMM`, `READ_VAR` e `WRITE_VAR` nel log S7 diventano tutti `command = S7COMM`.
- `validate_record` non applica ancora uno schema MySQL/SCADA a parsing, classificazione e inserimento.
- Il servizio S7 non registra indirizzi e valori; non è un campo che il solo parser possa recuperare.

Fix: estendere il contratto validato, mantenere evento, protocollo, sessione, porte e
operazione separati; conservare i campi effettivamente presenti e rendere visibili gli scarti.
Le INSERT esaminate sono parametrizzate; non occorre sostituirle con SQL costruito da input.

### Medio — Classificazione e MITRE troppo generici per SCADA

`_classify_scada` restituisce sempre `SCADA Attack`, anche per un semplice `connection`.
I due incidenti principali Modbus e S7 contengono infatti come payload rappresentativo
la sola connessione TCP. Il secondo è stato classificato attacco prima che fallisse il handshake.

Mapping esistente:

- I tre login MySQL attivano `Credential Attack` → T1110, confidenza Alto; il dettaglio API include i tre login.
- Le query MySQL avrebbero `Database Attack` → T1190, Medio, ma il servizio non emette eventi query.
- Qualsiasi evento SCADA riceve T1210, Basso; non esiste un catalogo ATT&CK ICS.

Una connessione o lettura non dimostra sfruttamento di una vulnerabilità, come descritto
da T1210/T1190. Fix: distinguere rumore, negoziato, richieste e operazioni rilevanti;
non assegnare una technique non dimostrata. Un eventuale mapping ICS deve usare il catalogo
ufficiale aggiornato e dichiarare dominio/versione, senza inventare ID o dedurre effetti non osservati.

### Limite funzionale — Query MySQL non raggiungibili con client standard

PyMySQL riceve correttamente 1045 in tutti e tre i login. Username e database richiesto
sono preservati: il secondo tentativo registra `audit_HPX-P4-20261020T170943Z`.
Il client non invia `SELECT 1`, perché l'autenticazione non riesce. Il servizio chiude
subito dopo il diniego e non implementa una fase query.

Proposta: mantenere il diniego per default e documentare questo limite. Se serve catturare
query con un client standard, occorre approvare esplicitamente una modalità emulativa con
autenticazione accettata e query rifiutate/loggate, senza collegamento a database reali.

## DB, API e dashboard

Incidenti principali: 3133 MySQL Credential Attack; 3134 Modbus; 3148 S7.
La diagnosi successiva aggiunge l'incidente S7 3149. Tutti sono restituiti da `/events`;
`/incident/{id}/detail` risponde 200. Le funzioni delle due tabelle della dashboard
renderizzano gli stessi ID e i servizi MYSQL/MODBUS/S7COMM usando risposte API reali.
Non è stata eseguita una prova visuale con browser.

Il totale `/stats` concorda con `COUNT(*)` degli incidenti `true_positive`: **35** al termine
del collaudo. Gli offset MySQL e SCADA raggiungono EOF. Questo esclude un arresto del tail
in questa prova, ma non risolve le collisioni dei grezzi descritte sopra.

## Ordine proposto dei fix

1. Contenimento di rete, privilegi e permessi dei log, con verifica dell'accesso amministrativo.
2. Timestamp/identificatori e payload completi per evitare nuove perdite di eventi.
3. Framing e interoperabilità S7; semantica Modbus coerente e risposte di errore esplicite.
4. Schema e parser dedicati; classificazione e MITRE fondati sull'evidenza.
5. Ripetere client reali, richieste duplicate/distinte, confronto log/DB/API/rendering e test di isolamento.

## Fonti primarie consultate

- Docker, firewall e bridge: https://docs.docker.com/engine/network/firewall-iptables/ e https://docs.docker.com/engine/network/drivers/bridge/
- RFC 1006, formato TPKT: https://www.rfc-editor.org/rfc/rfc1006
- Client python-snap7: https://python-snap7.readthedocs.io/en/latest/API/client.html ; per le chiamate effettive è stata ispezionata anche la versione installata.
- MITRE T1210: https://attack.mitre.org/techniques/T1210/
- MITRE T1190: https://attack.mitre.org/techniques/T1190/
- Catalogo ICS: https://attack.mitre.org/techniques/ics/


## Fix autorizzati applicati e collaudo conclusivo

### Isolamento e privilegi — risolto nell'ambiente attuale

`scripts/honeypot_isolation.py` installa soltanto le proprie tabelle nftables
`inet hpx_isolation` (input/forward) e `bridge hpx_isolation` (fra container), senza
modificare policy generali o tabelle Docker. Le risposte alle connessioni ricevute sono
consentite, le nuove connessioni originate dagli honeypot sono bloccate. Il servizio
systemd carica il bridge salvato prima di Docker e il timer refresh lo verifica ogni 30s.
Installazione root eseguita dall'utente, esito confermato; servizio e timer risultano active.
Tutti i container hanno DNS 127.0.0.1 per evitare inoltro upstream dal resolver Docker.

Dopo la ricreazione dei container: sei connessioni TCP MySQL/SCADA verso gateway e IP
LAN dell'host sono tutte rifiutate; zero connessioni accettate dal listener temporaneo.
Entrambi non raggiungono OpenCanary sullo stesso bridge (timeout). IPv6 verso il link-local
del bridge restituisce Network is unreachable: regole inet dual stack installate, ma
non è disponibile un percorso IPv6 per una prova positiva del filtraggio IPv6.
Non sono stati sondati altri dispositivi LAN; il filtraggio inoltrato è verificato nelle
regole, il test attivo LAN riguarda soltanto le interfacce dell'host.
Le porte pubblicate 21/22/23/80/443/102/445/502/3306 rispondono ancora dall'host;
anche l'accesso amministrativo 2222 risponde. Nessun reboot dell'host eseguito.

MySQL UID 10001, SCADA UID 10002; entrambi cap_drop ALL, no-new-privileges,
root filesystem read-only. I file log sono 0644, proprietà 10001/10002 rispettivamente.
Entrambi healthy con check passivi (listen socket e permesso di scrittura log).
Gli altri quattro servizi sono Up; non hanno un healthcheck configurato.
Il vecchio container orfano `conpot`, in stato Created da tre mesi, è conservato.

### Identità, schema e pipeline — risolto per i nuovi eventi

Timestamp UTC generato ad ogni emissione, UUID per evento e sessione, append protetto
da lock. Le stesse richieste ripetute hanno hash distinti; rileggere la stessa riga
rimane idempotente. Parser dedicati preservano evento, funzione, indirizzo, valori,
porta sorgente/destinazione e JSON integrale. Validazione a parser, classifier e insert;
INSERT e query usano parametri. Il contratto ammette correttamente `s7_request`.
Connessioni, handshake e setup non generano incidenti SCADA; le operazioni sì.
Il raggruppamento SCADA comprende la funzione, così una lettura non nasconde una
successiva scrittura. Gli incidenti restano aggregati: il loro numero non è il numero
complessivo delle richieste, conservate in raw_events.

### Protocolli — risolti entro il perimetro dichiarato

Modbus: framing MBAP completo e limitato, FC 1/2/3/4/5/6/15/16/17/23; indirizzi,
quantità, letture/scritture coerenti con memoria emulata limitata (128 registri e
2048 coil per unità). Richieste invalide/operazioni non supportate hanno eccezioni esplicite.
Client pymodbus: lettura di 10 registri completa; scrittura 321 riletta come 321;
scrittura multipla [11,22] riletta allo stesso indirizzo; coil true/false riletta false;
FC23 restituisce [44,55] dopo scrittura.

S7: TPKT/COTP corretti, negoziato PDU e sequence echo, READ_VAR/WRITE_VAR BYTE su DB1,
una variabile per richiesta, memoria di 4096 byte e limiti PDU. Snap7 reale completa
connect, legge, scrive [12,34] all'indirizzo 10 e rilegge [12,34]. La chiusura COTP DR
è riconosciuta e loggata come disconnect, senza falso protocol_error. Altre aree,
tipi o richieste multiple non sono una completa emulazione Siemens e ricevono errori.
Nessun collegamento a PLC reali. Lo stato dei responder è volatile al riavvio.

MySQL: capability/packet length/auth parsing validati, database estratto solo se il
client dichiara CONNECT_WITH_DB; il plugin non viene confuso con il nome database.
Tre login PyMySQL producono 1045, come richiesto. Query non inviate dopo il diniego;
la cattura query autenticata rimane intenzionalmente fuori perimetro.

### MITRE — corretto per i nuovi incidenti

Rimosso il mapping generico T1210/T1190 non dimostrato. Letture SCADA senza mapping;
scritture osservate Modbus/S7 mappate a ICS TA0106 / T1692 / T1692.001, confidenza Medio.
API espone dominio ICS, data verifica catalogo 2026-10-20 e versione oggetto subtechnique
2.0; badge dashboard indica ICS. Non viene dedotto un effetto su un PLC reale.
Fonte: https://attack.mitre.org/techniques/T1692/001/ (modifica 13 ottobre 2026).
Lo storico non è riscritto: vecchi incidenti possono conservare mapping precedenti.

### Prove e risultati

- `.venv/bin/python -m unittest discover -s tests`: **84 test OK**. Nuovi casi per
  semantica Modbus, autenticazione MySQL, framing/sequence/roundtrip/disconnect S7,
  schema nei tre stadi, dedup e visibilità delle scritture, mapping ICS.
  Fixture esclusivamente temporanee; nessun record di test unitario inserito nei dati operativi.
- `docker compose -f honeypots/docker-compose.yml up -d --build`: completato;
  backend aggiornato avviato con riconciliazione storica disabilitata.
- Ultimo collaudo `/tmp/hpx_phase4_fixed_clients.py` con marker
  `HPX-P4-20261020T173622Z` (il valore esatto è nell'evidence JSON): **15 eventi MySQL +
  23 SCADA**, **38 hash distinti e 38 righe DB**, nessun protocol_error o perdita.
  JSON grezzo integrale e campi normalizzati confrontati per uguaglianza con i log.
- `/tmp/hpx_phase4_fixed_verify.py`: nove incidenti aggregati dell'ultimo giro presenti
  in `/events`; tutti i dettagli rispondono 200; offset MySQL/SCADA a EOF.
  Evidence: `/tmp/hpx-phase4-fixed-client-evidence.json`,
  `/tmp/hpx-phase4-final-clients.log`, `/tmp/hpx-phase4-final-verify.log`.
- `node /tmp/hpx-phase4-dashboard-check.js`: i dati API reali MySQL/Modbus/S7 sono
  renderizzati nelle due tabelle; nessun collaudo visuale in browser.
- Regressione `/tmp/hpx_phase3_fixed_probe.py`: nuovi login falliti e sessioni riuscite
  SSH/Telnet, comandi whoami/uname/pwd/echo/exit, login FTP e diniego trasferimenti.
  **56 nuovi eventi Cowrie e 17 FTP** verificati nel DB/API; il verificatore include
  anche 24 precedenti eventi FTP di framing, totale FTP controllato 41.
  Otto incidenti aggregati presenti in API, credenziali correlate su tre sessioni per
  SSH e Telnet. Esiti `/tmp/hpx-phase4-regression*.log`.
- Backup SQLite consistente e offset: percorso in `/tmp/hpx-phase4-backup-path`.
  **37 incidenti e 286 grezzi pre-deploy invariati** dopo tutti i fix.
  Al controllo successivo ai collaudi MySQL/SCADA e SSH/Telnet/FTP: 63 incidenti,
  453 grezzi; `/stats.total` = 63, concordante con DB true_positive.
  Eventuali prove successive aumentano legittimamente questi conteggi.
- Isolamento: `/tmp/hpx-phase4-isolation-evidence.json` contiene ora il collaudo dopo
  il fix (sei rifiuti); `/tmp/hpx-phase4-peer-ipv6-evidence.json` contiene peer/IPv6.
  La prova precedente di sei connessioni ammesse resta descritta nella diagnosi sopra.
- Regressione HTTP/HTTPS: quattro GET iniziali su `/` e `/admin`; i redirect seguiti
  dal client producono sei eventi (due 3003 e quattro 3000), tutti nel DB una volta.
  Evidence `/tmp/hpx-phase4-web-regression.json`.
- Nessun commit/push, volume eliminato, reset di offset o riconciliazione distruttiva.

### Aperto per la fase 5

Produrre report complessivo e proposta regressione ripetibile per tutti i servizi.
Restano: collaudo visuale browser, prova di riavvio host/persistenza, copertura attiva
IPv6 quando configurata una route, eventuale ampliamento S7 e acquisizione query MySQL
solo se richiesti. La ricreazione della rete può richiedere fino a 30s al timer per
aggiornare il nome bridge: verificare le regole prima di esporre una nuova rete.
