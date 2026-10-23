# Proposta di regressione HoneypotX

Specifiche per uno script futuro `scripts/check_end_to_end.py`, da consolidare dagli
script di audit. Non è ancora implementato; la suite di 84 test esistente resta eseguibile.

## Contratto di esecuzione

Target esplicito limitato alla propria installazione. Nessun INSERT di test nel DB operativo:
solo connessioni reali ai responder. Marker UTC/UUID univoco in username, User-Agent e comandi;
per SCADA correlazione con sessione/transaction e intervallo dei log, senza inventare eventi.
Autenticazione API in memoria, senza stampare token/password. Esito JSON privo di segreti,
exit code nonzero per errori o copertura richiesta mancante; timeout globale e per servizio.
Nessun commit, riavvio automatico, cancellazione, truncate, reset o variazione del firewall.

Preflight: acquisire inode/dimensione dei log, UID/permessi, container/health e timestamp;
verificare API, parametri dei servizi e sola lettura SQLite. Il collaudo genera eventi reali
visibili anche in dashboard: non elimina le proprie tracce dopo l'esecuzione.
Dipendenze client in ambiente separato: PyMySQL, pymodbus, python-snap7; SSH/Telnet/FTP con
client adatti. Per SMB aggiungere un client NTLM reale. Non simulare successi in loro assenza.

## Matrice minima

| Servizio | Traffico reale | Asserzioni |
|---|---|---|
| HTTP/HTTPS | GET /, GET /admin, login falliti fino alla soglia configurata | Eventi richieste/redirect/login, timestamp attuale, porte 80/443; credenziali preservate; grezzi e contatore login crescono; incidenti secondo soglie e bucket. |
| SSH/Telnet | Login negati e sessione consentita dall'honeypot, whoami/pwd/echo marker/exit | Credenziali, comandi, sessioni e porte 22/23; opzioni Telnet escluse dai comandi; contesto credenziali multi-sessione. |
| FTP | USER/PASS, SYST/PWD, STOR/RETR/PASV, QUIT; invii spezzati/coalescenti | Ogni comando una volta, sessione/credenziali/porte conservate; diniego dati 530; nessuna connessione dati. |
| MySQL | Login con e senza database, password errata | Handshake credibile e 1045; database distinto dal plugin; eventi completi, query non inviata dopo diniego. |
| Modbus | Due letture identiche; letture a indirizzi differenti; count10; write/readback; FC23; richiesta fuori range | Nessuna collisione delle richieste distinte, valori/indirizzi/quantità corretti, errori espliciti e log di ogni richiesta. |
| S7 | Connect, DB1 read, write/readback, indirizzo diverso, area non supportata, disconnect | Framing/sequence, roundtrip, errore esplicito e chiusura senza protocol_error spurio; indirizzi/valori preservati. |
| SMB | Negotiate e autenticazione NTLM negata | Protocollo risponde, evento JSON valido e campi account/domain/sessione preservati fino ad API. Copertura da implementare. |

## Verifica della catena

1. Attendere acquisizione con polling limitato (es. 30s), non una pausa fissa che nasconde errori.
2. Leggere soltanto le nuove righe complete; gestire cambio inode senza assumere che il marker
   compaia in tutti gli eventi di connessione. Validare e correlare prima di confrontare.
3. Calcolare hash con il codice reale e cercare con query parametrizzate: una riga per ogni
   evento unico; eventi ripetuti reali distinti e nessuna collisione inattesa. Confrontare JSON
   originale e campi normalizzati. Non chiamare process_once in parallelo al processor operativo.
4. Verificare incidenti previsti e dettaglio API, senza imporre un incidente per ogni log.
   Rispettare filtri, soglie, bucket e possibili incidenti già esistenti nella stessa finestra.
5. Confrontare `/stats` con SQL usando lo stesso filtro triage; verificare contatore OpenCanary.
6. Eseguire rendering JS e, nella regressione browser, login/polling/filtri/modali/badge senza
   rimpiazzare la risposta API con fixture. Nessun traffico di altri attaccanti deve invalidare
   confronti basati ingenuamente sul totale globale: correlare i propri eventi.

## Sicurezza e resilienza

Prova di isolamento separata: listener temporaneo sull'host, tentativi da MySQL/SCADA verso
IP gateway e IP dell'host, peer honeypot e listener IPv6 quando disponibile. Verificare zero
connessioni ammesse e ingressi ancora funzionanti. Non sondare host LAN di terzi né servizi
esterni. Regole/servizi controllati in lettura; nessuna modifica automatica.

Rotazione, copytruncate ricresciuto, righe incomplete, input JSON/schema malevolo, replay,
frammentazione e richieste eccessive restano test su file/DB/listener temporanei, separati
 dai volumi reali. Il test di reboot/ricreazione rete va pianificato in manutenzione e deve
verificare l'ordine firewall → esposizione, includendo la finestra del timer di refresh.

## Criterio di successo

Tutti i protocolli selezionati rispondono entro timeout; ogni evento reale correlato è
acquisito esattamente una volta con campi attesi; API/dashboard concordano con DB; nessuna
connessione vietata riesce. Segnalare separatamente FAIL, PASS e SKIP con motivazione:
un client mancante o IPv6 senza route non è un PASS della funzione non provata.
