# Rilevamento port scan host

OpenCanary disabilita il suo modulo portscan in Docker. Il nuovo servizio
`honeypotx-portscan` osserva passivamente il traffico TCP in ingresso al server
con tcpdump (già presente sul deployment), senza modificare firewall o Docker.
Registra un allarme quando lo stesso IP sorgente contatta **12 porte distinte
sullo stesso IP del server entro 10 secondi**. SYN ritrasmessi sulla stessa porta
non incrementano la soglia; SYN/ACK e risposte vengono ignorati. Cooldown: 60
secondi per coppia sorgente/destinazione; memoria limitata a 4096 coppie.
Non archivia pacchetti, payload, password o singole connessioni.

## Installazione su questo server

```bash
sudo bash scripts/install_portscan_sensor.sh
```

Il servizio usa l'utente `cyferwall` e solo `CAP_NET_RAW`; il codice installato
in `/usr/local/libexec` è di root e non è modificabile dal servizio.
Il log leggibile dall'app è `/var/log/honeypotx-portscan/events.jsonl`, con
rotazione a 5 MiB e 3 backup. L'installer non modifica ownership di data/,
config/ o log dei container. Usa systemd e richiede Linux, tcpdump e iproute2.

Riavviare il processo API HoneypotX **come utente normale**, per caricare la
nuova sorgente. Nel deployment attuale è avviato tramite `python3 run_all.py`;
se gestito da systemd, usare il proprio servizio API. La sorgente è attivabile/disattivabile nelle impostazioni della dashboard
tramite “Port scan del server”; disattivarla sospende la lettura, non il sensore.
`HPX_PORTSCAN_LOG` permette di scegliere un percorso alternativo per il reader;
aggiornare anche `--output` del servizio se si cambia il percorso del writer.

## Verifica reale

Da un altro PC autorizzato della LAN:

```bash
nmap -sT -Pn -p 1-100 192.168.1.84
```

È possibile usare anche `nmap indirizzo_ip_server` (TCP connect/SYN); almeno
12 porte distinte devono raggiungere il server nella finestra configurata.
Il test va eseguito contro l'IP del server, non contro l'IP interno di un container.

```bash
systemctl status honeypotx-portscan.service
journalctl -u honeypotx-portscan.service -n 30 --no-pager
```

Dopo il polling, compare l'incidente `Port Scan`, sorgente `portscan`, con IP
sorgente reale e mapping MITRE T1595. La normale deduplicazione degli incidenti
(15 minuti per default) può aggregare scansioni successive. Per IP privati la
mappa usa la posizione configurata dell'honeypot (Dalmine), non quella dello scanner.

## Configurazione e limiti

Usare `sudo systemctl edit honeypotx-portscan.service` per cambiare i parametri:

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/python3 -I /usr/local/libexec/honeypotx-portscan.py --threshold 12 --window 10 --cooldown 60
```

Poi `sudo systemctl daemon-reload` e `sudo systemctl restart honeypotx-portscan`.
Le modifiche alle soglie non richiedono riavvio dell'API.
Il sensore include IPv4 e IPv6 decodificati da tcpdump, ascolta anche VPN e loopback,
e aggiorna ogni 30 secondi gli IP locali. Esclude come destinazioni i bridge Docker.
Non rileva scansioni UDP, FIN/NULL/Xmas, scansioni più lente della soglia o traffico
bloccato prima di raggiungere la macchina. Le scansioni dello stesso server contro
se stesso possono dipendere dalla modalità di cattura del kernel: preferire un PC esterno.
Un'attività legittima su molte porte può superare la soglia; l'allarme indica la
scansione osservata, non prova da solo l'intento malevolo. Con NAT si vede l'IP
presentato al server. Sotto carico tcpdump può perdere pacchetti: consultarne i log.

Disattivazione reversibile: `sudo systemctl disable --now honeypotx-portscan`.
Nessuna regola firewall deve essere rimossa.

## Test

`python3 -m unittest discover -s tests -v` include test parser TCP IPv4/IPv6,
soglia, cooldown, memoria, selezione IP host e integrazione sensore → parser →
classificazione → DB → riconciliazione. I test usano dati isolati e non inseriscono
incidenti simulati nel database di produzione.

Riferimenti: [packet socket Linux](https://man7.org/linux/man-pages/man7/packet.7.html),
[interfaccia socket Python](https://docs.python.org/3.11/library/socket.html).
