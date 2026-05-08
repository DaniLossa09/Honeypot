# Installazione HoneypotX

Questa procedura prepara il progetto per un ambiente aziendale senza modificare i file Python a mano.

## Installazione guidata

Esegui dalla root del progetto:

```bash
chmod +x scripts/install.sh
./scripts/install.sh
```

Lo script chiede:

- path log Cowrie
- path log OpenCanary
- path log FTP
- host e porta API
- intervallo di polling
- credenziali dashboard

Poi crea:

- `.env`
- cartelle runtime in `data/`
- `config/dashboard_auth.json`
- `config/attack_settings.json`

## File `.env`

Il backend carica automaticamente `.env` all'avvio. Se `.env` non esiste, vengono usati i default attuali del progetto.

Variabili principali:

```bash
HPX_COWRIE_LOG=/path/to/cowrie.json
HPX_OPENCANARY_LOG=/path/to/opencanary.log
HPX_FTP_LOG=/path/to/ftp.json
HPX_API_HOST=0.0.0.0
HPX_API_PORT=8000
HPX_DASHBOARD_AUTH_PATH=/path/to/dashboard_auth.json
HPX_ATTACK_SETTINGS_PATH=/path/to/attack_settings.json
```

## Healthcheck

Dopo la configurazione:

```bash
./scripts/healthcheck.sh
```

Controlla container, porte, log configurati e mount principali.

## Password dashboard

Per cambiare credenziali:

```bash
python3 scripts/set_dashboard_password.py
```

Lo script usa `HPX_DASHBOARD_AUTH_PATH` da `.env`, quindi salva nel path configurato.

## Note aziendali

- Non committare `.env`, `config/dashboard_auth.json` o `config/attack_settings.json`.
- Verifica permessi di lettura sui log reali.
- Se Cowrie gira in Docker con UID/GID 999, mantieni corretti i permessi della cartella log.
- Esporre `HPX_API_HOST=0.0.0.0` rende l'API raggiungibile in rete: proteggi firewall e accessi.
