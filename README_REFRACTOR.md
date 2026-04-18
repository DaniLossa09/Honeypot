# HoneypotX Refactor

## Avvio

```bash
cd honeypotx_refactor
python -m venv .venv
source .venv/bin/activate   # Linux
pip install -r requirements.txt
python run_all.py
```

API: `http://localhost:8000`

## Path log reali

Configura via variabili ambiente:

```bash
export HPX_COWRIE_LOG=/percorso/reale/cowrie.json
export HPX_OPENCANARY_LOG=/percorso/reale/opencanary.log
export HPX_DIONAEA_LOG=/percorso/reale/dionaea.json
export HPX_FTP_LOG=/percorso/reale/ftp.log
python run_all.py
```

## Comportamento atteso

- log vuoti => `/stats` restituisce tutti zero
- nessun file => nessun crash, nessun evento inventato
- nuovi log => lettura incrementale con offset persistenti in `data/state/offsets.json`
- deduplica => hash evento univoco in SQLite

## Frontend

Apri `frontend/dashboard_live.html` e punta l'API con:

```html
<script>
window.HONEYPOTX_API_BASE = 'http://SERVER:8000';
</script>
```

oppure lascia `http://localhost:8000`.
