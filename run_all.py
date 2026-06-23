import os
import sys

import uvicorn

from backend.config import API_HOST, API_PORT

if __name__ == '__main__':
    # Evita che il processo scriva DB/report come root: file di proprieta root
    # bloccano poi le esecuzioni come utente normale (DB readonly).
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        sys.exit(
            'Errore: non avviare HoneypotX come root (o con sudo). '
            'Avvialo come utente normale per non creare file di proprieta root.'
        )
    uvicorn.run('api.main:app', host=API_HOST, port=API_PORT, reload=False)
