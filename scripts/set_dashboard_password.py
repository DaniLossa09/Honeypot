#!/usr/bin/env python3
import getpass
import json
import secrets
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.auth import hash_password  # noqa: E402
from backend.config import DASHBOARD_AUTH_PATH  # noqa: E402


def main() -> int:
    username = input('Username dashboard: ').strip()
    if not username:
        print('Username obbligatorio.', file=sys.stderr)
        return 1

    password = getpass.getpass('Nuova password dashboard: ')
    confirm = getpass.getpass('Conferma password: ')
    if password != confirm:
        print('Le password non coincidono.', file=sys.stderr)
        return 1
    if len(password) < 8:
        print('Usa almeno 8 caratteri.', file=sys.stderr)
        return 1

    DASHBOARD_AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    config = {
        'username': username,
        'password_hash': hash_password(password),
        'token_secret': secrets.token_urlsafe(48),
        'token_ttl_seconds': 28800,
    }
    DASHBOARD_AUTH_PATH.write_text(json.dumps(config, indent=2) + '\n', encoding='utf-8')
    print(f'Credenziali dashboard aggiornate: {DASHBOARD_AUTH_PATH}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
