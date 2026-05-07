import base64
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Any, Dict

from .config import DASHBOARD_AUTH_PATH


DEFAULT_TTL_SECONDS = 8 * 60 * 60


class AuthError(Exception):
    pass


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode('ascii').rstrip('=')


def _b64url_decode(value: str) -> bytes:
    padding = '=' * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def hash_password(password: str, *, iterations: int = 200_000, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations).hex()
    return f'pbkdf2_sha256${iterations}${salt}${digest}'


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, salt, expected = stored_hash.split('$', 3)
    except ValueError:
        return False
    if algorithm != 'pbkdf2_sha256':
        return False
    actual = hash_password(password, iterations=int(iterations), salt=salt).split('$', 3)[3]
    return hmac.compare_digest(actual, expected)


def load_auth_config(path: Path = DASHBOARD_AUTH_PATH) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f'Dashboard auth config missing: {path}')
    with path.open('r', encoding='utf-8') as f:
        config = json.load(f)
    required = {'username', 'password_hash', 'token_secret'}
    missing = required - set(config)
    if missing:
        raise RuntimeError(f'Dashboard auth config missing fields: {", ".join(sorted(missing))}')
    return config


def create_token(username: str, config: Dict[str, Any] | None = None) -> str:
    config = config or load_auth_config()
    now = int(time.time())
    ttl = int(config.get('token_ttl_seconds') or DEFAULT_TTL_SECONDS)
    payload = {
        'sub': username,
        'iat': now,
        'exp': now + ttl,
    }
    payload_raw = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    payload_b64 = _b64url_encode(payload_raw)
    signature = hmac.new(
        str(config['token_secret']).encode(),
        payload_b64.encode(),
        hashlib.sha256,
    ).digest()
    return f'{payload_b64}.{_b64url_encode(signature)}'


def verify_token(token: str, config: Dict[str, Any] | None = None) -> Dict[str, Any]:
    config = config or load_auth_config()
    try:
        payload_b64, signature_b64 = token.split('.', 1)
        expected = hmac.new(
            str(config['token_secret']).encode(),
            payload_b64.encode(),
            hashlib.sha256,
        ).digest()
        supplied = _b64url_decode(signature_b64)
        if not hmac.compare_digest(expected, supplied):
            raise ValueError
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception as exc:
        raise AuthError('Invalid token') from exc

    if int(payload.get('exp') or 0) < int(time.time()):
        raise AuthError('Token expired')
    return payload


def authenticate(username: str, password: str) -> str:
    config = load_auth_config()
    if not hmac.compare_digest(str(username), str(config['username'])):
        raise AuthError('Invalid credentials')
    if not verify_password(password, str(config['password_hash'])):
        raise AuthError('Invalid credentials')
    return create_token(username, config)


def verify_authorization_header(authorization: str) -> Dict[str, Any]:
    prefix = 'Bearer '
    if not authorization.startswith(prefix):
        raise AuthError('Authentication required')
    return verify_token(authorization[len(prefix):].strip())
