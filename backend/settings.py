import json
from typing import Any, Dict

from .config import ATTACK_SETTINGS_PATH

DEFAULT_ATTACK_SETTINGS: Dict[str, Any] = {
    'credential_threshold': 3,
    'credential_window_seconds': 600,
    'incident_bucket_seconds': 900,
    'post_login_dedupe_by_session': True,
    'enabled_sources': {
        'cowrie': True,
        'opencanary': True,
        'ftp': True,
        'mysql': True,
        'smb': True,
        'scada': True,
    },
    'enabled_direct_attacks': {
        'unauthorized_login': True,
        'post_login_activity': True,
        'sql_injection': True,
        'xss': True,
        'idor': True,
        'command_injection': True,
        'malware_upload': True,
        'web_recon': True,
        'ftp_transfer': True,
        'database_attack': True,
        'scada_attack': True,
    },
}

LIMITS = {
    'credential_threshold': (1, 20),
    'credential_window_seconds': (60, 86400),
    'incident_bucket_seconds': (60, 86400),
}


def _deep_merge(defaults: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
    result = defaults.copy()
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _bounded_int(value: Any, fallback: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = fallback
    return max(minimum, min(parsed, maximum))


def validate_attack_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    merged = _deep_merge(DEFAULT_ATTACK_SETTINGS, settings if isinstance(settings, dict) else {})
    validated = DEFAULT_ATTACK_SETTINGS.copy()

    for key, fallback in (
        ('credential_threshold', DEFAULT_ATTACK_SETTINGS['credential_threshold']),
        ('credential_window_seconds', DEFAULT_ATTACK_SETTINGS['credential_window_seconds']),
        ('incident_bucket_seconds', DEFAULT_ATTACK_SETTINGS['incident_bucket_seconds']),
    ):
        minimum, maximum = LIMITS[key]
        validated[key] = _bounded_int(merged.get(key), fallback, minimum, maximum)

    validated['post_login_dedupe_by_session'] = bool(merged.get('post_login_dedupe_by_session'))
    # Unisce le sorgenti/attacchi del file di config con i default, preservando
    # chiavi nuove aggiunte in DEFAULT che potrebbero non essere nel file salvato.
    merged_sources = {**DEFAULT_ATTACK_SETTINGS['enabled_sources'], **merged.get('enabled_sources', {})}
    validated['enabled_sources'] = {
        source: bool(merged_sources.get(source, enabled))
        for source, enabled in DEFAULT_ATTACK_SETTINGS['enabled_sources'].items()
    }
    merged_attacks = {**DEFAULT_ATTACK_SETTINGS['enabled_direct_attacks'], **merged.get('enabled_direct_attacks', {})}
    validated['enabled_direct_attacks'] = {
        attack: bool(merged_attacks.get(attack, enabled))
        for attack, enabled in DEFAULT_ATTACK_SETTINGS['enabled_direct_attacks'].items()
    }
    return validated


def load_attack_settings() -> Dict[str, Any]:
    if not ATTACK_SETTINGS_PATH.exists():
        return validate_attack_settings({})
    try:
        data = json.loads(ATTACK_SETTINGS_PATH.read_text(encoding='utf-8'))
    except Exception:
        data = {}
    return validate_attack_settings(data)


def save_attack_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    validated = validate_attack_settings(settings)
    ATTACK_SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    ATTACK_SETTINGS_PATH.write_text(json.dumps(validated, ensure_ascii=False, indent=2), encoding='utf-8')
    return validated
