from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / 'data'
CACHE_DIR = DATA_DIR / 'cache'
EXPORT_DIR = DATA_DIR / 'exports'
STATE_DIR = DATA_DIR / 'state'
CONFIG_DIR = BASE_DIR / 'config'

for d in (DATA_DIR, CACHE_DIR, EXPORT_DIR, STATE_DIR, CONFIG_DIR):
    d.mkdir(parents=True, exist_ok=True)

DB_PATH = Path(os.getenv('HPX_DB_PATH', DATA_DIR / 'honeypotx.db'))
GEO_CACHE_PATH = Path(os.getenv('HPX_GEO_CACHE_PATH', CACHE_DIR / 'geo_cache.json'))
OFFSETS_PATH = Path(os.getenv('HPX_OFFSETS_PATH', STATE_DIR / 'offsets.json'))
EVENTS_EXPORT_PATH = Path(os.getenv('HPX_EVENTS_EXPORT_PATH', EXPORT_DIR / 'events_export.json'))
DASHBOARD_AUTH_PATH = Path(os.getenv('HPX_DASHBOARD_AUTH_PATH', CONFIG_DIR / 'dashboard_auth.json'))
ATTACK_SETTINGS_PATH = Path(os.getenv('HPX_ATTACK_SETTINGS_PATH', CONFIG_DIR / 'attack_settings.json'))

LOG_PATHS = {
    'cowrie': os.getenv('HPX_COWRIE_LOG', '/home/cyferwall/honeypot/honeypots/logs/cowrie/cowrie.json'),
    'opencanary': os.getenv('HPX_OPENCANARY_LOG', '/home/cyferwall/honeypot/honeypots/logs/opencanary/opencanary.log'),
    'ftp': os.getenv('HPX_FTP_LOG', '/home/cyferwall/honeypot/honeypots/logs/ftp/ftp.json'),
}

GEO_API_BASE = os.getenv('HPX_GEO_API_BASE', 'http://ip-api.com/json')
POLL_INTERVAL_SECONDS = int(os.getenv('HPX_POLL_INTERVAL', '3'))
API_HOST = os.getenv('HPX_API_HOST', '0.0.0.0')
API_PORT = int(os.getenv('HPX_API_PORT', '8000'))
FRONTEND_ORIGIN = os.getenv('HPX_FRONTEND_ORIGIN', '*')
