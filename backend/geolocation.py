import json
import time
from pathlib import Path
from typing import Dict, Optional

import requests

from .config import GEO_API_BASE, GEO_CACHE_PATH
from .utils import is_local_ip


class GeoResolver:
    def __init__(self, cache_path: Path = GEO_CACHE_PATH):
        self.cache_path = cache_path
        self.cache: Dict[str, Dict] = self._load_cache()
        self.last_call_ts = 0.0

    def _load_cache(self) -> Dict[str, Dict]:
        if not self.cache_path.exists():
            return {}
        try:
            return json.loads(self.cache_path.read_text(encoding='utf-8'))
        except Exception:
            return {}

    def _save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(self.cache, ensure_ascii=False, indent=2), encoding='utf-8')

    def resolve(self, ip: Optional[str]) -> Dict:
        if not ip or is_local_ip(ip):
            return {'country': 'Local', 'city': 'Local', 'lat': None, 'lon': None}
        if ip in self.cache:
            return self.cache[ip]

        # semplice rate limit client-side
        elapsed = time.time() - self.last_call_ts
        if elapsed < 0.5:
            time.sleep(0.5 - elapsed)

        try:
            resp = requests.get(f'{GEO_API_BASE}/{ip}', params={'fields': 'status,country,city,lat,lon,message'}, timeout=4)
            self.last_call_ts = time.time()
            data = resp.json()
            if data.get('status') == 'success':
                result = {
                    'country': data.get('country') or 'Unknown',
                    'city': data.get('city') or 'Unknown',
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                }
            else:
                result = {'country': 'Unknown', 'city': 'Unknown', 'lat': None, 'lon': None}
        except Exception:
            result = {'country': 'Unknown', 'city': 'Unknown', 'lat': None, 'lon': None}

        self.cache[ip] = result
        self._save_cache()
        return result
