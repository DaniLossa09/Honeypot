"""Analisi AI degli eventi honeypot via Claude (Anthropic).

Produce tre campi per ogni evento classificato:
- ai_explanation: cosa ha fatto l'attaccante e cosa cercava (dinamico, contestuale)
- ai_attacker_profile: tipo di attaccante, sofisticazione, motivazione probabile
- ai_defense: consigli di difesa personalizzati sull'evento specifico

Usa `requests` (gia dipendenza del progetto) per le chiamate HTTP invece
dell'SDK Anthropic, cosi non si aggiungono dipendenze. Output sempre in italiano.

Fallback: se l'API non e' disponibile o HPX_ANTHROPIC_API_KEY non e' impostata,
`analyze_event` restituisce valori None e il processor usa il testo statico di
explainer.py.

Rate limiting in memoria: lo stesso (ip, attack_type) viene analizzato al piu'
una volta per ora, per evitare chiamate ridondanti durante attacchi a volume.
"""
import json
import logging
import time
from typing import Any, Dict, Optional

import requests

from .config import AI_ENABLED, AI_MODEL, ANTHROPIC_API_KEY
from .mitre import TACTICS, TECHNIQUES

_log = logging.getLogger(__name__)
_API_URL = "https://api.anthropic.com/v1/messages"
_TIMEOUT = 15

# Cache (ip, attack_type) -> timestamp ultima analisi (TTL 1 ora).
_cache: Dict[str, float] = {}
_CACHE_TTL = 3600


def _cache_key(record: Dict[str, Any]) -> str:
    return f"{record.get('ip', '')}|{record.get('attack_type', '')}"


def _cached(record: Dict[str, Any]) -> bool:
    ts = _cache.get(_cache_key(record))
    return ts is not None and (time.time() - ts) < _CACHE_TTL


def _set_cache(record: Dict[str, Any]) -> None:
    _cache[_cache_key(record)] = time.time()


def _build_prompt(record: Dict[str, Any]) -> str:
    attack_type = record.get('attack_type') or 'Unknown'
    ip = record.get('ip') or 'N/D'
    service = (record.get('service') or 'N/D').upper()
    port = record.get('port') or 'N/D'
    country = record.get('country') or 'N/D'
    city = record.get('city') or ''
    source = record.get('source') or 'N/D'

    tactic_id = record.get('mitre_tactic') or ''
    technique_id = record.get('mitre_technique') or ''
    tactic_name = TACTICS.get(tactic_id, tactic_id) or 'N/D'
    technique_name = TECHNIQUES.get(technique_id, technique_id) or 'N/D'
    mitre_str = f"{tactic_name} / {technique_name}" if tactic_name != 'N/D' else 'N/D'

    location = f"{city}, {country}" if city else country

    details = []
    if record.get('username'):
        details.append(f"Username: {record['username']}")
    if record.get('command'):
        details.append(f"Comando: {record['command']}")
    if record.get('uri') or record.get('path'):
        details.append(f"URI/Path: {record.get('uri') or record.get('path')}")
    if record.get('user_agent'):
        details.append(f"User-Agent: {record['user_agent']}")
    details_str = '\n'.join(f"- {d}" for d in details) if details else "- (nessun dettaglio aggiuntivo)"

    return f"""Sei un analista di sicurezza informatica. Analizza questo evento rilevato da un honeypot e rispondi SOLO con un oggetto JSON valido, senza markdown ne' testo aggiuntivo.

Evento:
- Tipo attacco: {attack_type}
- IP sorgente: {ip} ({location})
- Servizio: {service} porta {port} via {source}
- MITRE ATT&CK: {mitre_str}
{details_str}

Rispondi con questo JSON esatto (tutto in italiano):
{{
  "spiegazione": "2-3 frasi: cosa ha fatto l'attaccante, cosa cercava, cosa rivela del suo metodo",
  "profilo": "1-2 frasi: tipo di attaccante (bot automatico / scanner / umano), livello di sofisticazione, motivazione probabile",
  "difesa": "2-3 azioni concrete e specifiche per proteggersi da questo attacco"
}}"""


def analyze_event(record: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Analizza un evento con Claude e restituisce i 3 campi AI.

    Ritorna valori None se AI disabilitata, API non disponibile o errore.
    Il chiamante usa il testo statico di explainer.py come fallback.
    """
    empty: Dict[str, Optional[str]] = {
        'ai_explanation': None,
        'ai_attacker_profile': None,
        'ai_defense': None,
    }

    if not AI_ENABLED or not ANTHROPIC_API_KEY:
        return empty

    if _cached(record):
        return empty

    try:
        response = requests.post(
            _API_URL,
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": AI_MODEL,
                "max_tokens": 512,
                "messages": [{"role": "user", "content": _build_prompt(record)}],
            },
            timeout=_TIMEOUT,
        )
        response.raise_for_status()

        text = response.json()["content"][0]["text"].strip()
        # Rimuovi eventuali backtick markdown che il modello potrebbe aggiungere.
        if text.startswith("```"):
            parts = text.split("```")
            text = parts[1] if len(parts) > 1 else text
            if text.startswith("json"):
                text = text[4:]

        data = json.loads(text)
        _set_cache(record)

        return {
            'ai_explanation': (str(data.get('spiegazione') or '').strip()) or None,
            'ai_attacker_profile': (str(data.get('profilo') or '').strip()) or None,
            'ai_defense': (str(data.get('difesa') or '').strip()) or None,
        }

    except Exception as exc:
        _log.warning(
            "AI analysis failed for %s / %s: %s",
            record.get('ip'), record.get('attack_type'), exc,
        )
        return empty
