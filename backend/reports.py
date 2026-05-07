import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .config import EXPORT_DIR
from .db import fetch_incident_detail, fetch_ip_detail

REPORT_DIR = EXPORT_DIR / 'reports'


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def _safe_name(value: Any) -> str:
    text = str(value or 'unknown').strip().lower()
    text = re.sub(r'[^a-z0-9_.-]+', '-', text)
    return text.strip('-') or 'unknown'


def _write_report(filename: str, content: str) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORT_DIR / filename
    path.write_text(content, encoding='utf-8')
    return path


def _json_report(data: Dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def _table_rows(items: Iterable[Dict[str, Any]], fields: List[str]) -> str:
    rows = []
    for item in items:
        cells = ''.join(f'<td>{html.escape(str(item.get(field) or ""))}</td>' for field in fields)
        rows.append(f'<tr>{cells}</tr>')
    if not rows:
        return f'<tr><td colspan="{len(fields)}">Nessun dato disponibile</td></tr>'
    return ''.join(rows)


def _top_list(items: Iterable[Dict[str, Any]]) -> str:
    rows = []
    for item in items:
        rows.append(
            '<li>'
            f'<span>{html.escape(str(item.get("value") or ""))}</span>'
            f'<strong>{html.escape(str(item.get("count") or 0))}</strong>'
            '</li>'
        )
    return '<ul>' + ''.join(rows or ['<li>Nessun dato disponibile</li>']) + '</ul>'


def _html_document(title: str, body: str) -> str:
    return f'''<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #162033; }}
    h1 {{ margin-bottom: 4px; }}
    h2 {{ margin-top: 28px; border-bottom: 1px solid #d7dce5; padding-bottom: 6px; }}
    .meta {{ color: #5b6678; margin-bottom: 18px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }}
    .card {{ border: 1px solid #d7dce5; border-radius: 8px; padding: 12px; background: #f8fafc; }}
    .label {{ font-size: 11px; text-transform: uppercase; color: #5b6678; }}
    .value {{ font-size: 20px; font-weight: 700; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th, td {{ border: 1px solid #d7dce5; padding: 7px; text-align: left; vertical-align: top; font-size: 13px; }}
    th {{ background: #edf2f7; }}
    li {{ margin: 5px 0; }}
    li strong {{ margin-left: 8px; }}
    pre {{ white-space: pre-wrap; background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 8px; overflow-wrap: anywhere; }}
  </style>
</head>
<body>
{body}
</body>
</html>'''


def _incident_html(detail: Dict[str, Any]) -> str:
    event = detail.get('event') or {}
    evidence = detail.get('evidence') or {}
    title = f"Report incidente {event.get('id') or ''} - {event.get('attack_type') or 'Unknown'}"
    body = f'''
<h1>{html.escape(title)}</h1>
<div class="meta">Generato: {html.escape(_now_stamp())}</div>
<div class="grid">
  <div class="card"><div class="label">IP</div><div class="value">{html.escape(str(event.get('ip') or 'n/d'))}</div></div>
  <div class="card"><div class="label">Servizio</div><div class="value">{html.escape(str(event.get('service') or 'unknown').upper())}</div></div>
  <div class="card"><div class="label">Risk</div><div class="value">{html.escape(str(event.get('risk_score') or 0))}/100</div></div>
  <div class="card"><div class="label">Pericolo</div><div class="value">{html.escape(str(event.get('danger_level') or 'Basso'))}</div></div>
</div>
<h2>Spiegazione</h2>
<p>{html.escape(str(event.get('explanation_it') or ''))}</p>
<h2>Perche e stato segnalato</h2>
<p>{html.escape(str(detail.get('technical_reason') or ''))}</p>
<h2>Come difendersi</h2>
<p>{html.escape(str(event.get('advice') or ''))}</p>
<h2>Evidenze</h2>
<h3>Credenziali</h3>
{_top_list([*(evidence.get('usernames') or []), *(evidence.get('passwords') or [])])}
<h3>Comandi</h3>
{_top_list(evidence.get('commands') or [])}
<h3>Path / URI</h3>
{_top_list(evidence.get('paths') or [])}
<h2>Timeline</h2>
<table>
  <thead><tr><th>Timestamp</th><th>Tipo</th><th>Servizio</th><th>Descrizione</th></tr></thead>
  <tbody>{_table_rows(detail.get('timeline') or [], ['timestamp', 'event_type', 'service', 'summary'])}</tbody>
</table>
<h2>Raw Event</h2>
<pre>{html.escape(json.dumps(detail.get('raw_events') or [], ensure_ascii=False, indent=2))}</pre>
'''
    return _html_document(title, body)


def _ip_html(detail: Dict[str, Any]) -> str:
    title = f"Report IP {detail.get('ip') or 'unknown'}"
    body = f'''
<h1>{html.escape(title)}</h1>
<div class="meta">Generato: {html.escape(_now_stamp())}</div>
<div class="grid">
  <div class="card"><div class="label">Risk</div><div class="value">{html.escape(str(detail.get('risk_score') or 0))}/100</div></div>
  <div class="card"><div class="label">Incidenti</div><div class="value">{html.escape(str(detail.get('event_count') or 0))}</div></div>
  <div class="card"><div class="label">Raw Event</div><div class="value">{html.escape(str(detail.get('raw_event_count') or 0))}</div></div>
  <div class="card"><div class="label">Protocolli</div><div class="value">{html.escape(str(len(detail.get('services') or [])))}</div></div>
</div>
<h2>Identita</h2>
<p><strong>IP:</strong> {html.escape(str(detail.get('ip') or 'n/d'))}</p>
<p><strong>Localita:</strong> {html.escape(str(detail.get('city') or 'Unknown'))}, {html.escape(str(detail.get('country') or 'Unknown'))}</p>
<p><strong>Prima vista:</strong> {html.escape(str(detail.get('first_seen') or 'n/d'))}</p>
<p><strong>Ultima vista:</strong> {html.escape(str(detail.get('last_seen') or 'n/d'))}</p>
<h2>Evidenze principali</h2>
<h3>Username</h3>{_top_list(detail.get('top_usernames') or [])}
<h3>Password</h3>{_top_list(detail.get('top_passwords') or [])}
<h3>Comandi</h3>{_top_list(detail.get('top_commands') or [])}
<h3>Path / URI</h3>{_top_list(detail.get('top_paths') or [])}
<h2>Timeline</h2>
<table>
  <thead><tr><th>Timestamp</th><th>Tipo</th><th>Servizio</th><th>Descrizione</th></tr></thead>
  <tbody>{_table_rows(detail.get('timeline') or [], ['timestamp', 'attack_type', 'service', 'summary'])}</tbody>
</table>
<h2>Raw Event</h2>
<pre>{html.escape(json.dumps(detail.get('raw_events') or [], ensure_ascii=False, indent=2))}</pre>
'''
    return _html_document(title, body)


def export_incident_report(event_id: int, report_format: str = 'html') -> Path:
    detail = fetch_incident_detail(event_id, limit=250)
    if not detail:
        raise ValueError('Event not found')
    fmt = 'json' if report_format == 'json' else 'html'
    event = detail.get('event') or {}
    base = f"incident-{event.get('id') or event_id}-{_safe_name(event.get('attack_type'))}-{_now_stamp()}"
    content = _json_report(detail) if fmt == 'json' else _incident_html(detail)
    return _write_report(f'{base}.{fmt}', content)


def export_ip_report(ip: str, report_format: str = 'html') -> Path:
    detail = fetch_ip_detail(ip, limit=500)
    if not detail:
        raise ValueError('IP not found')
    fmt = 'json' if report_format == 'json' else 'html'
    base = f"ip-{_safe_name(ip)}-{_now_stamp()}"
    content = _json_report(detail) if fmt == 'json' else _ip_html(detail)
    return _write_report(f'{base}.{fmt}', content)
