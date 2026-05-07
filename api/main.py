import contextlib
import asyncio
from contextlib import asynccontextmanager
from typing import Any, Dict, List

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from backend.auth import AuthError, authenticate, verify_authorization_header
from backend.config import FRONTEND_ORIGIN, POLL_INTERVAL_SECONDS
from backend.db import (
    fetch_attack_distribution,
    fetch_event_by_id,
    fetch_event_context,
    fetch_events,
    fetch_incident_detail,
    fetch_ip_detail,
    fetch_map_points,
    fetch_stats,
    fetch_storylines,
)
from backend.processor import Processor
from backend.reports import export_incident_report, export_ip_report
from backend.settings import load_attack_settings, save_attack_settings

processor = Processor()


def require_auth(authorization: str = Header(default='')) -> Dict[str, Any]:
    try:
        return verify_authorization_header(authorization)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


async def background_processor():
    while True:
        try:
            processor.process_once()
        except Exception as exc:
            print(f'[processor] cycle failed: {exc}')
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    processor.process_once()
    task = asyncio.create_task(background_processor())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(title='HoneypotX API', version='2.0.0', lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'] if FRONTEND_ORIGIN == '*' else [FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


@app.get('/health')
def health() -> Dict[str, Any]:
    return {'status': 'ok'}


@app.post('/auth/login')
def login(credentials: Dict[str, str]) -> Dict[str, Any]:
    try:
        token = authenticate(credentials.get('username') or '', credentials.get('password') or '')
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return {'access_token': token, 'token_type': 'bearer'}


@app.get('/auth/me')
def auth_me(user: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    return {'username': user.get('sub')}


@app.get('/events')
def get_events(limit: int = 200, _: Dict[str, Any] = Depends(require_auth)) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(limit, 1000))
    return fetch_events(limit=safe_limit)


@app.get('/stats')
def get_stats(_: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    return fetch_stats()


@app.get('/attack-distribution')
def get_attack_distribution(_: Dict[str, Any] = Depends(require_auth)) -> List[Dict[str, Any]]:
    return fetch_attack_distribution()


@app.get('/map-points')
def get_map_points(_: Dict[str, Any] = Depends(require_auth)) -> List[Dict[str, Any]]:
    return fetch_map_points()


@app.get('/storylines')
def get_storylines(limit: int = 50, _: Dict[str, Any] = Depends(require_auth)) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(limit, 200))
    return fetch_storylines(limit=safe_limit)


@app.post('/reset-attacks')
def reset_attacks(_: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    result = processor.reset_attacks()
    return {'status': 'ok', **result}


@app.get('/settings/attacks')
def get_attack_settings(_: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    return load_attack_settings()


@app.put('/settings/attacks')
def update_attack_settings(
    settings: Dict[str, Any],
    _: Dict[str, Any] = Depends(require_auth),
) -> Dict[str, Any]:
    saved = save_attack_settings(settings)
    processor.reload_attack_settings()
    return saved


@app.get('/event/{event_id}')
def get_event(event_id: int, _: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    event = fetch_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail='Event not found')
    return event


@app.get('/event/{event_id}/context')
def get_event_context(
    event_id: int,
    limit: int = 80,
    _: Dict[str, Any] = Depends(require_auth),
) -> Dict[str, Any]:
    safe_limit = max(1, min(limit, 200))
    context = fetch_event_context(event_id, limit=safe_limit)
    if not context:
        raise HTTPException(status_code=404, detail='Event not found')
    return context


@app.get('/incident/{event_id}/detail')
def get_incident_detail(
    event_id: int,
    limit: int = 120,
    _: Dict[str, Any] = Depends(require_auth),
) -> Dict[str, Any]:
    safe_limit = max(1, min(limit, 250))
    detail = fetch_incident_detail(event_id, limit=safe_limit)
    if not detail:
        raise HTTPException(status_code=404, detail='Event not found')
    return detail


@app.get('/incident/{event_id}/export')
def export_incident(
    event_id: int,
    format: str = 'html',
    _: Dict[str, Any] = Depends(require_auth),
) -> FileResponse:
    report_format = 'json' if format == 'json' else 'html'
    try:
        path = export_incident_report(event_id, report_format=report_format)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    media_type = 'application/json' if report_format == 'json' else 'text/html'
    return FileResponse(path, media_type=media_type, filename=path.name)


@app.get('/ip/{ip}/detail')
def get_ip_detail(
    ip: str,
    limit: int = 200,
    _: Dict[str, Any] = Depends(require_auth),
) -> Dict[str, Any]:
    safe_limit = max(1, min(limit, 500))
    detail = fetch_ip_detail(ip, limit=safe_limit)
    if not detail:
        raise HTTPException(status_code=404, detail='IP not found')
    return detail


@app.get('/ip/{ip}/export')
def export_ip(
    ip: str,
    format: str = 'html',
    _: Dict[str, Any] = Depends(require_auth),
) -> FileResponse:
    report_format = 'json' if format == 'json' else 'html'
    try:
        path = export_ip_report(ip, report_format=report_format)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    media_type = 'application/json' if report_format == 'json' else 'text/html'
    return FileResponse(path, media_type=media_type, filename=path.name)
