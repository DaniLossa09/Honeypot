import contextlib
import asyncio
from contextlib import asynccontextmanager
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.config import FRONTEND_ORIGIN, POLL_INTERVAL_SECONDS
from backend.db import fetch_attack_distribution, fetch_event_by_id, fetch_events, fetch_map_points, fetch_stats
from backend.processor import Processor

processor = Processor()


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


@app.get('/events')
def get_events(limit: int = 200) -> List[Dict[str, Any]]:
    safe_limit = max(1, min(limit, 1000))
    return fetch_events(limit=safe_limit)


@app.get('/stats')
def get_stats() -> Dict[str, Any]:
    return fetch_stats()


@app.get('/attack-distribution')
def get_attack_distribution() -> List[Dict[str, Any]]:
    return fetch_attack_distribution()


@app.get('/map-points')
def get_map_points() -> List[Dict[str, Any]]:
    return fetch_map_points()


@app.get('/event/{event_id}')
def get_event(event_id: int) -> Dict[str, Any]:
    event = fetch_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail='Event not found')
    return event
