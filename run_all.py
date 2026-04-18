import uvicorn

from backend.config import API_HOST, API_PORT
from backend.db import reset_events

if __name__ == '__main__':
    reset_events()
    uvicorn.run('api.main:app', host=API_HOST, port=API_PORT, reload=False)
