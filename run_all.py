import uvicorn

from backend.config import API_HOST, API_PORT

if __name__ == '__main__':
    uvicorn.run('api.main:app', host=API_HOST, port=API_PORT, reload=False)
