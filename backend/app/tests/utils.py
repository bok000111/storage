from httpx import ASGITransport, AsyncClient
from app.main import app


def new_async_client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
