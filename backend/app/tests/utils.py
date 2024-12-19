from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import IntegrityError

from app.main import app
from app.utils.jwt import access_security, refresh_security
from app.tests.factories import AsyncUserFactory
from app.utils.hash import hash_password


def new_async_client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def new_signed_client(
    username: str = None, email: str = None, password: str = "securepassword"
):
    user_data = {"password": password}
    if username:
        user_data["username"] = username
    if email:
        user_data["email"] = email

    user = await AsyncUserFactory(**user_data)

    access_token = access_security.create_access_token(
        subject={"username": user.username}
    )
    refresh_token = refresh_security.create_refresh_token(
        subject={"username": user.username}
    )

    client = AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {access_token}"},
        cookies={"refresh_token_cookie": refresh_token},
    )

    client.__setattr__("user", user)

    return client
