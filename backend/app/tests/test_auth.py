import pytest
import logging

from app.tests.utils import new_async_client
from app.tests.factories import AsyncUserFactory
from app.utils.auth import get_user, decode_token
from app.utils.jwt import hash_password, create_access_token

logger = logging.getLogger("auth")


@pytest.mark.asyncio
async def test_user_create():
    user = await AsyncUserFactory(username="johndoe", email="johndoe@example.com")
    assert user.username == "johndoe"
    assert user.email == "johndoe@example.com"


@pytest.mark.asyncio
async def test_signup():
    async with new_async_client() as client:
        user_data = {
            "username": "johndoe",
            "email": "johndoe@example.com",
            "password": "securepassword",
        }

        response = await client.post("/api/auth/signup", json=user_data)
        assert response.status_code == 200

        response_data = response.json()
        assert response_data["username"] == "johndoe"
        assert response_data["email"] == "johndoe@example.com"
        assert "id" in response_data


@pytest.mark.asyncio
async def test_signup_duplicate():
    await AsyncUserFactory(username="johndoe", email="johndoe@example.com")

    async with new_async_client() as client:
        user_data = {
            "username": "johndoe",
            "email": "johndoe2@example.com",
            "password": "securepassword",
        }
        response = await client.post("/api/auth/signup", json=user_data)
        assert response.status_code == 400
        assert response.json() == {"detail": "Username already exists"}

    async with new_async_client() as client:
        user_data = {
            "username": "johndoe2",
            "email": "johndoe@example.com",
            "password": "securepassword",
        }
        response = await client.post("/api/auth/signup", json=user_data)
        assert response.status_code == 400
        assert response.json() == {"detail": "Email already exists"}


@pytest.mark.asyncio
async def test_login(db):
    await AsyncUserFactory(
        username="johndoe",
        email="johndoe@example.com",
        password=hash_password("securepassword"),
    )

    async with new_async_client() as client:
        login_data = {
            "username": "johndoe",
            "password": "securepassword",
        }

        response = await client.post("/api/auth/login", data=login_data)
        assert response.status_code == 200

        response_data = response.json()
        assert response_data["token_type"] == "bearer"
        assert "access_token" in response_data

        payload = decode_token(response_data["access_token"])

        test_user = await get_user(payload=payload.get("sub"), db=db)
        assert test_user.username == "johndoe"
        assert test_user.email == "johndoe@example.com"

        cookies = response.cookies
        assert "refresh_token" in cookies

        set_cookie_header = response.headers.get("set-cookie")
        assert set_cookie_header is not None
        assert "HttpOnly" in set_cookie_header

        refresh_token = cookies["refresh_token"]
        payload = decode_token(refresh_token)
        assert payload is not None
        assert payload.get("sub") == "johndoe"


@pytest.mark.asyncio
async def test_login_invalid():
    await AsyncUserFactory(
        username="johndoe",
        email="johndoe@example.com",
        password=hash_password("securepassword"),
    )

    async with new_async_client() as client:
        login_data = {
            "username": "johndoe",
            "password": "wrongpassword",
        }

        response = await client.post("/api/auth/login", data=login_data)
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid credentials"}


@pytest.mark.asyncio
async def test_logout(db):
    await AsyncUserFactory(
        username="johndoe",
        email="johndoe@example.com",
        password=hash_password("securepassword"),
    )

    async with new_async_client() as client:
        login_data = {
            "username": "johndoe",
            "password": "securepassword",
        }

        response = await client.post("/api/auth/login", data=login_data)
        assert response.status_code == 200

        cookies = response.cookies
        assert "refresh_token" in cookies

        response = await client.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {response.json()['access_token']}"},
        )
        assert response.status_code == 200

        cookies = response.cookies
        assert "refresh_token" not in cookies

        set_cookie_header = response.headers.get("set-cookie")
        assert set_cookie_header is not None
        assert "expires" in set_cookie_header


@pytest.mark.asyncio
async def test_me(db):
    await AsyncUserFactory(
        username="johndoe",
        email="johndoe@example.com",
        password=hash_password("securepassword"),
    )

    token = create_access_token({"sub": "johndoe"})

    async with new_async_client() as client:
        response = await client.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        response_data = response.json()
        assert response_data["username"] == "johndoe"
        assert response_data["email"] == "johndoe@example.com"
        assert "id" in response_data


@pytest.mark.asyncio
async def test_me_invalid_token(db):
    token = create_access_token({"sub": "johndoe"})

    async with new_async_client() as client:
        response = await client.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid credentials"}

    async with new_async_client() as client:
        response = await client.get(
            "/api/auth/me", headers={"Authorization": "Bearer invalidtoken"}
        )

        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid credentials"}
