import pytest
from app.main import app
from app.tests.utils import new_async_client
from app.tests.factories import AsyncUserFactory
from app.utils.auth import get_current_user, get_user, decode_token
from app.utils.jwt import hash_password


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

        data = decode_token(response_data["access_token"])

        test_user = await get_current_user(token=response_data["access_token"], db=db)
        assert test_user.username == "johndoe"
        assert test_user.email == "johndoe@example.com"
