import pytest
import logging

from app.tests.utils import new_async_client
from app.tests.factories import AsyncUserFactory
from app.utils.hash import hash_password
from app.utils.jwt import access_security, refresh_security

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
async def test_login():
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

        cookies = response.cookies
        assert "refresh_token_cookie" in cookies

    async with new_async_client() as client:
        login_data = {
            "username": "johndoe",
            "password": "wrongpassword",
        }

        response = await client.post("/api/auth/login", data=login_data)
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid credentials"}


@pytest.mark.asyncio
async def test_logout():
    await AsyncUserFactory(
        username="johndoe",
        email="johndoe@example.com",
        password=hash_password("securepassword"),
    )
    access_token = access_security.create_access_token(subject={"username": "johndoe"})
    refresh_token = refresh_security.create_refresh_token(
        subject={"username": "johndoe"}
    )

    async with new_async_client() as client:
        client.cookies.set("refresh_token_cookie", refresh_token)
        response = await client.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert response.status_code == 200

        cookies = response.cookies
        assert "refresh_token_cookie" not in cookies

        set_cookie_header = response.headers.get("set-cookie")
        assert set_cookie_header is not None
        assert 'refresh_token_cookie="";' in set_cookie_header

    async with new_async_client() as client:
        response = await client.post(
            "/api/auth/logout",
        )
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_me():
    await AsyncUserFactory(
        username="johndoe",
        email="johndoe@example.com",
        password=hash_password("securepassword"),
    )
    access_token = access_security.create_access_token(subject={"username": "johndoe"})

    async with new_async_client() as client:
        response = await client.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert response.status_code == 200

        response_data = response.json()
        assert response_data["username"] == "johndoe"

    async with new_async_client() as client:
        response = await client.get(
            "/api/auth/me", headers={"Authorization": "Bearer invalidtoken"}
        )
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token(db):
    await AsyncUserFactory(
        username="johndoe",
        email="johndoe@example.com",
        password=hash_password("securepassword"),
    )
    access_token = access_security.create_access_token(subject={"username": "johndoe"})
    refresh_token = refresh_security.create_refresh_token(
        subject={"username": "johndoe"}
    )

    async with new_async_client() as client:
        client.cookies.set("refresh_token_cookie", refresh_token)
        response = await client.post(
            "/api/auth/refresh",
        )
        assert response.status_code == 200

        response_data = response.json()
        assert response_data["token_type"] == "bearer"
        assert "access_token" in response_data

        cookies = response.cookies
        assert "refresh_token_cookie" in cookies

    async with new_async_client() as client:
        response = await client.post(
            "/api/auth/refresh",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_upload_public_key():
    await AsyncUserFactory(
        username="johndoe",
        email="johndoe@example.com",
        password=hash_password("securepassword"),
    )
    access_token = access_security.create_access_token(subject={"username": "johndoe"})

    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization, hashes

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signed_data = private_key.sign(
        b"johndoe",
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )

    async with new_async_client() as client:
        response = await client.post(
            "/api/auth/pubkey",
            json={
                "key": "invalidkey",
                "key_type": "RSA",
                "signed_data": "invalidsigneddata",
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert response.status_code == 400
        assert response.json() == {"detail": "Invalid public key format"}

    async with new_async_client() as client:
        response = await client.post(
            "/api/auth/pubkey",
            json={
                "key": public_pem.decode(),
                "key_type": "RSA",
                "signed_data": signed_data.hex(),
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert response.status_code == 200
        assert response.json() == {"message": "Public key registered"}

    async with new_async_client() as client:
        response = await client.post(
            "/api/auth/pubkey",
            json={
                "key": public_pem.decode(),
                "key_type": "RSA",
                "signed_data": signed_data.hex(),
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert response.status_code == 400
        assert response.json() == {"detail": "Public key already exists"}
