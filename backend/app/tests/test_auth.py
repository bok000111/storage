import base64
import os

import pytest
import logging

from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from app.tests.utils import new_async_client, new_signed_client
from app.tests.factories import AsyncUserFactory, AsymmetricKeyFactory
from app.utils.hash import hash_password

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
    async with await new_signed_client() as client:
        response = await client.post("/api/auth/logout")
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
    async with await new_signed_client() as client:
        response = await client.get("/api/auth/me")
        assert response.status_code == 200

        response_data = response.json()
        assert response_data["username"] == client.user.username

    async with new_async_client() as client:
        response = await client.get("/api/auth/me")
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token():
    async with await new_signed_client() as client:
        response = await client.post("/api/auth/refresh")

        response_data = response.json()
        assert response_data["token_type"] == "bearer"
        assert "access_token" in response_data

        cookies = response.cookies
        assert "refresh_token_cookie" in cookies

    async with new_async_client() as client:
        client.cookies["refresh_token_cookie"] = "invalidtoken"
        response = await client.post(
            "/api/auth/refresh",
        )
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_upload_public_key():

    async with await new_signed_client() as client:
        response = await client.post(
            "/api/auth/pubkey",
            json={
                "key": base64.b64encode(b"invalidkey").decode(),
                "signature": base64.b64encode(b"invalidsigneddata").decode(),
                "nonce": base64.b64encode(b"invalidnonce").decode(),
            },
        )
        assert response.status_code == 400
        assert response.json() == {"detail": "Invalid public key format"}

    async with await new_signed_client() as client:
        asymmetric_key = AsymmetricKeyFactory()

        response = await client.post(
            "/api/auth/pubkey",
            json={
                "key": base64.b64encode(asymmetric_key["public_key_der"]).decode(),
                "signature": base64.b64encode(b"invalidsigneddata").decode(),
                "nonce": base64.b64encode(b"invalidnonce").decode(),
            },
        )
        assert response.status_code == 400

    async with await new_signed_client() as client:
        asymmetric_key = AsymmetricKeyFactory()
        asymmetric_key2 = AsymmetricKeyFactory()
        private_key = load_der_private_key(
            asymmetric_key2["private_key_der"],
            password=None,
        )

        nonce = os.urandom(32)
        data = client.user.username.encode() + nonce

        signed_data_with_invalid_key = private_key.sign(
            data=data,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            algorithm=hashes.SHA256(),
        )

        response = await client.post(
            "/api/auth/pubkey",
            json={
                "key": base64.b64encode(asymmetric_key["public_key_der"]).decode(),
                "signature": base64.b64encode(signed_data_with_invalid_key).decode(),
                "nonce": base64.b64encode(nonce).decode(),
            },
        )

        assert response.status_code == 400

    async with await new_signed_client() as client:
        asymmetric_key = AsymmetricKeyFactory()
        private_key = load_der_private_key(
            asymmetric_key["private_key_der"],
            password=None,
        )

        nonce = os.urandom(32)
        invalid_data = client.user.username.encode() + nonce + b"invaliddata"

        signed_data = private_key.sign(
            data=invalid_data,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            algorithm=hashes.SHA256(),
        )

        response = await client.post(
            "/api/auth/pubkey",
            json={
                "key": base64.b64encode(asymmetric_key["public_key_der"]).decode(),
                "signature": base64.b64encode(signed_data).decode(),
                "nonce": base64.b64encode(nonce).decode(),
            },
        )

        assert response.status_code == 400

    async with await new_signed_client() as client:
        asymmetric_key = AsymmetricKeyFactory()
        private_key = load_der_private_key(
            asymmetric_key["private_key_der"],
            password=None,
        )

        nonce = os.urandom(32)
        data = client.user.username.encode() + nonce

        signed_data = private_key.sign(
            data=data,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            algorithm=hashes.SHA256(),
        )

        response = await client.post(
            "/api/auth/pubkey",
            json={
                "key": base64.b64encode(asymmetric_key["public_key_der"]).decode(),
                "signature": base64.b64encode(signed_data).decode(),
                "nonce": base64.b64encode(nonce).decode(),
            },
        )

        assert response.status_code == 200
        assert response.json() == {"message": "Public key registered"}
