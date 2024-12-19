from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    Security,
    Response,
    HTTPException,
)
from fastapi_jwt import JwtAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from app.database import get_db
from app.models.auth import UserModel, PublicKeyModel
from app.schemas.auth import User, UserCreate, Token, PubKeyRegister
from app.utils.jwt import (
    access_security,
    refresh_security,
)
from app.utils.auth import auth_user, get_current_user
from app.config import settings

router = APIRouter()


@router.get("/me", response_model=User)
async def me(
    user: Annotated[User, Depends(get_current_user)],
):
    return user


@router.post("/signup", response_model=User)
async def signup(
    data: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    exist = result.scalars().first()
    if exist:
        raise HTTPException(status_code=400, detail="Email already exists")
    result = await db.execute(
        select(UserModel).where(UserModel.username == data.username)
    )
    exist = result.scalars().first()
    if exist:
        raise HTTPException(status_code=400, detail="Username already exists")

    new_user = UserModel.create(
        username=data.username,
        email=data.email,
        password=data.password,
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return new_user


@router.post("/login", response_model=Token)
async def login(
    user: Annotated[User, Security(auth_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    response: Response,
):
    access_token = access_security.create_access_token(
        subject={"username": user.username}
    )
    refresh_token = refresh_security.create_refresh_token(
        subject={"username": user.username}
    )

    response.set_cookie(
        key="refresh_token_cookie",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        secure=not settings.debug,
        max_age=60 * 60 * 24 * 7,
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
    )


@router.post("/logout")
async def logout(
    response: Response,
    _: Annotated[JwtAuthorizationCredentials, Security(refresh_security)],
):
    response.delete_cookie(
        key="refresh_token_cookie",
        httponly=True,
        samesite="lax",
        secure=not settings.debug,
    )

    return {"message": "Successfully logged out"}


@router.post("/refresh")
async def refresh(
    credentials: Annotated[JwtAuthorizationCredentials, Security(refresh_security)],
    response: Response,
):
    access_token = access_security.create_access_token(subject=credentials.subject)
    refesh_token = refresh_security.create_refresh_token(subject=credentials.subject)

    response.set_cookie(
        key="refresh_token_cookie",
        value=refesh_token,
        httponly=True,
        samesite="lax",
        secure=not settings.debug,
        max_age=60 * 60 * 24 * 7,
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
    )


# @router.get("/pubkey")
# async def pubkey(
#     user: Annotated[User, Depends(get_current_user)],
#     db: Annotated[AsyncSession, Depends(get_db)],
# ):
#     query = select(PublicKeyModel).where(PublicKeyModel.user_id == user.id)
#     result = await db.execute(query)
#     public_key = result.scalars().first()
#     if not public_key:
#         raise HTTPException(status_code=404, detail="Public key not found")

#     return {"key": public_key.key, "key_type": public_key.key_type}


@router.post("/pubkey")
async def pubkey(
    data: PubKeyRegister,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    # TODO: 의존성 주입을 사용하여 분리
    query = select(PublicKeyModel).where(
        PublicKeyModel.user_id == user.id,
    )
    result = await db.execute(query)
    exist = result.scalars().first()
    if exist:
        raise HTTPException(status_code=400, detail="Public key already exists")

    try:
        public_key = serialization.load_der_public_key(data.key)
        public_key.verify(
            data.signature,
            user.username.encode() + data.nonce,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid public key format")
    except InvalidSignature:
        raise HTTPException(status_code=400, detail="Signature verification failed")

    new_key = PublicKeyModel(key=data.key, user_id=user.id)
    db.add(new_key)
    await db.commit()

    return {"message": "Public key registered"}
