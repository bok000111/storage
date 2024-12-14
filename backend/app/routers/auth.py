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

from app.database import get_db
from app.models.auth import UserModel
from app.schemas.auth import User, UserCreate, Token
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
    user: Annotated[User, Depends(auth_user)],
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
