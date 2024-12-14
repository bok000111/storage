from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.config import settings
from app.database import get_db
from app.models.auth import UserModel
from app.schemas.auth import User, UserCreate, Token
from app.utils.jwt import (
    hash_password,
    create_access_token,
    create_refresh_token,
    register_refresh_token,
    unregister_refresh_token,
)
from app.utils.auth import auth_user, get_current_user

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

    hashed_password = hash_password(data.password)

    new_user = UserModel(
        username=data.username,
        email=data.email,
        password=hashed_password,
        is_email_verified=True,
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
    access_token = create_access_token({"sub": user.username})
    refresh_token = create_refresh_token({"sub": user.username})

    await register_refresh_token(user=user, token=refresh_token, db=db)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=not settings.debug,
        samesite="Lax",
        max_age=settings.jwt_exp_day * 24 * 60 * 60,
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
    )


@router.post("/logout")
async def logout(
    _: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
    response: Response,
):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token not found in cookies",
        )

    await unregister_refresh_token(refresh_token=refresh_token, db=db)
    response.delete_cookie("refresh_token")

    return {"message": "Successfully logged out"}
