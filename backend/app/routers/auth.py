from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.config import settings
from app.database import get_db
from app.models.auth import UserModel
from app.schemas.auth import User, UserCreate, Token
from app.utils.jwt import create_access_token, hash_password
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
):
    access_token = create_access_token({"sub": user.username})

    return Token(
        access_token=access_token,
        token_type="bearer",
    )


@router.post("/logout")
async def logout(
    user: Annotated[User, Depends(get_current_user)],
):
    return {"msg": "Logout"}
