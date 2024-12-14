from typing import Annotated, Optional

from fastapi import Depends, Security, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi_jwt import JwtAuthorizationCredentials
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from passlib.context import CryptContext

from app.database import get_db
from app.models.auth import UserModel
from app.schemas.auth import User
from app.utils.hash import verify_password
from app.utils.jwt import access_security


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


async def get_user(
    id: Optional[int] = None,
    username: Optional[str] = None,
    email: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    if not any([id, username, email]):
        return None

    query = select(UserModel)
    if id:
        query = query.where(UserModel.id == id)
    elif username:
        query = query.where(UserModel.username == username)
    elif email:
        query = query.where(UserModel.email == email)

    try:
        result = await db.execute(query)
        user_model = result.scalars().first()
        if not user_model:
            return None
        return User.model_validate(user_model)
    except SQLAlchemyError as orm_err:
        print(f"Error fetching user: {orm_err}")
        return None


async def auth_user(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    try:
        result = await db.execute(
            select(UserModel).where(UserModel.username == form_data.username)
        )
        user_model = result.scalars().first()
        if not user_model or not verify_password(
            form_data.password, user_model.password
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return User.model_validate(user_model)
    except SQLAlchemyError as orm_err:
        print(f"Error during authentication: {orm_err}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: JwtAuthorizationCredentials = Security(access_security),
    db: AsyncSession = Depends(get_db),
):
    return await get_user(username=credentials.subject.get("username"), db=db)
