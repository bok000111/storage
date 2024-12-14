from typing import Annotated, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError

from app.database import get_db
from app.models.auth import UserModel
from app.schemas.auth import User
from app.utils.jwt import decode_token, verify_password, oauth2_scheme


async def get_token_payload(token: Annotated[str, Depends(oauth2_scheme)]):
    if not token:
        return None
    try:
        payload = decode_token(token)
        if not payload:
            return None
    except ExpiredSignatureError:
        return None
    except InvalidTokenError:
        return None
    return payload.get("sub")


async def get_user(
    id: Optional[int] = None,
    username: Optional[str] = None,
    email: Optional[str] = None,
    payload: Optional[str] = Depends(get_token_payload),
    db: AsyncSession = Depends(get_db),
):
    if not any([id, username, email, payload]):
        return None

    query = select(UserModel)
    if id:
        query = query.where(UserModel.id == id)
    elif username:
        query = query.where(UserModel.username == username)
    elif email:
        query = query.where(UserModel.email == email)
    elif payload:
        query = query.where(UserModel.username == payload)

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
    user: Annotated[User, Depends(get_user)],
):
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    return user
