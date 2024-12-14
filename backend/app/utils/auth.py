from typing import Annotated, Optional

from fastapi import Depends, HTTPException, status
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError

from app.database import get_db
from app.models.auth import UserModel
from app.utils.jwt import decode_token, verify_password, oauth2_scheme


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
        return result.scalars().first()
    except Exception as e:
        print(f"Error fetching user: {e}")
    return None


async def auth_user(
    username: str, password: str, db: Annotated[AsyncSession, Depends(get_db)]
):
    result = await db.execute(select(UserModel).where(UserModel.username == username))
    user = result.scalars().first()
    if not user or not verify_password(password, user.password):
        return None
    return user


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except InvalidTokenError:
        raise credentials_exception

    user = await get_user(username=username, db=db)
    if user is None:
        raise credentials_exception

    return user
