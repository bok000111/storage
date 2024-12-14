from datetime import datetime, timedelta, timezone

from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi_jwt import (
    JwtAccessBearer,
    JwtRefreshCookie,
)

from app.config import settings
from app.models.auth import RefreshTokenModel
from app.schemas.auth import User


access_security = JwtAccessBearer(
    secret_key=settings.jwt_secret_key,
    auto_error=True,
    access_expires_delta=timedelta(minutes=settings.jwt_access_token_expire_minutes),
)
refresh_security = JwtRefreshCookie(
    secret_key=settings.jwt_secret_key,
    auto_error=True,
    refresh_expires_delta=timedelta(days=settings.jwt_refresh_token_expire_days),
)
