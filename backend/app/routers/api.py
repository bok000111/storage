from fastapi import APIRouter

from app.routers import auth

router = APIRouter()

router.include_router(auth.router, prefix="/auth", tags=["auth"])
