from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.database import engine, Base
from app.routers import api


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(lifespan=lifespan)

app.include_router(api.router, prefix="/api")
