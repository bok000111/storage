import pytest_asyncio

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database import Base, get_db
from app.tests.factories import AsyncUserFactory

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture(scope="function", autouse=True)
async def db():
    engine = create_async_engine(TEST_DATABASE_URL, echo=True)
    TestSessionLocal = sessionmaker(
        bind=engine,
        class_=AsyncSession,
        autocommit=False,
        autoflush=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async def override_get_db():
        async with TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    AsyncUserFactory._meta.sqlalchemy_session = TestSessionLocal()

    async with TestSessionLocal() as session:
        yield session

    # `engine.dispose()`를 마지막에 호출
    await engine.dispose()
