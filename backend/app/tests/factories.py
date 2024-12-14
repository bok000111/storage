import factory
from faker import Faker
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.auth import UserModel
from app.utils.jwt import hash_password

faker = Faker()


class AsyncUserFactory(factory.alchemy.SQLAlchemyModelFactory):
    class Meta:
        model = UserModel
        sqlalchemy_session = None

    username = factory.LazyAttribute(lambda _: faker.user_name())
    email = factory.LazyAttribute(lambda _: faker.email())
    password = factory.LazyFunction(lambda: hash_password("securepassword"))
    is_email_verified = True
    is_superuser = False

    @classmethod
    async def _create(cls, model_class, *args, **kwargs):
        instance = super()._create(model_class, *args, **kwargs)
        async with cls._meta.sqlalchemy_session as session:  # 세션 사용
            await session.commit()
            await session.refresh(instance)
        return instance
