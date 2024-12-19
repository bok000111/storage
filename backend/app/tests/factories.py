import factory
from faker import Faker
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from app.models.auth import UserModel
from app.utils.hash import hash_password

fake = Faker()


class AsyncUserFactory(factory.alchemy.SQLAlchemyModelFactory):
    class Meta:
        model = UserModel
        sqlalchemy_session = None

    username = factory.LazyAttribute(lambda _: fake.unique.user_name())
    email = factory.LazyAttribute(lambda _: fake.unique.email())
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


class AsymmetricKeyFactory(factory.DictFactory):
    private_key_der = factory.LazyAttribute(
        lambda _: AsymmetricKeyFactory._generate_private_key()
    )
    public_key_der = factory.LazyAttribute(
        lambda obj: AsymmetricKeyFactory._get_public_key(obj.private_key_der)
    )

    @staticmethod
    def _generate_private_key():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        private_key_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return private_key_der

    @staticmethod
    def _get_public_key(private_key_der: bytes):
        private_key = serialization.load_der_private_key(
            private_key_der,
            password=None,
        )
        public_key = private_key.public_key()
        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return public_key_der
