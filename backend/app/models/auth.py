from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base
from app.utils.hash import hash_password


class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    is_email_verified = Column(Boolean, default=False)
    is_superuser = Column(Boolean, default=False)

    refresh_tokens = relationship(
        "RefreshTokenModel", back_populates="user", cascade="all, delete-orphan"
    )

    @classmethod
    def create(
        cls,
        username: str,
        email: str,
        password: str,
        is_email_verified: bool = True,
        is_superuser: bool = False,
    ):
        return cls(
            username=username,
            email=email,
            password=hash_password(password),
            is_email_verified=is_email_verified,
            is_superuser=is_superuser,
        )


class RefreshTokenModel(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    is_revoked = Column(Boolean, default=False)

    user = relationship("UserModel", back_populates="refresh_tokens")
