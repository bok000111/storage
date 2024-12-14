from sqlalchemy import Column, Integer, String, Boolean

from app.database import Base


class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String, nullable=False)
    is_email_verified = Column(Boolean, default=False)
    is_superuser = Column(Boolean, default=False)
