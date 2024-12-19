from pydantic import BaseModel, EmailStr, ConfigDict
from pydantic.types import Base64Bytes


class Token(BaseModel):
    access_token: str
    token_type: str


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class User(BaseModel):
    id: int
    username: str
    email: EmailStr
    is_email_verified: bool

    model_config = ConfigDict(from_attributes=True)


class PubKeyRegister(BaseModel):
    key: Base64Bytes
    signature: Base64Bytes
    nonce: Base64Bytes
