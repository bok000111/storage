from pydantic import BaseModel, EmailStr, ConfigDict


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
