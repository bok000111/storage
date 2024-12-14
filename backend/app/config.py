from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "e2ee"
    debug: bool = False
    postgres_addr: str
    postgres_port: int
    postgres_user: str
    postgres_password: str
    postgres_db: str
    jwt_secret_key: str
    jwt_algorithm: str
    jwt_access_token_expire_minutes: int
    jwt_refresh_token_expire_days: int

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()
