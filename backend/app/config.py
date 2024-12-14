from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "e2ee"
    debug: bool = False
    postgres_addr: str
    postgres_port: int
    postgres_user: str
    postgres_password: str
    postgres_db: str
    jwt_secret: str
    jwt_algorithm: str
    jwt_exp_min: int
    jwt_exp_day: int

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()
