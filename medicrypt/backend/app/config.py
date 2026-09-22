"""
Central configuration for MediCrypt backend.
All values can be overridden via environment variables (see .env.example).
"""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv is optional; env vars can also be set directly

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/


class Settings:
    # --- App ---
    APP_NAME: str = "MediCrypt API"
    APP_VERSION: str = "1.0.0"
    ENV: str = os.getenv("ENV", "development")

    # --- Database ---
    # Defaults to local SQLite so the project runs out-of-the-box with zero setup.
    # For production, set DATABASE_URL to a Postgres DSN, e.g.:
    # postgresql+psycopg2://user:password@localhost:5432/medicrypt
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'medicrypt.db'}"
    )

    # --- Auth / JWT ---
    JWT_SECRET_KEY: str = os.getenv(
        "JWT_SECRET_KEY", "CHANGE_ME_IN_PRODUCTION_" + os.urandom(8).hex()
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

    # --- Storage ---
    STORAGE_DIR: Path = BASE_DIR / "storage"
    ENCRYPTED_IMAGES_DIR: Path = STORAGE_DIR / "encrypted_images"
    KEYS_DIR: Path = STORAGE_DIR / "keys"

    # --- Crypto ---
    RSA_KEY_SIZE: int = 2048
    AES_KEY_SIZE_BYTES: int = 32  # AES-256
    AES_NONCE_SIZE_BYTES: int = 12  # 96-bit nonce, recommended for GCM

    # --- CORS ---
    CORS_ORIGINS: list = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")


settings = Settings()

# Ensure storage directories exist at import time.
settings.ENCRYPTED_IMAGES_DIR.mkdir(parents=True, exist_ok=True)
settings.KEYS_DIR.mkdir(parents=True, exist_ok=True)
