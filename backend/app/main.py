from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import Base, engine
from .routers import auth, images, audit

# Create all tables on startup (fine for SQLite/dev; for Postgres in
# production prefer Alembic migrations -- see README).
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "MediCrypt -- Secure Medical Image Sharing and Tampering Detection System.\n\n"
        "Provides AES-256-GCM encryption of medical images, RSA-OAEP hybrid key "
        "exchange, RSA-PSS digital signatures for authenticity, role-based access "
        "control (Admin/Doctor/Patient), and a full audit trail of every access."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(images.router)
app.include_router(audit.router)


@app.get("/", tags=["Health"])
def health_check():
    return {"status": "ok", "service": settings.APP_NAME, "version": settings.APP_VERSION}
