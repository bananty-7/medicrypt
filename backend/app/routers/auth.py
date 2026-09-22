from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import models, schemas, crypto_utils
from ..database import get_db
from ..auth import hash_password, verify_password, create_access_token
from ..audit import log_action

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="A user with this email already exists.")

    user = models.User(
        full_name=payload.full_name,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Generate this user's RSA keypair immediately, so they can receive
    # encrypted images (public key) and sign / decrypt (private key)
    # the moment they sign up.
    pub_path, priv_path = crypto_utils.generate_rsa_keypair(user.id)
    user.public_key_path = pub_path
    user.private_key_path = priv_path
    db.commit()

    return user


@router.post("/login", response_model=schemas.Token)
def login(payload: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    client_ip = request.client.host if request.client else None

    if not user or not verify_password(payload.password, user.hashed_password):
        log_action(
            db, models.AuditAction.LOGIN_FAILED,
            detail=f"Failed login attempt for email={payload.email}",
            ip_address=client_ip,
        )
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="This account has been deactivated.")

    token = create_access_token(subject=user.id, extra={"role": user.role.value})
    log_action(db, models.AuditAction.LOGIN, actor=user, ip_address=client_ip)

    return schemas.Token(access_token=token, user=user)
