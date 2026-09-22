import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, DateTime, Enum, ForeignKey, Text, Boolean, Integer
)
from sqlalchemy.orm import relationship

from .database import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    DOCTOR = "doctor"
    PATIENT = "patient"


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=gen_uuid)
    full_name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.PATIENT)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Path to this user's RSA public/private key files (private key is
    # itself encrypted at rest with a key derived from the user's password
    # in a real production system; see README "Threat model" notes).
    public_key_path = Column(String, nullable=True)
    private_key_path = Column(String, nullable=True)

    images_owned = relationship(
        "MedicalImage", back_populates="patient", foreign_keys="MedicalImage.patient_id"
    )


class MedicalImage(Base):
    __tablename__ = "medical_images"

    id = Column(String, primary_key=True, default=gen_uuid)
    filename = Column(String, nullable=False)          # original filename
    storage_path = Column(String, nullable=False)       # path to ciphertext on disk
    content_type = Column(String, nullable=False)

    patient_id = Column(String, ForeignKey("users.id"), nullable=False)
    uploaded_by_id = Column(String, ForeignKey("users.id"), nullable=False)

    # --- Crypto metadata (all needed for decryption / verification) ---
    # NOTE: the raw AES key itself is never stored. Only per-recipient
    # RSA-wrapped copies exist, in the ImageKeyGrant table below.
    nonce = Column(String, nullable=False)               # base64, AES-GCM nonce
    auth_tag = Column(String, nullable=False)            # base64, AES-GCM tag
    sha256_hash = Column(String, nullable=False)         # hash of the ORIGINAL plaintext image
    signature = Column(Text, nullable=False)             # RSA-PSS signature of sha256_hash, by uploader
    signer_id = Column(String, ForeignKey("users.id"), nullable=False)

    modality = Column(String, nullable=True)             # X-ray / CT / MRI (free text)
    notes = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    patient = relationship("User", foreign_keys=[patient_id], back_populates="images_owned")
    uploaded_by = relationship("User", foreign_keys=[uploaded_by_id])
    signer = relationship("User", foreign_keys=[signer_id])
    key_grants = relationship(
        "ImageKeyGrant", back_populates="image", cascade="all, delete-orphan"
    )


class ImageKeyGrant(Base):
    """
    Implements per-user, multi-recipient hybrid encryption ("key exchange").
    Each row is one AES key, wrapped with ONE recipient's RSA public key.
    Only a principal holding the matching private key can unwrap it and
    therefore decrypt the image -- this is what enforces doctor<->patient
    access control at the cryptographic layer, not just at the API layer.

    By design, admins are NOT granted a key unless explicitly shared with
    them: an admin can manage accounts and read the audit trail, but cannot
    silently decrypt patient data. This is a deliberate least-privilege
    property of the system (see README "Threat Model & Limitations").
    """
    __tablename__ = "image_key_grants"

    id = Column(Integer, primary_key=True, autoincrement=True)
    image_id = Column(String, ForeignKey("medical_images.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    wrapped_key = Column(Text, nullable=False)  # base64 RSA-OAEP ciphertext of the AES key
    granted_at = Column(DateTime, default=datetime.utcnow)
    granted_by_id = Column(String, ForeignKey("users.id"), nullable=True)

    image = relationship("MedicalImage", back_populates="key_grants")
    user = relationship("User", foreign_keys=[user_id])


class AuditAction(str, enum.Enum):
    UPLOAD = "UPLOAD"
    VIEW_METADATA = "VIEW_METADATA"
    DOWNLOAD = "DOWNLOAD"
    DECRYPT_SUCCESS = "DECRYPT_SUCCESS"
    DECRYPT_FAILURE = "DECRYPT_FAILURE"
    TAMPERING_DETECTED = "TAMPERING_DETECTED"
    LOGIN = "LOGIN"
    LOGIN_FAILED = "LOGIN_FAILED"
    ACCESS_DENIED = "ACCESS_DENIED"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    actor_id = Column(String, ForeignKey("users.id"), nullable=True)
    actor_email = Column(String, nullable=True)
    action = Column(Enum(AuditAction), nullable=False)
    image_id = Column(String, ForeignKey("medical_images.id"), nullable=True)
    detail = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)
