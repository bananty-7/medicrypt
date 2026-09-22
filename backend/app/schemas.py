from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, EmailStr, Field

from .models import UserRole, AuditAction


# ---------- Auth ----------

class UserCreate(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8)
    role: UserRole = UserRole.PATIENT


class UserOut(BaseModel):
    id: str
    full_name: str
    email: EmailStr
    role: UserRole
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# ---------- Images ----------

class ImageOut(BaseModel):
    id: str
    filename: str
    content_type: str
    modality: Optional[str]
    notes: Optional[str]
    patient_id: str
    uploaded_by_id: str
    signer_id: str
    sha256_hash: str
    created_at: datetime

    class Config:
        from_attributes = True


class ImageUploadResponse(BaseModel):
    image: ImageOut
    message: str = "Image encrypted, signed, and stored successfully."


class ShareImageRequest(BaseModel):
    grant_to_email: EmailStr


class DecryptResult(BaseModel):
    image_id: str
    integrity_verified: bool
    signature_valid: bool
    message: str


# ---------- Audit ----------

class AuditLogOut(BaseModel):
    id: int
    timestamp: datetime
    actor_email: Optional[str]
    action: AuditAction
    image_id: Optional[str]
    detail: Optional[str]
    ip_address: Optional[str]

    class Config:
        from_attributes = True


class AuditLogList(BaseModel):
    total: int
    logs: List[AuditLogOut]
