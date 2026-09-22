from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..auth import get_current_user, require_roles

router = APIRouter(prefix="/audit", tags=["Audit Log"])


@router.get("/", response_model=schemas.AuditLogList)
def list_all_audit_logs(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles(models.UserRole.ADMIN)),
):
    """Admin-only: full system audit trail (logins, uploads, downloads, access denials, tampering events)."""
    query = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc())
    total = query.count()
    logs = query.offset(offset).limit(limit).all()
    return schemas.AuditLogList(total=total, logs=logs)


@router.get("/image/{image_id}", response_model=schemas.AuditLogList)
def list_logs_for_image(
    image_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Anyone with access to the image (patient/doctor/admin) can see its
    access history -- this is the transparency feature patients need to
    know who has viewed or downloaded their scans.
    """
    image = db.query(models.MedicalImage).filter(models.MedicalImage.id == image_id).first()
    if not image:
        raise HTTPException(status_code=404, detail="Image not found.")

    is_owner_or_uploader = current_user.id in (image.patient_id, image.uploaded_by_id)
    has_grant = any(g.user_id == current_user.id for g in image.key_grants)
    if not (is_owner_or_uploader or has_grant or current_user.role == models.UserRole.ADMIN):
        raise HTTPException(status_code=403, detail="You do not have access to this image's history.")

    query = db.query(models.AuditLog).filter(
        models.AuditLog.image_id == image_id
    ).order_by(models.AuditLog.timestamp.desc())
    logs = query.all()
    return schemas.AuditLogList(total=len(logs), logs=logs)
