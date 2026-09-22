from typing import Optional
from sqlalchemy.orm import Session

from . import models


def log_action(
    db: Session,
    action: models.AuditAction,
    actor: Optional[models.User] = None,
    image_id: Optional[str] = None,
    detail: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> models.AuditLog:
    entry = models.AuditLog(
        actor_id=actor.id if actor else None,
        actor_email=actor.email if actor else None,
        action=action,
        image_id=image_id,
        detail=detail,
        ip_address=ip_address,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
