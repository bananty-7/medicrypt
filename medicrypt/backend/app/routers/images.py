import io
import os
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from cryptography.exceptions import InvalidTag

from .. import models, schemas, crypto_utils
from ..database import get_db
from ..auth import get_current_user, require_roles
from ..audit import log_action
from ..config import settings

router = APIRouter(prefix="/images", tags=["Medical Images"])

ALLOWED_CONTENT_TYPES = {"image/png", "image/jpeg", "image/tiff", "application/dicom"}
MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB


def _user_has_access(image: models.MedicalImage, user: models.User) -> bool:
    if user.role == models.UserRole.ADMIN:
        return True  # admins can see metadata/audit trail, enforced separately for decryption
    if image.patient_id == user.id or image.uploaded_by_id == user.id:
        return True
    return any(g.user_id == user.id for g in image.key_grants)


def _get_image_or_404(db: Session, image_id: str) -> models.MedicalImage:
    image = db.query(models.MedicalImage).filter(models.MedicalImage.id == image_id).first()
    if not image:
        raise HTTPException(status_code=404, detail="Image not found.")
    return image


@router.post("/upload", response_model=schemas.ImageUploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_image(
    request: Request,
    patient_email: str = Form(...),
    modality: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles(models.UserRole.DOCTOR, models.UserRole.ADMIN)),
):
    """
    Doctor/Admin uploads a medical image on behalf of a patient.

    Pipeline: read bytes -> SHA-256 hash -> AES-256-GCM encrypt -> wrap the
    AES key with the PATIENT's RSA public key AND the UPLOADER's RSA public
    key (so both can later decrypt) -> sign the hash with the uploader's
    RSA private key -> persist ciphertext + metadata.
    """
    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported content type '{file.content_type}'. Allowed: {sorted(ALLOWED_CONTENT_TYPES)}",
        )

    plaintext = await file.read()
    if len(plaintext) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(plaintext) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds the 25 MB upload limit.")

    patient = db.query(models.User).filter(models.User.email == patient_email).first()
    if not patient or patient.role != models.UserRole.PATIENT:
        raise HTTPException(status_code=404, detail="No patient found with that email.")
    if not patient.public_key_path:
        raise HTTPException(status_code=500, detail="Patient has no encryption key on file.")

    # 1. Hash the ORIGINAL plaintext (this is what we sign, and what we
    #    re-verify against after every future decryption).
    digest = crypto_utils.sha256_hex(plaintext)
    digest_bytes = bytes.fromhex(digest)

    # 2. Symmetric encryption of the image bytes.
    aes_key = crypto_utils.generate_aes_key()
    ciphertext, nonce, tag = crypto_utils.aes_gcm_encrypt(plaintext, aes_key)

    # 3. Hybrid key exchange: wrap the one-time AES key for each recipient
    #    who should be able to decrypt (patient + uploading doctor).
    recipients = {patient.id: patient, current_user.id: current_user}
    wrapped_keys = {}
    for uid, u in recipients.items():
        pub = crypto_utils.load_public_key(u.public_key_path)
        wrapped_keys[uid] = crypto_utils.b64(crypto_utils.rsa_wrap_key(aes_key, pub))

    # 4. Digital signature over the plaintext hash, by the uploader.
    if not current_user.private_key_path:
        raise HTTPException(status_code=500, detail="Uploader has no signing key on file.")
    signer_priv = crypto_utils.load_private_key(current_user.private_key_path)
    signature = crypto_utils.sign_data(digest_bytes, signer_priv)

    # 5. Persist ciphertext to disk.
    image_id = models.gen_uuid()
    storage_path = settings.ENCRYPTED_IMAGES_DIR / f"{image_id}.enc"
    storage_path.write_bytes(ciphertext)

    image = models.MedicalImage(
        id=image_id,
        filename=file.filename,
        storage_path=str(storage_path),
        content_type=file.content_type,
        patient_id=patient.id,
        uploaded_by_id=current_user.id,
        nonce=crypto_utils.b64(nonce),
        auth_tag=crypto_utils.b64(tag),
        sha256_hash=digest,
        signature=crypto_utils.b64(signature),
        signer_id=current_user.id,
        modality=modality,
        notes=notes,
    )
    db.add(image)
    db.flush()  # get image.id available for FK rows below

    for uid, wrapped in wrapped_keys.items():
        db.add(models.ImageKeyGrant(
            image_id=image.id, user_id=uid, wrapped_key=wrapped, granted_by_id=current_user.id
        ))

    db.commit()
    db.refresh(image)

    log_action(
        db, models.AuditAction.UPLOAD, actor=current_user, image_id=image.id,
        detail=f"Uploaded '{file.filename}' ({modality or 'unspecified modality'}) for patient {patient.email}",
        ip_address=request.client.host if request.client else None,
    )

    return schemas.ImageUploadResponse(image=image)


@router.get("/", response_model=List[schemas.ImageOut])
def list_images(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Returns metadata only (never decrypted pixel data) for every image the caller may access."""
    if current_user.role == models.UserRole.ADMIN:
        images = db.query(models.MedicalImage).all()
    elif current_user.role == models.UserRole.PATIENT:
        images = db.query(models.MedicalImage).filter(
            models.MedicalImage.patient_id == current_user.id
        ).all()
    else:  # doctor
        granted_ids = [
            g.image_id for g in db.query(models.ImageKeyGrant).filter(
                models.ImageKeyGrant.user_id == current_user.id
            ).all()
        ]
        images = db.query(models.MedicalImage).filter(
            (models.MedicalImage.uploaded_by_id == current_user.id) |
            (models.MedicalImage.id.in_(granted_ids))
        ).all()
    return images


@router.get("/{image_id}", response_model=schemas.ImageOut)
def get_image_metadata(
    image_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    image = _get_image_or_404(db, image_id)
    if not _user_has_access(image, current_user):
        log_action(db, models.AuditAction.ACCESS_DENIED, actor=current_user, image_id=image_id,
                   ip_address=request.client.host if request.client else None)
        raise HTTPException(status_code=403, detail="You do not have access to this image.")

    log_action(db, models.AuditAction.VIEW_METADATA, actor=current_user, image_id=image_id,
               ip_address=request.client.host if request.client else None)
    return image


@router.get("/{image_id}/download")
def download_and_decrypt_image(
    image_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Decrypts the image for the current user and streams back the plaintext
    bytes, but ONLY if:
      1. The current user holds a valid key grant (RSA-wrapped AES key), AND
      2. AES-GCM authentication succeeds (catches ciphertext tampering), AND
      3. The uploader's RSA-PSS signature over SHA-256(plaintext) verifies
         (catches tampering of the hash/signature/metadata rows, and proves
         the image really came from the claimed uploader).
    Any failure is treated as tampering and logged, and the request is refused.
    """
    image = _get_image_or_404(db, image_id)
    ip = request.client.host if request.client else None

    # Decryption always requires an explicit RSA key grant, regardless of
    # role. Admins do NOT get a free pass here (see ImageKeyGrant docstring):
    # they can see metadata and audit logs, but cannot decrypt pixel data
    # unless a grant was explicitly created for them.
    grant = db.query(models.ImageKeyGrant).filter(
        models.ImageKeyGrant.image_id == image_id,
        models.ImageKeyGrant.user_id == current_user.id,
    ).first()
    if not grant:
        log_action(db, models.AuditAction.ACCESS_DENIED, actor=current_user, image_id=image_id, ip_address=ip)
        raise HTTPException(status_code=403, detail="You do not have decryption rights for this image.")

    if not current_user.private_key_path:
        raise HTTPException(status_code=500, detail="Your account has no private key on file.")

    try:
        priv = crypto_utils.load_private_key(current_user.private_key_path)
        aes_key = crypto_utils.rsa_unwrap_key(crypto_utils.unb64(grant.wrapped_key), priv)

        ciphertext = open(image.storage_path, "rb").read()
        nonce = crypto_utils.unb64(image.nonce)
        tag = crypto_utils.unb64(image.auth_tag)

        plaintext = crypto_utils.aes_gcm_decrypt(ciphertext, aes_key, nonce, tag)
    except InvalidTag:
        log_action(db, models.AuditAction.TAMPERING_DETECTED, actor=current_user, image_id=image_id,
                   detail="AES-GCM authentication tag mismatch: ciphertext has been altered.", ip_address=ip)
        raise HTTPException(status_code=409, detail="Integrity check failed: this image's ciphertext has been tampered with.")
    except Exception as exc:
        log_action(db, models.AuditAction.DECRYPT_FAILURE, actor=current_user, image_id=image_id,
                   detail=str(exc), ip_address=ip)
        raise HTTPException(status_code=500, detail="Decryption failed.")

    # Verify authenticity: recompute hash of recovered plaintext, verify
    # the uploader's signature over it.
    recomputed_hash = crypto_utils.sha256_hex(plaintext)
    signer = db.query(models.User).filter(models.User.id == image.signer_id).first()
    signer_pub = crypto_utils.load_public_key(signer.public_key_path)
    sig_valid = crypto_utils.verify_signature(
        bytes.fromhex(recomputed_hash), crypto_utils.unb64(image.signature), signer_pub
    )
    hash_matches_record = recomputed_hash == image.sha256_hash

    if not sig_valid or not hash_matches_record:
        log_action(
            db, models.AuditAction.TAMPERING_DETECTED, actor=current_user, image_id=image_id,
            detail=f"Signature valid={sig_valid}, hash matches stored record={hash_matches_record}",
            ip_address=ip,
        )
        raise HTTPException(
            status_code=409,
            detail="Authenticity check failed: digital signature does not match. This image may have been tampered with or does not originate from the recorded uploader.",
        )

    log_action(db, models.AuditAction.DECRYPT_SUCCESS, actor=current_user, image_id=image_id, ip_address=ip)
    log_action(db, models.AuditAction.DOWNLOAD, actor=current_user, image_id=image_id, ip_address=ip)

    return StreamingResponse(
        io.BytesIO(plaintext),
        media_type=image.content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{image.filename}"',
            "X-Integrity-Verified": "true",
            "X-Signature-Valid": "true",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
        },
    )

@router.post("/{image_id}/share", status_code=status.HTTP_201_CREATED)
def share_image(
    image_id: str,
    payload: schemas.ShareImageRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Re-shares decryption access with another registered user (e.g. a
    patient granting a second-opinion doctor access). The caller must
    already hold a key grant; their private key is used to unwrap the AES
    key, which is then re-wrapped with the target user's public key. The
    raw AES key never leaves server memory and is never persisted.
    """
    image = _get_image_or_404(db, image_id)
    my_grant = db.query(models.ImageKeyGrant).filter(
        models.ImageKeyGrant.image_id == image_id,
        models.ImageKeyGrant.user_id == current_user.id,
    ).first()
    if not my_grant:
        raise HTTPException(status_code=403, detail="You must already have access to share this image.")

    target = db.query(models.User).filter(models.User.email == payload.grant_to_email).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found.")

    existing = db.query(models.ImageKeyGrant).filter(
        models.ImageKeyGrant.image_id == image_id, models.ImageKeyGrant.user_id == target.id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="That user already has access.")

    my_priv = crypto_utils.load_private_key(current_user.private_key_path)
    aes_key = crypto_utils.rsa_unwrap_key(crypto_utils.unb64(my_grant.wrapped_key), my_priv)

    target_pub = crypto_utils.load_public_key(target.public_key_path)
    rewrapped = crypto_utils.b64(crypto_utils.rsa_wrap_key(aes_key, target_pub))

    grant = models.ImageKeyGrant(
        image_id=image_id, user_id=target.id, wrapped_key=rewrapped, granted_by_id=current_user.id
    )
    db.add(grant)
    db.commit()

    log_action(
        db, models.AuditAction.VIEW_METADATA, actor=current_user, image_id=image_id,
        detail=f"Shared decryption access with {target.email}",
        ip_address=request.client.host if request.client else None,
    )
    return {"message": f"Access granted to {target.email}."}


@router.post("/{image_id}/simulate-tamper")
def simulate_tampering(
    image_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles(models.UserRole.ADMIN)),
):
    """
    DEMO/TEST ONLY: flips a single byte in the stored ciphertext on disk so
    the tampering-detection pipeline can be demonstrated end-to-end
    (upload -> tamper -> download attempt -> 409 + audit log entry).
    Restricted to admins; would not exist in a production deployment.
    """
    image = _get_image_or_404(db, image_id)
    path = image.storage_path
    data = bytearray(open(path, "rb").read())
    if not data:
        raise HTTPException(status_code=400, detail="Stored file is empty; nothing to tamper with.")
    data[0] ^= 0xFF  # flip the first byte
    with open(path, "wb") as f:
        f.write(data)
    return {"message": f"Ciphertext for image {image_id} has been deliberately corrupted for demo purposes."}
