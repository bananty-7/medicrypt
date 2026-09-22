"""
Quick demo-data seeder. Creates one admin, one doctor, and one patient
account so you can log in immediately without registering by hand.

Run from the backend/ directory (after installing requirements):
    python seed_demo_data.py
"""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from app.database import Base, engine, SessionLocal
from app import models, crypto_utils
from app.auth import hash_password

DEMO_USERS = [
    ("Alice Admin", "admin@medicrypt.demo", "AdminPass123!", models.UserRole.ADMIN),
    ("Dr. Daniel Rahman", "doctor@medicrypt.demo", "DoctorPass123!", models.UserRole.DOCTOR),
    ("Priya Patient", "patient@medicrypt.demo", "PatientPass123!", models.UserRole.PATIENT),
]


def main():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for name, email, password, role in DEMO_USERS:
            existing = db.query(models.User).filter(models.User.email == email).first()
            if existing:
                print(f"skip (already exists): {email}")
                continue
            user = models.User(
                full_name=name, email=email, hashed_password=hash_password(password), role=role,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            pub, priv = crypto_utils.generate_rsa_keypair(user.id)
            user.public_key_path = pub
            user.private_key_path = priv
            db.commit()
            print(f"created: {email} / {password}  (role={role.value})")
    finally:
        db.close()

    print("\nDemo accounts ready. Log in at the frontend with any of the emails/passwords above.")


if __name__ == "__main__":
    main()
