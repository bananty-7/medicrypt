"""
End-to-end API integration tests using FastAPI's TestClient.

These exercise the full HTTP flow: register -> login -> upload -> download ->
tamper -> re-download (expect 409). They require the full dependency set
from requirements.txt to be installed:

    pip install -r requirements.txt --break-system-packages
    pytest backend/tests/test_api.py -v

Each test run uses a fresh temp SQLite DB and temp storage dirs so tests
never touch your real medicrypt.db.
"""
import io
import os
import tempfile

import pytest


@pytest.fixture()
def client(monkeypatch, tmp_path):
    # Point the app at isolated, throwaway storage BEFORE importing it.
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")

    from app.config import settings
    settings.ENCRYPTED_IMAGES_DIR = tmp_path / "encrypted_images"
    settings.KEYS_DIR = tmp_path / "keys"
    settings.ENCRYPTED_IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    settings.KEYS_DIR.mkdir(parents=True, exist_ok=True)

    from fastapi.testclient import TestClient
    from app.main import app

    return TestClient(app)


def _register(client, email, role, password="password123", name="Test User"):
    r = client.post("/auth/register", json={
        "full_name": name, "email": email, "password": password, "role": role,
    })
    assert r.status_code == 201, r.text
    return r.json()


def _login(client, email, password="password123"):
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_register_and_login(client):
    _register(client, "patient@example.com", "patient")
    token = _login(client, "patient@example.com")
    assert token


def test_full_upload_download_flow(client):
    _register(client, "doc@example.com", "doctor")
    _register(client, "pat@example.com", "patient")
    doc_token = _login(client, "doc@example.com")

    fake_image = b"\x89PNG\r\n\x1a\n" + os.urandom(500)  # fake PNG-ish bytes
    r = client.post(
        "/images/upload",
        headers={"Authorization": f"Bearer {doc_token}"},
        data={"patient_email": "pat@example.com", "modality": "X-ray", "notes": "routine"},
        files={"file": ("scan.png", io.BytesIO(fake_image), "image/png")},
    )
    assert r.status_code == 201, r.text
    image_id = r.json()["image"]["id"]

    pat_token = _login(client, "pat@example.com")
    r2 = client.get(f"/images/{image_id}/download", headers={"Authorization": f"Bearer {pat_token}"})
    assert r2.status_code == 200
    assert r2.content == fake_image
    assert r2.headers["X-Integrity-Verified"] == "true"


def test_tampering_is_detected_on_download(client):
    _register(client, "doc2@example.com", "doctor")
    _register(client, "pat2@example.com", "patient")
    _register(client, "admin2@example.com", "admin")
    doc_token = _login(client, "doc2@example.com")

    r = client.post(
        "/images/upload",
        headers={"Authorization": f"Bearer {doc_token}"},
        data={"patient_email": "pat2@example.com", "modality": "CT"},
        files={"file": ("scan.png", io.BytesIO(os.urandom(300)), "image/png")},
    )
    image_id = r.json()["image"]["id"]

    admin_token = _login(client, "admin2@example.com")
    r2 = client.post(f"/images/{image_id}/simulate-tamper", headers={"Authorization": f"Bearer {admin_token}"})
    assert r2.status_code == 200

    pat_token = _login(client, "pat2@example.com")
    r3 = client.get(f"/images/{image_id}/download", headers={"Authorization": f"Bearer {pat_token}"})
    assert r3.status_code == 409
    assert "tamper" in r3.json()["detail"].lower()


def test_patient_cannot_see_others_images(client):
    _register(client, "doc3@example.com", "doctor")
    _register(client, "patA@example.com", "patient")
    _register(client, "patB@example.com", "patient")
    doc_token = _login(client, "doc3@example.com")

    r = client.post(
        "/images/upload",
        headers={"Authorization": f"Bearer {doc_token}"},
        data={"patient_email": "patA@example.com", "modality": "MRI"},
        files={"file": ("scan.png", io.BytesIO(os.urandom(200)), "image/png")},
    )
    image_id = r.json()["image"]["id"]

    patB_token = _login(client, "patB@example.com")
    r2 = client.get(f"/images/{image_id}", headers={"Authorization": f"Bearer {patB_token}"})
    assert r2.status_code == 403

    r3 = client.get(f"/images/{image_id}/download", headers={"Authorization": f"Bearer {patB_token}"})
    assert r3.status_code == 403


def test_admin_cannot_decrypt_without_explicit_grant(client):
    _register(client, "doc4@example.com", "doctor")
    _register(client, "patC@example.com", "patient")
    _register(client, "admin4@example.com", "admin")
    doc_token = _login(client, "doc4@example.com")

    r = client.post(
        "/images/upload",
        headers={"Authorization": f"Bearer {doc_token}"},
        data={"patient_email": "patC@example.com", "modality": "X-ray"},
        files={"file": ("scan.png", io.BytesIO(os.urandom(200)), "image/png")},
    )
    image_id = r.json()["image"]["id"]

    admin_token = _login(client, "admin4@example.com")
    r2 = client.get(f"/images/{image_id}/download", headers={"Authorization": f"Bearer {admin_token}"})
    assert r2.status_code == 403  # least privilege: admins don't get a free decryption pass
