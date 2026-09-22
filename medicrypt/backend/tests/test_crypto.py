"""
Unit tests for app.crypto_utils. These only depend on the `cryptography`
package, not on FastAPI/SQLAlchemy, so they can run in almost any
environment as a fast sanity check of the security-critical code path.

Run with:  pytest backend/tests/test_crypto.py -v
"""
import os
import tempfile
import shutil

import pytest
from cryptography.exceptions import InvalidTag

from app import crypto_utils


@pytest.fixture()
def key_dir(tmp_path, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "KEYS_DIR", tmp_path)
    return tmp_path


def test_rsa_keypair_roundtrip(key_dir):
    pub_path, priv_path = crypto_utils.generate_rsa_keypair("test_user")
    assert os.path.exists(pub_path)
    assert os.path.exists(priv_path)

    pub = crypto_utils.load_public_key(pub_path)
    priv = crypto_utils.load_private_key(priv_path)
    assert pub is not None and priv is not None


def test_aes_gcm_encrypt_decrypt_roundtrip():
    key = crypto_utils.generate_aes_key()
    plaintext = b"this is fake medical image bytes" * 100
    ciphertext, nonce, tag = crypto_utils.aes_gcm_encrypt(plaintext, key)

    recovered = crypto_utils.aes_gcm_decrypt(ciphertext, key, nonce, tag)
    assert recovered == plaintext


def test_aes_gcm_detects_tampering():
    key = crypto_utils.generate_aes_key()
    plaintext = b"sensitive scan data"
    ciphertext, nonce, tag = crypto_utils.aes_gcm_encrypt(plaintext, key)

    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF

    with pytest.raises(InvalidTag):
        crypto_utils.aes_gcm_decrypt(bytes(tampered), key, nonce, tag)


def test_rsa_key_wrapping_roundtrip(key_dir):
    pub_path, priv_path = crypto_utils.generate_rsa_keypair("patient_x")
    pub = crypto_utils.load_public_key(pub_path)
    priv = crypto_utils.load_private_key(priv_path)

    aes_key = crypto_utils.generate_aes_key()
    wrapped = crypto_utils.rsa_wrap_key(aes_key, pub)
    unwrapped = crypto_utils.rsa_unwrap_key(wrapped, priv)

    assert unwrapped == aes_key


def test_signature_valid_for_correct_data(key_dir):
    pub_path, priv_path = crypto_utils.generate_rsa_keypair("doctor_x")
    pub = crypto_utils.load_public_key(pub_path)
    priv = crypto_utils.load_private_key(priv_path)

    digest = crypto_utils.sha256_hex(b"original image bytes")
    digest_bytes = bytes.fromhex(digest)

    signature = crypto_utils.sign_data(digest_bytes, priv)
    assert crypto_utils.verify_signature(digest_bytes, signature, pub) is True


def test_signature_invalid_for_tampered_hash(key_dir):
    pub_path, priv_path = crypto_utils.generate_rsa_keypair("doctor_y")
    pub = crypto_utils.load_public_key(pub_path)
    priv = crypto_utils.load_private_key(priv_path)

    original_digest = bytes.fromhex(crypto_utils.sha256_hex(b"original"))
    tampered_digest = bytes.fromhex(crypto_utils.sha256_hex(b"tampered"))

    signature = crypto_utils.sign_data(original_digest, priv)
    assert crypto_utils.verify_signature(tampered_digest, signature, pub) is False


def test_full_hybrid_pipeline_end_to_end(key_dir):
    """Mirrors exactly what the /images/upload and /images/{id}/download routes do."""
    doc_pub, doc_priv = crypto_utils.generate_rsa_keypair("doc")
    pat_pub, pat_priv = crypto_utils.generate_rsa_keypair("pat")

    plaintext = os.urandom(2048)
    digest_hex = crypto_utils.sha256_hex(plaintext)

    aes_key = crypto_utils.generate_aes_key()
    ciphertext, nonce, tag = crypto_utils.aes_gcm_encrypt(plaintext, aes_key)

    wrapped_for_patient = crypto_utils.rsa_wrap_key(
        aes_key, crypto_utils.load_public_key(pat_pub)
    )
    signature = crypto_utils.sign_data(
        bytes.fromhex(digest_hex), crypto_utils.load_private_key(doc_priv)
    )

    # patient side
    recovered_key = crypto_utils.rsa_unwrap_key(
        wrapped_for_patient, crypto_utils.load_private_key(pat_priv)
    )
    recovered_plaintext = crypto_utils.aes_gcm_decrypt(ciphertext, recovered_key, nonce, tag)
    assert recovered_plaintext == plaintext

    recomputed_hex = crypto_utils.sha256_hex(recovered_plaintext)
    assert recomputed_hex == digest_hex
    assert crypto_utils.verify_signature(
        bytes.fromhex(recomputed_hex), signature, crypto_utils.load_public_key(doc_pub)
    )
