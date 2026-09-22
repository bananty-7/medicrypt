"""
crypto_utils.py
================
All cryptographic primitives used by MediCrypt live in this single module so
they can be audited, unit-tested, and swapped out independently of business
logic (upload/download routes, DB models, etc).

Design summary
--------------
1. Confidentiality  : AES-256-GCM (authenticated encryption) on the image bytes.
2. Key exchange     : The one-time AES key is wrapped with RSA-OAEP(SHA-256)
                       using the RECIPIENT's public key ("hybrid encryption").
                       Only the recipient's private key can unwrap it.
3. Authenticity     : The uploader signs SHA-256(plaintext image) with
                       RSA-PSS(SHA-256) using their OWN private key.
4. Tampering check  : On decrypt, we (a) let AES-GCM's authentication tag
                       catch ciphertext tampering, and (b) recompute
                       SHA-256 of the recovered plaintext and verify the
                       stored signature against it, catching any tampering
                       of the stored hash/signature/metadata rows too.

All keys are generated with `cryptography` (pyca), the de-facto standard,
audited Python crypto library. No custom/home-grown crypto is used anywhere.
"""
import base64
import hashlib
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

from .config import settings


# --------------------------------------------------------------------------
# RSA key pair management (used for both key-exchange and signatures)
# --------------------------------------------------------------------------

def generate_rsa_keypair(user_id: str) -> Tuple[str, str]:
    """
    Generate an RSA keypair for a user and persist it to disk (PEM format).
    Returns (public_key_path, private_key_path).

    NOTE on threat model: in this reference implementation, private keys are
    stored unencrypted on the server filesystem for simplicity/demo purposes.
    In a production deployment you should either:
      (a) encrypt the private key at rest with a key derived from the user's
          password (e.g. via PBKDF2/Argon2) and never let it touch the
          server unencrypted, or
      (b) keep private keys client-side only (e.g. in the browser / a
          hardware token) and never upload them at all.
    This is called out explicitly in README.md under "Threat Model & Limitations".
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=settings.RSA_KEY_SIZE
    )
    public_key = private_key.public_key()

    priv_path = settings.KEYS_DIR / f"{user_id}_private.pem"
    pub_path = settings.KEYS_DIR / f"{user_id}_public.pem"

    priv_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return str(pub_path), str(priv_path)


def load_public_key(path: str):
    data = Path(path).read_bytes()
    return serialization.load_pem_public_key(data)


def load_private_key(path: str):
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=None)


# --------------------------------------------------------------------------
# AES-256-GCM symmetric encryption of the image payload
# --------------------------------------------------------------------------

def generate_aes_key() -> bytes:
    return AESGCM.generate_key(bit_length=settings.AES_KEY_SIZE_BYTES * 8)


def aes_gcm_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypts plaintext with AES-256-GCM.
    Returns (ciphertext, nonce, tag) with ciphertext NOT including the tag
    (we split it out for explicit storage/inspection, which is friendlier
    for the audit/tamper-detection demo in the frontend).
    """
    aesgcm = AESGCM(key)
    nonce = __import__("os").urandom(settings.AES_NONCE_SIZE_BYTES)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    tag = ct_and_tag[-16:]
    ciphertext = ct_and_tag[:-16]
    return ciphertext, nonce, tag


def aes_gcm_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypts and verifies AES-GCM ciphertext. Raises
    cryptography.exceptions.InvalidTag if the ciphertext or tag was tampered
    with (this is how bit-flip attacks on the stored file are caught).
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, associated_data=None)


# --------------------------------------------------------------------------
# RSA-OAEP key wrapping (the "key exchange" step of hybrid encryption)
# --------------------------------------------------------------------------

def rsa_wrap_key(aes_key: bytes, recipient_public_key) -> bytes:
    return recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_unwrap_key(wrapped_key: bytes, recipient_private_key) -> bytes:
    return recipient_private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# --------------------------------------------------------------------------
# RSA-PSS digital signatures (authenticity + tamper detection)
# --------------------------------------------------------------------------

def sign_data(data_hash: bytes, signer_private_key) -> bytes:
    return signer_private_key.sign(
        data_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(data_hash: bytes, signature: bytes, signer_public_key) -> bool:
    try:
        signer_public_key.verify(
            signature,
            data_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------
# Hashing + base64 helpers
# --------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))
