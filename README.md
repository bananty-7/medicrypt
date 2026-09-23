# 🛡️ MediCrypt — Secure Medical Image Sharing \& Tampering Detection System



🔗 \*\*Live Demo:\*\* \[https://lighthearted-squirrel-d1f861.netlify.app](https://lighthearted-squirrel-d1f861.netlify.app)



> ⚠️ Backend is hosted on Render's free tier and spins down after 15 minutes of inactivity — the first request may take 30–50 seconds to wake it up.



MediCrypt lets doctors upload medical images...

MediCrypt lets doctors upload medical images (X-ray / CT / MRI) that are
end-to-end encrypted, cryptographically signed, and shared with patients
(and other doctors) under role-based access control, with every access
recorded in an audit trail.

This is a **reference / academic-project implementation**. The cryptography
is real and correctly implemented (see "Security Design" below and the test
suite), but before any real clinical deployment you must address the items
in **"Threat Model \& Limitations"** — most importantly, private-key custody.

\---

## 1\. What it does

|Feature|How it's implemented|
|-|-|
|Confidentiality|AES-256-GCM authenticated encryption of every image|
|Key exchange|RSA-OAEP(SHA-256) — the one-time AES key is wrapped separately for each authorized recipient (hybrid encryption)|
|Authenticity|RSA-PSS(SHA-256) digital signature over SHA-256(plaintext), by the uploader|
|Tampering detection|AES-GCM's auth tag catches ciphertext bit-flips; signature re-verification on every decrypt catches metadata/record tampering|
|Access control|Roles: `admin`, `doctor`, `patient`. Decryption requires an explicit per-user RSA key grant — **admins do not get automatic decryption rights** (least privilege)|
|Sharing|A user who already has access can grant a new user access; the AES key is unwrapped with the sharer's private key and re-wrapped for the recipient — the raw key is never persisted|
|Audit trail|Every login, upload, view, download, share, access-denial, and tampering event is logged with actor, timestamp, and detail|

\---

## 2\. Architecture

```
┌────────────────┐        HTTPS/JSON         ┌─────────────────────┐
│  React (Vite)  │ ───────────────────────▶  │   FastAPI backend    │
│  frontend      │ ◀─────────────────────── │  (JWT-authenticated) │
└────────────────┘                            └──────────┬───────────┘
                                                          │
                                    ┌─────────────────────┼─────────────────────┐
                                    ▼                     ▼                     ▼
                            SQLAlchemy ORM        crypto\_utils.py        Filesystem
                          (SQLite / Postgres)   (AES-GCM / RSA-OAEP /   (encrypted
                          users, images,          RSA-PSS, via the       image blobs,
                          key grants, audit log    `cryptography` lib)   RSA key PEMs)
```

**Upload pipeline:** file bytes → SHA-256 hash → AES-256-GCM encrypt →
wrap AES key with patient's + doctor's RSA public keys → sign the hash with
the doctor's RSA private key → store ciphertext + metadata.

**Download pipeline:** look up the caller's key grant → RSA-unwrap the AES
key with the caller's private key → AES-GCM decrypt (tag mismatch = 409,
tamper logged) → recompute SHA-256 of the recovered plaintext → verify the
uploader's signature against it (mismatch = 409, tamper logged) → stream
the plaintext back only if both checks pass.

\---

## 3\. Project structure

```
medicrypt/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI app, CORS, router wiring
│   │   ├── config.py          # env-driven settings
│   │   ├── database.py        # SQLAlchemy engine/session
│   │   ├── models.py          # User, MedicalImage, ImageKeyGrant, AuditLog
│   │   ├── schemas.py         # Pydantic request/response models
│   │   ├── crypto\_utils.py    # AES-GCM / RSA-OAEP / RSA-PSS primitives
│   │   ├── auth.py            # JWT + bcrypt + role-based dependencies
│   │   ├── audit.py           # audit-log helper
│   │   └── routers/
│   │       ├── auth.py        # /auth/register, /auth/login
│   │       ├── images.py      # /images/... upload, list, download, share
│   │       └── audit.py       # /audit/...
│   ├── tests/
│   │   ├── test\_crypto.py     # pure crypto unit tests (no server needed)
│   │   └── test\_api.py        # full HTTP integration tests (TestClient)
│   ├── seed\_demo\_data.py      # creates demo admin/doctor/patient accounts
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── pages/ (Login, Register, Dashboard, ImageDetail, AdminAudit)
│   │   ├── api/ (axios client, AuthContext)
│   │   └── App.jsx, main.jsx, index.css
│   ├── package.json
│   ├── vite.config.js
│   ├── Dockerfile
│   └── .env.example
├── docker-compose.yml
└── README.md
```

\---

## 4\. Running it

### Option A — Docker Compose (recommended, one command)

```bash
git clone <your-fork-url> medicrypt
cd medicrypt
docker compose up --build
```

* Backend: http://localhost:8000 (interactive API docs at `/docs`)
* Frontend: http://localhost:5173

### Option B — Manual local dev

**Backend:**

```bash
cd backend
python3 -m venv venv \&\& source venv/bin/activate      # Windows: venv\\Scripts\\activate
pip install -r requirements.txt
cp .env.example .env                                   # edit JWT\_SECRET\_KEY etc.
python seed\_demo\_data.py                                # optional: creates demo accounts
uvicorn app.main:app --reload
```

API docs: http://localhost:8000/docs

**Frontend (separate terminal):**

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Open http://localhost:5173

### Demo accounts (after running `seed\_demo\_data.py`)

|Role|Email|Password|
|-|-|-|
|Admin|admin@medicrypt.demo|AdminPass123!|
|Doctor|doctor@medicrypt.demo|DoctorPass123!|
|Patient|patient@medicrypt.demo|PatientPass123!|

**Demo flow:** log in as the doctor → upload an image for `patient@medicrypt.demo`
→ log in as the patient → open the image → "Decrypt \& View" → check the
access-history table at the bottom. Log in as admin → open the same image →
click "Corrupt stored ciphertext" → log back in as the patient → try to
decrypt again → you'll get a tampering-detected error, logged in the audit
trail in real time.

\---

## 5\. Running the tests

```bash
cd backend
pip install -r requirements.txt pytest --break-system-packages
pytest tests/ -v
```

`test\_crypto.py` exercises the cryptography in isolation (key generation,
AES-GCM round-trip, tamper detection, RSA wrapping, signatures — no server
needed). `test\_api.py` drives the full HTTP API with FastAPI's `TestClient`
against an isolated temp SQLite DB, covering: register/login, full
upload→download round-trip, tamper-then-download (expects 409), patient
cross-access denial, and admin-without-grant denial.

\---

## 6\. API reference (see also the live Swagger UI at `/docs`)

|Method|Path|Role|Description|
|-|-|-|-|
|POST|`/auth/register`|any|Create account (auto-generates the user's RSA keypair)|
|POST|`/auth/login`|any|Returns a JWT access token|
|POST|`/images/upload`|doctor, admin|Encrypt + sign + store an image for a patient|
|GET|`/images/`|any|List images the caller may access (metadata only)|
|GET|`/images/{id}`|with access|Image metadata|
|GET|`/images/{id}/download`|with key grant|Decrypt, verify, stream plaintext image|
|POST|`/images/{id}/share`|with key grant|Grant another user decryption access|
|POST|`/images/{id}/simulate-tamper`|admin|Demo-only: corrupts the stored ciphertext|
|GET|`/audit/`|admin|Full system audit trail|
|GET|`/audit/image/{id}`|with access|Access history for one image|

\---

## 7\. Security design notes

* **No home-grown crypto.** Everything goes through `cryptography` (pyca),
the standard, audited Python crypto library — AES-GCM, RSA-OAEP, RSA-PSS.
* **Hybrid encryption.** Images are encrypted once with a random AES-256
key; only that small key is RSA-wrapped per recipient, which is the
standard, efficient pattern for encrypting large payloads for multiple
recipients (RSA alone can't directly encrypt arbitrary-length data).
* **Authenticated encryption.** AES-**GCM** (not CBC) is used specifically
so that any bit-flip in the stored ciphertext is cryptographically
detected on decrypt (`InvalidTag`), rather than silently producing
corrupted output.
* **Non-repudiation / provenance.** The RSA-PSS signature proves the image
hash was produced by a specific uploader's private key and hasn't been
swapped or altered since — this is what "digital signature-based
authenticity" means in the original spec.
* **Least privilege.** Admins can manage accounts and read the full audit
log, but are **not** automatically granted decryption rights over patient
images — they'd need an explicit key grant, same as anyone else. This is
a deliberate design choice, not an oversight.

## 8\. Threat model \& limitations (read before any real deployment)

This is a teaching/portfolio-grade reference implementation. Known gaps to
address before production/clinical use:

1. **Private key custody.** For simplicity, RSA private keys are generated
server-side and stored unencrypted on disk (`backend/storage/keys/`).
In a real system, private keys should either be encrypted at rest with
a key derived from the user's password (PBKDF2/Argon2 + envelope
encryption) or, better, generated and held **client-side only**
(WebCrypto in-browser, or a hardware token/HSM), so the server never
sees them. This is the single most important change for a production
system, since anyone with server/disk access currently could decrypt
any image.
2. **Transport security.** Run behind HTTPS/TLS in any real deployment —
docker-compose here is HTTP-only for local development.
3. **JWT secret \& expiry.** Rotate `JWT\_SECRET\_KEY` regularly and tune
`ACCESS\_TOKEN\_EXPIRE\_MINUTES`; add refresh tokens for a production UX.
4. **Database.** SQLite is the zero-setup default; switch
`DATABASE\_URL` to Postgres (a commented example is in
`docker-compose.yml`) and use Alembic migrations for schema changes in
production instead of `Base.metadata.create\_all`.
5. **Compliance.** Handling real patient data (PHI) requires HIPAA/GDPR
controls (BAAs, encryption-at-rest key management, breach notification
procedures, access minimization, etc.) well beyond this codebase's
scope.
6. **Rate limiting / brute force protection** on `/auth/login` is not
implemented here and should be added (e.g. via a reverse proxy or
`slowapi`).

## 9\. Suggested extensions (mentioned in the original spec)

* **Disease classification on decrypted images**: add an
`ml/` module (e.g. a small CNN via `torch`/`tensorflow`) that runs
inference on the plaintext right after successful decryption, and store
the prediction alongside the audit log entry — deliberately kept out of
this reference build so the security core stays auditable on its own.
* **Algorithm performance comparison**: the `crypto\_utils.py` functions are
isolated enough to benchmark directly, e.g. compare RSA-2048 vs. an ECC
(X25519/ECIES) key-exchange variant for latency, or AES-GCM vs.
ChaCha20-Poly1305 for throughput on large DICOM files.

\---

## 10\. Publishing to GitHub

```bash
cd medicrypt
git init
git add .
git commit -m "Initial commit: MediCrypt secure medical image sharing system"
git branch -M main
git remote add origin https://github.com/<your-username>/medicrypt.git
git push -u origin main
```

The `.gitignore` already excludes the local SQLite DB, generated RSA keys,
and encrypted image blobs, so you won't accidentally commit runtime/demo
data or key material.

\---

## License

MIT — use freely for academic, portfolio, or research purposes. See
"Threat Model \& Limitations" before any real-world clinical use.

