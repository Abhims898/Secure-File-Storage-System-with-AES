import os
import json
import base64
import hashlib
import secrets
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# --- Key Handling ---
MASTER_KEY_B64 = os.environ.get("MASTER_KEY_B64")
if not MASTER_KEY_B64:
    if os.environ.get("RENDER"):  # Enforce secure key in Render
        raise RuntimeError("MASTER_KEY_B64 is not set. Please configure it in Render environment variables.")
    else:
        MASTER_KEY_B64 = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        print("[WARN] No MASTER_KEY_B64 set. Using ephemeral dev key. Files will NOT be decryptable later.")

MASTER_KEY = base64.urlsafe_b64decode(MASTER_KEY_B64)
if len(MASTER_KEY) != 32:
    raise ValueError("MASTER_KEY must decode to 32 bytes")

# --- Crypto Helpers ---
def derive_file_key(file_salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=file_salt,
        info=b"file-encryption",
        backend=default_backend()
    )
    return hkdf.derive(MASTER_KEY)

def encrypt_file(file_bytes: bytes, filename: str) -> (bytes, dict):
    file_salt = os.urandom(16)
    aes_key = derive_file_key(file_salt)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, file_bytes, None)
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    metadata = {
        "filename": filename,
        "timestamp": datetime.utcnow().isoformat(),
        "hash": file_hash,
        "salt": base64.b64encode(file_salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
    }

    blob = {
        "metadata": metadata,
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }

    return json.dumps(blob).encode(), metadata

def decrypt_file(enc_bytes: bytes) -> (bytes, dict):
    blob = json.loads(enc_bytes.decode())
    metadata = blob["metadata"]
    ciphertext = base64.b64decode(blob["ciphertext"])
    file_salt = base64.b64decode(metadata["salt"])
    nonce = base64.b64decode(metadata["nonce"])

    aes_key = derive_file_key(file_salt)
    aesgcm = AESGCM(aes_key)
    file_bytes = aesgcm.decrypt(nonce, ciphertext, None)

    calc_hash = hashlib.sha256(file_bytes).hexdigest()
    if calc_hash != metadata["hash"]:
        raise ValueError("File integrity verification failed (hash mismatch)")

    return file_bytes, metadata
