import os
import json
import base64
import time
from dataclasses import dataclass
from typing import Tuple, Dict, Any

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD = b"SFSS_v1"  # Additional Authenticated Data for domain separation

def _get_master_key() -> bytes:
    """Return 32-byte AES-256 master key from env MASTER_KEY_B64 (Base64)."""
    b64 = os.getenv("MASTER_KEY_B64", "").strip()
    if not b64:
        raise RuntimeError("MASTER_KEY_B64 is not set. Generate a 32-byte key and base64-encode it.")
    try:
        raw = base64.urlsafe_b64decode(b64)
    except Exception as e:
        raise RuntimeError("MASTER_KEY_B64 is not valid base64") from e
    if len(raw) != 32:
        raise RuntimeError(f"MASTER_KEY_B64 must decode to 32 bytes, got {len(raw)}")
    return raw

def _hkdf(master_key: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"sfss-file-key",
    )
    return hkdf.derive(master_key)

def sha256(data: bytes) -> str:
    from hashlib import sha256 as _s
    return _s(data).hexdigest()

@dataclass
class EncryptedPackage:
    version: int
    salt_b64: str
    nonce_b64: str
    ciphertext_b64: str  # AES-GCM ciphertext (includes tag)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, separators=(",", ":"))

    @staticmethod
    def from_json(s: str) -> "EncryptedPackage":
        obj = json.loads(s)
        return EncryptedPackage(**obj)

def encrypt_blob(filename: str, data: bytes) -> Tuple[EncryptedPackage, Dict[str, Any]]:
    """Encrypt bytes and return (package, metadata)."""
    master = _get_master_key()
    salt = os.urandom(16)
    file_key = _hkdf(master, salt)
    aes = AESGCM(file_key)
    nonce = os.urandom(12)

    metadata = {
        "filename": filename,
        "stored_at": int(time.time()),
        "algo": "AES-256-GCM",
        "hash": sha256(data),
    }
    inner = json.dumps(metadata, separators=(",", ":")).encode("utf-8") + b"\0" + data
    ct = aes.encrypt(nonce, inner, AAD)

    pkg = EncryptedPackage(
        version=1,
        salt_b64=base64.urlsafe_b64encode(salt).decode(),
        nonce_b64=base64.urlsafe_b64encode(nonce).decode(),
        ciphertext_b64=base64.urlsafe_b64encode(ct).decode(),
    )
    return pkg, metadata

def decrypt_blob(blob: bytes) -> Tuple[bytes, Dict[str, Any]]:
    """Accept raw .enc bytes, return (plaintext, metadata)."""
    pkg = EncryptedPackage.from_json(blob.decode("utf-8"))
    salt = base64.urlsafe_b64decode(pkg.salt_b64)
    nonce = base64.urlsafe_b64decode(pkg.nonce_b64)
    ct = base64.urlsafe_b64decode(pkg.ciphertext_b64)

    master = _get_master_key()
    file_key = _hkdf(master, salt)
    aes = AESGCM(file_key)
    inner = aes.decrypt(nonce, ct, AAD)  # raises InvalidTag on tamper

    try:
        meta_json, file_bytes = inner.split(b"\0", 1)
    except ValueError:
        raise ValueError("Corrupted package format")

    metadata = json.loads(meta_json.decode("utf-8"))
    from hashlib import sha256 as _s
    digest = _s(file_bytes).hexdigest()
    if digest != metadata.get("hash"):
        raise ValueError("Hash mismatch: file tampered or corrupted")
    return file_bytes, metadata
