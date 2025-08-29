# Secure File Storage (AES‑256‑GCM)

A minimal Flask app that encrypts uploaded files using AES‑256‑GCM with per‑file keys derived via HKDF from a master key. 
Metadata (original filename, upload time, SHA‑256) is sealed inside the encrypted package. Integrity is validated with both GCM auth and a separate SHA‑256 check.

## Features
- AES‑256‑GCM with a 32‑byte master key (Base64 in `MASTER_KEY_B64`).
- Per‑file unique salt and nonce; per‑file key via HKDF.
- Encrypted package format (`.enc`) is JSON with Base64 fields.
- Independent SHA‑256 verification of plaintext to detect tampering.
- Simple UI: upload to encrypt/store, upload `.enc` to decrypt, list/download stored files.

## Quick Start (Local)
```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# Generate a 32‑byte master key:
python - <<'PY'
import os, base64
key = os.urandom(32)
print(base64.urlsafe_b64encode(key).decode())
PY
# Export it:
export MASTER_KEY_B64="paste-the-output-here"
# (Optional) Flask secret for session flash messages
export FLASK_SECRET="$(python -c 'import os,base64;print(base64.urlsafe_b64encode(os.urandom(16)).decode())')"
python app.py
# open http://localhost:8000
```

## Deploy to Render
1. Create a new **Web Service** from this repo (or upload zip).
2. Runtime: **Python**.
3. Build Command: `pip install -r requirements.txt`
4. Start Command: `gunicorn app:app`
5. Add an environment variable:
   - `MASTER_KEY_B64`: **required**. Base64 of a 32‑byte key (keep it secret; do not commit).
6. Deploy.

`render.yaml` is included so you can **Blueprint** the service.

## Security Notes
- Losing `MASTER_KEY_B64` means you cannot decrypt stored files.
- Rotating the master key breaks decryption of old files. If you need rotation, add a key id in the package header.
- GCM already authenticates; the extra SHA‑256 is defense‑in‑depth and to satisfy explicit "hash verification".
- The UI allows server‑side decryption for convenience; protect the service with authentication if hosting publicly.
- This is a sample; review and harden for production (auth, rate limits, size limits, logging, backups).

## File Format
```json
{
  "version": 1,
  "salt_b64": "...",
  "nonce_b64": "...",
  "ciphertext_b64": "..." // AES‑GCM over ( JSON(metadata) + 0x00 + PLAINTEXT )
}
```
