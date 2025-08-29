# Secure File Storage with AES-256

## Features
- AES-256 GCM encryption with per-file keys derived from MASTER_KEY_B64
- Metadata (original filename, SHA256, timestamp) protected inside ciphertext
- Upload & encrypt, download & decrypt via Flask web UI
- Integrity verification with SHA-256 after decryption

## Local Run
```bash
pip install -r requirements.txt
export MASTER_KEY_B64=$(python -c 'import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')
export FLASK_SECRET=$(python -c 'import os,base64;print(base64.urlsafe_b64encode(os.urandom(16)).decode())')
python app.py
```
Open [http://localhost:8000](http://localhost:8000)

## Deploy on Render
- Upload this repo or push to GitHub and connect to Render
- Set `MASTER_KEY_B64` as a secret env var
- Service auto-starts with `gunicorn app:app`
