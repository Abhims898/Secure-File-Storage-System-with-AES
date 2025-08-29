# Secure File Storage System with AES

A web-based application for securely encrypting and decrypting files using AES-256 encryption.

## Features

- AES-256 encryption with CBC mode
- PBKDF2 key derivation with salt
- SHA-256 hash verification for integrity checking
- Secure metadata storage (filename, timestamp, hash)
- Modern, responsive web interface
- Drag and drop file uploads

## Deployment on Render

### Method 1: Using GitHub Repository
1. Fork or upload this repository to your GitHub account
2. Create a new Web Service on Render
3. Connect your GitHub repository
4. Use the following settings:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`
5. Click "Create Web Service"

### Method 2: Using Render Blueprint
1. Fork or upload this repository to your GitHub account
2. Ensure your repository includes the `render.yaml` file
3. Go to the Render Dashboard and click "New Blueprint Instance"
4. Connect your GitHub repository
5. Render will automatically detect the `render.yaml` file and configure the service

## Local Development

1. Clone the repository
2. Create a virtual environment: `python -m venv venv`
3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - macOS/Linux: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Run the application: `python app.py`
6. Open http://localhost:5000 in your browser

## Usage

1. **Encrypt a file**:
   - Select the "Encrypt File" tab
   - Drag and drop or click to select a file
   - Enter a strong password
   - Click "Encrypt File"
   - Download the encrypted file (.enc extension)

2. **Decrypt a file**:
   - Select the "Decrypt File" tab
   - Drag and drop or click to select a .enc file
   - Enter the decryption password
   - Click "Decrypt File"
   - Download the decrypted file

## Security Notes

- Passwords are not stored anywhere
- Each encryption generates a unique salt and IV
- Files are temporarily stored on the server during processing
- Always use strong, unique passwords for encryption
