from flask import Flask, render_template, request, send_file, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import json
import time
from datetime import datetime

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_data, password):
    # Generate random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    # Derive key from password
    key = derive_key(password, salt)
    
    # Encrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Apply padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    
    # Encrypt
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Calculate hash of original file for integrity verification
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(file_data)
    file_hash = digest.finalize()
    
    # Prepare metadata
    metadata = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'hash': base64.b64encode(file_hash).decode('utf-8'),
        'timestamp': datetime.now().isoformat()
    }
    
    # Combine metadata and encrypted data
    metadata_json = json.dumps(metadata).encode('utf-8')
    metadata_length = len(metadata_json).to_bytes(4, 'big')
    
    return metadata_length + metadata_json + encrypted_data

def decrypt_file(encrypted_data, password):
    try:
        # Extract metadata length
        metadata_length = int.from_bytes(encrypted_data[:4], 'big')
        
        # Extract metadata
        metadata_json = encrypted_data[4:4+metadata_length]
        metadata = json.loads(metadata_json.decode('utf-8'))
        
        # Extract encrypted content
        encrypted_content = encrypted_data[4+metadata_length:]
        
        # Decode salt and IV
        salt = base64.b64decode(metadata['salt'])
        iv = base64.b64decode(metadata['iv'])
        stored_hash = base64.b64decode(metadata['hash'])
        
        # Derive key from password
        key = derive_key(password, salt)
        
        # Decrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt and unpad
        decrypted_padded = decryptor.update(encrypted_content) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        # Verify integrity
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(decrypted_data)
        calculated_hash = digest.finalize()
        
        if calculated_hash != stored_hash:
            raise ValueError("Hash verification failed - file may have been tampered with")
        
        return decrypted_data, metadata
    
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        if 'file' not in request.files or 'password' not in request.form:
            return jsonify({'error': 'Missing file or password'}), 400
        
        file = request.files['file']
        password = request.form['password']
        
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        file_data = file.read()
        encrypted_data = encrypt_file(file_data, password)
        
        # Save encrypted file
        filename = f"encrypted_{int(time.time())}.enc"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        with open(filepath, 'wb') as f:
            f.write(encrypted_data)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'message': 'File encrypted successfully'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        if 'file' not in request.files or 'password' not in request.form:
            return jsonify({'error': 'Missing file or password'}), 400
        
        file = request.files['file']
        password = request.form['password']
        
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        encrypted_data = file.read()
        decrypted_data, metadata = decrypt_file(encrypted_data, password)
        
        # Get original filename if available
        original_filename = "decrypted_file"
        if file.filename.endswith('.enc'):
            original_filename = file.filename[:-4]
        
        # Save decrypted file temporarily
        filename = f"decrypted_{int(time.time())}_{original_filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        with open(filepath, 'wb') as f:
            f.write(decrypted_data)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'original_name': metadata.get('original_name', original_filename),
            'timestamp': metadata.get('timestamp', 'Unknown'),
            'message': 'File decrypted successfully'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>')
def download_file(filename):
    try:
        return send_file(
            os.path.join(app.config['UPLOAD_FOLDER'], filename),
            as_attachment=True
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 404

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
