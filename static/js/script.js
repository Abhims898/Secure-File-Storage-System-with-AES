document.addEventListener('DOMContentLoaded', function() {
    // Tab switching functionality
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabPanes = document.querySelectorAll('.tab-pane');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.getAttribute('data-tab');
            
            // Update active tab button
            tabButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            
            // Show active tab pane
            tabPanes.forEach(pane => pane.classList.remove('active'));
            document.getElementById(`${tabId}-tab`).classList.add('active');
            
            // Clear results
            document.getElementById('encrypt-result').className = 'result';
            document.getElementById('decrypt-result').className = 'result';
        });
    });
    
    // File upload functionality for encryption
    const encryptUploadArea = document.getElementById('encrypt-upload-area');
    const encryptFileInput = document.getElementById('encrypt-file');
    const encryptFileInfo = document.getElementById('encrypt-file-info');
    
    encryptUploadArea.addEventListener('click', () => {
        encryptFileInput.click();
    });
    
    encryptUploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        encryptUploadArea.style.borderColor = '#007bff';
        encryptUploadArea.style.background = '#f8f9fa';
    });
    
    encryptUploadArea.addEventListener('dragleave', () => {
        encryptUploadArea.style.borderColor = '#4facfe';
        encryptUploadArea.style.background = 'white';
    });
    
    encryptUploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        encryptUploadArea.style.borderColor = '#4facfe';
        encryptUploadArea.style.background = 'white';
        
        if (e.dataTransfer.files.length) {
            handleEncryptFileSelect(e.dataTransfer.files[0]);
        }
    });
    
    encryptFileInput.addEventListener('change', () => {
        if (encryptFileInput.files.length) {
            handleEncryptFileSelect(encryptFileInput.files[0]);
        }
    });
    
    // File upload functionality for decryption
    const decryptUploadArea = document.getElementById('decrypt-upload-area');
    const decryptFileInput = document.getElementById('decrypt-file');
    const decryptFileInfo = document.getElementById('decrypt-file-info');
    
    decryptUploadArea.addEventListener('click', () => {
        decryptFileInput.click();
    });
    
    decryptUploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        decryptUploadArea.style.borderColor = '#007bff';
        decryptUploadArea.style.background = '#f8f9fa';
    });
    
    decryptUploadArea.addEventListener('dragleave', () => {
        decryptUploadArea.style.borderColor = '#4facfe';
        decryptUploadArea.style.background = 'white';
    });
    
    decryptUploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        decryptUploadArea.style.borderColor = '#4facfe';
        decryptUploadArea.style.background = 'white';
        
        if (e.dataTransfer.files.length) {
            handleDecryptFileSelect(e.dataTransfer.files[0]);
        }
    });
    
    decryptFileInput.addEventListener('change', () => {
        if (decryptFileInput.files.length) {
            handleDecryptFileSelect(decryptFileInput.files[0]);
        }
    });
    
    // Password strength indicator
    const encryptPassword = document.getElementById('encrypt-password');
    const strengthBar = document.querySelector('.strength-bar');
    
    encryptPassword.addEventListener('input', () => {
        const password = encryptPassword.value;
        let strength = 0;
        
        if (password.length >= 8) strength += 25;
        if (password.length >= 12) strength += 25;
        if (/[A-Z]/.test(password)) strength += 25;
        if (/[0-9]/.test(password)) strength += 25;
        
        strengthBar.style.width = strength + '%';
        
        if (strength < 50) {
            strengthBar.style.background = '#dc3545';
        } else if (strength < 75) {
            strengthBar.style.background = '#ffc107';
        } else {
            strengthBar.style.background = '#28a745';
        }
    });
    
    // Encryption handler
    document.getElementById('encrypt-button').addEventListener('click', () => {
        const file = encryptFileInput.files[0];
        const password = encryptPassword.value;
        const resultDiv = document.getElementById('encrypt-result');
        
        if (!file) {
            showResult(resultDiv, 'Please select a file to encrypt', 'error');
            return;
        }
        
        if (!password) {
            showResult(resultDiv, 'Please enter an encryption password', 'error');
            return;
        }
        
        const formData = new FormData();
        formData.append('file', file);
        formData.append('password', password);
        
        fetch('/encrypt', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const downloadLink = `<a href="/download/${data.filename}" class="download-link"><i class="fas fa-download"></i> Download Encrypted File</a>`;
                showResult(resultDiv, `${data.message}<br>${downloadLink}`, 'success');
            } else {
                showResult(resultDiv, data.error, 'error');
            }
        })
        .catch(error => {
            showResult(resultDiv, 'An error occurred during encryption', 'error');
        });
    });
    
    // Decryption handler
    document.getElementById('decrypt-button').addEventListener('click', () => {
        const file = decryptFileInput.files[0];
        const password = document.getElementById('decrypt-password').value;
        const resultDiv = document.getElementById('decrypt-result');
        
        if (!file) {
            showResult(resultDiv, 'Please select a file to decrypt', 'error');
            return;
        }
        
        if (!password) {
            showResult(resultDiv, 'Please enter the decryption password', 'error');
            return;
        }
        
        const formData = new FormData();
        formData.append('file', file);
        formData.append('password', password);
        
        fetch('/decrypt', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const downloadLink = `<a href="/download/${data.filename}" class="download-link"><i class="fas fa-download"></i> Download Decrypted File</a>`;
                const metadata = `<div class="file-metadata">
                    <strong>Original Name:</strong> ${data.original_name}<br>
                    <strong>Encrypted At:</strong> ${new Date(data.timestamp).toLocaleString()}
                </div>`;
                showResult(resultDiv, `${data.message}<br>${downloadLink}${metadata}`, 'success');
            } else {
                showResult(resultDiv, data.error, 'error');
            }
        })
        .catch(error => {
            showResult(resultDiv, 'An error occurred during decryption', 'error');
        });
    });
    
    // Helper functions
    function handleEncryptFileSelect(file) {
        encryptFileInfo.textContent = `Selected file: ${file.name} (${formatFileSize(file.size)})`;
        encryptFileInfo.style.display = 'block';
    }
    
    function handleDecryptFileSelect(file) {
        if (!file.name.endsWith('.enc')) {
            alert('Please select a .enc file for decryption');
            return;
        }
        
        decryptFileInfo.textContent = `Selected file: ${file.name} (${formatFileSize(file.size)})`;
        decryptFileInfo.style.display = 'block';
    }
    
    function formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' bytes';
        else if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
        else return (bytes / 1048576).toFixed(2) + ' MB';
    }
    
    function showResult(element, message, type) {
        element.innerHTML = message;
        element.className = `result ${type}`;
    }
});