// Update the encryption handler in static/js/script.js
document.getElementById('encrypt-button').addEventListener('click', async () => {
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
    
    // Show loading state
    const encryptButton = document.getElementById('encrypt-button');
    const originalText = encryptButton.innerHTML;
    encryptButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Encrypting...';
    encryptButton.disabled = true;
    
    try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('password', password);
        
        const response = await fetch('/encrypt', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            const downloadLink = `<a href="/download/${data.filename}" class="download-link" download="${file.name}.enc"><i class="fas fa-download"></i> Download Encrypted File</a>`;
            showResult(resultDiv, `${data.message}<br>${downloadLink}`, 'success');
        } else {
            showResult(resultDiv, data.error, 'error');
            console.error('Encryption error:', data.error);
        }
    } catch (error) {
        showResult(resultDiv, 'An error occurred during encryption. Please check the console for details.', 'error');
        console.error('Encryption request failed:', error);
    } finally {
        // Reset button state
        encryptButton.innerHTML = '<i class="fas fa-lock"></i> Encrypt File';
        encryptButton.disabled = false;
    }
});
