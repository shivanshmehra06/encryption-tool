// Encryption/Decryption functions
class CipherSafe {
    static encrypt(text, key, method = 'aes') {
        if (!text || !key) return null;
        
        try {
            switch (method.toLowerCase()) {
                case 'aes':
                    return this.aesEncrypt(text, key);
                case 'des':
                    return this.desEncrypt(text, key);
                case 'xor':
                    return this.xorEncrypt(text, key);
                default:
                    return this.aesEncrypt(text, key);
            }
        } catch (e) {
            console.error('Encryption error:', e);
            return null;
        }
    }
    
    static decrypt(text, key, method = 'aes') {
        if (!text || !key) return null;
        
        try {
            switch (method.toLowerCase()) {
                case 'aes':
                    return this.aesDecrypt(text, key);
                case 'des':
                    return this.desDecrypt(text, key);
                case 'xor':
                    return this.xorDecrypt(text, key);
                default:
                    return this.aesDecrypt(text, key);
            }
        } catch (e) {
            console.error('Decryption error:', e);
            return null;
        }
    }
    
    // AES Encryption (using Web Crypto API)
    static async aesEncrypt(text, key) {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('Web Crypto API not supported');
        }
        
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        
        // Derive key from password
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            encoder.encode(key),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const derivedKey = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );
        
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            derivedKey,
            data
        );
        
        // Combine salt, iv, and ciphertext
        const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
        combined.set(salt);
        combined.set(iv, salt.length);
        combined.set(new Uint8Array(encrypted), salt.length + iv.length);
        
        return btoa(String.fromCharCode.apply(null, combined));
    }
    
    // AES Decryption
    static async aesDecrypt(encrypted, key) {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('Web Crypto API not supported');
        }
        
        const encoder = new TextEncoder();
        
        // Decode base64
        const combined = new Uint8Array(atob(encrypted).split('').map(c => c.charCodeAt(0)));
        
        // Extract salt, iv, and ciphertext
        const salt = combined.slice(0, 16);
        const iv = combined.slice(16, 28);
        const ciphertext = combined.slice(28);
        
        // Derive key from password
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            encoder.encode(key),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        
        const derivedKey = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );
        
        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            derivedKey,
            ciphertext
        );
        
        return new TextDecoder().decode(decrypted);
    }
    
    // DES Encryption (simulated - Web Crypto doesn't support DES)
    static desEncrypt(text, key) {
        // Note: This is a simulated DES encryption for demo purposes
        // In a real application, you should use AES instead of DES
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const keyData = encoder.encode(key.padEnd(8, '0').slice(0, 8)); // DES uses 8-byte keys
        
        let result = '';
        for (let i = 0; i < data.length; i++) {
            const charCode = data[i] ^ keyData[i % keyData.length];
            result += String.fromCharCode(charCode);
        }
        
        return btoa(result);
    }
    
    // DES Decryption
    static desDecrypt(text, key) {
        try {
            const decoded = atob(text);
            const encoder = new TextEncoder();
            const keyData = encoder.encode(key.padEnd(8, '0').slice(0, 8));
            
            let result = '';
            for (let i = 0; i < decoded.length; i++) {
                const charCode = decoded.charCodeAt(i) ^ keyData[i % keyData.length];
                result += String.fromCharCode(charCode);
            }
            
            return result;
        } catch (e) {
            return null;
        }
    }
    
    // XOR Encryption (basic)
    static xorEncrypt(text, key) {
        let result = '';
        for (let i = 0; i < text.length; i++) {
            const charCode = text.charCodeAt(i) ^ key.charCodeAt(i % key.length);
            result += String.fromCharCode(charCode);
        }
        return btoa(result);
    }
    
    // XOR Decryption
    static xorDecrypt(text, key) {
        try {
            const decoded = atob(text);
            let result = '';
            for (let i = 0; i < decoded.length; i++) {
                const charCode = decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length);
                result += String.fromCharCode(charCode);
            }
            return result;
        } catch (e) {
            return null;
        }
    }
}

// UI Management
class CipherSafeUI {
    constructor() {
        this.initElements();
        this.initEventListeners();
        this.renderHistory();
    }
    
    initElements() {
        // Input fields
        this.encryptText = document.getElementById('encrypt-text');
        this.encryptKey = document.getElementById('encrypt-key');
        this.encryptMethod = document.getElementById('encrypt-method');
        this.decryptText = document.getElementById('decrypt-text');
        this.decryptKey = document.getElementById('decrypt-key');
        this.decryptMethod = document.getElementById('decrypt-method');
        
        // Buttons
        this.encryptBtn = document.getElementById('encrypt-btn');
        this.decryptBtn = document.getElementById('decrypt-btn');
        this.clearEncryptBtn = document.getElementById('clear-encrypt');
        this.clearDecryptBtn = document.getElementById('clear-decrypt');
        this.copyEncryptBtn = document.getElementById('copy-encrypt');
        this.copyDecryptBtn = document.getElementById('copy-decrypt');
        this.clearHistoryBtn = document.getElementById('clear-history');
        this.exportHistoryBtn = document.getElementById('export-history');
        this.importHistoryBtn = document.getElementById('import-history');
        this.historyFileInput = document.getElementById('history-file');
        
        // Alerts
        this.encryptAlert = document.getElementById('encrypt-alert');
        this.decryptAlert = document.getElementById('decrypt-alert');
        
        // History
        this.historyList = document.getElementById('history-list');
        
        // Password toggles
        this.togglePasswordBtns = document.querySelectorAll('.toggle-password');
    }
    
    initEventListeners() {
        // Encryption
        this.encryptBtn.addEventListener('click', () => this.handleEncrypt());
        this.clearEncryptBtn.addEventListener('click', () => this.clearEncrypt());
        this.copyEncryptBtn.addEventListener('click', () => this.copyResult('encrypt'));
        
        // Decryption
        this.decryptBtn.addEventListener('click', () => this.handleDecrypt());
        this.clearDecryptBtn.addEventListener('click', () => this.clearDecrypt());
        this.copyDecryptBtn.addEventListener('click', () => this.copyResult('decrypt'));
        
        // History
        this.clearHistoryBtn.addEventListener('click', () => this.clearHistory());
        this.exportHistoryBtn.addEventListener('click', () => this.exportHistory());
        this.importHistoryBtn.addEventListener('click', () => this.historyFileInput.click());
        this.historyFileInput.addEventListener('change', (e) => this.importHistory(e));
        
        // Password visibility toggles
        this.togglePasswordBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const targetId = e.target.getAttribute('data-target');
                const input = document.getElementById(targetId);
                if (input.type === 'password') {
                    input.type = 'text';
                    e.target.textContent = '👁️';
                } else {
                    input.type = 'password';
                    e.target.textContent = '👁️';
                }
            });
        });
    }
    
    async handleEncrypt() {
        const text = this.encryptText.value.trim();
        const key = this.encryptKey.value.trim();
        const method = this.encryptMethod.value;
        
        if (!text || !key) {
            this.showAlert(this.encryptAlert, 'Please enter both text and encryption key', false);
            return;
        }
        
        try {
            let encrypted;
            if (method === 'aes') {
                encrypted = await CipherSafe.aesEncrypt(text, key);
            } else {
                encrypted = CipherSafe.encrypt(text, key, method);
            }
            
            if (!encrypted) {
                throw new Error('Encryption failed');
            }
            
            this.decryptText.value = encrypted;
            this.saveToHistory('encrypt', text, key, method, encrypted);
            this.showAlert(this.encryptAlert, 'Text encrypted successfully!', true);
        } catch (e) {
            console.error('Encryption error:', e);
            this.showAlert(this.encryptAlert, 'Encryption failed. Please try again.', false);
        }
    }
    
    async handleDecrypt() {
        const text = this.decryptText.value.trim();
        const key = this.decryptKey.value.trim();
        const method = this.decryptMethod.value;
        
        if (!text || !key) {
            this.showAlert(this.decryptAlert, 'Please enter both encrypted text and decryption key', false);
            return;
        }
        
        try {
            let decrypted;
            if (method === 'aes') {
                decrypted = await CipherSafe.aesDecrypt(text, key);
            } else {
                decrypted = CipherSafe.decrypt(text, key, method);
            }
            
            if (!decrypted) {
                throw new Error('Decryption failed');
            }
            
            this.encryptText.value = decrypted;
            this.saveToHistory('decrypt', text, key, method, decrypted);
            this.showAlert(this.decryptAlert, 'Text decrypted successfully!', true);
        } catch (e) {
            console.error('Decryption error:', e);
            this.showAlert(this.decryptAlert, 'Decryption failed. Check your key and method.', false);
        }
    }
    
    clearEncrypt() {
        this.encryptText.value = '';
        this.encryptKey.value = '';
    }
    
    clearDecrypt() {
        this.decryptText.value = '';
        this.decryptKey.value = '';
    }
    
    copyResult(type) {
        const text = type === 'encrypt' ? this.decryptText.value : this.encryptText.value;
        if (!text) return;
        
        navigator.clipboard.writeText(text).then(() => {
            this.showAlert(
                type === 'encrypt' ? this.encryptAlert : this.decryptAlert,
                'Copied to clipboard!',
                true
            );
        });
    }
    
    showAlert(element, message, isSuccess) {
        element.textContent = message;
        element.className = `alert alert-${isSuccess ? 'success' : 'danger'}`;
        element.style.display = 'block';
        
        setTimeout(() => {
            element.style.display = 'none';
        }, 5000);
    }
    
    saveToHistory(operation, text, key, method, result) {
        const history = this.getHistory();
        const timestamp = new Date().toISOString();
        
        history.unshift({
            operation,
            originalText: text,
            key: '*'.repeat(key.length), // Don't store actual key
            method,
            result,
            timestamp
        });
        
        // Keep only the last 50 items
        if (history.length > 50) {
            history.pop();
        }
        
        localStorage.setItem('cipherSafeHistory', JSON.stringify(history));
        this.renderHistory();
    }
    
    getHistory() {
        return JSON.parse(localStorage.getItem('cipherSafeHistory') || []);
    }
    
    renderHistory() {
        const history = this.getHistory();
        this.historyList.innerHTML = '';
        
        if (history.length === 0) {
            this.historyList.innerHTML = '<p class="empty-history">No history yet. Your encrypted/decrypted messages will appear here.</p>';
            return;
        }
        
        history.forEach((item, index) => {
            const historyItem = document.createElement('div');
            historyItem.className = 'history-item';
            
            const title = document.createElement('h3');
            title.innerHTML = `
                <i class="icon ${item.operation === 'encrypt' ? 'lock' : 'unlock'}"></i>
                ${item.operation === 'encrypt' ? 'Encrypted' : 'Decrypted'} (${item.method.toUpperCase()})
            `;
            
            const originalText = document.createElement('p');
            originalText.innerHTML = `<strong>Original:</strong> ${this.truncateText(item.originalText)}`;
            
            const resultText = document.createElement('p');
            resultText.innerHTML = `<strong>Result:</strong> ${this.truncateText(item.result)}`;
            
            const meta = document.createElement('div');
            meta.className = 'meta';
            meta.innerHTML = `
                <span>Key: ${item.key}</span>
                <span>${new Date(item.timestamp).toLocaleString()}</span>
            `;
            
            const actions = document.createElement('div');
            actions.className = 'actions';
            actions.innerHTML = `
                <button class="btn btn-secondary" data-index="${index}">
                    <i class="icon load"></i> Load
                </button>
                <button class="btn btn-danger" data-index="${index}">
                    <i class="icon delete"></i> Delete
                </button>
            `;
            
            historyItem.appendChild(title);
            historyItem.appendChild(originalText);
            historyItem.appendChild(resultText);
            historyItem.appendChild(meta);
            historyItem.appendChild(actions);
            
            this.historyList.appendChild(historyItem);
        });
        
        // Add event listeners to history item buttons
        document.querySelectorAll('.history-item .btn-secondary').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const index = e.target.closest('button').getAttribute('data-index');
                this.loadHistoryItem(index);
            });
        });
        
        document.querySelectorAll('.history-item .btn-danger').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const index = e.target.closest('button').getAttribute('data-index');
                this.deleteHistoryItem(index);
            });
        });
    }
    
    truncateText(text, maxLength = 100) {
        if (text.length <= maxLength) return text;
        return `${text.substring(0, maxLength)}...`;
    }
    
    loadHistoryItem(index) {
        const history = this.getHistory();
        const item = history[index];
        
        if (item.operation === 'encrypt') {
            this.decryptText.value = item.result;
            this.decryptMethod.value = item.method;
            this.showAlert(this.decryptAlert, `Loaded encrypted text from history`, true);
        } else {
            this.encryptText.value = item.result;
            this.encryptMethod.value = item.method;
            this.showAlert(this.encryptAlert, `Loaded decrypted text from history`, true);
        }
    }
    
    deleteHistoryItem(index) {
        const history = this.getHistory();
        history.splice(index, 1);
        localStorage.setItem('cipherSafeHistory', JSON.stringify(history));
        this.renderHistory();
    }
    
    clearHistory() {
        if (confirm('Are you sure you want to clear all history? This cannot be undone.')) {
            localStorage.removeItem('cipherSafeHistory');
            this.renderHistory();
        }
    }
    
    exportHistory() {
        const history = this.getHistory();
        if (history.length === 0) {
            alert('No history to export');
            return;
        }
        
        const data = JSON.stringify(history, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `cipher-safe-history-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
    
    importHistory(event) {
        const file = event.target.files[0];
        if (!file) return;
        
        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const importedHistory = JSON.parse(e.target.result);
                if (!Array.isArray(importedHistory)) {
                    throw new Error('Invalid history file format');
                }
                
                // Merge with existing history
                const currentHistory = this.getHistory();
                const newHistory = [...importedHistory, ...currentHistory].slice(0, 50);
                
                localStorage.setItem('cipherSafeHistory', JSON.stringify(newHistory));
                this.renderHistory();
                alert(`Successfully imported ${importedHistory.length} history items`);
            } catch (e) {
                console.error('Import error:', e);
                alert('Failed to import history. The file may be corrupted or in the wrong format.');
            }
        };
        reader.readAsText(file);
        event.target.value = ''; // Reset file input
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    const cipherSafeUI = new CipherSafeUI();
    
    // Check for Web Crypto API support
    if (!window.crypto || !window.crypto.subtle) {
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-danger';
        alertDiv.style.margin = '10px';
        alertDiv.textContent = 'Warning: Your browser does not support Web Crypto API. AES encryption will not work.';
        document.body.insertBefore(alertDiv, document.body.firstChild);
    }
});
