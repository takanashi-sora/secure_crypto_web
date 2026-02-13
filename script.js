// Derive encryption key from password using PBKDF2
async function deriveKey(password, saltString = null) {
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);
    
    // Import password as key material
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        passwordData,
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
    );
    
    // Generate or use provided salt
    let salt;
    if (saltString) {
        // Decode salt from base64
        salt = Uint8Array.from(atob(saltString), c => c.charCodeAt(0));
    } else {
        // Generate random salt for encryption
        salt = crypto.getRandomValues(new Uint8Array(16));
    }
    
    // Derive actual encryption key
    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
    
    return { key, salt };
}

// Tab Switching
function switchTab(tabName, event) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-button').forEach(button => {
        button.classList.remove('active');
    });

    // Show selected tab
    document.getElementById(`${tabName}-tab`).classList.add('active');
    event.target.closest('.tab-button').classList.add('active');
}

// Toggle Password Visibility
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    input.type = input.type === 'password' ? 'text' : 'password';
}

// Password Strength Checker
function checkPasswordStrength(password) {
    const strengthDiv = document.getElementById('encrypt-strength');
    
    if (!password) {
        strengthDiv.textContent = '';
        strengthDiv.className = 'password-strength';
        return;
    }

    let strength = 0;
    const checks = {
        length: password.length >= 8,
        lowercase: /[a-z]/.test(password),
        uppercase: /[A-Z]/.test(password),
        numbers: /[0-9]/.test(password),
        special: /[^a-zA-Z0-9]/.test(password)
    };

    strength = Object.values(checks).filter(Boolean).length;

    if (strength <= 2) {
        strengthDiv.textContent = '⚠️ 弱密码 Weak Password';
        strengthDiv.className = 'password-strength weak';
    } else if (strength <= 4) {
        strengthDiv.textContent = '✓ 中等密码 Medium Password';
        strengthDiv.className = 'password-strength medium';
    } else {
        strengthDiv.textContent = '✓ 强密码 Strong Password';
        strengthDiv.className = 'password-strength strong';
    }
}

// Listen to password input
document.addEventListener('DOMContentLoaded', function() {
    const encryptPasswordInput = document.getElementById('encrypt-password');
    if (encryptPasswordInput) {
        encryptPasswordInput.addEventListener('input', function() {
            checkPasswordStrength(this.value);
        });
    }
});

// Encrypt Text using Web Crypto API
async function encryptText() {
    const input = document.getElementById('encrypt-input').value;
    const password = document.getElementById('encrypt-password').value;

    if (!input) {
        showNotification('请输入要加密的内容 Please enter content to encrypt', 'error');
        return;
    }

    if (!password) {
        showNotification('请输入密码 Please enter a password', 'error');
        return;
    }

    if (password.length < 8) {
        showNotification('密码至少需要8位 Password must be at least 8 characters', 'error');
        return;
    }

    try {
        // Show processing
        showNotification('正在加密... Encrypting...', 'info');

        // Convert password to key with random salt
        const { key, salt } = await deriveKey(password);
        
        // Generate random IV
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        // Encode the text
        const encoder = new TextEncoder();
        const data = encoder.encode(input);
        
        // Encrypt
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            data
        );
        
        // Combine salt, IV and encrypted data
        const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
        combined.set(salt);
        combined.set(iv, salt.length);
        combined.set(new Uint8Array(encrypted), salt.length + iv.length);
        
        // Convert to base64
        const base64 = btoa(String.fromCharCode(...combined));
        
        document.getElementById('encrypt-output').value = base64;
        document.getElementById('encrypt-output-section').style.display = 'block';
        
        showNotification('✓ 加密成功 Encryption successful!', 'success');
    } catch (error) {
        showNotification('加密失败 Encryption failed: ' + error.message, 'error');
    }
}

// Decrypt Text using Web Crypto API
async function decryptText() {
    const input = document.getElementById('decrypt-input').value;
    const password = document.getElementById('decrypt-password').value;

    if (!input) {
        showNotification('请输入要解密的内容 Please enter encrypted content', 'error');
        return;
    }

    if (!password) {
        showNotification('请输入密码 Please enter password', 'error');
        return;
    }

    try {
        // Show processing
        showNotification('正在解密... Decrypting...', 'info');

        // Decode from base64
        const combined = new Uint8Array(
            atob(input).split('').map(c => c.charCodeAt(0))
        );
        
        // Extract salt, IV and encrypted data
        const salt = combined.slice(0, 16);
        const iv = combined.slice(16, 28);
        const encrypted = combined.slice(28);
        
        // Convert salt to base64 string for deriveKey
        const saltBase64 = btoa(String.fromCharCode(...salt));
        
        // Convert password to key using the extracted salt
        const { key } = await deriveKey(password, saltBase64);
        
        // Decrypt
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encrypted
        );
        
        // Decode the text
        const decoder = new TextDecoder();
        const plaintext = decoder.decode(decrypted);

        document.getElementById('decrypt-output').value = plaintext;
        document.getElementById('decrypt-output-section').style.display = 'block';
        
        showNotification('✓ 解密成功 Decryption successful!', 'success');
    } catch (error) {
        showNotification('解密失败 Decryption failed: 密码错误或数据损坏 Invalid password or corrupted data', 'error');
        document.getElementById('decrypt-output').value = '';
    }
}

// Copy to Clipboard
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.value;

    if (!text) {
        showNotification('没有内容可复制 No content to copy', 'error');
        return;
    }

    // Modern clipboard API
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text)
            .then(() => {
                showNotification('✓ 已复制到剪贴板 Copied to clipboard!', 'success');
            })
            .catch(() => {
                // Fallback method
                fallbackCopy(element);
            });
    } else {
        // Fallback for older browsers
        fallbackCopy(element);
    }
}

// Fallback copy method
function fallbackCopy(element) {
    element.select();
    element.setSelectionRange(0, element.value.length);

    try {
        document.execCommand('copy');
        showNotification('✓ 已复制到剪贴板 Copied to clipboard!', 'success');
    } catch (error) {
        showNotification('复制失败 Copy failed', 'error');
    }
}

// Download Text
function downloadText(elementId, filename) {
    const text = document.getElementById(elementId).value;

    if (!text) {
        showNotification('没有内容可下载 No content to download', 'error');
        return;
    }

    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    
    link.href = url;
    link.download = filename;
    link.click();

    URL.revokeObjectURL(url);
    showNotification('✓ 下载成功 Download successful!', 'success');
}

// Clear Encrypt
function clearEncrypt() {
    document.getElementById('encrypt-input').value = '';
    document.getElementById('encrypt-password').value = '';
    document.getElementById('encrypt-output').value = '';
    document.getElementById('encrypt-output-section').style.display = 'none';
    document.getElementById('encrypt-strength').textContent = '';
    document.getElementById('encrypt-strength').className = 'password-strength';
    showNotification('✓ 已清除 Cleared', 'info');
}

// Clear Decrypt
function clearDecrypt() {
    document.getElementById('decrypt-input').value = '';
    document.getElementById('decrypt-password').value = '';
    document.getElementById('decrypt-output').value = '';
    document.getElementById('decrypt-output-section').style.display = 'none';
    showNotification('✓ 已清除 Cleared', 'info');
}

// Show Notification
function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `notification ${type} show`;

    setTimeout(() => {
        notification.classList.remove('show');
    }, 3000);
}

// Keyboard Shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + Enter to encrypt/decrypt
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        const activeTab = document.querySelector('.tab-content.active');
        if (activeTab.id === 'encrypt-tab') {
            encryptText();
        } else {
            decryptText();
        }
    }
});

// Prevent accidental page close with unsaved content
window.addEventListener('beforeunload', function(e) {
    const encryptInput = document.getElementById('encrypt-input').value;
    const decryptInput = document.getElementById('decrypt-input').value;
    
    if (encryptInput || decryptInput) {
        e.preventDefault();
        e.returnValue = '';
    }
});
