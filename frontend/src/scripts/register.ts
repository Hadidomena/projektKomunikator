import { arrayBufferToBase64, derivePasswordKey } from '../lib/crypto';

let currentStrength: any = null;
const passwordInput = document.getElementById('password') as HTMLInputElement;
const strengthMeter = document.getElementById('strength-meter') as HTMLDivElement;
const strengthText = document.getElementById('strength-text') as HTMLDivElement;
const passwordDetails = document.getElementById('password-details') as HTMLDivElement;
const submitBtn = document.getElementById('submit-btn') as HTMLButtonElement;

// Debounce function to avoid too many API calls
function debounce(func: Function, wait: number) {
  let timeout: number;
  return function (...args: any[]) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

async function checkPasswordStrength(password: string) {
  if (password.length === 0) {
    strengthMeter.className = 'strength-meter';
    strengthText.textContent = '';
    passwordDetails.innerHTML = '';
    currentStrength = null;
    return;
  }

  try {
    const response = await fetch('/api/check-password-strength', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });

    if (response.ok) {
      const strength = await response.json();
      currentStrength = strength;
      
      strengthMeter.className = `strength-meter ${strength.level}`;
      strengthText.className = `strength-text ${strength.level}`;
      strengthText.textContent = strength.feedback;

      const detailsHTML = `
        <ul>
          <li class="${strength.length >= 12 ? 'check' : 'cross'}">
            ${strength.length >= 12 ? '✓' : '✗'} At least 12 characters
          </li>
          <li class="${strength.has_upper ? 'check' : 'cross'}">
            ${strength.has_upper ? '✓' : '✗'} Uppercase letters
          </li>
          <li class="${strength.has_lower ? 'check' : 'cross'}">
            ${strength.has_lower ? '✓' : '✗'} Lowercase letters
          </li>
          <li class="${strength.has_numbers ? 'check' : 'cross'}">
            ${strength.has_numbers ? '✓' : '✗'} Numbers
          </li>
          <li class="${strength.has_symbols ? 'check' : 'cross'}">
            ${strength.has_symbols ? '✓' : '✗'} Special symbols
          </li>
          <li class="${!strength.is_common ? 'check' : 'cross'}">
            ${!strength.is_common ? '✓' : '✗'} Not a common password
          </li>
        </ul>
      `;
      passwordDetails.innerHTML = detailsHTML;
    }
  } catch (error) {
    console.error('Error checking password strength:', error);
  }
}

const debouncedCheck = debounce(checkPasswordStrength, 300);
passwordInput.addEventListener('input', (e) => {
  debouncedCheck((e.target as HTMLInputElement).value);
});

(document.getElementById('register-form') as HTMLFormElement).addEventListener('submit', async (event) => {
  event.preventDefault();
  const username = (document.getElementById('username') as HTMLInputElement).value;
  const email = (document.getElementById('email') as HTMLInputElement).value;
  const password = passwordInput.value;
  const messageEl = document.getElementById('message') as HTMLParagraphElement;

  if (currentStrength && currentStrength.level === 'weak') {
    messageEl.textContent = 'Please choose a stronger password';
    messageEl.style.color = 'red';
    return;
  }

  submitBtn.disabled = true;
  submitBtn.textContent = 'Generating keys...';

  const website = (document.getElementById('website') as HTMLInputElement).value;

  try {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveBits']
    ) as CryptoKeyPair;
    
    const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const privateKeyPkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    
    const publicKeyB64 = arrayBufferToBase64(publicKeyRaw);
    
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const aesKey = await derivePasswordKey(password, salt, ['encrypt', 'decrypt']);
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedPrivateKey = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      privateKeyPkcs8
    );
    
    const stored = new Uint8Array(salt.length + iv.length + encryptedPrivateKey.byteLength);
    stored.set(salt, 0);
    stored.set(iv, salt.length);
    stored.set(new Uint8Array(encryptedPrivateKey), salt.length + iv.length);
    const privateKeyEncryptedB64 = arrayBufferToBase64(stored.buffer);
    
    submitBtn.textContent = 'Registering...';

    const response = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        username, 
        email, 
        password, 
        website,
        e2ee_public_key: publicKeyB64,
        e2ee_private_key_encrypted: privateKeyEncryptedB64
      }),
    });

    if (response.ok) {
      localStorage.setItem(`e2ee_private_key_${email}`, privateKeyEncryptedB64);
      localStorage.setItem('e2ee_public_key', publicKeyB64);
      
      messageEl.textContent = 'Registration successful! E2EE keys generated. Redirecting to login...';
      messageEl.style.color = 'green';
      setTimeout(() => {
        window.location.href = '/';
      }, 1500);
    } else {
      const error = await response.json();
      messageEl.textContent = `Registration failed: ${error.message}`;
      messageEl.style.color = 'red';
      submitBtn.disabled = false;
      submitBtn.textContent = 'Register';
    }
  } catch (error) {
    console.error('Registration error:', error);
    messageEl.textContent = 'An error occurred during registration.';
    messageEl.style.color = 'red';
    submitBtn.disabled = false;
    submitBtn.textContent = 'Register';
  }
});
