import { API_URL, messageBox } from '../lib/api';
import { base64ToArrayBuffer, arrayBufferToBase64, derivePasswordKey } from '../lib/crypto';

const loginForm = document.getElementById('loginForm') as HTMLFormElement;
const loginBtn = document.getElementById('loginBtn') as HTMLButtonElement;
const messageEl = document.getElementById('message') as HTMLDivElement;
const totpSection = document.getElementById('totpSection') as HTMLDivElement;
const verifyTotpBtn = document.getElementById('verifyTotpBtn') as HTMLButtonElement;

const showMessage = messageBox(messageEl);

async function storeSession(data: any, email: string, password: string, successText: string) {
  localStorage.setItem('jwt_token', data.token);
  localStorage.setItem('user_email', email);
  localStorage.setItem('user_id', data.user_id);

  if (data.e2ee_public_key) {
    localStorage.setItem('e2ee_public_key', data.e2ee_public_key);
  }

  const encryptedPrivateKeyB64 = data.e2ee_private_key_encrypted || localStorage.getItem(`e2ee_private_key_${email}`);
  if (data.e2ee_private_key_encrypted) {
    localStorage.setItem(`e2ee_private_key_${email}`, data.e2ee_private_key_encrypted);
  }

  if (encryptedPrivateKeyB64) {
    try {
      const encryptedData = new Uint8Array(base64ToArrayBuffer(encryptedPrivateKeyB64));
      const salt = encryptedData.slice(0, 16);
      const iv = encryptedData.slice(16, 28);
      const ciphertext = encryptedData.slice(28);

      const aesKey = await derivePasswordKey(password, salt, ['decrypt']);
      const decryptedPrivateKey = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        aesKey,
        ciphertext
      );

      const privateKeyB64 = arrayBufferToBase64(decryptedPrivateKey);
      sessionStorage.setItem('e2ee_private_key_pkcs8', privateKeyB64);
      console.log('E2EE private key decrypted successfully');
    } catch (e) {
      console.error('Failed to decrypt E2EE private key:', e);
    }
  } else {
    console.warn('No E2EE private key available - encryption will not work');
  }

  showMessage(successText, false);
  setTimeout(() => window.location.href = '/dashboard', 1000);
}

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const email = (document.getElementById('email') as HTMLInputElement).value;
  const password = (document.getElementById('password') as HTMLInputElement).value;
  
  // Get honeypot field values (should be empty for real users)
  const website = (document.getElementById('website') as HTMLInputElement).value;
  const phone = (document.getElementById('phone') as HTMLInputElement).value;
  const middleName = (document.getElementById('middle_name') as HTMLInputElement).value;

  loginBtn.disabled = true;
  loginBtn.textContent = 'Logging in...';
  
  try {
    const response = await fetch(`${API_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        email, 
        password,
        website,
        phone,
        middle_name: middleName
      })
    });

    const data = await response.json();

    if (response.ok) {
      if (data.requires_totp) {
        totpSection.classList.add('active');
        (document.getElementById('email') as HTMLInputElement).disabled = true;
        (document.getElementById('password') as HTMLInputElement).disabled = true;
        loginBtn.disabled = true;
        loginBtn.textContent = '2FA Required';
        showMessage('Please enter your 2FA code', false);
        (document.getElementById('totpCode') as HTMLInputElement).focus();
      } else {
        await storeSession(data, email, password, 'Login successful! Redirecting...');
      }
    } else {
      showMessage(data.message || 'Login failed', true);
    }
  } catch (error) {
    console.error('Login error:', error);
    showMessage('Network error. Please try again.', true);
  } finally {
    loginBtn.disabled = false;
    loginBtn.textContent = 'Login';
  }
});

verifyTotpBtn.addEventListener('click', async () => {
  const totpCode = (document.getElementById('totpCode') as HTMLInputElement).value;
  
  if (!totpCode || totpCode.length !== 6) {
    showMessage('Please enter a valid 6-digit code', true);
    return;
  }

  verifyTotpBtn.disabled = true;
  verifyTotpBtn.textContent = 'Verifying...';

  try {
    const email = (document.getElementById('email') as HTMLInputElement).value;
    const password = (document.getElementById('password') as HTMLInputElement).value;

    const response = await fetch(`${API_URL}/api/2fa/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        password,
        totp_code: totpCode
      })
    });

    const data = await response.json();

    if (response.ok) {
      await storeSession(data, email, password, '2FA verification successful! Redirecting...');
    } else {
      showMessage(data.message || '2FA verification failed', true);
    }
  } catch (error) {
    console.error('2FA verification error:', error);
    showMessage('Network error. Please try again.', true);
  } finally {
    verifyTotpBtn.disabled = false;
    verifyTotpBtn.textContent = 'Verify 2FA';
  }
});
