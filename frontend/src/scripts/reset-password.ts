import { API_URL, showMessage as setMessage } from '../lib/api';

const requestForm = document.getElementById('requestForm') as HTMLFormElement;
const verifyForm = document.getElementById('verifyForm') as HTMLFormElement;
const requestSection = document.getElementById('requestSection') as HTMLDivElement;
const verifySection = document.getElementById('verifySection') as HTMLDivElement;
const messageEl = document.getElementById('message') as HTMLDivElement;

function showMessage(text: string, isError: boolean = false) {
  setMessage(messageEl, text, isError);
}

requestForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const email = (document.getElementById('email') as HTMLInputElement).value;
  const requestBtn = document.getElementById('requestBtn') as HTMLButtonElement;

  requestBtn.disabled = true;
  requestBtn.textContent = 'Sending...';

  try {
    const response = await fetch(`${API_URL}/api/password-reset/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });

    const data = await response.json();

    if (response.ok) {
      showMessage('Reset link sent! Check your email and enter the token below.', false);
      requestSection.style.display = 'none';
      verifySection.classList.add('active');
    } else {
      showMessage(data.message || 'Failed to send reset link', true);
    }
  } catch (error) {
    console.error('Request error:', error);
    showMessage('Network error. Please try again.', true);
  } finally {
    requestBtn.disabled = false;
    requestBtn.textContent = 'Send Reset Link';
  }
});

verifyForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const token = (document.getElementById('token') as HTMLInputElement).value;
  const newPassword = (document.getElementById('newPassword') as HTMLInputElement).value;
  const verifyBtn = document.getElementById('verifyBtn') as HTMLButtonElement;

  verifyBtn.disabled = true;
  verifyBtn.textContent = 'Resetting...';

  try {
    const response = await fetch(`${API_URL}/api/password-reset/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, new_password: newPassword })
    });

    const data = await response.json();

    if (response.ok) {
      showMessage('Password reset successful! Redirecting to login...', false);
      setTimeout(() => window.location.href = '/login', 2000);
    } else {
      showMessage(data.message || 'Failed to reset password', true);
    }
  } catch (error) {
    console.error('Verify error:', error);
    showMessage('Network error. Please try again.', true);
  } finally {
    verifyBtn.disabled = false;
    verifyBtn.textContent = 'Reset Password';
  }
});
