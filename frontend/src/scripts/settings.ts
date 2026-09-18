import { apiFetch, requireLogin, fetchCSRFToken as apiFetchCSRFToken, showMessage as setMessage } from '../lib/api';

requireLogin();
let csrfToken = '';

function showMessage(elementId: string, message: string, isError: boolean) {
  const el = document.getElementById(elementId);
  setMessage(el, message, isError);
  if (el) {
    setTimeout(() => { el.style.display = 'none'; }, 5000);
  }
}

async function init() {
  csrfToken = await apiFetchCSRFToken();
  await check2FAStatus();
  await loadLoginHistory();
  await loadHoneypotStats();
}

async function check2FAStatus() {
  try {
    const response = await apiFetch('/api/2fa/status');

    if (response.ok) {
      const data = await response.json();

      document.getElementById('totp-disabled')?.classList.add('hidden');
      document.getElementById('totp-setup')?.classList.add('hidden');
      document.getElementById('totp-enabled')?.classList.add('hidden');

      if (data.enabled) {
        document.getElementById('totp-enabled')?.classList.remove('hidden');
      } else if (data.setup_in_progress) {
        // Setup was started but not completed - let user start fresh
        document.getElementById('totp-disabled')?.classList.remove('hidden');
      } else {
        document.getElementById('totp-disabled')?.classList.remove('hidden');
      }
    } else {
      // Default to showing enable button on error
      document.getElementById('totp-disabled')?.classList.remove('hidden');
    }
  } catch (error) {
    console.error('Failed to check 2FA status:', error);
    document.getElementById('totp-disabled')?.classList.remove('hidden');
  }
}

document.getElementById('enable2faBtn')?.addEventListener('click', async () => {
  const password = prompt('Enter your password to secure the 2FA secret:');
  if (!password) {
    showMessage('enable2faMessage', 'Password is required', true);
    return;
  }

  try {
    const response = await apiFetch('/api/2fa/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        csrf_token: csrfToken,
        password: password
      })
    });

    const data = await response.json();

    if (response.ok) {
      document.getElementById('totp-disabled')?.classList.add('hidden');
      document.getElementById('totp-setup')?.classList.remove('hidden');
      const qrContainer = document.getElementById('qrCodeContainer');
      if (qrContainer && data.secret) {
        // Display the secret locally - no third-party QR service (would leak the secret)
        const otpauthUrl = data.qr_code || '';
        qrContainer.innerHTML = `
          <div style="text-align: center; padding: 20px; background: white; border-radius: 10px;">
            <p style="color: #666; margin-bottom: 10px; font-size: 13px;">Enter this secret manually in your authenticator app:</p>
            <div style="display: flex; align-items: center; justify-content: center; gap: 8px; margin-bottom: 15px;">
              <code style="background: #f0f0f0; padding: 10px 15px; border-radius: 5px; font-size: 16px; letter-spacing: 2px; font-weight: bold;">${data.secret}</code>
              <button type="button" id="copySecretBtn" style="padding: 8px 12px; font-size: 12px;">Copy</button>
            </div>
            <p style="color: #666; margin-bottom: 5px; font-size: 12px;">Or copy the otpauth:// link:</p>
            <div style="display: flex; align-items: center; justify-content: center; gap: 8px;">
              <code style="word-break: break-all; background: #f0f0f0; padding: 8px; border-radius: 5px; font-size: 10px; max-width: 90%;">${otpauthUrl}</code>
              <button type="button" id="copyUriBtn" style="padding: 8px 12px; font-size: 12px;">Copy</button>
            </div>
            <p style="margin-top: 12px; font-size: 11px; color: #999;">Your secret never leaves your browser or our server (encrypted at rest).</p>
          </div>
        `;

        function copyToClipboard(text: string, successMessage: string) {
          if (!navigator.clipboard) {
            showMessage('enable2faMessage', 'Clipboard not available in this browser', true);
            return;
          }
          navigator.clipboard.writeText(text).then(() => {
            showMessage('enable2faMessage', successMessage, false);
          }).catch(() => {
            showMessage('enable2faMessage', 'Failed to copy to clipboard', true);
          });
        }

        document.getElementById('copySecretBtn')?.addEventListener('click', () => {
          copyToClipboard(data.secret, 'Secret copied to clipboard');
        });

        document.getElementById('copyUriBtn')?.addEventListener('click', () => {
          copyToClipboard(otpauthUrl, 'otpauth:// link copied to clipboard');
        });
      }
    } else {
      showMessage('enable2faMessage', data.message, true);
    }
  } catch (error) {
    console.error('2FA setup error:', error);
    showMessage('enable2faMessage', 'Failed to setup 2FA', true);
  }
});

document.getElementById('verify2faBtn')?.addEventListener('click', async () => {
  const code = (document.getElementById('verifyCode') as HTMLInputElement).value;

  if (!code || code.length !== 6) {
    showMessage('verify2faMessage', 'Please enter a valid 6-digit code', true);
    return;
  }

  try {
    const response = await apiFetch('/api/2fa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ totp_code: code, csrf_token: csrfToken })
    });

    const data = await response.json();

    if (response.ok) {
      document.getElementById('totp-setup')?.classList.add('hidden');
      document.getElementById('totp-enabled')?.classList.remove('hidden');
      showMessage('verify2faMessage', '2FA enabled successfully!', false);
    } else {
      showMessage('verify2faMessage', data.message || 'Verification failed', true);
    }
  } catch (error) {
    showMessage('verify2faMessage', 'Verification failed', true);
  }
});

document.getElementById('disable2faBtn')?.addEventListener('click', async () => {
  const code = prompt('Enter your current 6-digit 2FA code to confirm disabling 2FA:');
  if (!code) return;
  if (code.length !== 6) {
    showMessage('disable2faMessage', 'Please enter a valid 6-digit code', true);
    return;
  }

  try {
    const response = await apiFetch('/api/2fa/disable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csrf_token: csrfToken, totp_code: code })
    });

    const data = await response.json();

    if (response.ok) {
      document.getElementById('totp-enabled')?.classList.add('hidden');
      document.getElementById('totp-disabled')?.classList.remove('hidden');
      showMessage('disable2faMessage', '2FA disabled', false);
    } else {
      showMessage('disable2faMessage', data.message || 'Failed to disable 2FA', true);
    }
  } catch (error) {
    showMessage('disable2faMessage', 'Failed to disable 2FA', true);
  }
});

async function loadLoginHistory() {
  try {
    const response = await apiFetch('/api/login-history');

    const history = await response.json();
    const container = document.getElementById('loginHistory');

    if (!container) return;

    if (history.length === 0) {
      container.innerHTML = '<p style="color: #999;">No login history</p>';
      return;
    }

    container.innerHTML = history.map((item: any) => `
      <div class="login-item">
        <div class="ip">🌐 ${item.ip_address}</div>
        <div class="date">📅 ${new Date(item.login_time).toLocaleString()}</div>
        <div class="device">💻 ${item.user_agent || 'Unknown device'}</div>
        ${item.new_device ? '<div class="new-device">🆕 New Device</div>' : ''}
      </div>
    `).join('');
  } catch (error) {
    console.error('Failed to load login history:', error);
  }
}

async function loadHoneypotStats() {
  try {
    const response = await apiFetch('/api/admin/honeypot-stats');

    const stats = await response.json();
    const container = document.getElementById('honeypotStats');

    if (!container) return;

    container.innerHTML = `
      <div class="stat-card">
        <div class="stat-value">${stats.total_attempts || 0}</div>
        <div class="stat-label">Bot Attempts</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${stats.unique_ips || 0}</div>
        <div class="stat-label">Unique IPs</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${stats.last_24h || 0}</div>
        <div class="stat-label">Last 24h</div>
      </div>
    `;
  } catch (error) {
    const statsContainer = document.getElementById('honeypotStats');
    if (statsContainer) {
      statsContainer.innerHTML = '<p style="color: #999;">Stats unavailable</p>';
    }
  }
}

init();
