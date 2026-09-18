export const API_URL = '';

export function getToken(): string | null {
  return localStorage.getItem('jwt_token');
}

export function getEmail(): string | null {
  return localStorage.getItem('user_email');
}

export function requireLogin(): boolean {
  const token = getToken();
  const email = getEmail();
  if (!token || !email) {
    window.location.href = '/login';
    return false;
  }
  return true;
}

export async function fetchCSRFToken(): Promise<string> {
  const response = await fetch(`${API_URL}/api/csrf-token`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  if (!response.ok) {
    return '';
  }
  const data = await response.json();
  return data.csrf_token || '';
}

export function showMessage(el: HTMLElement | null, text: string, isError = false): void {
  if (!el) {
    return;
  }
  el.textContent = text;
  el.className = `message ${isError ? 'error' : 'success'}`;
  el.style.display = 'block';
}
