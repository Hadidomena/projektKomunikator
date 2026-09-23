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

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const token = getToken();
  const headers: Record<string, string> = { ...(options.headers as Record<string, string> || {}) };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return fetch(`${API_URL}${path}`, { ...options, headers });
}

export async function sendJSON(path: string, method: string, body: unknown): Promise<Response> {
  return apiFetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export async function fetchCSRFToken(): Promise<string> {
  try {
    const response = await apiFetch('/api/csrf-token');
    if (!response.ok) {
      console.error('Failed to fetch CSRF token:', response.status);
      return '';
    }
    const data = await response.json();
    return data.csrf_token || '';
  } catch (error) {
    console.error('Failed to fetch CSRF token:', error);
    return '';
  }
}

export function showMessage(el: HTMLElement | null, text: string, isError = false): void {
  if (!el) {
    return;
  }
  el.textContent = text;
  el.className = `message ${isError ? 'error' : 'success'}`;
  el.style.display = 'block';
}

export function messageBox(el: HTMLElement | null): (text: string, isError?: boolean) => void {
  return (text: string, isError = false) => showMessage(el, text, isError);
}
