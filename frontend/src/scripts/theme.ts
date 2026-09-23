const KEY = 'theme';

function currentTheme(): string {
  return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light';
}

function setTheme(theme: string): void {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem(KEY, theme);
}

for (const toggle of document.querySelectorAll<HTMLElement>('[data-theme-toggle]')) {
  toggle.addEventListener('click', () => {
    setTheme(currentTheme() === 'dark' ? 'light' : 'dark');
  });
}
