/**
 * Theme Management Module (Light, Dark, High-Contrast)
 * Persisted in localStorage, matches Microsoft Learn pattern.
 */

const THEME_STORAGE_KEY = 'rp_theme_preference';

export function initTheme() {
  let theme = 'dark'; // Default to dark for RemotePulse
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    if (/^(light|dark|high-contrast)$/.test(stored)) {
      theme = stored;
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
      theme = 'light';
    }
  } catch (e) {
    // Fallback if localStorage is inaccessible
  }
  
  applyTheme(theme);
}

export function applyTheme(theme) {
  const root = document.documentElement;
  root.classList.remove('theme-light', 'theme-dark', 'theme-high-contrast');
  root.classList.add(`theme-${theme}`);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch (e) {}

  // Update theme button label & options
  const themeLabel = document.getElementById('currentThemeLabel');
  if (themeLabel) {
    themeLabel.textContent = theme.charAt(0).toUpperCase() + theme.slice(1).replace('-', ' ');
  }

  document.querySelectorAll('.theme-option').forEach(opt => {
    opt.classList.toggle('active', opt.dataset.theme === theme);
  });
}

export function setupThemeDropdown() {
  const btn = document.getElementById('themeDropdownBtn');
  const menu = document.getElementById('themeDropdownMenu');

  if (!btn || !menu) return;

  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    menu.classList.toggle('active');
  });

  document.addEventListener('click', () => {
    menu.classList.remove('active');
  });

  document.querySelectorAll('.theme-option').forEach(opt => {
    opt.addEventListener('click', () => {
      const selected = opt.dataset.theme;
      applyTheme(selected);
      menu.classList.remove('active');
    });
  });
}
