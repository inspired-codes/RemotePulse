import { initTheme, setupThemeDropdown } from './theme.js';
import { initAnnouncementBanner } from './banner.js';
import { initTerminalTabs } from './terminal.js';
import { initHubStatusCheck } from './status.js';
import { initSupportReportForm } from './support-report.js';

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  setupThemeDropdown();
  initAnnouncementBanner();
  initTerminalTabs();
  initHubStatusCheck();
  initSupportReportForm();
});
