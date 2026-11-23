/**
 * Terminal Interactive Snippet & Download Tab Module
 */
export function initTerminalTabs() {
  const tabs = document.querySelectorAll('.terminal-tab');
  const snippetElement = document.getElementById('terminalSnippet');
  const promptElement = document.getElementById('terminalPrompt');
  const copyBtn = document.getElementById('terminalCopyBtn');
  const codeView = document.getElementById('terminalCodeView');
  const downloadView = document.getElementById('terminalDownloadView');

  if (!tabs.length) return;

  const origin = window.location && window.location.origin
    ? window.location.origin.replace(/\/$/, '')
    : 'https://psrun.inspired.codes';

  const snippets = {
    powershell: `irm ${origin}/get-worker.ps1 | iex`,
    bash: `pwsh -c "irm ${origin}/get-worker.ps1 | iex"`
  };

  const prompts = {
    powershell: 'PS >',
    bash: '$'
  };

  // Set initial dynamic origin
  if (snippetElement && snippets.powershell) {
    snippetElement.textContent = snippets.powershell;
  }

  // Dynamically update SHA-256 hashes on download cards from worker-version.json
  fetch('/downloads/worker-version.json')
    .then(r => r.ok ? r.json() : null)
    .then(data => {
      if (!data) return;
      const winShaEl = document.getElementById('dlShaWindows');
      const linShaEl = document.getElementById('dlShaLinux');
      if (winShaEl && data.windowsSha256) {
        winShaEl.textContent = `SHA-256: ${data.windowsSha256}`;
      }
      if (linShaEl && data.linuxSha256) {
        linShaEl.textContent = `SHA-256: ${data.linuxSha256}`;
      }
    })
    .catch(() => {});

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      const os = tab.dataset.os;

      if (os === 'manual' || os === 'offline') {
        if (codeView) codeView.style.display = 'none';
        if (downloadView) downloadView.style.display = 'flex';
      } else {
        if (codeView) codeView.style.display = 'flex';
        if (downloadView) downloadView.style.display = 'none';

        if (snippets[os] && snippetElement) {
          snippetElement.textContent = snippets[os];
        }
        if (prompts[os] && promptElement) {
          promptElement.textContent = prompts[os];
        }
      }
    });
  });

  if (copyBtn && snippetElement) {
    copyBtn.addEventListener('click', async () => {
      const text = snippetElement.textContent;
      try {
        await navigator.clipboard.writeText(text);
        const originalText = copyBtn.textContent;
        copyBtn.textContent = 'Copied!';
        copyBtn.style.background = 'var(--emerald)';
        copyBtn.style.borderColor = 'var(--emerald)';
        copyBtn.style.color = '#ffffff';

        setTimeout(() => {
          copyBtn.textContent = originalText;
          copyBtn.style.background = '';
          copyBtn.style.borderColor = '';
          copyBtn.style.color = '';
        }, 2000);
      } catch (err) {
        console.error('Failed to copy: ', err);
      }
    });
  }
}

// Backward compatibility alias
export const initTerminal = initTerminalTabs;
