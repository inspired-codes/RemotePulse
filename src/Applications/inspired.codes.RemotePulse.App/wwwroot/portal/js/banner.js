/**
 * Modular Announcement Banner Module
 * Fetches latest worker release metadata dynamically without requiring portal redeploy.
 */

export async function initAnnouncementBanner() {
  const banner = document.getElementById('announcementBanner');
  const closeBtn = document.getElementById('announcementCloseBtn');
  const textEl = document.getElementById('announcementText');
  const linkEl = document.getElementById('announcementLink');

  if (!banner) return;

  try {
    const res = await fetch('/downloads/worker-version.json');
    if (!res.ok) {
      banner.style.display = 'none';
      return;
    }

    const data = await res.json();
    if (!data || !data.version) {
      banner.style.display = 'none';
      return;
    }

    const storageKey = `rp_announcement_v${data.version}_dismissed`;
    let isDismissed = 'false';
    try {
      isDismissed = localStorage.getItem(storageKey);
    } catch (e) {}

    if (isDismissed === 'true') {
      banner.style.display = 'none';
      return;
    }

    // Populate dynamic text
    if (textEl) {
      const strong = document.createElement('strong');
      strong.textContent = data.title ? `${data.title}: ` : `RemotePulse Worker v${data.version} Released: `;
      textEl.replaceChildren(strong, document.createTextNode(data.message || 'Latest worker build is now available.'));
    }

    if (linkEl && data.link) {
      linkEl.href = data.link;
    }

    banner.style.display = 'block';

    if (closeBtn) {
      // Replace existing listener cleanly
      const newCloseBtn = closeBtn.cloneNode(true);
      closeBtn.parentNode.replaceChild(newCloseBtn, closeBtn);
      newCloseBtn.addEventListener('click', () => {
        banner.style.display = 'none';
        try {
          localStorage.setItem(storageKey, 'true');
        } catch (e) {}
      });
    }
  } catch (e) {
    // If offline, 404, or fetch fails, fail gracefully by hiding banner
    banner.style.display = 'none';
  }
}

export function resetAnnouncementBanner() {
  try {
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const key = localStorage.key(i);
      if (key && key.startsWith('rp_announcement_')) {
        localStorage.removeItem(key);
      }
    }
  } catch (e) {}
  const banner = document.getElementById('announcementBanner');
  if (banner) banner.style.display = 'block';
}
