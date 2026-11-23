/**
 * Live Hub liveness check for the nav status badge. Stage A extraction from
 * portal.html's inline script — same behavior (silent no-op on failure, keeps
 * the default "Relay Active" text), just moved into a module.
 */
export function initHubStatusCheck() {
  fetch('/api/pairing/status/health', { method: 'GET' })
    .then(res => {
      const el = document.getElementById('hubStatusText');
      if (el && res.ok) {
        el.innerText = 'Relay Active';
      }
    })
    .catch(() => {
      // If offline or CORS restricted, retain default active indicator gracefully
    });
}
