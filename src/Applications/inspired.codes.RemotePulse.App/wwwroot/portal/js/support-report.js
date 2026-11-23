/**
 * Support & bug report form submission. Stage A extraction from portal.html's
 * inline script — same payload shape and behavior, wired via addEventListener
 * instead of inline onsubmit=.
 */
export function initSupportReportForm() {
  const form = document.getElementById('supportReportForm');
  if (!form) return;

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const btn = document.getElementById('reportSubmitBtn');
    const statusEl = document.getElementById('reportStatus');
    const msgInput = document.getElementById('reportMessage');
    const machineIdInput = document.getElementById('reportMachineId');
    const contactInput = document.getElementById('reportContact');

    const msg = msgInput.value.trim();
    const machineId = machineIdInput.value.trim();
    const contact = contactInput.value.trim();

    if (!msg) return;

    btn.disabled = true;
    btn.style.opacity = '0.7';
    btn.innerText = 'Transmitting...';
    statusEl.innerText = '';

    const payload = {
      source: 'Web',
      message: msg,
      machineId: machineId || null,
      detailsJson: JSON.stringify({
        contact: contact || null,
        userAgent: navigator.userAgent,
        submittedAt: new Date().toISOString()
      })
    };

    fetch('/api/support/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
      .then(res => {
        if (res.ok) {
          statusEl.style.color = 'var(--emerald)';
          statusEl.innerText = '✓ Report received successfully. Thank you!';
          form.reset();
        } else if (res.status === 429) {
          statusEl.style.color = '#f87171';
          statusEl.innerText = '⚠ Rate limit exceeded. Please wait a moment before trying again.';
        } else {
          statusEl.style.color = '#f87171';
          statusEl.innerText = `⚠ Submission failed (HTTP ${res.status}).`;
        }
      })
      .catch(err => {
        statusEl.style.color = '#f87171';
        statusEl.innerText = `⚠ Could not reach Hub: ${err.message}`;
      })
      .finally(() => {
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.innerHTML = '<span>🚀</span> Send';
      });
  });
}
