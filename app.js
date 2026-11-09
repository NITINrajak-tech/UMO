const form = document.querySelector('#scan-form');
const targetInput = document.querySelector('#target');
const scanButton = document.querySelector('#scan-button');
const notice = document.querySelector('#notice');
const results = document.querySelector('#results');
const emptyState = document.querySelector('#empty-state');
let latestReport = null;

document.querySelector('#today').textContent = new Intl.DateTimeFormat(undefined, {
  weekday: 'short', month: 'short', day: 'numeric', year: 'numeric',
}).format(new Date()).toUpperCase();

document.querySelectorAll('.example-target').forEach((button) => {
  button.addEventListener('click', () => {
    targetInput.value = button.dataset.target;
    targetInput.focus();
  });
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  notice.hidden = true;
  results.hidden = true;
  emptyState.hidden = false;
  scanButton.disabled = true;
  scanButton.querySelector('span:first-child').textContent = 'Scanning…';
  scanButton.querySelector('.button-arrow').textContent = '◌';
  scanButton.setAttribute('aria-busy', 'true');

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: targetInput.value }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || 'The scan could not be completed.');
    latestReport = payload;
    renderReport(payload);
    results.hidden = false;
    emptyState.hidden = true;
  } catch (error) {
    notice.textContent = error.message || 'Could not reach the local scanner. Restart the app and try again.';
    notice.hidden = false;
  } finally {
    scanButton.disabled = false;
    scanButton.querySelector('span:first-child').textContent = 'Run scan';
    scanButton.querySelector('.button-arrow').textContent = '↗';
    scanButton.removeAttribute('aria-busy');
  }
});

function renderReport(report) {
  document.querySelector('#result-host').textContent = report.target;
  document.querySelector('#scan-time').textContent = new Date(report.scanned_at).toLocaleTimeString([], {
    hour: '2-digit', minute: '2-digit',
  }).toUpperCase();
  for (const severity of ['high', 'medium', 'low', 'info']) {
    document.querySelector(`#count-${severity}`).textContent = report.counts[severity];
  }
  document.querySelector('#finding-count').textContent = `${report.findings.length} ITEMS`;
  document.querySelector('#port-count').textContent = `${report.open_ports.length} FOUND`;
  document.querySelector('#resolved-addresses').textContent = `RESOLVED ${report.resolved_addresses.join(', ')}`;

  const findings = document.querySelector('#findings-list');
  findings.replaceChildren(...report.findings.map((finding, index) => {
    const row = document.createElement('article');
    row.className = `finding-item severity-${finding.severity}`;
    row.style.animationDelay = `${Math.min(index * 35, 280)}ms`;
    const dot = document.createElement('span');
    dot.className = 'finding-dot';
    const copy = document.createElement('div');
    copy.className = 'finding-copy';
    const title = document.createElement('strong');
    title.textContent = finding.title;
    const detail = document.createElement('p');
    detail.textContent = finding.detail;
    copy.append(title, detail);
    const severity = document.createElement('span');
    severity.className = 'severity-label';
    severity.textContent = finding.severity;
    row.append(dot, copy, severity);
    return row;
  }));

  const ports = document.querySelector('#ports-list');
  if (!report.open_ports.length) {
    const empty = document.createElement('p');
    empty.className = 'no-ports';
    empty.textContent = 'No common ports responded.';
    ports.replaceChildren(empty);
    return;
  }
  ports.replaceChildren(...report.open_ports.map((entry, index) => {
    const row = document.createElement('div');
    row.className = 'port-row';
    row.style.animationDelay = `${Math.min(index * 35, 280)}ms`;
    const number = document.createElement('span');
    number.className = 'port-number';
    number.textContent = entry.port;
    const service = document.createElement('span');
    service.className = 'port-service';
    service.textContent = entry.service;
    const open = document.createElement('span');
    open.className = 'port-open';
    open.textContent = 'OPEN';
    row.append(number, service, open);
    return row;
  }));
}

document.querySelector('#export-button').addEventListener('click', () => {
  if (!latestReport) return;
  const file = new Blob([JSON.stringify(latestReport, null, 2)], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(file);
  link.download = `umo-${new Date(latestReport.scanned_at).toISOString().replaceAll(':', '-')}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});