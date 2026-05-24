// =============================================================================
// popup.js — UI logic for the extension popup
// Communicates with background.js via chrome.runtime.sendMessage.
// =============================================================================

const scanBtn        = document.getElementById('scanBtn');
const retryBtn       = document.getElementById('retryBtn');
const loadingEl      = document.getElementById('loading');
const errorEl        = document.getElementById('error');
const errorMsgEl     = document.getElementById('errorMsg');
const emailListEl    = document.getElementById('emailList');
const lastScannedEl  = document.getElementById('lastScanned');
const emailCountEl   = document.getElementById('emailCount');

// ─── RISK BADGE CONFIG ────────────────────────────────────────────────────────
// Extend this map if you add new risk tiers (e.g. 'Critical').
const RISK_META = {
  Safe:      { emoji: '✅', className: 'badge-safe' },
  Caution:   { emoji: '⚠️', className: 'badge-caution' },
  Dangerous: { emoji: '🚨', className: 'badge-dangerous' },
};

// ─── UI STATE MACHINE ─────────────────────────────────────────────────────────
// States: 'idle' | 'loading' | 'error' | 'results'

function setState(state) {
  loadingEl.classList.toggle('hidden',   state !== 'loading');
  errorEl.classList.toggle('hidden',     state !== 'error');
  emailListEl.classList.toggle('hidden', state !== 'results');
  scanBtn.disabled = (state === 'loading');
}

// ─── RENDERING ────────────────────────────────────────────────────────────────

/**
 * Builds one email card <li> element.
 *
 * ── WHERE TO EXTEND THE UI ────────────────────────────────────────────────────
 * `result.analysis.reasons` is a string[] of triggered pattern labels.
 * You can render them as expandable detail rows, tooltips, or a modal.
 * `result.analysis.score` is the raw numeric score — useful for sorting.
 * ─────────────────────────────────────────────────────────────────────────────
 */
function buildEmailCard(result) {
  const { subject, from, date, snippet, analysis } = result;
  const { risk, reasons } = analysis;
  const meta = RISK_META[risk] ?? RISK_META.Safe;

  const li = document.createElement('li');
  li.className = 'email-card';

  const reasonPills = reasons.length
    ? `<div class="reasons" aria-label="Triggered patterns">
         ${reasons.map(r => `<span class="pill">${esc(r)}</span>`).join('')}
       </div>`
    : '';

  li.innerHTML = `
    <div class="card-top">
      <div class="card-meta">
        <span class="subject" title="${esc(subject)}">${esc(trunc(subject, 46))}</span>
        <span class="from"    title="${esc(from)}">${esc(trunc(from, 44))}</span>
      </div>
      <span class="badge ${meta.className}" role="status">
        ${meta.emoji} ${risk}
      </span>
    </div>
    <p class="snippet">${esc(trunc(snippet, 110))}</p>
    ${reasonPills}
  `;

  return li;
}

function renderResults(results) {
  emailListEl.innerHTML = '';

  if (!results.length) {
    emailListEl.innerHTML = '<li class="empty">No emails found in your inbox.</li>';
  } else {
    // Sort most dangerous first so high-risk items are immediately visible.
    const order = { Dangerous: 0, Caution: 1, Safe: 2 };
    results
      .slice()
      .sort((a, b) => order[a.analysis.risk] - order[b.analysis.risk])
      .forEach(r => emailListEl.appendChild(buildEmailCard(r)));
  }

  setState('results');
}

// ─── SCAN TRIGGER ─────────────────────────────────────────────────────────────

function triggerScan() {
  const count = Math.min(50, Math.max(1, parseInt(emailCountEl.value) || 10));
  emailCountEl.value = count;
  chrome.storage.local.set({ emailCount: count });

  loadingEl.querySelector('p').textContent = `Scanning your last ${count} email${count === 1 ? '' : 's'}…`;
  setState('loading');

  chrome.runtime.sendMessage({ action: 'SCAN_EMAILS', count }, response => {
    if (chrome.runtime.lastError) {
      showError(chrome.runtime.lastError.message);
      return;
    }
    if (!response?.success) {
      showError(response?.error || 'Unknown error during scan.');
      return;
    }
    lastScannedEl.textContent = `Last scan: ${new Date().toLocaleTimeString()}`;
    renderResults(response.results);
  });
}

function showError(msg) {
  errorMsgEl.textContent = msg;
  setState('error');
}

// ─── INIT ─────────────────────────────────────────────────────────────────────

scanBtn.addEventListener('click', triggerScan);
retryBtn.addEventListener('click', triggerScan);

// On popup open, restore saved count preference and last cached results.
chrome.storage.local.get(['lastScan', 'emailCount'], ({ lastScan, emailCount }) => {
  if (emailCount) emailCountEl.value = emailCount;
  if (lastScan?.results?.length) {
    const ageMin = Math.round((Date.now() - lastScan.timestamp) / 60_000);
    lastScannedEl.textContent = `Last scan: ${ageMin}m ago`;
    renderResults(lastScan.results);
  }
});

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function trunc(str, n) {
  return str && str.length > n ? str.slice(0, n) + '…' : str ?? '';
}
