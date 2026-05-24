(function () {
  'use strict';

  const HOST_ID = 'scam-scanner-host';
  let lastCheckedId = null;

  // ─── URL PARSING ─────────────────────────────────────────────────────────────
  // Gmail URL hash: #inbox/ID, #sent/ID, #spam/ID, #all/ID, etc.
  // The ID can be an old-style hex string or a newer longer base-62-like token.

  function getEmailIdFromUrl() {
    const match = window.location.hash.match(/#[a-z0-9_*]+\/([a-zA-Z0-9]+)/);
    return match ? match[1] : null;
  }

  // ─── RISK CHECK ───────────────────────────────────────────────────────────────

  function checkCurrentEmail() {
    const emailId = getEmailIdFromUrl();

    // No email open, or same email we already checked — clear any stale banner.
    if (!emailId) { removeWarning(); lastCheckedId = null; return; }
    if (emailId === lastCheckedId) return;
    lastCheckedId = emailId;

    try {
      chrome.runtime.sendMessage({ action: 'CHECK_EMAIL_RISK', emailId }, response => {
        if (chrome.runtime.lastError) return; // Extension was reloaded mid-session.
        removeWarning();
        if (response?.risk === 'Dangerous') showWarning(response.reasons ?? []);
      });
    } catch (_) {
      // Extension context invalidated — silently ignore until next page load.
    }
  }

  // ─── BANNER ───────────────────────────────────────────────────────────────────

  function removeWarning() {
    document.getElementById(HOST_ID)?.remove();
  }

  function showWarning(reasons) {
    removeWarning();

    // Shadow DOM keeps our styles completely isolated from Gmail's stylesheet.
    const host = document.createElement('div');
    host.id = HOST_ID;
    Object.assign(host.style, {
      position: 'fixed',
      top: '0',
      left: '0',
      width: '100%',
      zIndex: '2147483647',
    });

    const shadow = host.attachShadow({ mode: 'open' });

    const safeReasons = reasons.map(r =>
      r.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    );

    const pillsHtml = safeReasons.length
      ? `<div class="pills">${safeReasons.map(r => `<span class="pill">${r}</span>`).join('')}</div>`
      : '';

    shadow.innerHTML = `
      <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        .banner {
          display: flex;
          align-items: flex-start;
          gap: 14px;
          background: #7f1d1d;
          border-bottom: 3px solid #ef4444;
          color: #fff;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          font-size: 13px;
          line-height: 1.4;
          padding: 12px 18px;
          box-shadow: 0 3px 16px rgba(0,0,0,0.45);
          animation: slideDown 0.22s ease-out;
        }

        @keyframes slideDown {
          from { transform: translateY(-100%); opacity: 0; }
          to   { transform: translateY(0);     opacity: 1; }
        }

        .icon { font-size: 24px; flex-shrink: 0; padding-top: 1px; }

        .body { flex: 1; min-width: 0; }

        .title {
          font-size: 14px;
          font-weight: 700;
          margin-bottom: 3px;
        }

        .subtitle {
          font-size: 12px;
          color: #fca5a5;
          margin-bottom: 8px;
        }

        .pills {
          display: flex;
          flex-wrap: wrap;
          gap: 5px;
        }

        .pill {
          background: rgba(255,255,255,0.14);
          border: 1px solid rgba(255,255,255,0.28);
          border-radius: 999px;
          font-size: 11px;
          padding: 2px 9px;
          white-space: nowrap;
        }

        .actions {
          display: flex;
          flex-direction: column;
          gap: 6px;
          flex-shrink: 0;
          align-self: flex-start;
        }

        button {
          cursor: pointer;
          border-radius: 6px;
          font-size: 12px;
          font-weight: 600;
          padding: 5px 13px;
          white-space: nowrap;
          transition: background 0.15s;
        }

        .btn-dismiss {
          background: transparent;
          border: 1px solid rgba(255,255,255,0.45);
          color: #fff;
        }
        .btn-dismiss:hover { background: rgba(255,255,255,0.12); }
      </style>

      <div class="banner" role="alert" aria-live="assertive">
        <span class="icon" aria-hidden="true">🚨</span>
        <div class="body">
          <div class="title">Scam Scanner — Dangerous Email Detected</div>
          <div class="subtitle">This email matched patterns linked to phishing or scams. Do not click links or share personal information.</div>
          ${pillsHtml}
        </div>
        <div class="actions">
          <button class="btn-dismiss" id="btn-dismiss">Dismiss</button>
        </div>
      </div>
    `;

    shadow.getElementById('btn-dismiss').addEventListener('click', removeWarning);
    document.documentElement.appendChild(host);
  }

  // ─── NAVIGATION DETECTION ─────────────────────────────────────────────────────
  // Gmail is a SPA — intercept history API calls and hash changes.

  const _push    = history.pushState.bind(history);
  const _replace = history.replaceState.bind(history);

  history.pushState = function (...args) {
    _push(...args);
    setTimeout(checkCurrentEmail, 120);
  };
  history.replaceState = function (...args) {
    _replace(...args);
    setTimeout(checkCurrentEmail, 120);
  };

  window.addEventListener('popstate',   () => setTimeout(checkCurrentEmail, 120));
  window.addEventListener('hashchange', () => setTimeout(checkCurrentEmail, 120));

  // Initial check (user may have landed directly on an email URL).
  checkCurrentEmail();
})();
