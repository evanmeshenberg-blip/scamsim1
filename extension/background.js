// =============================================================================
// background.js — MV3 Service Worker
// Listens for messages from popup.js, orchestrates Gmail fetch + scam analysis.
// =============================================================================

import { fetchRecentEmails } from './gmailApi.js';
import { analyzeEmail }      from './scamAnalyzer.js';

// ─── MESSAGE ROUTER ───────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.action === 'SCAN_EMAILS') {
    scanEmails(message.count || 10)
      .then(sendResponse)
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.action === 'CHECK_EMAIL_RISK') {
    chrome.storage.local.get('lastScan', ({ lastScan }) => {
      // Gmail URLs expose the threadId; match on either id or threadId.
      const hit = lastScan?.results?.find(
        r => r.id === message.emailId || r.threadId === message.emailId
      );
      sendResponse(hit ? { risk: hit.analysis.risk, reasons: hit.analysis.reasons } : null);
    });
    return true;
  }
});

// ─── CORE SCAN LOGIC ─────────────────────────────────────────────────────────

/**
 * Fetches the most recent inbox emails, runs scam analysis on each, caches the
 * results in chrome.storage.local, then returns the enriched array to the caller.
 *
 * ── WHERE TO EXTEND ───────────────────────────────────────────────────────────
 * To add a server-side AI pass after local analysis:
 *
 *   const aiEnrichedResults = await Promise.all(
 *     results.map(r => enrichWithRemoteAI(r))   // your async function
 *   );
 *   return { success: true, results: aiEnrichedResults };
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */
async function scanEmails(count = 10) {
  const emails = await fetchRecentEmails(count);

  const results = emails.map(email => ({
    ...email,
    analysis: analyzeEmail(email),
  }));

  // Cache so the popup can display stale results instantly on re-open.
  await chrome.storage.local.set({
    lastScan: { results, timestamp: Date.now() },
  });

  return { success: true, results };
}
