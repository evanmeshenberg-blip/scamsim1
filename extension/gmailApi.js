// =============================================================================
// gmailApi.js — OAuth token acquisition + Gmail REST API helpers
// =============================================================================

import { getHeader, extractPlainText } from './utils.js';

const GMAIL_BASE = 'https://gmail.googleapis.com/gmail/v1/users/me';

// ─── AUTH ─────────────────────────────────────────────────────────────────────

/**
 * Acquires a Google OAuth 2.0 access token via the Chrome Identity API.
 * Launches an interactive consent screen the first time (or if token expired).
 * Subsequent calls return a cached token instantly.
 */
export function getAuthToken() {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive: true }, token => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(token);
      }
    });
  });
}

/**
 * Removes `token` from Chrome's cache and revokes it with Google.
 * Call this after receiving a 401 so the next getAuthToken() forces a fresh login.
 */
export function revokeAuthToken(token) {
  return new Promise(resolve => chrome.identity.removeCachedAuthToken({ token }, resolve));
}

// ─── LOW-LEVEL GMAIL FETCHERS ─────────────────────────────────────────────────

/**
 * Returns an array of the `maxResults` most recent inbox message IDs.
 * Throws 'AUTH_EXPIRED' if the token is stale (HTTP 401).
 */
async function listMessageIds(token, maxResults = 10) {
  const url = `${GMAIL_BASE}/messages?maxResults=${maxResults}&labelIds=INBOX`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (res.status === 401) {
    await revokeAuthToken(token);
    throw new Error('AUTH_EXPIRED');
  }
  if (!res.ok) throw new Error(`Gmail list failed (HTTP ${res.status})`);

  const data = await res.json();
  return (data.messages ?? []).map(m => m.id);
}

/**
 * Fetches one message by ID with automatic retry on 429 (rate-limit).
 * Respects the Retry-After header if present, otherwise backs off 1s then 3s.
 */
async function fetchMessageById(token, id, attempt = 0) {
  const url = `${GMAIL_BASE}/messages/${id}?format=full`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (res.status === 429 && attempt < 3) {
    const retryAfter = parseInt(res.headers.get('Retry-After') || '0', 10);
    const backoff    = retryAfter > 0 ? retryAfter * 1000 : (attempt + 1) * 1500;
    await delay(backoff);
    return fetchMessageById(token, id, attempt + 1);
  }

  if (!res.ok) throw new Error(`Gmail get failed for ${id} (HTTP ${res.status})`);
  return res.json();
}

/**
 * Fetches all `ids` in sequential batches of `batchSize`, with a `pauseMs`
 * gap between batches. Keeps total concurrent requests low enough to avoid
 * Gmail's per-user rate limit (250 quota units/sec; messages.get = 5 units).
 */
async function fetchInBatches(token, ids, batchSize = 5, pauseMs = 200) {
  const results = [];
  for (let i = 0; i < ids.length; i += batchSize) {
    const batch = ids.slice(i, i + batchSize);
    const batchResults = await Promise.all(batch.map(id => fetchMessageById(token, id)));
    results.push(...batchResults);
    if (i + batchSize < ids.length) await delay(pauseMs);
  }
  return results;
}

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// ─── PARSING ─────────────────────────────────────────────────────────────────

/**
 * Flattens a raw Gmail API message object into a plain, UI-ready struct.
 *
 * ── WHERE TO ADD EXTRACTION FIELDS ───────────────────────────────────────────
 * Need the Reply-To header? Add: replyTo: getHeader(headers, 'Reply-To')
 * Need all URLs? Run a regex over `body` here and attach as `links: string[]`.
 * ─────────────────────────────────────────────────────────────────────────────
 */
function parseMessage(raw) {
  const headers = raw.payload?.headers ?? [];
  return {
    id:       raw.id,
    threadId: raw.threadId,
    subject:  getHeader(headers, 'Subject') || '(No Subject)',
    from:     getHeader(headers, 'From')    || '(Unknown Sender)',
    date:     getHeader(headers, 'Date')    || '',
    snippet:  raw.snippet                   || '',
    body:     extractPlainText(raw.payload),
  };
}

// ─── PUBLIC API ───────────────────────────────────────────────────────────────

/**
 * Top-level helper: authenticates, fetches, and parses the N most recent
 * inbox emails. All message fetches run in parallel for speed.
 *
 * @param {number} count  Number of emails to fetch (default 10).
 * @returns {Promise<Array<{ id, subject, from, date, snippet, body }>>}
 */
export async function fetchRecentEmails(count = 10) {
  const token = await getAuthToken();
  const ids   = await listMessageIds(token, count);

  if (!ids.length) return [];

  const rawMessages = await fetchInBatches(token, ids);
  return rawMessages.map(parseMessage);
}
