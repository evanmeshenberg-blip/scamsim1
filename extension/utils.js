/**
 * Decodes a base64url string (Gmail uses base64url: `-` instead of `+`, `_` instead of `/`).
 * Falls back to raw atob() if the URI decode fails (e.g. pure ASCII content).
 */
export function decodeBase64Url(data) {
  const base64 = data.replace(/-/g, '+').replace(/_/g, '/');
  try {
    return decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join('')
    );
  } catch {
    return atob(base64);
  }
}

/**
 * Extracts a named header value from a Gmail message headers array.
 * Header name matching is case-insensitive per RFC 2822.
 */
export function getHeader(headers = [], name) {
  const h = headers.find(h => h.name.toLowerCase() === name.toLowerCase());
  return h ? h.value : '';
}

/**
 * Truncates a string to maxLength characters with a trailing ellipsis.
 */
export function truncate(str, maxLength = 120) {
  if (!str || str.length <= maxLength) return str ?? '';
  return str.slice(0, maxLength) + '…';
}

/**
 * Recursively walks a Gmail message payload tree to extract the first
 * plain-text body part. Handles both simple (body.data) and multipart
 * (parts[]) message structures.
 */
export function extractPlainText(payload) {
  if (!payload) return '';

  if (payload.mimeType === 'text/plain' && payload.body?.data) {
    return decodeBase64Url(payload.body.data);
  }

  if (payload.parts) {
    for (const part of payload.parts) {
      const text = extractPlainText(part);
      if (text) return text;
    }
  }

  // Last resort: decode whatever is in body.data regardless of MIME type
  if (payload.body?.data) {
    return decodeBase64Url(payload.body.data);
  }

  return '';
}
