/**
 * Thin wrappers over the JSON API.
 *
 * Errors come back as RFC 9457 application/problem+json with a stable `code`.
 * Callers branch on the code, never on the text — the text is translated and
 * changes; the code does not.
 */

import { t } from './util.js';

const BASE = '/api/v1';

export class ApiError extends Error {
  constructor(code, status, detail, title) {
    super(detail || title || code);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.detail = detail || '';
    this.title = title || '';
  }
}

/** Thrown when the request never reached the server (offline, DNS, abort). */
export class NetworkError extends Error {
  constructor(cause) {
    super('network');
    this.name = 'NetworkError';
    this.code = 'network';
    this.cause = cause;
  }
}

async function request(path, init) {
  let res;
  try {
    res = await fetch(path, {
      credentials: 'same-origin',
      redirect: 'error',
      ...init,
    });
  } catch (err) {
    if (err && err.name === 'AbortError') throw err;
    throw new NetworkError(err);
  }

  if (!res.ok) {
    // A problem document is expected, but a proxy or a 502 page may return
    // anything at all, so failing to parse must not mask the status.
    let body = null;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    const code = (body && body.code) || statusToCode(res.status);
    throw new ApiError(code, res.status, body && body.detail, body && body.title);
  }

  if (res.status === 204) return null;
  return res.json();
}

function statusToCode(status) {
  if (status === 404) return 'not_found';
  if (status === 410) return 'already_revealed';
  if (status === 413) return 'payload_too_large';
  if (status === 429) return 'rate_limited';
  if (status === 503) return 'read_only';
  return 'internal';
}

function postJSON(path, body, init = {}) {
  return request(BASE + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    ...init,
  });
}

/** A human-readable message for any thrown error, in the current language. */
export function messageFor(err) {
  if (!err) return t('js.err.generic');
  if (err instanceof NetworkError) return t('js.err.network');
  const code = err.code;
  if (!code) return t('js.err.generic');
  const key = 'js.err.' + code;
  const msg = t(key);
  // t() echoes unknown keys back, which would put "js.err.foo" on the screen.
  return msg === key ? err.detail || t('js.err.generic') : msg;
}

// --- Sender ---------------------------------------------------------------

export function createSecret({ secret, ttlDays, passphrase }, init) {
  return postJSON(
    '/secret',
    {
      secret,
      ttl_days: ttlDays,
      ...(passphrase ? { passphrase } : {}),
    },
    init
  );
}

export function generatePassword({ length = 24, alphabet = 'symbols', ttlDays = 14 } = {}, init) {
  return postJSON(
    '/generate',
    {
      length,
      alphabet,
      ttl_days: ttlDays,
      // The generated value is only ever needed as a link.
      return_value: true,
    },
    init
  );
}

// --- Recipient ------------------------------------------------------------

/** Reads metadata without consuming the secret. Safe to call on page load. */
export function peek(key, init) {
  return postJSON('/peek', { key }, init);
}

/**
 * Consumes the secret. `confirm: true` is what separates a human click from a
 * link prefetcher, so it is never sent implicitly.
 */
export function reveal(key, { passphrase } = {}, init) {
  return postJSON(
    '/reveal',
    {
      key,
      confirm: true,
      ...(passphrase ? { passphrase } : {}),
    },
    init
  );
}

/**
 * Fetches the file with the one-shot ticket and returns a Blob. Done with
 * fetch rather than by navigating so that the ticket travels in a header and
 * never lands in a URL, a log or the history.
 */
export async function downloadFile(downloadURL, ticket) {
  let res;
  try {
    res = await fetch(downloadURL || BASE + '/download', {
      method: 'GET',
      credentials: 'same-origin',
      headers: { 'X-Onetime-Ticket': ticket },
    });
  } catch (err) {
    throw new NetworkError(err);
  }
  if (!res.ok) {
    let body = null;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    throw new ApiError(
      (body && body.code) || statusToCode(res.status),
      res.status,
      body && body.detail,
      body && body.title
    );
  }
  return res.blob();
}

// --- Receipt --------------------------------------------------------------

export function receipt(key, init) {
  return postJSON('/receipt', { key }, init);
}

export function burn(key, init) {
  return postJSON('/receipt/burn', { key, confirm: true }, init);
}
