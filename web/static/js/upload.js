/**
 * Multipart upload with progress.
 *
 * XMLHttpRequest rather than fetch: fetch still has no upload progress event,
 * and a 50 MB file on a phone connection without a progress bar looks like a
 * frozen page.
 */

import { ApiError, NetworkError } from './api.js';

/**
 * @param {object}   opts
 * @param {string}   opts.url         endpoint
 * @param {object}   opts.fields      scalar form fields
 * @param {File}     opts.file        the file, appended last
 * @param {Function} opts.onProgress  ({loaded, total, ratio, bytesPerSecond, secondsLeft})
 * @returns {{promise: Promise<object>, abort: Function}}
 */
export function uploadFile({ url, fields, file, onProgress }) {
  const xhr = new XMLHttpRequest();

  const form = new FormData();
  for (const [name, value] of Object.entries(fields || {})) {
    if (value !== undefined && value !== null && value !== '') {
      form.append(name, String(value));
    }
  }
  // Must be last: the server reads the scalar fields before it starts
  // streaming the body to disk, so it can reject an oversized or disallowed
  // upload without buffering it first.
  form.append('file', file, file.name);

  const started = Date.now();

  const promise = new Promise((resolve, reject) => {
    xhr.open('POST', url, true);
    xhr.responseType = 'text';
    xhr.withCredentials = false;

    if (xhr.upload && typeof onProgress === 'function') {
      xhr.upload.addEventListener('progress', (e) => {
        if (!e.lengthComputable) return;
        const elapsed = (Date.now() - started) / 1000;
        const bytesPerSecond = elapsed > 0 ? e.loaded / elapsed : 0;
        const secondsLeft = bytesPerSecond > 0 ? (e.total - e.loaded) / bytesPerSecond : NaN;
        onProgress({
          loaded: e.loaded,
          total: e.total,
          ratio: e.total > 0 ? e.loaded / e.total : 0,
          bytesPerSecond,
          secondsLeft,
        });
      });
    }

    xhr.addEventListener('load', () => {
      let body = null;
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        body = null;
      }

      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body);
        return;
      }
      reject(
        new ApiError(
          (body && body.code) || fallbackCode(xhr.status),
          xhr.status,
          body && body.detail,
          body && body.title
        )
      );
    });

    xhr.addEventListener('error', () => reject(new NetworkError()));
    xhr.addEventListener('timeout', () => reject(new NetworkError()));
    xhr.addEventListener('abort', () => {
      const err = new Error('aborted');
      err.name = 'AbortError';
      reject(err);
    });

    xhr.send(form);
  });

  return { promise, abort: () => xhr.abort() };
}

function fallbackCode(status) {
  if (status === 413) return 'payload_too_large';
  if (status === 403) return 'files_disabled';
  if (status === 429) return 'rate_limited';
  if (status === 503) return 'read_only';
  if (status === 507) return 'storage_full';
  return 'internal';
}
