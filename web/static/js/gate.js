/**
 * Recipient flow for gate.gohtml.
 *
 * The decryption key is the URL fragment. Browsers never send a fragment to a
 * server, so the key reaches the API only in a request body that this code
 * builds — which is what keeps it out of server logs, proxy logs and referrers.
 *
 * Two rules shape everything here:
 *   1. Nothing is revealed without an explicit human click. GET on this page
 *      is inert, so a chat client's link preview cannot consume the secret.
 *   2. The secret is never placed in a live region and never read aloud
 *      automatically.
 */

import {
  $, t, show, hide, toggle, setText, plural, announce, alertNow,
  formatBytes, formatDateTime, isInAppBrowser, reducedMotion, onSubmitShortcut,
} from './util.js';
import { peek, reveal, downloadFile, messageFor, ApiError } from './api.js';
import { copyWithFeedback } from './clipboard.js';

export function init() {
  const loading = $('#gate-loading');
  const intro = $('#gate-intro');
  const passStep = $('#gate-pass');
  const revealed = $('#gate-revealed');
  const statusBox = $('#gate-status');

  const passWindowFails = Number(document.body.dataset.passFails) || 5;

  let key = readKey();
  let meta = null;
  // Filled in from /peek. Until then it is null and the counter stays hidden,
  // rather than announcing a number this page invented.
  let attemptsLeft = null;
  let busy = false;

  /**
   * The key lives after the "#". If it is missing the link was truncated
   * somewhere in a chat client or a mail composer — a common enough failure
   * that it gets its own explanation rather than a generic error.
   */
  function readKey() {
    const hash = window.location.hash || '';
    return hash.startsWith('#') ? hash.slice(1).trim() : hash.trim();
  }

  /** Drop the key from the address bar once it has been used. */
  function scrubFragment() {
    try {
      const url = window.location.pathname + window.location.search;
      window.history.replaceState(null, '', url);
    } catch {
      /* replaceState can throw in exotic embeddings; not worth failing over */
    }
  }

  function only(section) {
    [loading, intro, passStep, revealed, statusBox].forEach((el) => hide(el));
    show(section);
  }

  /** Render one of the dead ends from the catalog Go rendered into the page. */
  function showStatus(variant) {
    const entry =
      $(`#status-catalog [data-variant="${variant}"]`) ||
      $('#status-catalog [data-variant="server_error"]');

    if (!entry) {
      setText($('#gate-status-title'), t('js.err.generic'));
      only(statusBox);
      return;
    }

    setText($('#gate-status-title'), entry.querySelector('[data-title]').textContent);
    setText($('#gate-status-body'), entry.querySelector('[data-body]').textContent);

    const icon = $('#gate-status-icon');
    icon.className = 'status__icon status__icon--' + (entry.dataset.tone || 'muted');
    icon.innerHTML = '';
    const glyph = entry.querySelector('[data-icon] svg');
    if (glyph) icon.appendChild(glyph.cloneNode(true));

    // Some dead ends carry advice worth more than the headline — after an
    // unexpected read, that the password should be rotated.
    const more = $('#gate-status-more');
    const moreSummary = entry.querySelector('[data-more-summary]');
    const moreBody = entry.querySelector('[data-more-body]');
    if (more && moreSummary && moreBody) {
      setText($('#gate-status-more-summary'), moreSummary.textContent);
      setText($('#gate-status-more-body'), moreBody.textContent);
      show(more);
    } else if (more) {
      hide(more);
    }

    only(statusBox);
    alertNow(entry.querySelector('[data-title]').textContent);
  }

  /** Map an API error onto a dead end, or onto an inline message. */
  function handleError(err, inline) {
    const code = err && err.code;
    const terminal = [
      'not_found', 'already_revealed', 'burned', 'destroyed',
      'too_many_attempts', 'expired', 'rate_limited',
    ];
    if (terminal.includes(code)) {
      showStatus(code);
      return;
    }
    if (inline) {
      inline(messageFor(err));
      return;
    }
    showStatus('server_error');
  }

  // --- step 1: peek --------------------------------------------------------

  async function start() {
    if (!key) {
      showStatus('missing_key');
      return;
    }
    try {
      meta = await peek(key);
      renderIntro(meta);
    } catch (err) {
      handleError(err);
    }
  }

  function renderIntro(data) {
    const isFile = data.kind === 'file';

    // The heading names what happened, not what to do.
    toggle($('#gate-h2-text'), !isFile);
    toggle($('#gate-h2-file'), isFile);

    toggle($('#chip-kind-text'), !isFile);
    toggle($('#chip-kind-file'), isFile);

    if (data.size) {
      setText($('#chip-size-text'), formatBytes(data.size));
      show($('#chip-size'));
    }
    if (data.expires_at) {
      setText($('#chip-expires-text'), t('js.expires_on', { date: formatDateTime(data.expires_at) }));
      show($('#chip-expires'));
    }

    // Saying "password protected" up front means the extra step later is an
    // announced change of plan rather than a surprise.
    toggle($('#chip-pass'), Boolean(data.has_passphrase));

    if (typeof data.attempts_left === 'number') attemptsLeft = data.attempts_left;

    const label = $('#gate-cta-label');
    setText(label, data.has_passphrase ? label.dataset.pass : label.dataset.plain);

    only(intro);
  }

  // --- step 2: reveal ------------------------------------------------------

  $('#gate-reveal')?.addEventListener('click', () => void doReveal());

  async function doReveal(passphrase) {
    if (busy) return;

    if (meta && meta.has_passphrase && !passphrase) {
      only(passStep);
      renderAttempts();
      $('#gate-pass-input')?.focus();
      return;
    }

    busy = true;
    const btn = passphrase ? $('#pass-submit') : $('#gate-reveal');
    const label = passphrase ? $('#pass-submit-label') : $('#gate-cta-label');
    const original = label ? label.textContent : '';
    if (btn) btn.disabled = true;
    setText(label, t('js.gate.revealing'));

    try {
      const data = await reveal(key, { passphrase });
      // The key has done its job; take it out of the address bar so it is not
      // in the history, in a screenshot or in a shoulder-surfer's view.
      scrubFragment();
      renderRevealed(data);
    } catch (err) {
      if (err instanceof ApiError && err.code === 'bad_passphrase') {
        onWrongPassphrase();
      } else if (err instanceof ApiError && err.code === 'passphrase_required') {
        only(passStep);
        renderAttempts();
        $('#gate-pass-input')?.focus();
      } else {
        handleError(err, (msg) => showPassError(msg));
      }
    } finally {
      busy = false;
      if (btn) btn.disabled = false;
      setText(label, original);
    }
  }

  // --- passphrase ----------------------------------------------------------

  const passForm = $('#pass-form');
  const passInput = $('#gate-pass-input');

  passForm?.addEventListener('submit', (e) => {
    e.preventDefault();
    const value = passInput.value;
    if (!value) {
      showPassError(t('js.gate.pass_required'));
      return;
    }
    void doReveal(value);
  });

  if (passInput) onSubmitShortcut(passInput, () => passForm.requestSubmit());

  /**
   * Only ever shown once the count means something: either the server said
   * some attempts are already gone, or one has just been used here. Greeting
   * someone with "five attempts left" before they have typed anything is a
   * threat about a thing they have not done.
   */
  function renderAttempts() {
    const el = $('#pass-attempts');
    if (attemptsLeft === null || attemptsLeft >= passWindowFails) {
      setText(el, '');
      return;
    }
    setText(
      el,
      attemptsLeft === 1
        ? t('js.gate.last_attempt')
        : t('js.gate.attempts_left', {
            n: attemptsLeft,
            unit: plural(attemptsLeft, 'js.attempts'),
          })
    );
  }

  function onWrongPassphrase() {
    attemptsLeft = attemptsLeft === null ? passWindowFails - 1 : Math.max(0, attemptsLeft - 1);
    const message =
      t('js.gate.wrong') +
      ' ' +
      (attemptsLeft === 1
        ? t('js.gate.last_attempt')
        : t('js.gate.attempts_left', {
            n: attemptsLeft,
            unit: plural(attemptsLeft, 'js.attempts'),
          }));

    showPassError(message);
    renderAttempts();

    passInput.setAttribute('aria-invalid', 'true');
    passInput.select();

    // A shake is a nice confirmation for people who can see it and a source of
    // nausea for people who cannot tolerate motion.
    if (!reducedMotion()) {
      passInput.classList.remove('shake');
      void passInput.offsetWidth; // restart the animation
      passInput.classList.add('shake');
    }
  }

  function showPassError(message) {
    setText($('#pass-error-text'), message);
    show($('#pass-error'));
    // #pass-error is role="alert", so writing into it announces it.
  }

  passInput?.addEventListener('input', () => {
    hide($('#pass-error'));
    passInput.removeAttribute('aria-invalid');
  });

  // --- step 3: revealed ----------------------------------------------------

  function renderRevealed(data) {
    only(revealed);

    if (data.kind === 'file') {
      renderFile(data);
    } else {
      renderText(data);
    }

    // Announces that content appeared and what to do — never the content.
    announce(t('js.gate.revealed_live'));
  }

  function renderText(data) {
    const out = $('#secret-out');
    setText(out, data.value || '');
    show($('#reveal-text-wrap'));

    // Same WebView, same broken clipboard — said before the button is pressed
    // rather than after it silently does nothing.
    toggle($('#inapp-hint-text'), isInAppBrowser());

    const btn = $('#copy-secret');
    const label = $('#copy-secret-label');
    btn.onclick = () => copyWithFeedback(btn, label, data.value || '', $('#copy-fallback'));

    out.focus();
  }

  function renderFile(data) {
    setText($('#dl-name'), data.filename || '');
    setText($('#dl-size'), formatBytes(data.size));
    show($('#reveal-file-wrap'));

    // In an in-app WebView a programmatic download usually fails silently, so
    // say so before the tap rather than leaving a dead button.
    toggle($('#inapp-hint'), isInAppBrowser());

    const btn = $('#download-btn');
    const label = $('#download-label');
    let done = false;

    btn.onclick = async () => {
      if (busy) return;
      busy = true;
      const original = label.textContent;
      btn.disabled = true;
      setText(label, t('js.gate.downloading'));

      try {
        const blob = await downloadFile(data.download_url, data.download_ticket);
        saveBlob(blob, data.filename || 'download');
        done = true;
        show($('#download-done'));
        // The offer stays: a download that vanished into a phone's Files app
        // is a common reason to want a second go.
        setText(label, t('js.gate.download_again'));
        announce($('#download-done').textContent);
      } catch (err) {
        handleError(err, (msg) => alertNow(msg));
      } finally {
        busy = false;
        btn.disabled = false;
        if (!done) setText(label, original);
      }
    };
  }

  /**
   * The ticket travels in a header, so the file arrives as a blob rather than
   * through a navigation. Handing it to the user needs a temporary object URL
   * and a synthetic click.
   */
  function saveBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    // Revoking immediately can cancel the download in some browsers.
    window.setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  // ⌘/Ctrl+Enter reveals, matching the shortcut on the composer.
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || !(e.metaKey || e.ctrlKey)) return;
    if (!intro.classList.contains('is-hidden')) {
      e.preventDefault();
      void doReveal();
    }
  });

  void start();
}
