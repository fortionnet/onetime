/**
 * Composer behaviour for create.gohtml.
 *
 * The central constraint: once a link is created we cannot show it again, so
 * the result replaces the form in place, the URL never changes, and leaving
 * before copying is guarded.
 */

import {
  $, t, num, show, hide, toggle, setText, plural, announce, alertNow,
  formatBytes, formatDate, formatDuration, onSubmitShortcut,
} from './util.js';
import { createSecret, messageFor } from './api.js';
import { copyWithFeedback } from './clipboard.js';
import { uploadFile } from './upload.js';

export function init() {
  const body = document.body;
  const form = $('#create-form');
  if (!form) return;

  const maxFileBytes = Number(body.dataset.maxFileBytes || 0);
  const maxTextBytes = Number(body.dataset.maxTextBytes || 0);
  const ttlMin = Number(body.dataset.ttlMin || 1);
  const ttlMax = Number(body.dataset.ttlMax || 30);
  const filesEnabled = body.dataset.filesDisabled !== '1';
  const readOnly = body.dataset.readOnly === '1';

  const textarea = $('#secret-text');
  const counter = $('#text-counter');
  const fileInput = $('#secret-file');
  const fileRow = $('#file-row');
  const dropZone = $('#drop-zone');
  const submit = $('#submit');
  const submitLabel = $('#submit-label');
  const submitRow = $('#submit-row');
  const errorBox = $('#form-error');
  const errorText = $('#form-error-text');
  const progress = $('#upload-progress');
  const progressBar = $('#progress-bar');
  const progressText = $('#progress-text');
  const result = $('#result');
  const resultUrl = $('#result-url');

  let selectedFile = null;
  let mode = 'text';
  let inFlight = null;
  let copied = false;

  // --- tabs ---------------------------------------------------------------

  const tabs = [$('#tab-text'), $('#tab-file')].filter(Boolean);

  function setMode(next, { focus = false } = {}) {
    if (next === 'file' && !filesEnabled) return;
    mode = next;
    tabs.forEach((tab) => {
      const active = tab.dataset.tab === next;
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
      // Roving tabindex: the tablist is one tab stop, arrows move within it.
      tab.tabIndex = active ? 0 : -1;
      if (active && focus) tab.focus();
    });
    toggle($('#panel-text'), next === 'text');
    toggle($('#panel-file'), next === 'file');
    clearError();
    updateCounter();
  }

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => setMode(tab.dataset.tab));
    tab.addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      e.preventDefault();
      const i = tabs.indexOf(tab);
      const next = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
      if (!next.disabled) setMode(next.dataset.tab, { focus: true });
    });
  });

  // --- character counter ---------------------------------------------------

  const byteLength = (s) => new TextEncoder().encode(s).length;

  function updateCounter() {
    if (!counter || !textarea) return;
    const used = byteLength(textarea.value);
    const ratio = maxTextBytes > 0 ? used / maxTextBytes : 0;
    setText(counter, `${num(used)} / ${num(maxTextBytes)}`);
    // Below 80% the number is noise; it fades in only once it starts to matter.
    counter.dataset.level = ratio >= 1 ? 'over' : ratio >= 0.8 ? 'near' : '';
    if (!counter.dataset.level) counter.removeAttribute('data-level');
  }

  if (textarea) {
    textarea.addEventListener('input', () => {
      updateCounter();
      clearError();
    });
  }

  // --- file selection ------------------------------------------------------

  function setFile(file) {
    if (!file || !filesEnabled) return;
    selectedFile = file;
    setText($('#file-name'), file.name);
    setText($('#file-size'), formatBytes(file.size));
    show(fileRow);
    hide(dropZone);
    clearError();
    if (maxFileBytes > 0 && file.size > maxFileBytes) {
      showError(tooLarge());
    }
  }

  // Two sentences, not a string and a number glued together: the size has to
  // read as part of the message, whichever language it is in.
  function tooLarge() {
    return (
      t('js.err.payload_too_large') +
      ' ' +
      t('js.err.max_size', { size: formatBytes(maxFileBytes) })
    );
  }

  function clearFile() {
    selectedFile = null;
    if (fileInput) fileInput.value = '';
    hide(fileRow);
    show(dropZone);
    clearError();
  }

  $('#file-pick')?.addEventListener('click', () => fileInput?.click());
  fileInput?.addEventListener('change', () => setFile(fileInput.files[0]));
  $('#file-remove')?.addEventListener('click', () => {
    clearFile();
    $('#file-pick')?.focus();
  });

  // Dropping anywhere on the page works and switches to the file tab, because
  // requiring people to find the right tab first is a pointless obstacle.
  if (filesEnabled) {
    let dragDepth = 0;
    const hasFiles = (e) => Array.from(e.dataTransfer?.types || []).includes('Files');

    window.addEventListener('dragenter', (e) => {
      if (!hasFiles(e)) return;
      dragDepth += 1;
      body.classList.add('is-dragging');
      if (mode !== 'file') setMode('file');
    });
    window.addEventListener('dragover', (e) => {
      if (hasFiles(e)) e.preventDefault();
    });
    window.addEventListener('dragleave', () => {
      dragDepth = Math.max(0, dragDepth - 1);
      if (dragDepth === 0) body.classList.remove('is-dragging');
    });
    window.addEventListener('drop', (e) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      dragDepth = 0;
      body.classList.remove('is-dragging');
      setMode('file');
      setFile(e.dataTransfer.files[0]);
    });
  }

  // --- options -------------------------------------------------------------

  const ttlRadios = Array.from(form.querySelectorAll('input[name="ttl_days"]'));
  const customRadio = $('#ttl-custom-radio');
  const customWrap = $('#ttl-custom-wrap');
  const customInput = $('#ttl-custom');
  const passInput = $('#passphrase');

  function currentTTL() {
    const checked = ttlRadios.find((r) => r.checked);
    if (!checked) return Number(body.dataset.ttlDefault || 14);
    if (checked.value !== 'custom') return Number(checked.value);
    const v = Number(customInput?.value || 0);
    return Math.min(ttlMax, Math.max(ttlMin, Number.isFinite(v) ? Math.round(v) : ttlMin));
  }

  function expiryDate(days) {
    const d = new Date();
    d.setDate(d.getDate() + days);
    return d;
  }

  function refreshOptions() {
    const days = currentTTL();
    const hasPass = Boolean(passInput?.value);

    // Live summary in the closed <details>, so the current settings are
    // visible without opening the panel.
    setText(
      $('#options-summary'),
      t('js.summary.expires', { n: num(days), unit: plural(days, 'js.days') }) +
        ' · ' +
        t(hasPass ? 'js.summary.pass' : 'js.summary.nopass')
    );
    setText($('#ttl-computed'), t('js.expires_on', { date: formatDate(expiryDate(days).toISOString()) }));

    const custom = customRadio?.checked;
    toggle(customWrap, Boolean(custom));
    // "Custom" replaces the chips rather than sitting beside them.
    toggle($('#ttl-chips'), !custom);
  }

  ttlRadios.forEach((r) =>
    r.addEventListener('change', () => {
      refreshOptions();
      // Choosing "custom" hides the chip that has focus, so focus has to move
      // with it or it falls back to the document.
      if (r === customRadio) customInput?.focus();
    })
  );
  customInput?.addEventListener('input', refreshOptions);
  passInput?.addEventListener('input', refreshOptions);

  $('#ttl-back')?.addEventListener('click', () => {
    const preset =
      ttlRadios.find((r) => Number(r.value) === currentTTL()) ||
      ttlRadios.find((r) => Number(r.value) === Number(body.dataset.ttlDefault || 14)) ||
      ttlRadios[0];
    preset.checked = true;
    refreshOptions();
    preset.focus();
  });

  // Escape closes the panel, matching the shortcut on every other disclosure.
  $('#options')?.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const details = $('#options');
      if (details.open) {
        details.open = false;
        details.querySelector('summary')?.focus();
      }
    }
  });

  // --- passphrase ----------------------------------------------------------

  const passToggle = $('#pass-toggle');
  passToggle?.addEventListener('click', () => {
    const shown = passInput.type === 'text';
    passInput.type = shown ? 'password' : 'text';
    passToggle.setAttribute('aria-pressed', shown ? 'false' : 'true');
    passInput.focus();
  });

  $('#pass-generate')?.addEventListener('click', () => {
    passInput.value = randomPassword(20);
    passInput.type = 'text';
    passToggle?.setAttribute('aria-pressed', 'true');
    refreshOptions();
    passInput.focus();
    passInput.select();
  });

  /**
   * Generated locally with the platform CSPRNG. Rejection sampling rather than
   * a modulo, so every character is uniformly distributed. Ambiguous glyphs
   * (0/O, 1/l/I) are left out because these get read down a phone line.
   */
  function randomPassword(length) {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    const limit = 256 - (256 % alphabet.length);
    const out = [];
    const buf = new Uint8Array(length * 2);
    while (out.length < length) {
      crypto.getRandomValues(buf);
      for (const b of buf) {
        if (b < limit) {
          out.push(alphabet[b % alphabet.length]);
          if (out.length === length) break;
        }
      }
    }
    return out.join('');
  }

  // --- errors --------------------------------------------------------------

  function showError(message) {
    setText(errorText, message);
    show(errorBox);
    alertNow(message);
  }

  function clearError() {
    hide(errorBox);
    setText(errorText, '');
  }

  // --- submit --------------------------------------------------------------

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    void go();
  });

  if (textarea) onSubmitShortcut(textarea, () => void go());
  if (passInput) onSubmitShortcut(passInput, () => void go());

  async function go() {
    if (inFlight || readOnly) return;
    clearError();

    const ttlDays = currentTTL();
    const passphrase = passInput?.value || '';

    if (mode === 'file') {
      if (!selectedFile) {
        showError(t('js.err.no_file'));
        $('#file-pick')?.focus();
        return;
      }
      if (maxFileBytes > 0 && selectedFile.size > maxFileBytes) {
        showError(tooLarge());
        return;
      }
      await sendFile({ ttlDays, passphrase });
      return;
    }

    const secret = textarea.value;
    if (!secret.trim()) {
      showError(t('js.err.empty'));
      textarea.focus();
      return;
    }
    if (maxTextBytes > 0 && byteLength(secret) > maxTextBytes) {
      showError(t('js.err.payload_too_large'));
      textarea.focus();
      return;
    }

    inFlight = true;
    const original = submitLabel.textContent;
    submit.disabled = true;
    setText(submitLabel, t('js.creating'));
    try {
      const data = await createSecret({ secret, ttlDays, passphrase });
      renderResult(data);
    } catch (err) {
      showError(messageFor(err));
    } finally {
      inFlight = null;
      submit.disabled = false;
      setText(submitLabel, original);
    }
  }

  async function sendFile({ ttlDays, passphrase }) {
    inFlight = true;
    hide(submitRow);
    show(progress);
    progressBar.style.width = '0%';

    const upload = uploadFile({
      url: '/api/v1/secret/file',
      fields: { ttl_days: ttlDays, passphrase },
      file: selectedFile,
      onProgress: ({ loaded, total, ratio, secondsLeft }) => {
        const pct = Math.round(ratio * 100);
        progressBar.style.width = pct + '%';
        progressBar.setAttribute('aria-valuenow', String(pct));
        const parts = [
          t('js.uploading'),
          `${formatBytes(loaded)} ${t('js.unit.of')} ${formatBytes(total)}`,
        ];
        if (Number.isFinite(secondsLeft)) {
          parts.push(t('js.upload_remaining', { t: formatDuration(secondsLeft) }));
        }
        setText(progressText, parts.join(' · '));
      },
    });

    $('#progress-cancel').onclick = () => upload.abort();

    try {
      const data = await upload.promise;
      renderResult(data);
    } catch (err) {
      if (err && err.name === 'AbortError') {
        announce(t('js.upload_canceled'));
      } else {
        showError(messageFor(err));
      }
    } finally {
      inFlight = null;
      hide(progress);
      show(submitRow);
    }
  }

  // --- result --------------------------------------------------------------

  function renderResult(data) {
    if (!data || !data.secret_url) {
      showError(t('js.err.generic'));
      return;
    }

    const passphrase = passInput?.value || '';

    hide(form);
    show(result);
    resultUrl.value = data.secret_url;
    renderPassphrase(passphrase);

    // The hero and the "how it works" strip belong to the empty page. Once the
    // link exists they are stale context around the one thing that matters, so
    // the result becomes the whole page.
    body.classList.add('is-result');

    renderExpiry(data);

    // Focus goes to the link, not to the copy button: it is the thing that
    // matters, it is selectable, and a screen reader reads it out here.
    result.focus();
    resultUrl.select();
    // Read back from the heading rather than from the catalog: the string is
    // already on the page, and duplicating it as a js.* key would be one more
    // thing to keep in sync.
    announce($('#result-title')?.textContent || '');

    copied = false;
    wireResultActions(data);
  }

  // Expiry is the one fact the sender cannot see anywhere else. The date alone,
  // without the minute: nobody plans around 13:43, and the extra precision only
  // makes the line harder to read.
  function renderExpiry(data) {
    const el = $('#result-expiry');
    if (!el) return;
    if (!data.expires_at) {
      hide(el);
      return;
    }
    setText(el, t('js.expires_on', { date: formatDate(data.expires_at) }));
  }

  // The sender has to send this by a different route than the link, so it has
  // to survive the switch to the result view. It is already on their screen —
  // repeating it here reveals nothing that was not visible a moment ago.
  function renderPassphrase(value) {
    const wrap = $('#result-pass-wrap');
    if (!wrap || !value) return;
    $('#result-pass').value = value;
    show(wrap);

    const btn = $('#copy-pass');
    const label = $('#copy-pass-label');
    btn.onclick = () => copyWithFeedback(btn, label, value, $('#copy-fallback'));
  }

  function wireResultActions(data) {
    const copyBtn = $('#copy-link');
    const copyLabel = $('#copy-link-label');
    copyBtn.onclick = async () => {
      const ok = await copyWithFeedback(copyBtn, copyLabel, data.secret_url, $('#copy-fallback'));
      if (ok) copied = true;
    };
  }

  // The link exists in this tab and nowhere else, so closing it before copying
  // loses it for good. Browsers show their own wording; the text is a formality.
  window.addEventListener('beforeunload', (e) => {
    if (!result || result.classList.contains('is-hidden') || copied) return;
    e.preventDefault();
    e.returnValue = t('js.leave_warning');
    return e.returnValue;
  });

  // --- initial state -------------------------------------------------------

  setMode('text');
  refreshOptions();
  updateCounter();
  if (readOnly) showError(t('js.err.read_only'));
}
