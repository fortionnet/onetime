/**
 * Sender's receipt for receipt.gohtml.
 *
 * Same fragment-key arrangement as the gate: the server cannot read this
 * record either, so the page fetches its own contents. Reading a receipt never
 * consumes anything, so this can run on load without a confirmation step.
 */

import {
  $, t, show, hide, toggle, setText, announce, alertNow,
  formatBytes, formatDateTime,
} from './util.js';
import { receipt, burn, messageFor } from './api.js';

export function init() {
  const card = $('#receipt-card');
  const loading = $('#receipt-loading');
  const body = $('#receipt-body');
  const confirmBox = $('#burn-confirm');
  const statusBox = $('#receipt-status');

  const key = (window.location.hash || '').replace(/^#/, '').trim();
  let busy = false;

  async function load() {
    if (!key) {
      fail(t('js.err.not_found'));
      return;
    }
    try {
      render(await receipt(key));
    } catch (err) {
      fail(messageFor(err));
    }
  }

  function fail(message) {
    hide(loading);
    hide(card);
    setText($('#receipt-status-text'), message);
    show(statusBox);
    alertNow(message);
  }

  function render(data) {
    hide(loading);
    hide(statusBox);
    show(card);
    hide(confirmBox);
    show(body);

    const state = data.state || 'new';
    const entry =
      $(`#state-catalog [data-state="${state}"]`) || $('#state-catalog [data-state="new"]');

    const block = $('#state-block');
    block.className = 'state state--' + state;

    // Colour, glyph and words all change together — the colour alone is never
    // the signal.
    const icon = $('#state-icon');
    icon.innerHTML = '';
    const glyph = entry.querySelector('[data-icon] svg');
    if (glyph) icon.appendChild(glyph.cloneNode(true));

    // A finished state reads better with the moment it finished attached.
    const when = data.consumed_at || null;
    const title = entry.querySelector('[data-title]').textContent;
    setText($('#state-title'), when && state !== 'new' ? `${title} ${formatDateTime(when)}` : title);
    setText($('#state-sub'), entry.querySelector('[data-sub]').textContent);

    setText($('#dd-created'), formatDateTime(data.created_at) || t('js.none'));
    setText($('#dd-expires'), formatDateTime(data.secret_expires_at) || t('js.none'));
    setText($('#dd-content'), describeContent(data));
    setText($('#dd-peeked'), formatDateTime(data.peeked_at) || t('js.none'));
    setText($('#dd-consumed'), formatDateTime(data.consumed_at) || t('js.none'));

    // Burning is only meaningful while the link is still unread.
    toggle($('#burn'), state === 'new');

    if (document.title && state) announce(entry.querySelector('[data-title]').textContent);

    const h2 = $('#receipt-h2');
    if (data.created_at) {
      setText(h2, t('js.receipt.h2', { date: formatDateTime(data.created_at) }));
    }
  }

  function describeContent(data) {
    const parts = [t(data.kind === 'file' ? 'js.kind.file' : 'js.kind.text')];
    if (data.size) parts.push(formatBytes(data.size));
    if (data.has_passphrase) parts.push(t('js.summary.pass'));
    return parts.join(' · ');
  }

  // --- burn ----------------------------------------------------------------

  const startBtn = $('#burn-start');
  const yesBtn = $('#burn-yes');
  const noBtn = $('#burn-no');

  /**
   * A two-step confirmation inside the card rather than window.confirm: a
   * native dialog cannot be styled or translated consistently, and on mobile
   * the tap that opens it often dismisses it too.
   */
  startBtn?.addEventListener('click', () => {
    hide(body);
    show(confirmBox);
    // Focus lands on "Back". The destructive option should never be one
    // stray Enter away.
    noBtn.focus();
  });

  noBtn?.addEventListener('click', cancelBurn);

  function cancelBurn() {
    hide(confirmBox);
    show(body);
    startBtn?.focus();
  }

  // Escape is the same "get me out of here" everywhere on the site.
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && confirmBox && !confirmBox.classList.contains('is-hidden')) {
      e.preventDefault();
      cancelBurn();
    }
  });

  yesBtn?.addEventListener('click', async () => {
    if (busy) return;
    busy = true;
    const label = $('#burn-yes-label');
    const original = label.textContent;
    yesBtn.disabled = true;
    setText(label, t('js.receipt.burning'));

    try {
      const data = await burn(key);
      render(data);
      announce(t('js.receipt.burned_live'));
    } catch (err) {
      fail(messageFor(err));
    } finally {
      busy = false;
      yesBtn.disabled = false;
      setText(label, original);
    }
  });

  void load();
}
