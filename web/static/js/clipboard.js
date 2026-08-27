/**
 * Copying, with the failure case treated as a first-class outcome.
 *
 * navigator.clipboard needs a secure context and a user gesture, and inside
 * in-app browsers it fails even then. Every call therefore has a fallback and,
 * when both routes fail, tells the reader how to copy by hand — silently doing
 * nothing on a page whose content cannot be reloaded is the worst outcome
 * available.
 */

import { t, announce, setText } from './util.js';

async function writeViaAPI(text) {
  if (!navigator.clipboard || !window.isSecureContext) return false;
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * Selection-based fallback. execCommand is deprecated but it is the only thing
 * that works in older WebViews, and a deprecated API that works beats a modern
 * one that does not.
 */
function writeViaSelection(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.setAttribute('aria-hidden', 'true');
  ta.style.position = 'fixed';
  ta.style.top = '0';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);

  let ok = false;
  try {
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, text.length);
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  } finally {
    ta.remove();
  }
  return ok;
}

export async function copyText(text) {
  if (!text) return false;
  if (await writeViaAPI(text)) return true;
  return writeViaSelection(text);
}

/**
 * Copy and report the outcome on the button itself.
 *
 * The label and the icon both change, never the colour alone: colour is not
 * available to everyone and disappears in forced-colours mode.
 *
 * @param {HTMLElement} button     the control that was pressed
 * @param {HTMLElement} labelEl    element holding the button's text
 * @param {string}      text       what to copy
 * @param {HTMLElement} [failEl]   where to put the manual-copy instructions
 */
export async function copyWithFeedback(button, labelEl, text, failEl) {
  const ok = await copyText(text);

  if (ok) {
    const original = labelEl ? labelEl.textContent : '';
    setText(labelEl, t('js.copied'));
    button.dataset.copied = '1';
    announce(t('js.copied'));

    window.setTimeout(() => {
      if (button.dataset.copied === '1') {
        setText(labelEl, original);
        delete button.dataset.copied;
      }
    }, 2400);
    return true;
  }

  const message = t('js.copy_failed');
  if (failEl) {
    setText(failEl, message);
    failEl.classList.remove('is-hidden');
  }
  announce(message);
  return false;
}

/**
 * Wires every <div class="code" data-copy> on the page with a copy button.
 * Used by the API docs, where the buttons are pure enhancement and so are
 * created here rather than shipped in the markup.
 */
export function enhanceCodeBlocks(root = document) {
  root.querySelectorAll('.code[data-copy]').forEach((block) => {
    if (block.querySelector('.code__copy')) return;

    const pre = block.querySelector('pre');
    if (!pre) return;

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'code__copy';
    btn.textContent = t('js.copy');

    btn.addEventListener('click', async () => {
      const ok = await copyText(pre.textContent);
      btn.textContent = ok ? t('js.copied') : t('js.copy_failed');
      announce(btn.textContent);
      window.setTimeout(() => {
        btn.textContent = t('js.copy');
      }, 2400);
    });

    block.appendChild(btn);
  });
}
