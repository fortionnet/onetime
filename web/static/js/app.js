/**
 * Entry point. Loads the module for the current page and nothing else.
 *
 * Page modules are pulled in with dynamic import(), so a recipient opening a
 * gate link never downloads the composer, and the composer never downloads the
 * QR encoder unless someone asks for a QR code.
 */

import { $, $$, t } from './util.js';

/** Behaviour every page shares, none of it essential. */
function initGlobal() {
  // The gate footer names the host people are actually on; the template can
  // only print the configured base URL, which may carry a scheme or a port.
  $$('[data-host]').forEach((el) => {
    el.textContent = window.location.host;
  });

  // Escape closes any open disclosure and returns focus to its summary.
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const open = document.querySelector('details[open]');
    if (!open || !open.contains(document.activeElement)) return;
    open.open = false;
    open.querySelector('summary')?.focus();
  });

  // Skip link: moving focus, not just the viewport, so the next Tab continues
  // from the content rather than from the header.
  const skip = document.querySelector('.skip');
  skip?.addEventListener('click', () => {
    const main = $('#main');
    if (main) window.setTimeout(() => main.focus(), 0);
  });
}

/** Highlights the current section in the API docs table of contents. */
function initTOC() {
  const links = $$('.toc a');
  if (!links.length || !('IntersectionObserver' in window)) return;

  const byId = new Map(links.map((a) => [a.getAttribute('href').slice(1), a]));
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        links.forEach((a) => a.removeAttribute('aria-current'));
        byId.get(entry.target.id)?.setAttribute('aria-current', 'true');
      }
    },
    { rootMargin: '-20% 0px -70% 0px' }
  );

  $$('.doc-section').forEach((section) => observer.observe(section));
}

async function main() {
  initGlobal();

  const page = document.body.dataset.page;

  try {
    if (page === 'create') {
      (await import('./create.js')).init();
    } else if (page === 'gate') {
      (await import('./gate.js')).init();
    } else if (page === 'receipt') {
      (await import('./receipt.js')).init();
    } else if (page === 'api') {
      (await import('./clipboard.js')).enhanceCodeBlocks();
      initTOC();
    }
  } catch (err) {
    // A page whose script failed to load must not look merely unresponsive —
    // on the gate that would read as "the link is broken".
    const alertRegion = document.getElementById('sr-alert');
    if (alertRegion) alertRegion.textContent = t('js.err.generic');
    throw err;
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => void main());
} else {
  void main();
}
