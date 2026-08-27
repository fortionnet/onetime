/**
 * Shared helpers: translation lookup, locale-aware formatting, small DOM and
 * screen-reader utilities. No dependencies, no side effects beyond reading the
 * embedded i18n payload once at load.
 */

/** Strings with the "js." prefix, emitted by i18n.JSONFor on the server. */
const dict = (() => {
  const el = document.getElementById('i18n');
  if (!el) return {};
  try {
    return JSON.parse(el.textContent) || {};
  } catch {
    return {};
  }
})();

export const LANG = dict['js.lang'] || document.documentElement.lang || 'cs';
export const LOCALE = dict['js.locale'] || (LANG === 'cs' ? 'cs-CZ' : 'en-GB');

/**
 * Translate a key, substituting {placeholders}. An unknown key returns itself
 * so that a missing string is visible rather than silently blank.
 */
export function t(key, vars) {
  let s = Object.prototype.hasOwnProperty.call(dict, key) ? dict[key] : key;
  if (vars) {
    for (const name of Object.keys(vars)) {
      s = s.split('{' + name + '}').join(String(vars[name]));
    }
  }
  return s;
}

const pluralRules = (() => {
  try {
    return new Intl.PluralRules(LOCALE);
  } catch {
    return null;
  }
})();

/**
 * Pick the plural form of a catalog family, e.g. plural(2, 'js.days') -> "dny".
 * Czech needs three forms (1 / 2-4 / 5+), which CLDR reports as one/few/other.
 */
export function plural(n, base) {
  const category = pluralRules ? pluralRules.select(n) : n === 1 ? 'one' : 'other';
  if (category === 'one') return t(base + '.one');
  if (category === 'few') return t(base + '.few');
  return t(base + '.many');
}

export function num(n) {
  try {
    return new Intl.NumberFormat(LOCALE).format(n);
  } catch {
    return String(n);
  }
}

/**
 * "2,4 MB" in Czech, "2.4 MB" in English.
 *
 * Binary units labelled kB/MB, matching the server's humanBytes: the 50 MiB
 * upload limit has to read as "50 MB" and not "52.4 MB".
 */
export function formatBytes(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return '';
  const units = ['B', 'kB', 'MB', 'GB'];
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  // One decimal only where it carries information: "2,4 MB" is useful,
  // "300,0 kB" is just noise.
  const digits = unit > 0 && value < 10 ? 1 : 0;
  try {
    return (
      new Intl.NumberFormat(LOCALE, {
        minimumFractionDigits: 0,
        maximumFractionDigits: digits,
      }).format(value) +
      ' ' +
      units[unit]
    );
  } catch {
    return value.toFixed(digits) + ' ' + units[unit];
  }
}

const dateOnlyOpts =
  LANG === 'cs'
    ? { day: 'numeric', month: 'numeric', year: 'numeric' }
    : { day: 'numeric', month: 'short', year: 'numeric' };

const dateTimeOpts = { ...dateOnlyOpts, hour: '2-digit', minute: '2-digit' };

/**
 * The server sends RFC 3339 in UTC; only the browser knows the reader's time
 * zone, so all formatting happens here.
 */
function fmt(iso, opts) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  try {
    return new Intl.DateTimeFormat(LOCALE, opts).format(d);
  } catch {
    return d.toISOString();
  }
}

export function formatDate(iso) {
  return fmt(iso, dateOnlyOpts);
}

export function formatDateTime(iso) {
  return fmt(iso, dateTimeOpts);
}

/** Whole days from now until iso, rounded up, never below zero. */
export function daysUntil(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return 0;
  return Math.max(0, Math.ceil((d.getTime() - Date.now()) / 86400000));
}

/** "~4 s" / "~2 min" — deliberately coarse, since the estimate is noisy. */
export function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return '';
  if (seconds < 60) return Math.max(1, Math.round(seconds)) + ' ' + t('js.unit.sec');
  return Math.round(seconds / 60) + ' ' + t('js.unit.min');
}

// --- DOM ------------------------------------------------------------------

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

export function show(el) {
  if (el) el.classList.remove('is-hidden');
}

export function hide(el) {
  if (el) el.classList.add('is-hidden');
}

export function toggle(el, visible) {
  if (el) el.classList.toggle('is-hidden', !visible);
}

export function setText(el, text) {
  if (el) el.textContent = text == null ? '' : String(text);
}

export const reducedMotion = () =>
  window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/**
 * In-app browsers (Messenger, Instagram, Teams, Slack, WeChat, LINE) run a
 * cut-down WebView: the clipboard API often fails and a programmatic download
 * is silently dropped. Worth telling people before they try.
 */
export function isInAppBrowser() {
  return /FBAN|FBAV|Instagram|Teams|Slack|Line\/|MicroMessenger/i.test(navigator.userAgent || '');
}

// --- Screen reader announcements ------------------------------------------

/**
 * Route announcements through the two permanent live regions in base.gohtml.
 * Clearing first makes a repeated identical message announce again; without it
 * the second "Copied" is silent.
 */
function announceIn(id, message) {
  const region = document.getElementById(id);
  if (!region) return;
  region.textContent = '';
  window.setTimeout(() => {
    region.textContent = message;
  }, 60);
}

export function announce(message) {
  announceIn('sr-status', message);
}

export function alertNow(message) {
  announceIn('sr-alert', message);
}

/** ⌘/Ctrl+Enter submits. Attached per page rather than globally. */
export function onSubmitShortcut(el, handler) {
  el.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      handler(e);
    }
  });
}
