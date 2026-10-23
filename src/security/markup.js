// Safe BBCode-style markup renderer — verbatim port of src/Markup.php
// (docs/03 C-XSS-1, C-XSS-4).
//
// Security model, unchanged from the PHP target:
//   1. the whole input is HTML-escaped FIRST — that is the XSS boundary;
//   2. only the whitelisted tags are converted, everything else stays inert text;
//   3. URLs need an absolute http(s) scheme and a host, control characters and
//      whitespace are rejected, and entities are decoded before the check;
//   4. replacement work is bounded to 25 passes.
//
// `vuln/xss_stored` is the branch that inverts step 1. Do not "tidy" this file.

const MAX_PASSES = 25;
const MAX_INPUT_CHARS = 20000;
const SIMPLE_TAGS = { b: 'strong', i: 'em', u: 'u' };

/** htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') */
export function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** html_entity_decode($value, ENT_QUOTES, 'UTF-8') for the entities we emit. */
export function decodeEntities(value) {
  return String(value ?? '')
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&#x27;/gi, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

export function render(raw) {
  let s = Array.from(String(raw ?? '')).slice(0, MAX_INPUT_CHARS).join('');

  // Normalize newlines, strip control chars except \n and \t.
  s = s.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  s = s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');

  // 1) Escape everything up front — this is the XSS boundary.
  s = escapeHtml(s);

  // 2) Parse whitelisted tags, innermost-first, bounded passes.
  for (let pass = 0; pass < MAX_PASSES; pass++) {
    let next = s;

    for (const [tag, element] of Object.entries(SIMPLE_TAGS)) {
      const pattern = new RegExp(`\\[${tag}\\]((?:(?!\\[\\/${tag}\\]).)*)\\[\\/${tag}\\]`, 'gis');
      next = next.replace(pattern, `<${element}>$1</${element}>`);
    }

    next = next.replace(/\[url\]((?:https?:\/\/)[^[\]\s]+)\[\/url\]/gi, linkReplacer(false));
    next = next.replace(
      /\[url=((?:https?:\/\/)[^[\]\s]+)\]((?:(?!\[\/url\]).)*)\[\/url\]/gis,
      linkReplacer(true),
    );
    next = next.replace(/\[img\]((?:https?:\/\/)[^[\]\s]+)\[\/img\]/gi, imgReplacer());

    if (next === s) break;
    s = next;
  }

  // 3) Newlines -> <br> (PHP nl2br with html=false: <br> before the newline).
  return s.replace(/\n/g, '<br>\n');
}

function linkReplacer(withText = false) {
  return (match, url, label) => {
    const decoded = decodeEntities(url);
    if (!isSafeUrl(decoded)) return match; // leave the (already escaped) literal
    const href = escapeHtml(decoded);
    if (withText) {
      const text = String(label ?? '').trim() !== '' ? label : href;
      return `<a href="${href}" rel="noopener noreferrer nofollow" target="_blank">${text}</a>`;
    }
    return `<a href="${href}" rel="noopener noreferrer nofollow">${escapeHtml(decoded)}</a>`;
  };
}

function imgReplacer() {
  return (match, url) => {
    const decoded = decodeEntities(url);
    if (!isSafeUrl(decoded)) return match;
    const src = escapeHtml(decoded);
    return `<img src="${src}" alt="user image" loading="lazy" class="post-image">`;
  };
}

/** Accepts only absolute http(s) URLs with a host and no control characters. */
export function isSafeUrl(url) {
  const value = String(url ?? '');
  if (/[\u0000-\u0020\u007F]/.test(value)) return false;
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  const scheme = parsed.protocol.replace(/:$/, '').toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') return false;
  return parsed.hostname !== '';
}

/** Strip markup to plain text (titles, teasers, listings). */
export function plain(raw) {
  let text = String(raw ?? '').replace(/\[\/?(b|i|u|url|img)(=[^\]]*)?\]/gi, '');
  text = text.replace(/\s+/gu, ' ');
  return Array.from(text.trim()).slice(0, 300).join('').trim();
}
