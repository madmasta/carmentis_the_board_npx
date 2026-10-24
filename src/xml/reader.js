// The in-house XML reader (docs/02 section 7, docs/03 C-XML-1).
//
// A third-party XML library is deliberately not used: the parser that matters for
// this benchmark is one whose limits are visible in this file.
//
// Limits, in the order they are applied:
//   * input is decoded as strict UTF-8 and must be ≤ MAX_XML_BYTES (64 KiB);
//   * a `DOCTYPE` declaring `SYSTEM` or `PUBLIC` — i.e. anything that could make
//     the parser fetch an external resource — is rejected outright;
//   * only internal entities defined in the internal subset are expanded, the
//     built-in five are always available, numeric character references are
//     allowed, and an undefined reference is an error, not a pass-through;
//   * expansion is counted and capped, so `<!ENTITY a "&a;&a;">` cannot blow up;
//   * element nesting is capped at MAX_DEPTH, so deep nesting cannot exhaust the
//     stack;
//   * text is text: entity-expanded text is never re-parsed as markup, which is
//     what keeps `&lt;b&gt;` from becoming a tag on the way out.
//
// The result is a plain tree: { tag, attrs, children, text }. Everything the
// importer accepts is read out of that tree by field name.

export const MAX_XML_BYTES = 64 * 1024;
export const MAX_DEPTH = 20;
export const MAX_ENTITY_EXPANSIONS = 64;

const BUILTIN_ENTITIES = {
  lt: '<',
  gt: '>',
  amp: '&',
  quot: '"',
  apos: "'",
};

export class XmlError extends Error {
  constructor(message) {
    super(message);
    this.name = 'XmlError';
  }
}

function byteLength(input) {
  return Buffer.byteLength(input, 'utf8');
}

/** Decode strictly: invalid UTF-8 is an error, not U+FFFD. */
export function decodeUtf8(input) {
  if (typeof input === 'string') {
    if (input.includes('\uFFFD')) throw new XmlError('input is not valid UTF-8');
    return input.replace(/^\uFEFF/, '');
  }
  if (!Buffer.isBuffer(input)) throw new XmlError('expected a string or a Buffer');
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(input).replace(/^\uFEFF/, '');
  } catch {
    throw new XmlError('input is not valid UTF-8');
  }
}

/** Character references and declared entities, never re-parsed as markup. */
function expandEntities(text, entities, budget) {
  let count = budget.used;
  const out = [];
  let index = 0;

  while (index < text.length) {
    const at = text.indexOf('&', index);
    if (at === -1) {
      out.push(text.slice(index));
      break;
    }
    out.push(text.slice(index, at));
    const match = /^&(#x?[0-9a-fA-F]+|[A-Za-z_][\w.-]*);/.exec(text.slice(at));
    if (match === null) throw new XmlError('bare ampersand in text');

    count += 1;
    if (count > MAX_ENTITY_EXPANSIONS) throw new XmlError('entity expansion limit exceeded');

    const body = match[1];
    let value;
    if (body.startsWith('#x') || body.startsWith('#X')) {
      const code = Number.parseInt(body.slice(2), 16);
      if (!Number.isInteger(code) || code < 0 || code > 0x10ffff) throw new XmlError('bad character reference');
      value = String.fromCodePoint(code);
    } else if (body.startsWith('#')) {
      const code = Number.parseInt(body.slice(1), 10);
      if (!Number.isInteger(code) || code < 0 || code > 0x10ffff) throw new XmlError('bad character reference');
      value = String.fromCodePoint(code);
    } else if (Object.hasOwn(BUILTIN_ENTITIES, body)) {
      value = BUILTIN_ENTITIES[body];
    } else if (entities.has(body)) {
      value = entities.get(body);
    } else {
      throw new XmlError(`undefined entity: ${body}`);
    }

    out.push(value);
    index = at + match[0].length;
  }

  budget.used = count;
  return out.join('');
}

function parseTagName(source, from) {
  const match = /^[A-Za-z_][\w.:-]*/.exec(source.slice(from));
  if (match === null) throw new XmlError('malformed tag');
  return { name: match[0], next: from + match[0].length };
}

function skipWhitespace(source, from) {
  const match = /^\s+/.exec(source.slice(from));
  return match === null ? from : from + match[0].length;
}

/** Attribute list up to `>` or `/>`. Duplicate attributes are an error. */
function parseAttributes(source, from, entities, budget) {
  const attrs = Object.create(null);
  let index = from;

  for (;;) {
    index = skipWhitespace(source, index);
    if (index >= source.length) throw new XmlError('unterminated tag');
    if (source[index] === '>' || (source[index] === '/' && source[index + 1] === '>')) break;

    const nameMatch = /^[A-Za-z_][\w.:-]*/.exec(source.slice(index));
    if (nameMatch === null) throw new XmlError('malformed attribute name');
    const name = nameMatch[0];
    index += nameMatch[0].length;
    index = skipWhitespace(source, index);

    if (source[index] !== '=') throw new XmlError(`attribute ${name} has no value`);
    index = skipWhitespace(source, index + 1);

    const quote = source[index];
    if (quote !== '"' && quote !== "'") throw new XmlError('attribute value must be quoted');
    const end = source.indexOf(quote, index + 1);
    if (end === -1) throw new XmlError('unterminated attribute value');

    const raw = source.slice(index + 1, end);
    if (raw.includes('<')) throw new XmlError('raw < in attribute value');
    if (Object.hasOwn(attrs, name)) throw new XmlError(`duplicate attribute: ${name}`);
    attrs[name] = expandEntities(raw, entities, budget);
    index = end + 1;
  }

  return { attrs, next: index, selfClosing: source[index] === '/' };
}

/** The internal subset: only `<!ENTITY name "value">` is accepted. */
function parseInternalSubset(source, from, to, entities) {
  let index = from;
  while (index < to) {
    const next = source.indexOf('<!', index);
    if (next === -1 || next >= to) break;
    const match = /^<!ENTITY\s+([A-Za-z_][\w.-]*)\s+("([^"]*)"|'([^']*)')\s*>/.exec(source.slice(next));
    if (match === null) throw new XmlError('only internal ENTITY declarations are allowed');
    entities.set(match[1], match[3] ?? match[4] ?? '');
    index = next + match[0].length;
  }
}

/**
 * Parse a document into `{ tag, attrs, children, text }`.
 * Throws XmlError for anything outside the limits above.
 */
export function parse(input, options = {}) {
  const maxBytes = options.maxBytes ?? MAX_XML_BYTES;
  const maxDepth = options.maxDepth ?? MAX_DEPTH;
  const source = decodeUtf8(input);

  if (byteLength(source) > maxBytes) throw new XmlError('document exceeds the size limit');

  const entities = new Map();
  const budget = { used: 0 };
  const root = { tag: '#document', attrs: {}, children: [], text: '' };
  const stack = [root];
  let index = 0;
  let sawRoot = false;

  const top = () => stack[stack.length - 1];

  while (index < source.length) {
    const lt = source.indexOf('<', index);
    if (lt === -1) {
      appendText(top(), source.slice(index), entities, budget);
      break;
    }
    if (lt > index) appendText(top(), source.slice(index, lt), entities, budget);

    if (source.startsWith('<!--', lt)) {
      const end = source.indexOf('-->', lt + 4);
      if (end === -1) throw new XmlError('unterminated comment');
      if (source.slice(lt + 4, end).includes('--')) throw new XmlError('nested comment marker');
      index = end + 3;
      continue;
    }

    if (source.startsWith('<?', lt)) {
      const end = source.indexOf('?>', lt + 2);
      if (end === -1) throw new XmlError('unterminated processing instruction');
      index = end + 2;
      continue;
    }

    if (source.startsWith('<![CDATA[', lt)) {
      const end = source.indexOf(']]>', lt + 9);
      if (end === -1) throw new XmlError('unterminated CDATA');
      top().text += source.slice(lt + 9, end);
      index = end + 3;
      continue;
    }

    if (source.startsWith('<!', lt)) {
      const decl = readMarkupDeclaration(source, lt);
      // The words that mean "go fetch something": they may appear in the DOCTYPE
      // name line or in the internal subset; either one is refused.
      if (/\b(SYSTEM|PUBLIC)\b/i.test(decl.body)) throw new XmlError('external entity declarations are not allowed');
      if (decl.name === 'DOCTYPE') {
        if (decl.subsetFrom !== null) parseInternalSubset(source, decl.subsetFrom, decl.subsetTo, entities);
      }
      index = decl.next;
      continue;
    }

    if (source.startsWith('</', lt)) {
      const { name, next } = parseTagName(source, lt + 2);
      const closed = skipWhitespace(source, next);
      if (source[closed] !== '>') throw new XmlError('unterminated end tag');
      if (stack.length <= 1 || top().tag !== name) throw new XmlError(`unexpected end tag: ${name}`);
      stack.pop();
      index = closed + 1;
      continue;
    }

    const { name, next } = parseTagName(source, lt + 1);
    const parsed = parseAttributes(source, next, entities, budget);
    if (parsed.selfClosing) {
      top().children.push({ tag: name, attrs: parsed.attrs, children: [], text: '' });
      index = skipWhitespace(source, parsed.next) + 2;
      sawRoot = true;
      continue;
    }

    if (stack.length >= maxDepth + 1) throw new XmlError('nesting limit exceeded');
    const element = { tag: name, attrs: parsed.attrs, children: [], text: '' };
    top().children.push(element);
    if (name !== '?xml') sawRoot = true;
    stack.push(element);
    index = parsed.next + 1;
  }

  if (stack.length !== 1) throw new XmlError('unclosed element');
  if (!sawRoot) throw new XmlError('no element found');
  return root;
}

/** `<!NAME ...>` up to its `>`, with the `[internal subset]` span if present. */
function readMarkupDeclaration(source, from) {
  const nameMatch = /^<!([A-Za-z]+)/.exec(source.slice(from));
  if (nameMatch === null) throw new XmlError('malformed declaration');
  const name = nameMatch[1].toUpperCase();

  let index = from + nameMatch[0].length;
  let depth = 0;
  let subsetFrom = null;
  let subsetTo = null;

  while (index < source.length) {
    const char = source[index];
    if (char === '[' && depth === 0) {
      depth = 1;
      subsetFrom = index + 1;
    } else if (char === '[') {
      depth += 1;
    } else if (char === ']') {
      depth -= 1;
      if (depth === 0) subsetTo = index;
    } else if (char === '>' && depth === 0) {
      return { name, body: source.slice(from + 2, index), subsetFrom, subsetTo, next: index + 1 };
    } else if (char === '"' || char === "'") {
      const end = source.indexOf(char, index + 1);
      if (end === -1) throw new XmlError('unterminated quoted declaration');
      index = end;
    }
    index += 1;
  }

  throw new XmlError('unterminated declaration');
}

function appendText(node, text, entities, budget) {
  const value = text.trim();
  if (value === '') return;
  node.text += expandEntities(value, entities, budget);
}

/** First child with a tag, or null. */
export function child(doc, tag) {
  return doc.children.find((entry) => entry.tag === tag) ?? null;
}

/** All children with a tag. */
export function children(doc, tag) {
  return doc.children.filter((entry) => entry.tag === tag);
}

/** The text of the first child with a tag, or ''. */
export function childText(doc, tag) {
  return child(doc, tag)?.text ?? '';
}
