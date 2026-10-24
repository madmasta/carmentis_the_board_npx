// C-XML-1 proof file (docs/03): the reader's limits are the contract.

import { describe, expect, it } from 'vitest';
import {
  MAX_DEPTH,
  MAX_ENTITY_EXPANSIONS,
  MAX_XML_BYTES,
  XmlError,
  childText,
  children,
  parse,
} from '../../src/xml/reader.js';

const DOCUMENT = `<?xml version="1.0" encoding="UTF-8"?>
<!-- a comment -->
<board id="7" name="General">
  <thread title="Hello &amp; goodbye">
    <post author="alice"><![CDATA[raw <text> stays text]]></post>
    <post author="bob">second</post>
  </thread>
</board>`;

describe('xml reader (C-XML-1)', () => {
  it('reads elements, attributes, text and CDATA', () => {
    const doc = parse(DOCUMENT);
    const board = doc.children[0];

    expect(board.tag).toBe('board');
    expect(board.attrs.id).toBe('7');
    expect(board.attrs.name).toBe('General');

    const thread = children(board, 'thread')[0];
    expect(childText(thread, 'unknown')).toBe('');
    expect(thread.attrs.title).toBe('Hello & goodbye');
    const posts = children(thread, 'post');

    expect(posts).toHaveLength(2);
    expect(posts[0].attrs.author).toBe('alice');
    expect(posts[0].text).toBe('raw <text> stays text');
  });

  it('rejects a document over the size cap', () => {
    const big = `<board>${'a'.repeat(MAX_XML_BYTES)}</board>`;
    expect(() => parse(big)).toThrow(XmlError);
    expect(() => parse(big)).toThrow(/size limit/);
    expect(MAX_XML_BYTES).toBe(65536);
  });

  it('rejects nesting deeper than the cap', () => {
    const deep = '<a>'.repeat(MAX_DEPTH + 5) + 'x' + '</a>'.repeat(MAX_DEPTH + 5);
    expect(() => parse(deep)).toThrow(/nesting limit/);
    expect(MAX_DEPTH).toBe(20);

    // One below the cap still parses.
    const ok = '<a>'.repeat(MAX_DEPTH - 1) + 'x' + '</a>'.repeat(MAX_DEPTH - 1);
    expect(parse(ok).children[0].tag).toBe('a');
  });

  it('rejects a DOCTYPE that declares an external resource', () => {
    const external = `<?xml version="1.0"?>
<!DOCTYPE board SYSTEM "http://evil.example/x.dtd">
<board/>`;
    expect(() => parse(external)).toThrow(/external entity declarations/);

    const publicDecl = `<?xml version="1.0"?>
<!DOCTYPE board PUBLIC "-//W3C//DTD//EN" "http://evil.example/x.dtd">
<board/>`;
    expect(() => parse(publicDecl)).toThrow(/external entity declarations/);

    const parameter = `<?xml version="1.0"?>
<!DOCTYPE board [ <!ENTITY % payl SYSTEM "file:///etc/passwd"> ]>
<board/>`;
    expect(() => parse(parameter)).toThrow(/external entity declarations|only internal ENTITY/);
  });

  it('expands internal entities but caps the expansion count', () => {
    const withEntity = `<?xml version="1.0"?>
<!DOCTYPE board [ <!ENTITY tick "T"> ]>
<board>${'&tick;'.repeat(MAX_ENTITY_EXPANSIONS)}</board>`;
    expect(parse(withEntity).children[0].text).toBe('T'.repeat(MAX_ENTITY_EXPANSIONS));

    const overCap = `<?xml version="1.0"?>
<!DOCTYPE board [ <!ENTITY tick "T"> ]>
<board>${'&tick;'.repeat(MAX_ENTITY_EXPANSIONS + 1)}</board>`;
    expect(() => parse(overCap)).toThrow(/entity expansion limit/);
  });

  it('a recursive entity cannot run away', () => {
    // Entity values are literal text: a self-referential declaration substitutes
    // once and its own references are never re-parsed, so there is no recursion.
    const recursive = `<?xml version="1.0"?>
<!DOCTYPE board [ <!ENTITY a "&a;&a;" > ]>
<board>&a;</board>`;
    expect(parse(recursive).children[0].text).toBe('&a;&a;');
  });

  it('rejects an undefined entity instead of passing it through', () => {
    expect(() => parse('<board>&nope;</board>')).toThrow(/undefined entity/);
    expect(() => parse('<board>a & b</board>')).toThrow(/bare ampersand/);
  });

  it('numeric character references become text, not markup', () => {
    const doc = parse('<board>&#60;b&#62;x&#60;/b&#62; &amp;y;</board>');
    expect(doc.children[0].text).toBe('<b>x</b> &y;');
    expect(doc.children[0].children).toEqual([]);
  });

  it('rejects invalid UTF-8', () => {
    expect(() => parse(Buffer.from([0x3c, 0x62, 0x3e, 0xff, 0xfe, 0x3c, 0x2f, 0x62, 0x3e]))).toThrow(/valid UTF-8/);
  });

  it('rejects markup that is not well formed', () => {
    for (const text of [
      '<board><thread></board>',
      '<board><thread></thread>',
      '<board attr="1" attr="2"/>',
      "<board attr='unterminated>",
      '<board attr=unquoted/>',
      '<board attr="a<b"/>',
      '<!-- unterminated',
      '<![CDATA[ unterminated',
      '<!ENTITY broken>',
      '   ',
      '<>bad name</>',
    ]) {
      expect(() => parse(text)).toThrow(XmlError);
    }
  });

  it('skips comments and processing instructions', () => {
    const doc = parse('<?xml version="1.0"?><!-- c --><?pi data?><board><!-- d -->t</board>');
    expect(doc.children.map((c) => c.tag)).toEqual(['board']);
    expect(doc.children[0].text).toBe('t');
  });
});
