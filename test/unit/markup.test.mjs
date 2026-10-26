// Port of tests/Unit/MarkupTest.php — the C-XSS-1 fence around the only
// raw-HTML exit in the app (docs/03 C-XSS-1, C-XSS-2).

import { describe, expect, it } from 'vitest';
import { plain, render } from '../../src/security/markup.js';

describe('markup', () => {
  it('testBoldIsRendered', () => {
    expect(render('[b]hi[/b]')).toBe('<strong>hi</strong>');
  });

  it('testItalicIsRendered', () => {
    expect(render('[i]hi[/i]')).toBe('<em>hi</em>');
  });

  it('testUnderlineIsRendered', () => {
    expect(render('[u]hi[/u]')).toBe('<u>hi</u>');
  });

  it('testNestedFormatting', () => {
    expect(render('[b]bold [i]italic[/i][/b]')).toBe('<strong>bold <em>italic</em></strong>');
  });

  it('testMultiLevelNesting', () => {
    expect(render('[b][i][u]x[/u][/i][/b]')).toBe('<strong><em><u>x</u></em></strong>');
  });

  it('testCaseInsensitiveTags', () => {
    expect(render('[B]hi[/B]')).toBe('<strong>hi</strong>');
  });

  it('testNewlinesBecomeBreaks', () => {
    expect(render('line1\nline2')).toBe('line1<br>\nline2');
  });

  it('testBareUrlTag', () => {
    const out = render('[url]https://example.com/a[/url]');
    expect(out).toContain('<a href="https://example.com/a"');
    expect(out).toContain('rel="noopener noreferrer nofollow"');
  });

  it('testUrlWithLabel', () => {
    expect(render('[url=https://example.com]click here[/url]')).toBe(
      '<a href="https://example.com" rel="noopener noreferrer nofollow" target="_blank">click here</a>',
    );
  });

  it('testHttpUrlIsAccepted', () => {
    expect(render('[url]http://example.com[/url]')).toContain('href="http://example.com"');
  });

  it('testJavascriptUrlIsRejected', () => {
    const out = render('[url]javascript:alert(1)[/url]');
    expect(out).not.toContain('<a ');
    expect(out).toContain('[url]javascript:alert(1)[/url]');
  });

  it('testJavascriptUrlInAttributeIsRejected', () => {
    expect(render('[url=javascript:alert(1)]click[/url]')).not.toContain('<a ');
  });

  it('testDataUrlIsRejected', () => {
    expect(render('[url]data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==[/url]')).not.toContain('<a ');
  });

  it('testVbscriptUrlIsRejected', () => {
    expect(render('[url]vbscript:x[/url]')).not.toContain('<a ');
  });

  it('testProtocolRelativeUrlIsRejected', () => {
    expect(render('[url]//evil.com/x[/url]')).not.toContain('<a ');
  });

  it('testUrlAttributeInjectionIsNeutralized', () => {
    // Quotes can never break out of the href attribute: they are escaped.
    const out = render('[url=https://evil.com"onmouseover="alert(1)]x[/url]');
    expect(out).not.toContain('onmouseover="');
    expect(out).not.toContain('<a href="https://evil.com" ');
  });

  it('testUrlTagWithSpacesStaysInert', () => {
    // A payload with spaces cannot match the strict URL grammar and is rendered
    // as harmless literal text.
    const out = render('[url=https://evil.com" onmouseover="alert(1)]x[/url]');
    expect(out).not.toContain('<a ');
    expect(out).toContain('&quot;');
  });

  it('testImageIsRendered', () => {
    expect(render('[img]https://example.com/pic.png[/img]')).toBe(
      '<img src="https://example.com/pic.png" alt="user image" loading="lazy" class="post-image">',
    );
  });

  it('testImageWithJavascriptUrlIsRejected', () => {
    expect(render('[img]javascript:alert(1)[/img]')).not.toContain('<img');
  });

  it('testImageOnerrorInjectionIsNeutralized', () => {
    // The quote must be escaped so no onerror attribute can exist.
    const out = render('[img]https://x.com/a"onerror="alert(1)[/img]');
    expect(out).not.toContain('onerror="');
    expect(out.split('<img').length - 1).toBe(1);
    expect(out).toContain('&quot;');
  });

  // The slug marks what these two prove: C-XSS-1 is the escape-the-whole-input-
  // first boundary, and `vuln/xss_stored` inverts it (docs/04 §6).
  it('c-xss-1 testRawHtmlIsEscaped', () => {
    expect(render('<script>alert(1)</script>')).toBe('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('c-xss-1 testScriptInsideBoldIsEscaped', () => {
    expect(render('[b]<script>alert(1)</script>[/b]')).toBe('<strong>&lt;script&gt;alert(1)&lt;/script&gt;</strong>');
  });

  it('testEventHandlerInBodyIsEscaped', () => {
    expect(render('[b]hello" onmouseover="alert(1)[/b]')).not.toContain('onmouseover="');
  });

  it('testUnknownTagsRemainInertText', () => {
    const out = render('[script]evil()[/script]');
    expect(out).not.toContain('<script');
    expect(out).toContain('[script]evil()[/script]');
  });

  it('testUnclosedTagsRemainLiteral', () => {
    expect(render('[b]never closed')).toBe('[b]never closed');
  });

  it('testControlCharactersAreStripped', () => {
    expect(render('a\u0000b')).toBe('ab');
  });

  it('testBoundedWorkOnPathologicalInput', () => {
    const payload = '[b][i][u]'.repeat(2000) + 'x' + '[/u][/i][/b]'.repeat(2000);
    const start = Date.now();
    const out = render(payload);
    const elapsed = (Date.now() - start) / 1000;
    expect(out).toContain('<strong>');
    expect(elapsed).toBeLessThan(2);
  });

  it('testLongInputIsTruncated', () => {
    expect(render('a'.repeat(50000)).length).toBeLessThanOrEqual(21000);
  });

  it('testPlainTextPassthrough', () => {
    expect(render('just text')).toBe('just text');
  });

  it('testPlainStripsMarkup', () => {
    expect(plain('[b]hello[/b] [url=https://x.com]world[/url]')).toBe('hello world');
  });
});
