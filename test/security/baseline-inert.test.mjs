// The inert-probe gate (docs/04 section 8).
//
// This file is NOT a proof case of any control — the case names deliberately
// carry no control slug, so no branch can skip it by declaring a control. It is a
// secondary differential: `verify:branch` expects it to pass on `main` and to
// fail on exactly the five XSS-family branches (xss_stored, xss_reflected,
// xss_dom, xss_config, ssti), each of which breaks one of the five probes below.

import { beforeAll, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { row, truncateAll } from '../helpers/db.mjs';
import { seedFixtures } from '../helpers/fixtures.mjs';
import { agent, loginAs } from '../helpers/http.mjs';
import { makeBoard, makeThread, makeUser } from '../helpers/users.mjs';
import { root } from '../../src/db/admin.js';

const PROBE_TITLE = 'Rendering probe (should be inert)';

/**
 * No executable construct may survive rendering, in any of its shapes.
 *
 * The one sanctioned element is the app's own external script, and it is matched
 * by an explicit pattern: an attacker-injected `<script src=…>` must not be able
 * to hide behind the exemption.
 */
const SANCTIONED_SCRIPT = /<script src="\/assets\/app\.js" defer><\/script>/g;

function assertInert(html) {
  const page = html.replaceAll(SANCTIONED_SCRIPT, '');
  expect(page).not.toBe(html); // the exemption actually matched the footer
  expect(page).not.toMatch(/<script[\s>]/i);
  expect(page).not.toMatch(/<img\s+src\s*=\s*x/i);
  // A live handler attribute, not the escaped text of a probe: `&quot;` proves
  // the quote never closed the attribute, so an `=` followed by `&` is inert.
  expect(page).not.toMatch(/<[a-z][^>]*\son[a-z]+\s*=\s*"/i);
  expect(page).not.toMatch(/href\s*=\s*"?\s*(javascript|data):/i);
  expect(page).not.toMatch(/<iframe|<object|<embed/i);
}

// The fixture is the subject of the first two probes, so this file does not
// truncate between cases: it starts from a wiped database plus the seeded
// fixture (beforeAll) and the last two cases only read files or add their own
// board.

describe('the seeded probe stays inert', () => {
  let probeThreadId = null;

  beforeAll(async () => {
    await truncateAll();
    await seedFixtures();
    const probe = await row('SELECT id FROM posts WHERE title = ?', [PROBE_TITLE]);
    expect(probe, 'the fixture must ship the sanitizer probe post').not.toBeNull();
    probeThreadId = Number(probe.id);
  });

  // Slugged with the control it proves: `vuln/xss_stored` inverts the escape-first
  // boundary (C-XSS-1), which is exactly what makes the stored probe live there, so the
  // branch run skips this case by declaration rather than pretending it holds.
  it('c-xss-1 the stored probe renders as escaped text, never as markup', async () => {
    const http = await agent();
    await loginAs(http, 'regular@test.theboard.local', 'TestPass123');

    const page = await http.get(`/thread/${probeThreadId}`);
    expect(page.status).toBe(200);

    // The payload is still legible to a human reader…
    expect(page.text).toContain('&lt;script&gt;');
    expect(page.text).toContain('&lt;img src=x onerror=alert(1)&gt;');
    // …and nothing executable survives.
    assertInert(page.text);
  });

  it('the search echo is inert on the way back out', async () => {
    const http = await agent();
    await loginAs(http, 'regular@test.theboard.local', 'TestPass123');

    const payload = '<script>alert(1)</script>" onmouseover="alert(2)';
    const page = await http.get(`/directory?q=${encodeURIComponent(payload)}`);
    expect(page.status).toBe(200);

    // The term does come back — as escaped text inside the input's value.
    expect(page.text).toContain('&lt;script&gt;alert(1)&lt;/script&gt;&quot; onmouseover=&quot;alert(2)');
    expect(page.text).not.toContain('" onmouseover="alert(2)');
    assertInert(page.text);
  });

  it('the one external script writes only through inert sinks', () => {
    const script = readFileSync(join(root(), 'public', 'assets', 'app.js'), 'utf8');

    expect(script).not.toMatch(/\.innerHTML\s*=/);
    expect(script).not.toMatch(/\.outerHTML\s*=/);
    expect(script).not.toMatch(/insertAdjacentHTML\s*\(/);
    expect(script).not.toMatch(/document\.write(i)?\s*\(/);
    expect(script).toMatch(/chip\.textContent\s*=/);
  });

  it('the page carries a strict CSP with no unsafe escape hatch', async () => {
    const res = await (await agent()).get('/login');
    const csp = res.headers['content-security-policy'];

    expect(csp).toBeDefined();
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toMatch(/unsafe-(inline|eval)/);
    expect(csp).not.toMatch(/script-src[^;]*\*/);
    // Inline script would defeat it even if the header were right.
    expect(res.text).not.toMatch(/<script>[^<]/i);
  });

  it('template syntax in stored text is data, not a template', async () => {
    const author = await makeUser('inert-author', 'inert-author@test.example', 'InertPass1234');
    const board = await makeBoard('Inert Board', true, Number(author.id));
    const threadId = Number(
      await makeThread(Number(board.id), Number(author.id), 'Template probe', '{{ 7*7 }} and {{7*7}} with [b]{{ 7 * 7 }}[/b]'),
    );

    const http = await agent();
    await loginAs(http, 'inert-author@test.example', 'InertPass1234');
    const page = await http.get(`/thread/${threadId}`);

    expect(page.text).toContain('{{ 7*7 }}');
    expect(page.text).not.toMatch(/with\s+<strong>49<\/strong>/);
    expect(page.text).not.toMatch(/>49</);
  });
});
