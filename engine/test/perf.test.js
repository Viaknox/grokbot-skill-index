// Performance and ReDoS guards for the scrubber (docs/SCRUBBER-V2-BRIEF.md, design item 8 and the growth test).
// Budget: sanitize() of a realistic 60k-character chat in under 100 ms, time roughly linear from 10k to 80k characters,
// and every hostile payload under 500 ms. Times are best-of-N after a warm-up, in milliseconds, and are printed.
// Test data is built at run time from a seeded generator, so no secret shape sits in this file.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { scrubber } from '../src/redact.js';
import { gen, makeRng } from './corpus/expand.js';

const TERMS = ['Acme', 'Acme Corp'];

// Asserts the v2 entry point exists, so a v1 scrubber fails these tests with one clear message instead of a TypeError.
function needSanitize() {
  assert.equal(typeof scrubber({ terms: TERMS }).sanitize, 'function', 'scrubber().sanitize is missing (the v2 contract)');
}

// Builds a realistic chat of about `size` characters: prose, a dotenv block, compact and pretty JSON, a YAML block,
// headers, a few emails, phones and cards, and (once) a PEM block. The same seed gives the same text, so runs compare.
function mixed(size) {
  const r = makeRng(20261012);
  const parts = []; let len = 0; let n = 0;
  const add = (s) => { parts.push(s); len += s.length + 1; };
  const prose = [
    'User: hi, my deploy keeps failing on the staging box and I am not sure why. Can you look at the logs?',
    'Assistant: Sure. The error says the build step timed out; the session cookie is fine, so this is not an auth problem.',
    'User: ok, I work at Acme Corp so I cannot paste everything, but here is the relevant config.',
    'Assistant: Thanks. Please also check the tokenLimit setting and whether the secretary service restarted overnight.',
    'User: it did restart. Call me on +1 415-555-0132 or write to jane.doe@example.com if you need more.',
    'User: the card used for the plan is 4111 1111 1111 1111 and the invoice went to billing@example.org.',
  ];
  while (len < size) {
    n++;
    for (const p of prose) add(p + ' ' + 'The quick brown fox jumps over the lazy dog. '.repeat(1 + Math.floor(r() * 3)));
    add(`DB_PASSWORD=${gen.secret(r, 24)}\nAPI_KEY="${gen.prefix(r, 'sk')}"\nAPP_NAME=tuneup\nPORT=3000\nmax_tokens=128000`);
    add(`{"user":"jo${n}","token":"${gen.b64(r, 40)}","tokenLimit":100000,"after":"still here"}`);
    add(`{\n  "service": "api",\n  "credentials": {\n    "client_secret": "${gen.secret(r, 32)}",\n    "username": "jo"\n  }\n}`);
    add(`database:\n  host: db.example.com\n  password: |\n    ${gen.secret(r, 20)}\n    ${gen.secret(r, 20)}\n  pool: 5`);
    add(`GET /api/v1/rooms HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer ${gen.b64url(r, 40)}\nCookie: sid=${gen.hex(r, 32)}`);
    add(`postgres://app:${gen.secret(r, 16)}@db.example.com:5432/app`);
    if (n === 1) add([gen.pemHead('RSA'), ...gen.pemLines(r, 25), gen.pemFoot('RSA')].join('\n'));
  }
  return parts.join('\n').slice(0, size);
}

// Best time in milliseconds over `runs` runs of fn (after one untimed warm-up), so a GC pause does not decide the result.
function best(fn, runs = 3) {
  fn();
  let t = Infinity;
  for (let i = 0; i < runs; i++) { const a = performance.now(); fn(); t = Math.min(t, performance.now() - a); }
  return t;
}

// Runs sanitize on a fresh scrubber (as a request would) with the never_send terms.
const sanitizeOnce = (text) => () => scrubber({ terms: TERMS }).sanitize(text);

test('perf: sanitize of a realistic 60k-character chat takes under 100 ms', () => {
  needSanitize();
  const text = mixed(60000);
  assert.equal(text.length, 60000);
  const t = best(sanitizeOnce(text));
  console.log(`perf: sanitize 60k = ${t.toFixed(1)} ms (budget 100)`);
  assert.ok(t < 100, `sanitize of 60k took ${t.toFixed(1)} ms`);
});

test('perf: residual() alone on the same 60k chat (inside the 100 ms budget)', async () => {
  needSanitize();
  const { residual } = await import('../src/redact.js');
  assert.equal(typeof residual, 'function', 'residual is not exported (the v2 contract)');
  const text = mixed(60000);
  const t = best(() => residual(text, { terms: TERMS }));
  console.log(`perf: residual 60k = ${t.toFixed(1)} ms`);
  assert.ok(t < 100, `residual of 60k took ${t.toFixed(1)} ms`);
});

test('perf: time grows roughly linearly from 10k to 80k characters', () => {
  needSanitize();
  const times = {};
  for (const size of [10000, 20000, 40000, 80000]) times[size] = best(sanitizeOnce(mixed(size)));
  console.log('perf: growth ' + Object.entries(times).map(([k, v]) => `${k / 1000}k=${v.toFixed(1)}ms`).join(' '));
  const base = Math.max(times[10000], 1);   // a 1 ms floor, so timer noise on a very fast 10k run cannot fail the ratio
  assert.ok(times[80000] < 12 * base, `80k took ${times[80000].toFixed(1)} ms, more than 12x the 10k time (${base.toFixed(1)} ms)`);
});

// ---- ReDoS payloads: each must finish in under 500 ms ----

const PAYLOADS = {
  'password- x10000': () => 'password-'.repeat(10000),
  'a. x40000 then @': () => 'a.'.repeat(40000) + '@',
  'PEM header x20000': () => ('-----BEGIN ' + 'PRIVATE KEY-----\n').repeat(20000),
  'double quote x50000': () => '"'.repeat(50000),
  'backslash x50000': () => '\\'.repeat(50000),
  'open bracket x50000': () => '['.repeat(50000),
  '": " x30000': () => ': '.repeat(30000),
  'equals x50000': () => '='.repeat(50000),
  'PASSWORD= x10000': () => 'PASSWORD='.repeat(10000),
  'Authorization: Bearer x5000': () => 'Authorization: Bearer '.repeat(5000),
  'Acme x20000 (with terms)': () => 'Acme '.repeat(20000),
  '2000 YAML lines, growing indent': () => Array.from({ length: 2000 }, (_, i) => ' '.repeat(i) + 'secret: |').join('\n'),
  'password: newline x20000': () => 'password:\n'.repeat(20000),
  'token: | newline x20000': () => 'token: |\n'.repeat(20000),
  '<token> newline x20000': () => '<token>\n'.repeat(20000),
  'x@ x30000': () => 'x@'.repeat(30000),
  '4111 x20000': () => '4111 '.repeat(20000),
  'eyJ then a x50000': () => 'eyJ' + 'a'.repeat(50000),
};
for (const [name, make] of Object.entries(PAYLOADS)) {
  test(`redos: ${name} finishes in under 500 ms`, () => {
    needSanitize();
    const text = make();
    const t = best(sanitizeOnce(text), 2);
    console.log(`redos: ${name} (${text.length} chars) = ${t.toFixed(1)} ms`);
    assert.ok(t < 500, `${name} took ${t.toFixed(1)} ms`);
  });
}
