// Performance and ReDoS guards for the scrubber (docs/SCRUBBER-V2-BRIEF.md, design item 8 and the growth test).
// Budgets are machine-independent (PR #16 review: fixed millisecond limits failed on a slower reviewer machine and
// would fail on a loaded CI runner). Every budget is a RATIO against a baseline measured in this same process on the
// same text: one "unit" is the best time of a fixed set of plain, linear string and regex scans over the 60k chat
// (`unit()` below). On the reference machine (the v2 build box) one unit is about 8 ms and the brief's absolute
// numbers hold: sanitize of 60k in under 100 ms (~12 units) and every hostile payload under 500 ms (~60 units).
// A slower machine scales both sides, so the ratios test the scrubber's cost, not the hardware. Times are best-of-N
// after a warm-up, in milliseconds, and are printed with the unit so an absolute number is still visible in CI logs.
// Test data is built at run time from a seeded generator, so no secret shape sits in this file.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { scrubber } from '../src/redact.js';
import { gen, makeRng } from './corpus/expand.js';

const TERMS = ['Acme', 'Acme Corp'];
// Budgets in units: the brief's 100 ms and 500 ms divided by the ~8 ms reference unit.
const SANITIZE_UNITS = 12, REDOS_UNITS = 60;

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

// The baseline: four passes of plain linear work over the 60k chat (a bounded-class regex replace, Unicode
// normalisation and lower-casing, an email-shaped match, a name=value replace). Nothing here backtracks, so its time
// tracks the machine's single-thread string speed, which is what the scrubber's own passes are made of. Measured
// once per process (best of 5) and floored at 1 ms so timer noise on a very fast machine cannot inflate a ratio.
let UNIT = null;
function unit() {
  if (UNIT !== null) return UNIT;
  const text = mixed(60000);
  const work = () => {
    let n = 0;
    for (let i = 0; i < 4; i++) {
      n += text.replace(/[A-Za-z0-9+/=_-]{20,}/g, 'x').length;
      n += text.normalize('NFKC').toLowerCase().split('\n').length;
      n += (text.match(/[\p{L}\p{N}._%+-]{1,64}@[\p{L}\p{N}.-]{1,253}\.\p{L}{2,63}/gu) || []).length;
      n += text.replace(/(\w+)\s*[:=]\s*(\S+)/g, '$1').length;
    }
    return n;
  };
  UNIT = Math.max(best(work, 5), 1);
  console.log(`perf: 1 unit = ${UNIT.toFixed(2)} ms on this machine (reference machine: ~8 ms)`);
  return UNIT;
}
const units = (ms) => (ms / unit()).toFixed(1);

// Runs sanitize on a fresh scrubber (as a request would) with the never_send terms.
// A ScrubError is the contract's fail-closed outcome past the caps (held, no call), so it counts as finishing.
const sanitizeOnce = (text) => () => { try { scrubber({ terms: TERMS }).sanitize(text); } catch (e) { if (!(e instanceof Error) || e.name !== 'ScrubError') throw e; } };

test(`[promised] perf: sanitize of a realistic 60k-character chat takes under ${SANITIZE_UNITS} units (100 ms on the reference machine)`, () => {
  needSanitize();
  const text = mixed(60000);
  assert.equal(text.length, 60000);
  const t = best(sanitizeOnce(text));
  console.log(`perf: sanitize 60k = ${t.toFixed(1)} ms = ${units(t)} units (budget ${SANITIZE_UNITS})`);
  assert.ok(t < SANITIZE_UNITS * unit(), `sanitize of 60k took ${t.toFixed(1)} ms = ${units(t)} units`);
});

test(`[promised] perf: residual() alone on the same 60k chat (inside the ${SANITIZE_UNITS}-unit budget)`, async () => {
  needSanitize();
  const { residual } = await import('../src/redact.js');
  assert.equal(typeof residual, 'function', 'residual is not exported (the v2 contract)');
  const text = mixed(60000);
  const t = best(() => residual(text, { terms: TERMS }));
  console.log(`perf: residual 60k = ${t.toFixed(1)} ms = ${units(t)} units`);
  assert.ok(t < SANITIZE_UNITS * unit(), `residual of 60k took ${t.toFixed(1)} ms = ${units(t)} units`);
});

// Growth is a ratio between two sizes on the same machine, so it never needed an absolute number; it is measured
// best-of-5 in two interleaved rounds so JIT warm-up or one GC pause on the larger text cannot fake a superlinear curve.
test('[promised] perf: time grows roughly linearly from 10k to 80k characters', () => {
  needSanitize();
  const sizes = [10000, 20000, 40000, 80000]; const texts = Object.fromEntries(sizes.map(s => [s, mixed(s)]));
  const times = Object.fromEntries(sizes.map(s => [s, Infinity]));
  for (let round = 0; round < 2; round++) for (const s of sizes) times[s] = Math.min(times[s], best(sanitizeOnce(texts[s]), 5));
  console.log('perf: growth ' + sizes.map(s => `${s / 1000}k=${times[s].toFixed(1)}ms`).join(' '));
  const base = Math.max(times[20000], 1);   // a 1 ms floor, so timer noise on a very fast run cannot fail the ratio
  assert.ok(times[80000] < 6 * base, `80k took ${times[80000].toFixed(1)} ms, more than 6x the 20k time (${base.toFixed(1)} ms); linear would be 4x`);
});

// ---- ReDoS payloads: each must finish in under REDOS_UNITS units (500 ms on the reference machine) ----

const PAYLOADS = {
  'password- x10000': () => 'password-'.repeat(10000),
  'a. x40000 then @': () => 'a.'.repeat(40000) + '@',
  'PEM header x20000': () => ('-----BEGIN ' + 'PRIVATE KEY-----\n').repeat(20000),
  '{ x59000 on one line (HCL heads; PR #27 review)': () => 'AGENT: ' + '{'.repeat(59000),
  'a{ x29500 on one line': () => 'AGENT: ' + 'a{'.repeat(29500),
  'credentials:{ x4000 unclosed (PR #27 review)': () => 'AGENT: ' + 'credentials:{a:'.repeat(4000),
  'JSON Secret data:{ x4000 unclosed': () => 'kind: Secret\n' + '{"data":{"a":'.repeat(4000),
  'unclosed <table><th>password x1500 (PR #27 review)': () => '<table><tr><th>password</th></tr>'.repeat(1500),
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
  'https://user: then a x20000 then @ (PR #16: userinfo without a ceiling)': () => 'https://user:' + 'a'.repeat(20000) + '@h.example ',
  '<textarea name=password> x5000 (PR #16: closing tag search)': () => '<textarea name="password">x'.repeat(5000),
  'credentials: then 5000 nested YAML lines (PR #16: scope walk)': () => 'credentials:\n' + Array.from({ length: 5000 }, (_, i) => '  k' + i + ':\n    v: x').join('\n'),
};
for (const [name, make] of Object.entries(PAYLOADS)) {
  test(`[promised] redos: ${name} finishes in under ${REDOS_UNITS} units`, () => {
    needSanitize();
    const text = make();
    const t = best(sanitizeOnce(text), 2);
    console.log(`redos: ${name} (${text.length} chars) = ${t.toFixed(1)} ms = ${units(t)} units`);
    assert.ok(t < REDOS_UNITS * unit(), `${name} took ${t.toFixed(1)} ms = ${units(t)} units`);
  });
}
