// Property fuzz and differential oracle for the scrubber (docs/SCRUBBER-V2-BRIEF.md, "Assurance").
// Seeded and dependency-free: FUZZ_SEED (default 20261012) and FUZZ_ITER (default 1500) are printed once, and every
// failure prints the seed, the iteration and the shape names (never the secret), so it can be replayed with
// FUZZ_SEED=<seed> FUZZ_ONLY=<iteration>. Secrets are built at run time, so no secret shape sits in this file.
// The contract it needs from redact.js: scrubber({terms}).sanitize(text) -> { text, held }, plus scrub and unscrub.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { scrubber } from '../src/redact.js';
import { gen, makeRng, seedOf } from './corpus/expand.js';
import { join, dirname } from 'node:path';

const SEED = Number(process.env.FUZZ_SEED ?? 20261012) >>> 0;
const ITER = Number(process.env.FUZZ_ITER ?? 1500);
const ONLY = process.env.FUZZ_ONLY === undefined ? null : Number(process.env.FUZZ_ONLY);
const TERMS = ['Acme', 'Acme Corp'];
const WIN = 8;   // a secret "survives" when any 8-character window of it is still in the output

const pick = (rng, list) => list[Math.floor(rng() * list.length)];
const between = (rng, lo, hi) => lo + Math.floor(rng() * (hi - lo + 1));

// True when any 8-character window of any fragment (or the whole fragment, if it is shorter) is still in `out`.
// Why windows: a scrubber that keeps the last 8 characters of a secret has still leaked it.
function survives(out, frags) {
  for (const f of frags) {
    if (f.length <= WIN) { if (out.includes(f)) return true; continue; }
    for (let i = 0; i + WIN <= f.length; i++) if (out.includes(f.slice(i, i + WIN))) return true;
  }
  return false;
}

// Classifies one text: 'scrub' when scrub() alone removed every fragment (and every never_send term), 'residual' when
// scrub() missed something but sanitize() held the text back, 'leak' when something survived into sanitized text that
// was not held. A fresh scrubber each time, so placeholder numbering never carries over between cases.
function judge(text, frags, terms) {
  const sc = scrubber({ terms });
  const scrubbed = sc.scrub(text);
  const san = sc.sanitize(text);
  const leaks = (out) => survives(out, frags) || (terms.length > 0 && /acme/i.test(text) && /acme/i.test(out));
  if (san.held !== true && leaks(san.text)) return 'leak';
  return leaks(scrubbed) ? 'residual' : 'scrub';
}

// ---- secret shapes: each returns the text to embed and the fragments that must not survive ----

const PREFIX_KINDS = ['sk', 'skor', 'skant', 'ghp', 'akia', 'asia', 'xoxb', 'xoxp', 'aiza', 'jwt', 'sklive', 'whsec', 'glpat', 'npm', 'ya29', 'pypi'];
const PEM_LABELS = ['', 'RSA', 'EC', 'DSA', 'OPENSSH', 'ENCRYPTED'];
const one = (value) => ({ value, frags: [value], multi: false });
const SHAPES = [
  ['secret', (r) => { const n = between(r, 8, 300); return [`secret/len=${n}`, one(gen.secret(r, n))]; }],
  ['b64', (r) => [`b64/len=${between(r, 24, 120)}`, one(gen.b64(r, between(r, 24, 120)))]],
  ['hex', (r) => { const n = pick(r, [32, 40, 64]); return [`hex/len=${n}`, one(gen.hex(r, n))]; }],
  ...PREFIX_KINDS.map(k => ['prefix:' + k, (r) => [`prefix:${k}`, one(gen.prefix(r, k))]]),
  ['pem', (r) => {
    const label = pick(r, PEM_LABELS); const lines = gen.pemLines(r, between(r, 2, 8));
    const foot = r() < 0.75;
    const value = [gen.pemHead(label), ...lines, ...(foot ? [gen.pemFoot(label)] : [])].join('\n');
    return [`pem/${label || 'plain'}${foot ? '' : '/no-footer'}`, { value, frags: lines, multi: true }];
  }],
  ['basic', (r) => { const { b64, plain } = gen.basic(r); return ['basic', { value: b64, frags: [b64, plain], multi: false }]; }],
];

const NAMES = ['password', 'PASSWORD', 'Password', 'passwd', 'apiKey', 'api-key', 'api_key', 'API_KEY', 'db.password', 'DB_PASSWORD',
  'AUTH_TOKEN', 'auth-token', 'authToken', 'client_secret', 'clientSecret', 'CLIENT_SECRET', 'secret', 'SECRET_KEY', 'access_token',
  'accessToken', 'private_key', 'PGPASSWORD', 'x-api-key'];
const ZERO_WIDTH = ['​', '‌', '‍', '﻿'];
const SPACES = ['', ' ', '  ', '\t', ' \t'];
const COMMENTS = ['', '', '', '  # my note', ' # old: Acme'];
const PRE = ['hey, can you look at this config?', 'thanks!', 'here is the file:', 'Meeting with Acme Corp about the roadmap'];
const POST = ['APP_NAME=tuneup', 'PORT=3000', 'that is all', 'tokenLimit=100000'];

// ---- contexts: how a value is wrapped. `split` says how a value may be broken across lines ----

const CTX = {
  dotenv:       { split: 'bs', f: ({ n, v, w, c }) => `${n}${w()}=${w()}${v}${c}` },
  'dotenv-dq':  { split: 'quote', f: ({ n, v, c }) => `${n}="${v}"${c}` },
  'dotenv-sq':  { split: 'quote', f: ({ n, v, c }) => `${n}='${v}'${c}` },
  export:       { split: 'bs', f: ({ n, v, c }) => `export ${n}=${v}${c}` },
  yaml:         { split: 'bs', f: ({ n, v, c }) => `${n}: ${v}${c}` },
  'yaml-block': { split: null, f: ({ n, v, c, r }) => `${n}: ${pick(r, ['|', '>'])}\n  ${v}${c}` },
  'json-compact': { split: null, f: ({ n, v }) => `{"${n}":"${v}","after":"x"}` },
  'json-pretty':  { split: null, f: ({ n, v }) => `{\n  "${n}": "${v}",\n  "after": "x"\n}` },
  bearer:       { split: null, noName: true, f: ({ v }) => `Authorization: Bearer ${v}` },
  basicauth:    { split: null, noName: true, f: ({ v }) => `Authorization: Basic ${v}` },
  cookie:       { split: null, noName: true, f: ({ v }) => `Cookie: sid=${v}` },
  url:          { split: null, noName: true, plainOnly: true, f: ({ v }) => `postgres://user:${v}@db.example.com:5432/app` },
  cli:          { split: 'bs', noName: true, f: ({ v, c, r }) => `mycli --${pick(r, ['password', 'token'])} ${v}${c}` },
  prose:        { split: null, f: ({ n, v, c }) => `my ${n}: ${v}${c}` },
  bracket:      { split: null, f: ({ n, v }) => `my ${n}: [${v}]` },
};
const PEM_CTX = {
  bare:         ({ v }) => `here is my key:\n${v}`,
  'dotenv-dq':  ({ n, v }) => `${n}="${v}"`,
  'yaml-block': ({ n, v }) => `${n}: |\n${v.split('\n').map(l => '  ' + l).join('\n')}`,
  json:         ({ n, v }) => `{"${n}":"${v.replaceAll('\n', '\\n')}"}`,
};

// Builds one fuzz case from its own seeded generator: the text, the fragments that must be gone, and a replay label
// (shape, context and tweaks; never a value). Each iteration has its own generator so FUZZ_ONLY can replay it alone.
function buildCase(i) {
  const r = makeRng((SEED ^ Math.imul(i + 1, 0x9E3779B1)) >>> 0);
  const [, make] = pick(r, SHAPES);
  const [shapeName, shape] = make(r);
  let { value, frags } = shape;
  const notes = [];
  const ctxName = shape.multi ? pick(r, Object.keys(PEM_CTX)) : pick(r, Object.keys(CTX));
  const ctx = CTX[ctxName];
  let name = pick(r, NAMES);
  if (r() < 0.12 && (shape.multi || !ctx.noName)) {   // a zero-width character hidden inside the credential name
    const at = between(r, 1, name.length - 1); name = name.slice(0, at) + pick(r, ZERO_WIDTH) + name.slice(at); notes.push('zero-width');
  }
  let ctxFinal = ctxName;
  if (!shape.multi && ctx.plainOnly && /[/+@:=]/.test(value)) ctxFinal = 'dotenv';   // userinfo cannot hold these characters
  const def = shape.multi ? null : CTX[ctxFinal];
  if (!shape.multi) {
    if (r() < 0.25 && value.length >= 20) {   // a never_send term inside the value
      const at = between(r, WIN, value.length - WIN); value = value.slice(0, at) + 'Acme' + value.slice(at);
      frags = [value.slice(0, at), value.slice(at + 4)]; notes.push('term-in-value');
    } else if (def.split && r() < 0.2 && value.length >= 2 * WIN) {   // a value broken across two lines
      const at = between(r, WIN, value.length - WIN); frags = [value.slice(0, at), value.slice(at)];
      value = frags.join(def.split === 'bs' ? '\\\n' : '\n'); notes.push('split:' + def.split);
    }
  }
  const w = () => pick(r, SPACES);
  const c = (!shape.multi && ['dotenv', 'yaml', 'export', 'cli', 'prose'].includes(ctxFinal)) ? pick(r, COMMENTS) : '';
  if (c) notes.push('comment');
  const block = shape.multi ? PEM_CTX[ctxName]({ n: name, v: value }) : def.f({ n: name, v: value, w, c, r });
  const lines = [...Array.from({ length: between(r, 0, 2) }, () => pick(r, PRE)), block, ...Array.from({ length: between(r, 0, 2) }, () => pick(r, POST))];
  let text = lines.join('\n');
  if (r() < 0.25) { text = text.replaceAll('\n', '\r\n'); notes.push('crlf'); }
  return { text, frags, label: `${shapeName} in ${ctxFinal}${notes.length ? ' +' + notes.join('+') : ''}` };
}

test('fuzz: no seeded secret survives sanitize() unless the text is held; scrub round-trips and is idempotent', () => {
  console.log(`fuzz: seed=${SEED} iterations=${ITER}${ONLY === null ? '' : ` only=${ONLY}`}`);
  assert.equal(typeof scrubber().sanitize, 'function', 'scrubber().sanitize is missing (the v2 contract)');
  const stats = { scrub: 0, residual: 0 }; const failures = [];
  const range = ONLY === null ? Array.from({ length: ITER }, (_, i) => i) : [ONLY];
  for (const i of range) {
    const { text, frags, label } = buildCase(i);
    const fail = (why) => failures.push(`seed=${SEED} iteration=${i} [${label}] ${why}`);
    try {
      const verdict = judge(text, frags, TERMS);
      if (verdict === 'leak') fail('a secret (or a never_send term) survived and the text was not held');
      else stats[verdict]++;
      const sc = scrubber({ terms: TERMS }); const once = sc.scrub(text);
      if (sc.unscrub(once) !== text) fail('unscrub(scrub(text)) !== text');
      if (sc.scrub(once) !== once) fail('scrub(scrub(text)) !== scrub(text)');
    } catch (e) { fail('threw ' + (e && e.name) + ': ' + (e && e.message ? String(e.message).slice(0, 80) : '')); }
  }
  console.log(`fuzz: caught by scrub alone=${stats.scrub}, caught only by the residual hold=${stats.residual}, failures=${failures.length}`);
  assert.equal(failures.length, 0, `${failures.length} fuzz failure(s); first ones:\n${failures.slice(0, 10).join('\n')}`);
});

// ---- differential oracle: sample secrets from gitleaks (MIT) and detect-secrets (Apache-2.0), see corpus/THIRD_PARTY.md ----

// Loads the oracle shapes (corpus/oracle-shapes.json, see THIRD_PARTY.md) and rebuilds every sample with the seeded
// generator: the file holds only line templates and value shapes (short prefixes, separators, charset + length), never a
// secret-shaped literal, so neither the repo gate nor a hosted secret scanner sees a credential, while the test still
// proves the scrubber removes a value of exactly that shape in exactly that context.
const ORACLE = join(dirname(fileURLToPath(import.meta.url)), 'corpus', 'oracle-shapes.json');
const ALPHA = { D: '0123456789', H: '0123456789abcdef', X: '0123456789ABCDEF', L: 'abcdefghijklmnopqrstuvwxyz', U: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  l: 'abcdefghijklmnopqrstuvwxyz0123456789', u: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', A: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' };
function loadOracle() {
  const doc = JSON.parse(readFileSync(ORACLE, 'utf8'));
  return doc.samples.map((s, i) => {
    const rng = makeRng(seedOf('oracle:' + i + ':' + s.source));
    const secret = s.value.map(p => p.l !== undefined ? p.l : Array.from({ length: p.n }, () => ALPHA[p.r][Math.floor(rng() * ALPHA[p.r].length)]).join('')).join('');
    const line = s.template.split('{{V}}').join(secret).replace(/\{\{R ([A-Za-z]) (\d+)\}\}/g, (m, c, n) => Array.from({ length: +n }, () => ALPHA[c][Math.floor(rng() * ALPHA[c].length)]).join('')).replace(/\{\{PEM_HEAD ?([A-Z0-9 ]*)\}\}/g, (m, l) => gen.pemHead(l.trim())).replace(/\{\{PEM_FOOT ?([A-Z0-9 ]*)\}\}/g, (m, l) => gen.pemFoot(l.trim()));
    return { source: s.source, line, secret };
  });
}

// Shannon entropy of a string over its own characters, in bits per character.
function entropy(s) {
  const n = new Map(); for (const ch of s) n.set(ch, (n.get(ch) || 0) + 1);
  let h = 0; for (const c of n.values()) h -= (c / s.length) * Math.log2(c / s.length);
  return h;
}
const KNOWN_SHAPE = /^(?:AKIA|ASIA|A3T|sk-|ghp_|gh[ousr]_|xox|AIza|eyJ|gl[a-z]{1,6}-|npm_|ya29\.|pypi-|AGE-SECRET-KEY-|ABSK|whsec_|sk_live_|pk_live_|rk_live_|-----BEGIN)/;

// Decision D13: a bare value with no context and no recognisable shape cannot be known to be a secret by any mechanism,
// so the bare assertion checks exactly what the contract's residual scan promises: a known token shape, or a contiguous
// run of 20+ token characters that is random enough (hex at 3.0 bits per character, anything else at 4.0) and is not a
// UUID (request and record ids look the same, so holding them would hold every log line).
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function knowable(secret) {
  const first = secret.split(/\r?\n/)[0];
  if (KNOWN_SHAPE.test(first) && first.length >= 20) return true;   // a real token of these shapes is never shorter
  return (secret.match(/[A-Za-z0-9+/=_-]{20,}/g) || []).some(run => !UUID.test(run) && entropy(run) >= (/^[0-9a-fA-F]+$/.test(run) ? 3.0 : 4.0));
}

// Sample lines the contract deliberately does not cover (docs/SCRUBBER-CONTRACT.md, "Known non-coverage"): counted with
// the not-knowable bare values, never asserted. Each entry is a needle in the decoded line and the reason.
const EXPECTED_MISSES = [
  ['secrete.assign(', 'a name that merely starts with a credential word (secrete, secretary) is not a credential, brief item 2'],
  ['other_value_here: ', 'no credential name on the line, no known shape, low entropy'],
];
test('oracle: every sample secret is gone (or the text is held), in its sample line and as a knowable bare value', () => {
  assert.equal(typeof scrubber().sanitize, 'function', 'scrubber().sanitize is missing (the v2 contract)');
  const samples = loadOracle();
  assert.ok(samples.length >= 300, 'oracle file looks too small: ' + samples.length);
  const stats = { line: { scrub: 0, residual: 0 }, bare: { scrub: 0, residual: 0 } }; const failures = [];
  const loose = { scrub: 0, residual: 0, leak: 0 };   // bare values that are not knowable: counted, not asserted
  samples.forEach((s, k) => {
    const frags = s.secret.split(/\r?\n/).filter(Boolean);
    for (const [mode, text] of [['line', s.line], ['bare', s.secret]]) {
      let verdict;
      try { verdict = judge(text, frags, []); } catch (e) { verdict = 'threw ' + (e && e.name); }
      if (mode === 'bare' && !knowable(s.secret)) { loose[verdict] = (loose[verdict] || 0) + 1; continue; }
      if (mode === 'line' && EXPECTED_MISSES.some(([needle]) => s.line.includes(needle))) { loose[verdict] = (loose[verdict] || 0) + 1; continue; }
      if (verdict === 'scrub' || verdict === 'residual') stats[mode][verdict]++;
      else failures.push(`#${k} ${s.source} (${mode}, ${verdict})`);
    }
  });
  const nLoose = Object.values(loose).reduce((a, b) => a + b, 0);
  console.log(`oracle: ${samples.length} samples; line: scrub=${stats.line.scrub} residual-only=${stats.line.residual}; bare knowable: scrub=${stats.bare.scrub} residual-only=${stats.bare.residual}; failures: line=${failures.filter(f => f.includes('(line,')).length} bare=${failures.filter(f => f.includes('(bare,')).length}`);
  console.log(`oracle: bare not knowable=${nLoose} (reported, not asserted)`);
  assert.equal(failures.length, 0, `${failures.length} oracle failure(s); first ones:\n${failures.slice(0, 20).join('\n')}`);
});
