// Runtime expander for the scrubber corpus.
// Fixture files hold no secret shapes: the repo's gate 2 refuses any commit whose diff contains a key prefix or a PEM
// header, and GitHub's secret scanners would flag them too. So fixtures carry {{TOKEN args}} markers and the
// secret-looking text is built here, from a seeded generator, when a test runs. Every generated value is returned with
// the text so a test can assert that none of its characters survived scrubbing. The same seed always gives the same
// values, so a failure can be repeated.
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export const CORPUS_DIR = dirname(fileURLToPath(import.meta.url));

// mulberry32: a small seeded generator, good enough for test data and reproducible across platforms.
export function makeRng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
// A stable 32-bit seed from a name (FNV-1a), so each fixture gets its own values without a seed table.
export function seedOf(name) {
  let h = 0x811C9DC5;
  for (const ch of String(name)) { h ^= ch.charCodeAt(0); h = Math.imul(h, 0x01000193) >>> 0; }
  return h;
}

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', LOWER = 'abcdefghijklmnopqrstuvwxyz', DIGIT = '0123456789';
const ALNUM = UPPER + LOWER + DIGIT, B64 = ALNUM + '+/', B64URL = ALNUM + '-_', HEX = DIGIT + 'abcdef';
const pick = (rng, alphabet, n) => Array.from({ length: n }, () => alphabet[Math.floor(rng() * alphabet.length)]).join('');

// Value builders. Each takes the generator first so callers (and the fuzz suite) can seed them.
export const gen = {
  // A password-like value: letters and digits with at least one of each, so it never looks like a plain word or number.
  secret: (rng, n) => { const s = pick(rng, ALNUM, n).split(''); if (n >= 3) { s[0] = UPPER[Math.floor(rng() * 26)]; s[1] = LOWER[Math.floor(rng() * 26)]; s[2] = DIGIT[Math.floor(rng() * 10)]; } return s.join(''); },
  b64: (rng, n) => pick(rng, B64, n),
  b64url: (rng, n) => pick(rng, B64URL, n),
  hex: (rng, n) => pick(rng, HEX, n),
  // Known token shapes, assembled from pieces so this file never holds a literal shape either.
  prefix: (rng, kind) => {
    switch (String(kind).toLowerCase()) {
      case 'sk': return 'sk-' + pick(rng, ALNUM, 40);
      case 'skor': return 'sk-or-v1-' + pick(rng, HEX, 48);
      case 'skant': return 'sk-ant-' + pick(rng, B64URL, 40);
      case 'ghp': return 'ghp_' + pick(rng, ALNUM, 36);
      case 'akia': return 'AKIA' + pick(rng, UPPER + DIGIT, 16);
      case 'asia': return 'ASIA' + pick(rng, UPPER + DIGIT, 16);
      case 'xoxb': return 'xox' + 'b-' + pick(rng, DIGIT, 12) + '-' + pick(rng, DIGIT, 12) + '-' + pick(rng, ALNUM, 24);
      case 'xoxp': return 'xox' + 'p-' + pick(rng, DIGIT, 12) + '-' + pick(rng, DIGIT, 12) + '-' + pick(rng, HEX, 32);
      case 'aiza': return 'AIza' + pick(rng, B64URL, 35);
      case 'jwt': return 'eyJ' + pick(rng, B64URL, 20) + '.eyJ' + pick(rng, B64URL, 40) + '.' + pick(rng, B64URL, 43);
      case 'sklive': return 'sk_live_' + pick(rng, ALNUM, 24);
      case 'whsec': return 'whsec_' + pick(rng, ALNUM, 32);
      case 'glpat': return 'glpat-' + pick(rng, B64URL, 20);
      case 'npm': return 'npm_' + pick(rng, ALNUM, 36);
      case 'ya29': return 'ya29.' + pick(rng, B64URL, 60);
      case 'pypi': return 'pypi-' + pick(rng, B64URL, 80);
      default: throw new Error('unknown prefix kind ' + kind);
    }
  },
  // PEM pieces. The header text is built from parts so no file in the repo holds the literal marker.
  pemHead: (label) => '-----BEGIN ' + (label ? label + ' ' : '') + 'PRIVATE' + ' KEY-----',
  pemFoot: (label) => '-----END ' + (label ? label + ' ' : '') + 'PRIVATE' + ' KEY-----',
  pemLines: (rng, n) => Array.from({ length: n }, () => pick(rng, B64, 64)),
  // Basic auth: base64 of user:secret. Both the base64 and the plain secret must be gone afterwards.
  basic: (rng) => { const plain = gen.secret(rng, 16); return { b64: Buffer.from('user:' + plain).toString('base64'), plain }; },
};

const TOKEN = /\{\{([A-Z0-9_]+)(?: ([^}]*))?\}\}/g;

/** Expands {{TOKEN args}} markers in a template. Returns the text and every secret value that was put into it. */
export function expand(template, seed = 1) {
  const rng = makeRng(seed); const secrets = [];
  const text = String(template).replace(TOKEN, (_, name, arg = '') => {
    const n = Number(arg) || 0;
    switch (name) {
      case 'SECRET': { const v = gen.secret(rng, n || 24); secrets.push(v); return v; }
      case 'B64': { const v = gen.b64(rng, n || 40); secrets.push(v); return v; }
      case 'HEX': { const v = gen.hex(rng, n || 32); secrets.push(v); return v; }
      case 'PREFIX': { const v = gen.prefix(rng, arg); secrets.push(v); return v; }
      case 'BASIC': { const { b64, plain } = gen.basic(rng); secrets.push(b64, plain); return b64; }
      case 'PEM_HEAD': return gen.pemHead(arg.trim());
      case 'PEM_FOOT': return gen.pemFoot(arg.trim());
      case 'PEM_BODY': { const lines = gen.pemLines(rng, n || 3); secrets.push(...lines); return lines.join('\n'); }
      default: throw new Error('unknown corpus token ' + name);
    }
  });
  return { text, secrets };
}

/** Loads a fixture file, normalises CRLF to LF (the checkout may be CRLF on Windows), and expands it. */
export function fixture(name) {
  const raw = readFileSync(join(CORPUS_DIR, name), 'utf8').replace(/\r\n/g, '\n');
  return expand(raw, seedOf(name));
}

/** Self-attack fixtures (Phase 3): every corpus/attack-round-N.json, each a list of {name, terms?, input, gone?, keep?}. */
export function attackRounds() {
  return readdirSync(CORPUS_DIR).filter(f => /^attack-round-\d+\.json$/.test(f)).sort()
    .map(f => ({ file: f, cases: JSON.parse(readFileSync(join(CORPUS_DIR, f), 'utf8')) }));
}
