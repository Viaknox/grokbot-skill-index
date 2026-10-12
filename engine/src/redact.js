// Local scrubbing: runs on the user's machine before any text goes to a remote model.
// Replaces personal data and secrets with stable placeholders ([EMAIL_1], [KEY_2]…) so the judge can still
// see that the same email came up twice, without seeing the email.

// Private keys only (public keys and certificates are meant to be shared), header to footer, before anything else
// (including the owner's never-send words, which could otherwise rename "PRIVATE" in the header).
const PEM = /-----BEGIN (?:[A-Z0-9]+ ){0,4}PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ ){0,4}PRIVATE KEY-----/g;

// Credential words must be whole parts of the name (split at _, -, and camelCase), so "secretary", "tokenizer" and
// "passwordless" are ordinary words, while CLIENT_SECRET_CURRENT, apiKey and db-password are credentials.
const ONE = new Set(['secret', 'secrets', 'token', 'tokens', 'password', 'passwd', 'pwd', 'credential', 'credentials', 'apikey', 'passphrase']);
const PAIR = new Set(['api key', 'access key', 'private key', 'secret key', 'auth token']);
export function isCredentialName(match) {
  const name = match.slice(0, match.search(/["']?[ \t]*[:=]/));
  const parts = name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[\s_-]+/).filter(Boolean);
  const value = match.slice(match.search(/[:=]/) + 1).trim().replace(/^["']|["']$/g, '');
  if (value.length < 6 || /^\[[A-Z]+_\d+\]$/.test(value)) return false;   // too short, or already a placeholder
  return parts.some((p, i) => ONE.has(p) || PAIR.has(`${p} ${parts[i + 1]}`));
}

const PATTERNS = [
  // Secrets first, so a key that contains digits is not half-eaten by the phone rule.
  ['KEY', /\b(?:sk-[A-Za-z0-9_-]{16,}|sk-or-v1-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g],
  ['KEY', /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}|\bwhsec_[A-Za-z0-9]{10,}|\bglpat-[A-Za-z0-9_-]{16,}|\bnpm_[A-Za-z0-9]{20,}|\bya29\.[A-Za-z0-9_-]{20,}|\bsk-ant-[A-Za-z0-9_-]{10,}/g],
  ['KEY', /\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*/g],
  ['KEY', /(?<=:\/\/[^/\s:@]{1,64}:)[^@\s/]{1,128}(?=@)/g],   // password inside a URL
  // Any setting that holds a credential: AWS_SECRET_ACCESS_KEY=…, PASSWORD_HASH=…, accessKeyId: …, X-Api-Key: …,
  // CLIENT_SECRET="two words". The name (at most 64 characters, one character class, so it runs in linear time) and
  // the value are matched here; isCredentialName (above) decides whether the name really is a credential.
  ['KEY', /\b[A-Za-z][A-Za-z0-9_-]{0,63}["']?[ \t]*[:=][ \t]*(?:"[^"\n]{1,200}"|'[^'\n]{1,200}'|["']?[^\s"',;]{6,})/g, (m) => isCredentialName(m)],
  ['EMAIL', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g],
  ['CARD', /\b(?:\d[ -]?){12,18}\d\b/g],   // separators only between digits, never after the last one
  ['SSN', /\b\d{3}-\d{2}-\d{4}\b/g],
  ['PHONE', /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\b\d{2,4}[\s.-])\d{3,4}[\s.-]\d{3,4}\b/g],
  ['IP', /\b(?:\d{1,3}\.){3}\d{1,3}\b/g],
];

function luhn(digits) {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = Number(digits[i]);
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}

// Returns a scrubber that keeps one placeholder per distinct value across every text it sees.
// `terms` are the owner's own never-send words (an employer, a client, a person): matched whole-word,
// any case, before the built-in patterns, and replaced with [PRIVATE_n].
export function scrubber({ terms = [] } = {}) {
  const esc = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const own = terms.map(t => String(t).trim()).filter(Boolean).sort((a, b) => b.length - a.length);
  const patterns = [['KEY', PEM], ...(own.length ? [['PRIVATE', new RegExp(`(?<![\\p{L}\\p{N}])(?:${own.map(esc).join('|')})(?![\\p{L}\\p{N}])`, 'giu')]] : []), ...PATTERNS];
  const seen = new Map(); const counts = {};
  const label = (kind, value) => {
    const k = kind + '\u0000' + value;
    if (!seen.has(k)) { counts[kind] = (counts[kind] || 0) + 1; seen.set(k, `[${kind}_${counts[kind]}]`); }
    return seen.get(k);
  };
  return {
    scrub(text) {
      let s = String(text ?? '');
      for (const [kind, re, keep] of patterns) {
        s = s.replace(re, (m) => {
          if (keep && !keep(m)) return m;
          if (kind === 'CARD') { const d = m.replace(/\D/g, ''); if (d.length < 13 || !luhn(d)) return m; }
          return label(kind, m.trim());
        });
      }
      return s;
    },
    // Puts the real values back into text that came back from a model (e.g. a revised instruction), locally.
    unscrub(text) {
      let s = String(text ?? '');
      for (const [k, ph] of seen) s = s.split(ph).join(k.split('\u0000')[1]);
      return s;
    },
    counts: () => ({ ...counts }),
  };
}
