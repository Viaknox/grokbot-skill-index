// Local scrubbing: runs on the user's machine before any text goes to a remote model.
// Replaces personal data and secrets with stable placeholders ([EMAIL_1], [KEY_2]…) so the judge can still
// see that the same email came up twice, without seeing the email.

// Private keys (public keys and certificates are meant to be shared), found in one forward pass so many headers can't
// make it slow, and run before anything else (including the owner's never-send words, which could rename the header).
// A header with no footer takes the base64 lines after it, so a cut-off key never leaks either.
const PEM_HEAD = /-----BEGIN (?:[A-Z0-9]+ ){0,4}PRIVATE KEY-----/g;
const PEM_FOOT = /-----END (?:[A-Z0-9]+ ){0,4}PRIVATE KEY-----/g;
function scrubPem(s, label) {
  let out = '', at = 0, foot = null; PEM_HEAD.lastIndex = 0;
  for (let h; (h = PEM_HEAD.exec(s));) {
    if (h.index < at) continue;
    if (!foot || foot.index < h.index) { PEM_FOOT.lastIndex = h.index; foot = PEM_FOOT.exec(s) || { index: Infinity }; }
    let stop;
    if (foot.index !== Infinity) stop = foot.index + foot[0].length;
    else { const tail = /^(?:\r?\n[A-Za-z0-9+/=]{8,})*/.exec(s.slice(h.index + h[0].length, h.index + h[0].length + 65536)); stop = h.index + h[0].length + tail[0].length; }
    out += s.slice(at, h.index) + label('KEY', s.slice(h.index, stop)); at = stop; PEM_HEAD.lastIndex = stop;
  }
  return out + s.slice(at);
}

// Settings that hold a credential: API_KEY=…, PGPASSWORD=…, SECRET_KEY_BASE=…, client_secret: "two words",
// CLIENT_SECRET=correct horse battery staple. When in doubt this scrubs: a missed secret is far worse than an
// over-scrubbed setting. These are labelled SECRET (not KEY), so a bot repeating one is "unsure", never a hard fail.
// One linear-time pattern finds name + separator + value (a value runs to the end of the line, at most 200 characters);
// the name check is done in code. A name that is not a credential is kept and its value is checked again, so
// "settings: API_KEY=…" still catches the inner credential.
const ASSIGN = /(?<![A-Za-z0-9_-])[A-Za-z_][A-Za-z0-9_-]{0,127}["']?[ \t]*[:=][ \t]*(?:"[^"\n]{1,200}"|'[^'\n]{1,200}'|[^\n]{1,200})/g;
const STRONG = /pass(?:word|wd|phrase)|pwd|secret|credential|api_?key|access_?key|private_?key|auth_?token|access_?token|api_?token|bearer/;
const USAGE = new Set(['limit', 'limits', 'budget', 'count', 'counts', 'usage', 'size', 'max', 'min', 'window', 'rate', 'length', 'cost', 'costs', 'price', 'per']);
export function isCredentialName(name) {
  const flat = name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().replace(/-/g, '_');
  if (STRONG.test(flat.replace(/_/g, '')) || STRONG.test(flat)) return true;
  const parts = flat.split('_').filter(Boolean);   // "token" alone: a credential unless it is clearly a model-token setting
  return parts.some((p, i) => /^tokens?$/.test(p) && !USAGE.has(parts[i + 1] || '') && !USAGE.has(parts[i - 1] || ''));
}
function scrubAssignments(s, label) {
  return s.replace(ASSIGN, function one(m) {
    const sep = m.search(/["']?[ \t]*[:=]/), name = m.slice(0, sep), rest = m.slice(sep), cut = rest.search(/[:=]/) + 1;
    const value = rest.slice(cut).trim(), bare = value.replace(/^["']|["']$/g, '');
    if (isCredentialName(name) && bare.length >= 6 && !/^\[[A-Z]+_\d+\]$/.test(bare)) return name + rest.slice(0, cut) + rest.slice(cut).match(/^[ \t]*/)[0] + label('SECRET', value);
    return name + rest.slice(0, cut) + rest.slice(cut).replace(ASSIGN, one);   // not a credential: look inside the value
  });
}

const PATTERNS = [
  // Secrets first, so a key that contains digits is not half-eaten by the phone rule.
  ['KEY', /\b(?:sk-[A-Za-z0-9_-]{16,}|sk-or-v1-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g],
  ['KEY', /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}|\bwhsec_[A-Za-z0-9]{10,}|\bglpat-[A-Za-z0-9_-]{16,}|\bnpm_[A-Za-z0-9]{20,}|\bya29\.[A-Za-z0-9_-]{20,}|\bsk-ant-[A-Za-z0-9_-]{10,}/g],
  ['KEY', /\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*/g],
  ['KEY', /(?<=:\/\/[^/\s:@]{1,64}:)[^@\s/]{1,128}(?=@)/g],   // password inside a URL
  ['EMAIL', /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\b/g],   // bounded, so long junk can't make it slow
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
  // Order: private keys, then the owner's never-send words (never inside a [KIND_n] placeholder), then credential
  // settings, then the built-in shapes.
  const patterns = [['KEY', scrubPem], ...(own.length ? [['PRIVATE', new RegExp(`(?<![\\p{L}\\p{N}\\[])(?:${own.map(esc).join('|')})(?![\\p{L}\\p{N}]|_\\d+\\])`, 'giu')]] : []), ['SECRET', scrubAssignments], ...PATTERNS];
  const seen = new Map(); const counts = {};
  const label = (kind, value) => {
    const k = kind + '\u0000' + value;
    if (!seen.has(k)) { counts[kind] = (counts[kind] || 0) + 1; seen.set(k, `[${kind}_${counts[kind]}]`); }
    return seen.get(k);
  };
  return {
    scrub(text) {
      let s = String(text ?? '');
      for (const [kind, re] of patterns) {
        if (typeof re === 'function') { s = re(s, label); continue; }
        s = s.replace(re, (m) => {
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
