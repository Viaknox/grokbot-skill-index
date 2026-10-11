// Local scrubbing: runs on the user's machine before any text goes to a remote model.
// Replaces personal data and secrets with stable placeholders ([EMAIL_1], [KEY_2]…) so the judge can still
// see that the same email came up twice, without seeing the email.

const PATTERNS = [
  // Secrets first, so a key that contains digits is not half-eaten by the phone rule.
  ['KEY', /\b(?:sk-[A-Za-z0-9_-]{16,}|sk-or-v1-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g],
  ['KEY', /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}|\bwhsec_[A-Za-z0-9]{10,}|\bglpat-[A-Za-z0-9_-]{16,}|\bnpm_[A-Za-z0-9]{20,}|\bya29\.[A-Za-z0-9_-]{20,}|\bsk-ant-[A-Za-z0-9_-]{10,}/g],
  ['KEY', /\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*/g],
  ['KEY', /(?<=:\/\/[^/\s:@]{1,64}:)[^@\s/]{1,128}(?=@)/g],   // password inside a URL
  ['KEY', /\b(?:api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{6,}/gi],
  ['EMAIL', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g],
  ['CARD', /\b(?:\d[ -]?){13,19}\b/g],
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
  const patterns = own.length ? [['PRIVATE', new RegExp(`(?<![\\p{L}\\p{N}])(?:${own.map(esc).join('|')})(?![\\p{L}\\p{N}])`, 'giu')], ...PATTERNS] : PATTERNS;
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
