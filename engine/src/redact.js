// Local scrubbing (v2): runs on the user's machine before any text goes to a remote model. It replaces secrets and
// personal data with stable placeholders ([EMAIL_1], [KEY_2], [SECRET_3]…) so the judge still sees that the same value
// came up twice without seeing the value, and a separate residual scan then holds the whole text back if anything
// secret-looking survived. The design is "when in doubt, remove more": a missed secret is far worse than an
// over-scrubbed setting.
//
// Why a redesign (v2): four review rounds kept finding new leaks because the old pass capped a value at 200 characters
// and matched credential names loosely. v2 is line-oriented, removes a credential value to the END of its line or field
// (with continuations), reads whole PEM blocks, understands headers and URL userinfo, and adds a second, independent
// residual mechanism that fails closed. Name matching runs on a "folded view" of the text (invisible characters,
// combining marks, fullwidth forms and PowerShell backticks removed, every kept character still pointing at its
// original index), so a disguised name or term is still found and the original span, disguise included, is replaced.

export const SCRUBBER_VERSION = '2.0.0';

// Private-use sentinels wrap every placeholder WHILE scrubbing, so no following pattern can match text inside a placeholder
// (e.g. the EMAIL rule can't eat part of a [SECRET_1]). They become the public [KIND_n] form at the very end.
const OPEN = '\uE000', CLOSE = '\uE001';
const SENT = /\uE000([A-Z]+)_(\d+)\uE001/g;
// Only the kinds this scrubber mints are reserved tokens: a value such as `password=[ATTACK_1]` is live data, not a
// placeholder, and must be scrubbed and residual-checked like any other (PR #16 review).
const PUB = /\[(KEY|SECRET|PRIVATE|EMAIL|CARD|SSN|PHONE|IP)_(\d+)\]/g;

// Characters attackers insert to hide a credential NAME from a word match. We strip/normalise these only to decide
// "is this a credential"; the output text itself is never changed except by replacement.
const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF\u00AD]/g;
const CONFUSABLE = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ѕ': 's', 'ј': 'j', 'α': 'a', 'ο': 'o', 'ρ': 'p', 'ϲ': 'c',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'І': 'I',
  'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X' };
// A Cyrillic or Greek look-alike is mapped to its Latin twin when the word it sits in (its run of letters) also holds a
// Latin letter ("p\u0430ssword", and "\u0455\u0435\u0441ret" with three look-alikes side by side; PR #27 review), never inside a
// genuine Cyrillic or Greek word ("\u043F\u0430\u0440\u043E\u043B\u044C" must stay itself to match its own entry). The scan looks at most
// 64 letters each way, so a long Cyrillic text stays linear.
const LATIN = /[A-Za-z]/, LETTER = /\p{L}/u;
const confusableAt = (c, idx, str) => {
  if (!CONFUSABLE[c]) return c;
  for (let j = idx - 1, k = 0; j >= 0 && k < 64 && LETTER.test(str[j]); j--, k++) if (LATIN.test(str[j])) return CONFUSABLE[c];
  for (let j = idx + 1, k = 0; j < str.length && k < 64 && LETTER.test(str[j]); j++, k++) if (LATIN.test(str[j])) return CONFUSABLE[c];
  return c;
};
function foldName(name) {
  let s = String(name).replace(ZERO_WIDTH, '').normalize('NFKC');
  return s.replace(/[\u0400-\u04FF\u0370-\u03FF]/g, confusableAt);
}
// A name may arrive escaped: JSON "pass\u0077ord" or a URL parameter pass%77ord. Decode before the credential check.
function decodeName(name) {
  // HTML character references too (p&#97;ssword, p&#x61;ssword; PR #27 review).
  // Named references: the basic five plus accented Latin letters (p&aacute;ssword), which the name check then folds.
  name = name.replace(/&(amp|lt|gt|quot|apos|nbsp);/gi, (m, n) => ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' })[n.toLowerCase()])
    .replace(/&([A-Za-z])(acute|grave|circ|uml|tilde|ring|cedil|caron);/g, (m, c, k) => (c + { acute: '\u0301', grave: '\u0300', circ: '\u0302', uml: '\u0308', tilde: '\u0303', ring: '\u030A', cedil: '\u0327', caron: '\u030C' }[k]).normalize('NFC'));
  name = name.replace(/&#(\d{1,7});/g, (m, d) => String.fromCodePoint(Math.min(Number(d), 0x10FFFF))).replace(/&#x([0-9a-f]{1,6});/gi, (m, h) => String.fromCodePoint(Math.min(parseInt(h, 16), 0x10FFFF)));
  return name.replace(/\\u([0-9a-fA-F]{4})/g, (m, h) => String.fromCharCode(parseInt(h, 16)))
    // A run of %HH bytes is UTF-8 (contrase%C3%B1a is contraseña; PR #27 review); a run that is not valid UTF-8 falls
    // back to one character per byte.
    .replace(/(?:%[0-9a-fA-F]{2})+/g, (m) => { try { return decodeURIComponent(m); } catch { return m.replace(/%([0-9a-fA-F]{2})/g, (x, h) => String.fromCharCode(parseInt(h, 16))); } });
}

// --- Folded view. One linear pass builds a copy of the text with zero-width characters, soft hyphens, combining marks
// and backticks removed, fullwidth and decomposed letters folded to their plain form and Turkish dotless/dotted i folded
// to i. `map[j]` is the original index of folded character j and `rev[i]` the folded index at original index i, so a
// match on the view maps back to the exact original span (invisible characters included). ASCII takes a fast path, so
// ordinary chat costs one comparison per character.
const DROP = /[\u200B-\u200D\u2060\uFEFF\u00AD`\u202A-\u202E\u2066-\u2069]/;
const MARK = /\p{M}/u;
const DECOMPOSABLE = /[A-Za-zÀ-ɏͰ-ϿЀ-ӿ]/;
const NEEDS_FOLD = /[^\x20-\x5F\x61-\x7E\n\r\t]|\\\r?\n/;   // anything non-ASCII, a control character, a backtick, or a backslash-newline
// Per-character fold results, cached: a text uses a small alphabet, so each distinct character is normalised once.
const FOLD_CACHE = new Map();
function foldChar(c) {
  let r = FOLD_CACHE.get(c);
  if (r !== undefined) return r;
  if (DROP.test(c)) r = '';
  else if (MARK.test(c)) r = '';
  else {
    // Decompose and drop the accent only for Latin, Greek and Cyrillic letters (é → e, й → и); kana and other scripts
    // keep their precomposed form (パ must not become ハ). Compatibility forms expand (ﬃ → ffi, Ａ → A).
    const d = c.normalize('NFD');
    r = DECOMPOSABLE.test(d[0]) ? d[0] : c;
    const k = r.normalize('NFKC'); if (k.length >= 1 && k.length <= 4) r = k;
    if (r === 'ı') r = 'i'; else if (r === 'İ') r = 'I';
  }
  if (FOLD_CACHE.size < 8192) FOLD_CACHE.set(c, r);
  return r;
}
// A view maps folded offsets to original ones with o(j) and back with f(i). Plain ASCII text without backticks (most
// chat) is its own view, so the common case costs one regex test and no copy.
function fold(s) {
  const n = s.length;
  if (!NEEDS_FOLD.test(s)) return { folded: s, o: (j) => j, f: (i) => i };
  const parts = [], map = [], rev = new Array(n + 1);
  for (let i = 0; i < n; i++) {
    rev[i] = parts.length;
    const code = s.charCodeAt(i);
    if (code < 0x80) {
      // A backslash that ends the line joins it to the next (Java .properties, shell): drop both so "pass\<newline>word"
      // reads as one name on the view. Backticks are PowerShell's escape and are dropped too.
      if (code === 0x5C && (s[i + 1] === '\n' || (s[i + 1] === '\r' && s[i + 2] === '\n'))) { i += s[i + 1] === '\r' ? 2 : 1; rev[i] = parts.length; continue; }
      if (code === 0x60) continue;
      // A control character other than newline, carriage return or tab (e.g. U+001E record separator) reads as a space.
      parts.push(code < 0x20 && code !== 0x0A && code !== 0x0D && code !== 0x09 || code === 0x7F ? ' ' : s[i]); map.push(i); continue;
    }
    if (code >= 0x80 && code <= 0x9F) { parts.push(' '); map.push(i); continue; }
    if (code >= 0xD800 && code <= 0xDBFF && i + 1 < n) { parts.push(s[i], s[i + 1]); map.push(i, i + 1); rev[i + 1] = parts.length - 1; i++; continue; }
    let r = foldChar(s[i]);
    if (r.length === 1) r = confusableAt(r, i, s);   // look-alike → Latin only next to a Latin letter
    for (let k = 0; k < r.length; k++) { parts.push(r[k]); map.push(i); }
  }
  rev[n] = parts.length;
  return { folded: parts.join(''), o: (j) => (j < map.length ? map[j] : n), f: (i) => rev[i] };
}
const foldStr = (t) => fold(String(t)).folded;
// Passes that run back to back on unchanged text share one view instead of folding again (strings are immutable, so
// an identical reference means an identical view).
function viewer() { let last = null, view = null; return (s) => (s === last ? view : (last = s, view = fold(s))); }

// A name is a credential when one of its parts (split on _ - . and camelCase) is a credential word, or the parts glue
// into a compound signal like apikey/accesskey/clientsecret/authtoken. So "secretary" and "tokenizer" (single parts)
// are not credentials, while "SECRET_KEY", "clientSecret", "db.password" and "OPENAI-API-KEY" are. "token" alone is a
// credential unless it sits next to a usage word (tokenLimit, max_tokens, token_count), which are model-size settings.
// A credential word counts when it is not immediately followed by another letter, so it matches at the end of a longer
// name ("PGPASSWORD", "dbSecret") or as a plural ("passwords:", "secrets:") but not as the prefix of an unrelated word
// ("secretary", "tokenizer", "author"). A few storage suffixes glued on still count ("DBPASSWORDHASH", "MYSECRETVALUE";
// PR #27 review).
const STORE_SUFFIX = 'hash|value|val|str|string|text|data|enc|encrypted|b64|base64|plain|raw|key|keys|token|tokens|file|env|var|prod|production|dev|development|test|testing|staging|stage|qa|uat|live|local|sandbox|old|new|backup|bak|primary|secondary';   // environment suffixes too (APIKEYPROD; PR #27)   // BEARERTOKEN too (PR #27)
// "pass" at the end of an ordinary word (compass, bypass, trespass, surpass, overpass) is not a credential (PR #16 review).
const STRONG = new RegExp(`(password|passwd|pwd|passphrase|passcode|secret|credential|bearer|auth|(?<!com|by|tres|sur|over|under|fly)pass)s?(?:${STORE_SUFFIX})?(?![a-z])`);
// A compound must END at the end of a name part (optionally after a plural "s" or a storage suffix), so "cookiecutter"
// is not a cookie; the generic-looking ones must also START at a part, so "monkeyvalue" and "hockeyname" stay plain,
// while "DBAPIKEY" and "OPENAI_API_KEY" still count (viaknox PR #27 review).
const COMPOUND_TAIL = new RegExp(`^s?(?:${STORE_SUFFIX})?$`);
const COMPOUND_HEAD = /^(?:cookie|setcookie|keyname|keyvalue)$/;
function hasCompound(parts) {
  const joined = parts.join(''), starts = new Set(), ends = [];
  let at = 0; for (const p of parts) { starts.add(at); at += p.length; ends.push(at); }
  const re = new RegExp(COMPOUND.source, 'g');
  for (let i = 0; i < joined.length; i++) {
    re.lastIndex = i; const m = re.exec(joined); if (!m) break; i = m.index;
    const end = m.index + m[0].length, partEnd = ends.find(e => e >= end);
    if (!COMPOUND_TAIL.test(joined.slice(end, partEnd))) continue;
    if (COMPOUND_HEAD.test(m[0]) && !starts.has(m.index)) continue;
    return true;
  }
  return false;
}
const COMPOUND = /(seedphrase|seedwords|recoveryphrase|secretphrase|walletphrase|mnemonicphrase|apikey|accesskey|privatekey|secretkey|sessionkey|authtoken|accesstoken|apitoken|clientsecret|refreshtoken|authorization|proxyauthorization|setcookie|cookie|recoverycode|backupcode|verificationcode|securitycode|authcode|2facode|mfacode|keyname|keyvalue|x509data|derencodedkeyvalue|pwfile|passfile|passwdfile|passwordfile|secretfile|tokenfile|keyfile|credfile|credentialsfile|sessionid|jsessionid|phpsessid)/;
const WHOLE = new Set(['pass', 'pw', 'pin', 'otp', 'creds', 'cred', 'session', 'sessions', 'sid', 'sids', 'otps', 'cvv', 'cvv2', 'cvc', 'cvc2', 'csc', 'cvn',   // card verification codes (PR #27)
  'mnemonic', 'mnemonics',   // wallet recovery words (PR #27)   // whole parts only: cloudant_pw, db_pass, pin; never passage, spinner
  // the same words in other languages (name parts are lower-cased and NFKC-folded before this lookup)
  'passe', 'mdp', 'clé', 'cle', 'jeton', 'passwort', 'kennwort', 'geheimnis', 'schlüssel', 'schluessel', 'schlussel', 'psk', 'zugangsdaten',   // psk: WPA pre-shared key (PR #27)
  'contraseña', 'contrasena', 'clave', 'secreto', 'credenciales', 'senha', 'chave', 'chiave', 'segreto', 'wachtwoord', 'sleutel',
  'пароль', 'секрет', 'ключ', 'токен', 'パスワード', '秘密鍵', 'トークン', '密码', '密钥', '口令', '令牌', '비밀번호', '암호']);
// "key"/"keys" as the LAST part of a multi-part name is a credential (ssh_key, signing-key, iam-key) unless the part
// before it says the key is structural, not secret (public_key, primary_key, cache_key…). A bare "key:" stays plain.
const STRUCTURAL_KEY = new Set(['public', 'foreign', 'primary', 'sort', 'partition', 'hash', 'cache', 'row', 'index', 'composite', 'idempotency', 'dedup', 'translation', 'i18n', 'shortcut', 'hot', 'map', 'dict', 'object', 'array', 'lookup']);
const USAGE = new Set(['output', 'input', 'completion', 'completions', 'cached', 'prompt', 'context', 'reasoning', 'generation', 'response', 'total', 'used', 'remaining', 'limit', 'limits', 'budget', 'count', 'counts', 'usage', 'size', 'max', 'min', 'window', 'rate', 'length', 'cost', 'costs', 'price', 'per', 'requirements', 'policy', 'rotation', 'economy']);
function nameParts(name) {
  // Split on separators, camelCase, AND letter/digit boundaries, so "PASSWORD2" and "api_key_v2" break into whole
  // words ("password", "2") while "secretary" and "tokenizer" stay single parts and are not credentials.
  // Accents on Latin letters are dropped for the name check (pássword, contraseña -> contrasena); other scripts keep theirs.
  const flat = foldName(name).normalize('NFD').replace(/([A-Za-z])\p{M}+/gu, '$1').normalize('NFC').replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/([A-Za-z])(\d)/g, '$1 $2').replace(/(\d)([A-Za-z])/g, '$1 $2');
  return flat.split(/[\s_\-.:$]+/).map(p => p.toLowerCase()).filter(Boolean);
}
// Why exported: transcripts.js and tests reuse the exact same "is this a credential setting" decision.
export function isCredentialName(name) {
  const raw = nameParts(name);
  if (!raw.length) return false;
  // A compact version suffix (PASSWORDV2, APIKEYV3) splits as "passwordv" + "2": drop the "v" before a number part
  // (viaknox PR #27 review). The unsplit form is checked too, so nothing that matched before stops matching.
  const devers = raw.map((p, i) => (p.length > 1 && p.endsWith('v') && /^\d+$/.test(raw[i + 1] || '') ? p.slice(0, -1) : p));
  return credParts(raw) || (devers.some((p, i) => p !== raw[i]) && credParts(devers));
}
function credParts(parts) {
  // Numbers split off by the letter/digit cut are glued back for the compound check too ("APIKEYB64"; PR #27 review).
  const glued = parts.reduce((a, p) => (/^\d+$/.test(p) && a.length ? (a[a.length - 1] += p, a) : (a.push(p), a)), []);
  if (hasCompound(parts) || hasCompound(glued)) return true;
  if (parts.length >= 2 && /^keys?$/.test(parts[parts.length - 1]) && !STRUCTURAL_KEY.has(parts[parts.length - 2])) return true;
  return parts.some((p, i) => {
    if (STRONG.test(p) || WHOLE.has(p)) return true;
    // The letter/digit split cuts "dbpasswordb64" into "dbpasswordb" + "64"; glue a number back on so the b64 suffix is
    // still seen (viaknox PR #27 review).
    if (/^\d+$/.test(parts[i + 1] || '') && STRONG.test(p + parts[i + 1])) return true;
    // A usage word anywhere in the name keeps it a setting (max_output_tokens, cached_input_tokens; PR #27 review).
    if (/^tokens?$/.test(p)) return !parts.some(q => USAGE.has(q));
    return false;
  });
}
// HTTP header names whose value is a credential wherever the name appears (HTML meta http-equiv, attributes).
const HEADER_CRED = /^(?:set-cookie|cookie|authorization|proxy-authorization)$/i;

// --- PEM: whole private-key blocks, header to footer, in one forward pass (so thousands of headers can't make it slow).
// A header with no footer takes the rest of the input, because a cut-off key still leaks. A JSON-escaped block (the
// header is followed on the same line by the two characters backslash-n) ends at the closing quote instead, so the
// surrounding JSON survives. Public keys and certificates are meant to be shared, so only PRIVATE KEY blocks go. Extra
// spaces or tabs between the header words still count.
const PEM_HEAD = new RegExp('-----BEGIN[ \\t]+((?:[A-Z0-9]+[ \\t]+){0,32})PRIVATE[ \\t]+KEY-----', 'g');
// The footer that closes a block must carry the header's type words (an RSA block ends at an RSA footer, not at an EC
// one); a mismatched footer is treated like no footer and the block runs to the end of the input (PR #16 review).
const pemFootFor = (label) => new RegExp('-----END[ \\t]+' + label.trim().split(/[ \t]+/).filter(Boolean).map(w => w + '[ \\t]+').join('') + 'PRIVATE[ \\t]+KEY-----', 'g');
function scrubPem(s, label) {
  let out = '', at = 0; PEM_HEAD.lastIndex = 0;
  for (let h; (h = PEM_HEAD.exec(s));) {
    if (h.index < at) { PEM_HEAD.lastIndex = at; continue; }
    const afterHead = h.index + h[0].length;
    let stop;
    if (s[afterHead] === '\\' && s[afterHead + 1] === 'n') {
      // A JSON-escaped key ends at the first unescaped quote, even if real newlines occur before it. No local bound: a
      // block with no closing quote takes the rest of the input (the overall size cap still applies), so a long key is
      // never cut short (PR #16 review). The scan stays linear because the next header search resumes at `stop`.
      let q = afterHead;
      while (q < s.length) { if (s[q] === '"' && s[q - 1] !== '\\') break; q++; }
      stop = q;
    } else {
      const PEM_FOOT = pemFootFor(h[1]); PEM_FOOT.lastIndex = afterHead;
      const foot = PEM_FOOT.exec(s);
      stop = foot ? foot.index + foot[0].length : s.length;
    }
    out += s.slice(at, h.index) + label('KEY', s.slice(h.index, stop));
    at = stop; PEM_HEAD.lastIndex = stop;
  }
  return out + s.slice(at);
}

// A value that STARTS with a placeholder this pass already made (any kind but PRIVATE) is already scrubbed and must not
// be scrubbed again: that would mint a second, pointless placeholder and break idempotence (e.g. a report line
// `(agent said: "Authorization: [SECRET_1]")`). A PRIVATE placeholder at the start is different: `PASSWORD=[PRIVATE_1]-abc`
// is a never-send word inside a live secret, and the whole value must still go (the nested-restore case). Every
// value-capturing pass routes its label through this guard.
// The exemption holds only when nothing but closers, punctuation and whitespace follows the leading placeholder(s) on
// that line (`[SECRET_1]`, `"[KEY_1]"`, `[SECRET_1]")`). If a word follows (`[SECRET_1]CorrectHorse9!`, `[KEY_2] abc`),
// the whole value, placeholder included, is scrubbed: a secret pasted next to an old placeholder is still a secret (the
// placeholder's number is reserved, so the stored value is that literal text and unscrub restores it).
// A placeholder followed by a field delimiter is complete only when a PROVEN sibling follows the delimiter: another
// placeholder (`[SECRET_1], [SECRET_2]`) or a named field (`[SECRET_1],"after":"x"`, `[SECRET_1]; next=1`). Anything else
// after a closer or delimiter (`[SECRET_1])CorrectHorse9!`, `[SECRET_1], CorrectHorse9!`) is data pasted beside an old
// placeholder, and the whole value goes (PR #16 review).
const SIBLING_AFTER = /^[\s"'`)\]}]*[,;][\s"']*(?:\uE000[A-Z]+_\d+\uE001|(?:"[^"\n]{1,160}"|'[^'\n]{1,160}'|[\w.\-]{1,160})[ \t]*[:=])/;
const isPlaceholderValue = (v) => {
  const t = String(v).trim(), m = /^["']?(?:\uE000(?!PRIVATE_)[A-Z]+_\d+\uE001)+/.exec(t);
  if (!m) return false;
  const rest = t.slice(m[0].length).split('\n')[0];
  return /^[\s"'`)\]},;.]*$/.test(rest) || SIBLING_AFTER.test(rest);
};

// Index just past the `]` that closes the `[` at `start`, skipping quoted strings; the text end if unterminated. Linear.
function bracketEnd(s, start) {
  let depth = 0;
  for (let i = start; i < s.length; i++) {
    const c = s[i];
    if (c === '"' || c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; continue; }
    if (c === '[') depth++;
    else if (c === ']' && --depth === 0) return i + 1;
  }
  return s.length;
}

// How far a credential value reaches from the first value character. A quoted value runs to the matching quote (escaped
// quotes skipped); an unterminated quote runs onto following lines until it closes; a trailing backslash continues onto
// the next line; a YAML block scalar (| or >) or an empty value takes the deeper-indented block below it; otherwise the
// value runs to the end of the line (so a trailing # comment goes too; plan D1: nothing on the line after a credential
// separator survives, not even after a comma).
function valueEnd(s, start) {
  // Multi-line literals run to their own closing delimiter: triple quotes, backticks and shell/HCL heredocs
  // (password = <<EOF … EOF; PR #27 review). An unclosed one takes the rest of the input.
  const tq = s.slice(start, start + 3);
  // A basic multi-line string (""") honours backslash escapes, so \" does not close it (PR #16 review); a literal one (''')
  // has no escapes.
  if (tq === '"""' || tq === "'''") { for (let i = start + 3; i < s.length; i++) { if (tq === '"""' && s[i] === '\\') { i++; continue; } if (s.startsWith(tq, i)) { let e = i + 3; while (e < s.length && e < i + 5 && s[e] === tq[0]) e++; return e; } } return s.length; }
  if (s[start] === '`') { for (let i = start + 1; i < s.length; i++) { if (s[i] === '\\') { i++; continue; } if (s[i] === '`') return i + 1; } return s.length; }
  const hd = /^<<[-~]?[ \t]*(["']?)([A-Za-z_]\w{0,40})\1/.exec(s.slice(start, start + 60));
  if (hd) {
    for (let ls = s.indexOf('\n', start); ls >= 0; ) { const le0 = s.indexOf('\n', ls + 1), le = le0 < 0 ? s.length : le0; if (s.slice(ls + 1, le).trim() === hd[2]) return le; if (le0 < 0) break; ls = le0; }
    return s.length;
  }
  // JSON allows any whitespace after the colon, newlines included ({"password":\n"x"}; PR #16 review): a quoted key
  // whose value starts on a later line takes that quoted value, whatever its indent.
  if ((s[start] === '\n' || s[start] === '\r') && /["']\s*:\s*$/.test(s.slice(Math.max(0, start - 200), start))) {
    let p = start; while (p < s.length && /\s/.test(s[p])) p++;
    if (s[p] === '"') { for (let i = p + 1; i < s.length; i++) { if (s[i] === '\\') { i++; continue; } if (s[i] === '"') return i + 1; } return s.length; }
  }
  const q = s[start];
  if (q === '"' || q === "'") {
    let i = start + 1;
    for (; i < s.length; i++) { if (s[i] === '\\') { i++; continue; } if (s[i] === q) return i + 1; }
    return s.length;
  }
  let nl = s.indexOf('\n', start);
  if (nl < 0) nl = s.length;
  const firstLine = s.slice(start, nl);
  const trimmed = firstLine.trim();
  // Block-scalar headers allow the indent and chomping indicators in either order (|-2 and |2-), PR #16 review.
  // A comment-only first line (password: # prod) and a bare scheme word (Authorization: Bearer, folded onto the next
  // line) are empty values too: the deeper-indented lines below hold the credential (PR #16 review).
  const emptyish = trimmed === '' || /^#/.test(trimmed) || /^(?:basic|bearer|digest)$/i.test(trimmed);
  if (emptyish || /^(?:!\S*[ \t]+)?[|>](?:[+-]?\d*|\d+[+-])$/.test(trimmed)) {
    // The key's own indent, read from its line start (a lastIndexOf, not a slice-and-match over the whole prefix, which
    // made thousands of empty "password:" lines quadratic).
    const lineStart0 = s.lastIndexOf('\n', start - 1) + 1;
    let indent = 0; while (s[lineStart0 + indent] === ' ' || s[lineStart0 + indent] === '\t') indent++;
    let i = nl;
    while (i < s.length) {
      const lineStart = i + 1;
      let lineEnd = s.indexOf('\n', lineStart); if (lineEnd < 0) lineEnd = s.length;
      const line = s.slice(lineStart, lineEnd);
      // An indentless YAML sequence (password:\n- x) at the key's own indent still belongs to an empty value (PR #27).
      if (line.trim() !== '' && (line.match(/^\s*/) || [''])[0].length <= indent && !(emptyish && (line.match(/^\s*/) || [''])[0].length === indent && /^\s*-(?:\s|$)/.test(line))) break;
      i = lineEnd;
    }
    return i;
  }
  // A trailing backslash continues the value on the next line; the line may end in \r before the \n (CRLF input).
  // Walked in a loop, not by recursion, so thousands of continued lines cannot overflow the stack (PR #16 review).
  let line = firstLine;
  while (/\\\r?$/.test(line) && nl < s.length) {
    const from = nl + 1;
    nl = s.indexOf('\n', from); if (nl < 0) nl = s.length;
    line = s.slice(from, nl);
  }
  return nl;
}

// Replaces every [start, end, kind] interval in one ordered pass; overlapping or empty spans and spans that are already
// placeholders are skipped. Passes that discover several spans at once (tables, scopes) gather intervals and call this.
function applyIntervals(s, ivs, label) {
  if (!ivs.length) return s;
  ivs.sort((a, b) => a[0] - b[0]);
  let out = '', at = 0;
  for (const [a, b, kind] of ivs) { if (a < at || b <= a) continue; const v = s.slice(a, b); if (!v.trim() || isPlaceholderValue(v)) continue; out += s.slice(at, a) + label(kind, v); at = b; }
  return out + s.slice(at);
}

// Runs a regex over the folded view and replaces, in the ORIGINAL text, the span that `pick` chooses from each match
// (folded offsets), so a token hidden with invisible characters is removed whole. Spans already consumed are skipped.
function applyOnView(s, view, re, label, pick) {
  const { folded } = view; let out = '', at = 0; re.lastIndex = 0;
  for (let m; (m = re.exec(folded));) {
    const r = pick(m); if (!r) continue;
    const so = view.o(r.from), eo = view.o(r.to);
    if (so < at) continue;
    const span = s.slice(so, eo);
    if (isPlaceholderValue(span)) continue;
    out += s.slice(at, so) + label(r.kind, span); at = eo;
    if (re.lastIndex < r.to) re.lastIndex = r.to;
  }
  return out + s.slice(at);
}

// Matches a setting name and its separator at a word boundary: a bare name (API_KEY=, client_secret:) or a quoted one
// ("password":, 'PASSWORD'=). Separators: = : := => -> ~= != == <<< and the Unicode look-alikes (ratio ∶, modifier colon ꞉,
// small colon ﹕, fullwidth ＝ ：, arrow →); a comparison still shows the password. The name class accepts backslashes and
// percent signs (escaped names are decoded before the check) and the internal placeholder sentinels (a never-send word
// already turned into a placeholder is resolved back). Bounded classes only, so hostile input stays linear.
const ASSIGN_START = new RegExp(
  '(?<![\\p{L}\\p{N}_$.\\-])' +
  '(["\']?)([\\p{L}\\p{N}_$\\uE000\\uFF21-\\uFF5A\\u200B-\\u200D\\u2060\\uFEFF][\\p{L}\\p{N}_$.\\-\\\\%\\u200B-\\u200D\\u2060\\uFEFF\\uE000\\uE001]{0,160})\\1' +
  // A short qualifier may sit between the name and the separator: "password (prod):", "token [staging]:", "key/prod:".
  '(?:[ \\t]*(?:\\([^()\\n]{1,40}\\)|\\[[^\\[\\]\\n]{1,40}\\]|/[\\p{L}\\p{N}_\\-]{1,40}))?[ \\t]*\\]?[ \\t]*(::=|:=|\\?=|\\+=|=>|->|~=|!=|==|<<<|[:=\\u2236\\uA789\\uFE55\\uFF1D\\uFF1A\\u2192])[ \\t]*', 'gu');

// Scans the folded view for a credential NAME + separator and removes the value (measured on the original text, so
// quotes, brackets and continuation lines are honoured) to its end; a non-credential name is left in place and scanning
// continues inside its value, so "settings: API_KEY=…" still catches the inner one. Runs after never_send so a disguised
// name (OPENAI-API-KEY with never_send OpenAI) is resolved back before the check.
function scrubAssignments(s, view, label, resolve) {
  const { folded } = view;
  let out = '', at = 0; ASSIGN_START.lastIndex = 0;
  for (let m; (m = ASSIGN_START.exec(folded));) {
    const sepEndF = m.index + m[0].length;
    const sepEnd = view.o(sepEndF);
    if (sepEnd < at) continue;
    const name = resolve(decodeName(m[2]));
    // A credential-named field whose value is an object ("credentials": { … }), or an array of objects, is structural:
    // descend into it rather than blanking the brace, so the secret fields inside are found one by one. A plain array
    // ("api_keys": ["…", "…"]) is a list of secrets and goes whole, to its closing bracket.
    // A brace only opens a structure when it holds a key/value and closes the value; "{noop}hunter2" and
    // "{bcrypt}$2a$…" are password-storage prefixes and the whole value goes (viaknox PR #27 review).
    // The brace must open with a key and a non-empty value, and a shell "export NAME={…}" is always a string
    // (export PASSWORD={hunter2:}; PR #16 review).
    const structured = s[sepEnd] === '{' && !/(?:^|\n)[ \t]*export[ \t]+[^\n]*$/.test(s.slice(Math.max(0, sepEnd - 200), sepEnd)) && (() => { const e = braceEnd(s, sepEnd); return /^\s*(?:"[^"\n]*"|'[^'\n]*'|\[[^\]\n]*\]|[\p{L}\p{N}_$.\-]+)\s*[:=]\s*[^\s,;}]/u.test(s.slice(sepEnd + 1, e)) && /^[ \t]*(?:[,;}\]\r\n]|$)/.test(s.slice(e + 1, e + 3)); })();
    if (isCredentialName(name) && !structured) {
      let end;
      // An array under a credential name goes whole even when it holds objects: the fields inside (`value`, `key`) are
      // often not credential names themselves, so descending would leave them (PR #27 review).
      if (s[sepEnd] === '[') { end = bracketEnd(s, sepEnd); }
      else {
        // An empty value whose indented block is itself a YAML map ("creds:" then "  token: …") is structural too:
        // descend into it so each child key is judged on its own, instead of blanking the whole map.
        let nl = s.indexOf('\n', sepEnd); if (nl < 0) nl = s.length;
        if (s.slice(sepEnd, nl).trim() === '' && /^[ \t]+[^\s:#\-][^\s:]{0,160}:(?:[ \t]|$)/m.test(s.slice(nl + 1, nl + 200).split(/\n(?=[ \t]*\S)/)[0] || '')) { ASSIGN_START.lastIndex = sepEndF; continue; }
        end = valueEnd(s, sepEnd);
      }
      const value = s.slice(sepEnd, end), t = value.trim();
      if (t && !isPlaceholderValue(t)) {
        out += s.slice(at, sepEnd) + label('SECRET', value);
        at = end; ASSIGN_START.lastIndex = view.f(end); continue;
      }
    }
    // Not a credential: resume right after the NAME (not after the separator), so a qualifier or separator that the
    // match swallowed ("example.test/login?password=") is scanned again and the real name is found.
    ASSIGN_START.lastIndex = m.index + m[1].length + m[2].length;
  }
  return out + s.slice(at);
}

// A quoted key that is not identifier-shaped ("api key": …, 'password field': …) is read whole and judged like any
// other setting name (PR #27 review). Identifier-shaped keys are left to scrubAssignments.
const QUOTED_KEY = /(["'])([^"'\n]{1,80})\1[ \t]*[:=][ \t]*/gu;
function scrubQuotedKeys(s, label, resolve) {
  let out = '', at = 0; QUOTED_KEY.lastIndex = 0;
  for (let m; (m = QUOTED_KEY.exec(s));) {
    const name = resolve(m[2]);
    if (/^[\p{L}\p{N}_$.\-]+$/u.test(name) || !isCredentialName(name)) continue;
    const vs = m.index + m[0].length; if (s[vs] === '{') continue;
    const ve = s[vs] === '[' ? bracketEnd(s, vs) : valueEnd(s, vs), v = s.slice(vs, ve);
    if (!v.trim() || isPlaceholderValue(v.trim())) continue;
    out += s.slice(at, vs) + label('SECRET', v); at = ve; QUOTED_KEY.lastIndex = ve;
  }
  return out + s.slice(at);
}

// Line forms that carry no separator at all, handled line by line in one forward walk:
//  - two tokens, the first a credential name at the line start (after an optional export/setenv/set, or a prefix with no
//    spaces such as //registry/:): "password CorrectHorse9!", "export PASSWORD x", "//r/:_authToken x". Prose such as
//    "I forgot my password yesterday" has more tokens and the name is not at the line start, so it survives;
//  - a credential name followed by a comma (CSV row "password,"…"", a quoted field may span lines);
//  - a CSV header with a credential column: that column goes in every following row with the same number of commas,
//    until a blank line;
//  - a YAML explicit key "? password" followed by a line starting with ":".
const TWO_TOKENS = /^[ \t]*(?:(?:export|setenv|set)[ \t]+)?(\S+)[ \t]+(\S+)[ \t]*$/;
const NAME_COMMA = /^[ \t]*["']?([\p{L}\p{N}_$.\-]{1,160})["']?,/u;
const IDENT_CELL = /^[ \t]*["']?[\p{L}\p{N}_$.\-]{1,60}["']?[ \t]*$/u;
// A short multiword column label ("Login Name", "Web Site URL"): up to four words.
const LABEL_CELL = /^[ \t]*["']?[\p{L}\p{N}_$.\-]{1,40}(?:[ \t]+[\p{L}\p{N}_$.\-]{1,40}){1,3}["']?[ \t]*$/u;
const YAML_Q = /^[ \t]*\?[ \t]+([\p{L}\p{N}_$.\-]{1,160})[ \t]*$/u;
const ENV_LINE = /^[ \t]*(?:ENV|ARG|export|set|setenv|env)[ \t]+/;
// "key"/"keys" as the whole name is a credential only in the dotenv form: the line is key=value or export key=value.
// A YAML/JSON label (key: user_id, {"key": "user_id"}) is a structural key and stays (integrator decision, review 5).
const BARE_KEY_LINE = /^[ \t]*(?:export[ \t]+)?keys?[ \t]*=[ \t]*/i;
const BARE_NAME = /^[ \t]*(["']?)([\p{L}_$][\p{L}\p{N}_$.\-]{0,160})\1[ \t]*(?:[;#][^\n]*)?$/u;   // an inline ; or # comment may follow
const SEP_LINE = /^[ \t]*(:=|=>|->|~=|[:=\u2236\uA789\uFE55\uFF1D\uFF1A\u2192])[ \t]*/;
// One CSV row from `i`, honouring double-quoted cells (which may contain commas and newlines). Returns the cell spans
// and the index of the newline that ends the row.
function csvRow(s, i) {
  const cells = []; let j = i, start = i, q = false;
  for (; j < s.length; j++) { const c = s[j]; if (c === '"') { q = !q; continue; } if (!q && c === ',') { cells.push([start, j]); start = j + 1; } else if (!q && c === '\n') break; }
  cells.push([start, j]); return { cells, end: j };
}
const trailingName = (tok) => (tok.replace(/[:=]+$/, '').replace(/["']$/, '').match(/[\p{L}\p{N}_$.\-]+$/u) || [''])[0];
// The judge's own role labels ("USER: AUTH x", "AGENT: …") are not part of the line a person typed (PR #27 review).
const ROLE_PREFIX = /^(?:USER|AGENT|AGENT INSTRUCTIONS|USER ACTION \(not a message the user typed\)):[ \t]*/;
function scrubLineForms(s, label, resolve) {
  let out = '', at = 0, i = 0; let csv = null;
  while (i < s.length) {
    let nl = s.indexOf('\n', i); if (nl < 0) nl = s.length;
    let line = s.slice(i, nl).replace(/\r$/, '');
    { const rp = ROLE_PREFIX.exec(line); if (rp) { i += rp[0].length; line = line.slice(rp[0].length); } }
    let m;
    if (csv && line.trim() === '') csv = null;
    if ((m = BARE_KEY_LINE.exec(line)) && line.length > m[0].length) {
      const vStart = i + m[0].length, end = valueEnd(s, vStart);
      if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) { out += s.slice(at, vStart) + label('SECRET', s.slice(vStart, end)); at = end; nl = Math.max(nl, end); }
    } else if ((m = ENV_LINE.exec(line)) && !TWO_TOKENS.test(line)) {
      // ENV USER=app PASSWORD x HOST=db: a bare credential name token takes the token after it.
      const toks = []; const TOK = /\S+/g; TOK.lastIndex = m[0].length;
      for (let t; (t = TOK.exec(line));) toks.push({ text: t[0], at: i + t.index });
      for (let k = 0; k + 1 < toks.length; k++) {
        const t = toks[k], v = toks[k + 1];
        if (!/[=:]/.test(t.text) && isCredentialName(resolve(t.text)) && !/[=:]/.test(v.text) && v.at >= at && !isPlaceholderValue(v.text)) { out += s.slice(at, v.at) + label('SECRET', v.text); at = v.at + v.text.length; k++; }
      }
    } else if ((m = TWO_TOKENS.exec(line)) && isCredentialName(resolve(trailingName(m[1])))) {
      const vStart = i + line.lastIndexOf(m[2]), vEnd = vStart + m[2].length;
      if (vStart >= at && !isPlaceholderValue(m[2])) { out += s.slice(at, vStart) + label('SECRET', m[2]); at = vEnd; }
    } else if ((m = NAME_COMMA.exec(line)) && isCredentialName(resolve(m[1]))) {
      const vStart = i + m[0].length, end = valueEnd(s, vStart);
      if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) { out += s.slice(at, vStart) + label('SECRET', s.slice(vStart, end)); at = end; nl = Math.max(nl, end); }
    } else if ((m = YAML_Q.exec(line)) && isCredentialName(resolve(m[1])) && nl < s.length) {
      let nl2 = s.indexOf('\n', nl + 1); if (nl2 < 0) nl2 = s.length;
      const next = s.slice(nl + 1, nl2), c = /^[ \t]*:[ \t]*/.exec(next);
      if (c) { const vStart = nl + 1 + c[0].length, end = valueEnd(s, vStart); if (vStart >= at && s.slice(vStart, end).trim()) { out += s.slice(at, vStart) + label('SECRET', s.slice(vStart, end)); at = end; nl = Math.max(nl, end); } }
    } else if ((m = BARE_NAME.exec(line)) && isCredentialName(resolve(m[2])) && nl < s.length) {
      // name / separator / value on consecutive lines: the name alone on its line, the separator on the next (with or
      // without the value), the value on the line after.
      let nl2 = s.indexOf('\n', nl + 1); if (nl2 < 0) nl2 = s.length;
      const c = SEP_LINE.exec(s.slice(nl + 1, nl2));
      if (c) {
        let vStart = nl + 1 + c[0].length; if (vStart >= nl2 && nl2 < s.length) vStart = nl2 + 1;
        const end = valueEnd(s, vStart);
        if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) { out += s.slice(at, vStart) + label('SECRET', s.slice(vStart, end)); at = end; nl = Math.max(nl, end); }
      } else {
        // No separator at all, but the next line is indented deeper than the name: that block is the value
        // (aws_secret_access_key on one line, the key on the next, indented).
        const nameIndent = (line.match(/^[ \t]*/) || [''])[0].length, next = s.slice(nl + 1, nl2), nextIndent = (next.match(/^[ \t]*/) || [''])[0].length;
        if (next.trim() && nextIndent > nameIndent) {
          let end = nl2;
          while (end < s.length) { let e2 = s.indexOf('\n', end + 1); if (e2 < 0) e2 = s.length; const l2 = s.slice(end + 1, e2); if (!l2.trim() || (l2.match(/^[ \t]*/) || [''])[0].length <= nameIndent) break; end = e2; }
          const vStart = nl + 1 + nextIndent;
          if (vStart >= at && !isPlaceholderValue(s.slice(vStart, end))) { out += s.slice(at, vStart) + label('SECRET', s.slice(vStart, end)); at = end; nl = Math.max(nl, end); }
        }
      }
    } else if (csv) {
      // A data row under a credential column (cells may be quoted and span lines): scrub those cells.
      const row = csvRow(s, i);
      if (row.cells.length === csv.n) {
        for (let k = 0; k < row.cells.length; k++) {
          const [a, b] = row.cells[k]; const cell = s.slice(a, b), lead = cell.length - cell.trimStart().length, core = cell.trim();
          if (csv.cols.has(k) && core && a + lead >= at && !isPlaceholderValue(core)) { out += s.slice(at, a + lead) + label('SECRET', core); at = a + lead + core.length; }
        }
        nl = Math.max(nl, row.end);
      }
    } else if (line.includes(',') && !csv) {
      // Header cells may be multiword labels ("Login Name", "Password"; PR #27 review): each column is judged on its own.
      const hdr = csvRow(s, i), cells = hdr.cells.map(([a, b]) => s.slice(a, b).replace(/\r$/, '').replace(/^\uFEFF/, ''));   // a UTF-8 BOM is not part of the first label (PR #27 review)
      if (cells.length >= 2 && hdr.end <= nl && cells.every(c => IDENT_CELL.test(c) || LABEL_CELL.test(c))) {
        const cols = new Set(); cells.forEach((c, k) => { if (isCredentialName(resolve(c.trim().replace(/^["']|["']$/g, '')))) cols.add(k); });
        if (cols.size) csv = { n: cells.length, cols };
      }
    }
    i = nl + 1;
  }
  return out + s.slice(at);
}

// Credential scopes: a section or block whose NAME is a credential makes the generic value keys inside it credentials.
//  - INI/TOML "[password]" or "[[credentials]]" until the next "[" header;
//  - HCL/HOCON `credentials { … }` and Terraform `variable "db_password" { … default = "…" }` until the matching brace
//    (bounded at 64 KB);
//  - a Kubernetes Secret (a "kind: Secret" line): every scalar under data: and stringData:, whatever its key.
// Inside such a scope EVERY scalar value goes (plan: when in doubt, remove more), nested objects are descended and their
// scalars go too; only the sibling text outside the scope survives.
// [section], [[table]], and git-config's [section "subsection"]: the section name before the quoted part decides.
const INI_HEADER = /^[ \t]*\[\[?[ \t]*(["']?)([^\]"'\n\s]{1,120})\1(?:[ \t]+"[^"\n]*")?[ \t]*\]\]?[ \t]*$/;
const INI_ASSIGN = /^[ \t]*(["']?)([A-Za-z_][\w.\-]{0,60})\1[ \t]*[=:][ \t]*/;
const BLOCK_NAME = /(["']?)([\p{L}_][\p{L}\p{N}_.\-]{0,80})\1[ \t]*$/u;
const GENERIC_ASSIGN = /(^|[\s{,;])(["']?)([\p{L}_$][\p{L}\p{N}_$.\-]{0,60})\2[ \t]*[=:][ \t]*/gu;
// A credential-named object or flow map: "credentials": { … }, credentials: { … }, "secret": { "metadata": { … } }.
const OBJ_KEY = /(?<![\p{L}\p{N}_$.\-])(["']?)([\p{L}_$][\p{L}\p{N}_$.\-]{0,160})\1[ \t]*[:=][ \t]*\{/gu;
// Any quoted property counts as a key inside a credential container ("alice@example.com", "my key", "1st"), not only
// identifier-shaped ones (viaknox PR #27 review).
// Computed keys ({ [provider]: "…" }) count too (PR #27 review).
const KV = /("[^"\n]{0,400}"|'[^'\n]{0,400}'|\[[^\[\]\n]{1,160}\]|[\p{L}\p{N}_$][\p{L}\p{N}_$.\-]{0,160})[ \t]*[:=][ \t]*/gu;   // numeric keys too ({123: …}; PR #27 review)
// Every scalar value between `open` ({) and `close` (its match): quoted strings whole, bare values up to , } ] or the
// line end; a nested { or [ is simply scanned through, so nested keys are seen one by one.
function objectScalars(s, open, close, ivs) {
  KV.lastIndex = open + 1;
  for (let m; (m = KV.exec(s)) && m.index < close;) {
    const vs = m.index + m[0].length, c = s[vs];
    // A key can be the secret itself in a token-indexed map ({"api_keys":{"hunter2":{…}}}; PR #16 review): a key whose
    // value is an object or an array, or that carries a digit, goes too.
    if ((c === '{' || c === '[' || /\d/.test(m[1])) && m[1].replace(/^["'\[]|["'\]]$/g, '').trim()) ivs.push([m.index, m.index + m[1].length, 'SECRET']);
    // An array of plain values inside a credential object goes whole ({"credentials":{"items":["…"]}}; PR #27 review);
    // an array of objects is scanned through so each object's fields are found.
    // Any array inside a credential container goes whole, mixed ones included (["…", {…}]; PR #27 review).
    if (c === '[') { const ae = Math.min(bracketEnd(s, vs), close); if (s.slice(vs + 1, ae - 1).trim()) ivs.push([vs, ae, 'SECRET']); KV.lastIndex = ae; continue; }
    if (c === '{') continue;
    let ve;
    if (c === '"' || c === "'") { ve = vs + 1; while (ve < close && s[ve] !== c) { if (s[ve] === '\\') ve++; ve++; } ve = Math.min(ve + 1, close); }
    else { ve = vs; while (ve < close && !',}]\n'.includes(s[ve])) ve++; }
    if (s.slice(vs, ve).trim()) ivs.push([vs, ve, 'SECRET']);
    KV.lastIndex = ve;
  }
}
// An optional list marker: "- credentials:" is a container too (PR #27 review); group 4 is the marker.
const YAML_MAP_KEY = /^([ \t]*)(-[ \t]+)?(["']?)([\p{L}_$][\p{L}\p{N}_$.\-]{0,160})\3:[ \t]*$/u;
// A child line inside a credential block: `key: …`, `- key: …` or a bare list item `- …`; the match is the prefix before
// the scalar. A map head (`nested:` with nothing after it) matches too and is told apart by having no value.
const YAML_CHILD = /^[ \t]*(?:(?:-[ \t]+)?(["']?)[^\s:#"'\-][^:\n]{0,160}\1:[ \t]*|-[ \t]+)/;
const K8S_SECRET = /^[ \t]*kind:[ \t]*(?:!\S+[ \t]+)?(["']?)Secret\1[ \t]*(?:#.*)?$/m;   // quoted, tagged or commented kinds too (PR #27 review)
function braceEnd(s, open) {
  let d = 0; const lim = Math.min(s.length, open + 65536);
  for (let i = open; i < lim; i++) {
    const c = s[i];
    if (c === '"' || c === "'") { for (i++; i < lim && s[i] !== c; i++) if (s[i] === '\\') i++; continue; }
    if (c === '{') d++; else if (c === '}' && --d === 0) return i;
  }
  return lim;
}
function scrubScopes(s, label, resolve) {
  // A JSON manifest ("kind": "Secret") is a Kubernetes Secret too (PR #16 review).
  const ivs = [];
  // Kubernetes Secret scope is per YAML document ("---" separates them), so a ConfigMap after a Secret keeps its data
  // (PR #27 review). `docs` holds [start, isSecret] for each document.
  // "..." ends a YAML document too (PR #16 review).
  const docs = []; { let d0 = 0; const SEP = /^(?:---|\.\.\.)[ \t]*(?:#.*)?$/gm; const add = (a, b) => { const t = s.slice(a, b); docs.push([a, K8S_SECRET.test(t) || /"kind"[ \t]*:[ \t]*"Secret"/.test(t)]); };
    for (let m; (m = SEP.exec(s));) { add(d0, m.index); d0 = m.index + m[0].length; } add(d0, s.length); }
  let di = 0, k8s = docs[0][1];
  // In a JSON Secret, data/stringData may sit across lines from its colon and brace ({"data"\n:\n{…}}; PR #27 review).
  docs.forEach(([a, sec], d) => { if (!sec) return; const b = d + 1 < docs.length ? docs[d + 1][0] : s.length; const JD = /(["'])(?:data|stringData)\1\s*:\s*\{/g; JD.lastIndex = a;
    for (let j; (j = JD.exec(s)) && j.index < b;) { const open = j.index + j[0].length - 1; objectScalars(s, open, braceEnd(s, open), ivs); } });
  // JSON objects and YAML flow maps under a credential key ("credentials": { … }, credentials: { … }), wherever they sit
  // on a line: every scalar inside goes, nested objects included.
  if (s.includes('{')) { OBJ_KEY.lastIndex = 0; for (let m; (m = OBJ_KEY.exec(s));) if (isCredentialName(resolve(m[2]))) { const open = m.index + m[0].length - 1, close = braceEnd(s, open);
    // A credential object longer than the 64 KB scan window fails closed: everything after its brace goes (PR #16 review).
    if (s[close] !== '}' && close < s.length) { ivs.push([open + 1, s.length, 'SECRET']); break; }
    objectScalars(s, open, close, ivs); OBJ_KEY.lastIndex = open + 1; } }
  let i = 0, ini = false;
  while (i < s.length) {
    let nl = s.indexOf('\n', i); if (nl < 0) nl = s.length;
    const line = s.slice(i, nl); let m;
    while (di + 1 < docs.length && docs[di + 1][0] <= i) k8s = docs[++di][1];
    if ((m = INI_HEADER.exec(line))) ini = isCredentialName(resolve(m[2]));
    else if (ini && (m = INI_ASSIGN.exec(line))) { const vs = i + m[0].length; ivs.push([vs, valueEnd(s, vs), 'SECRET']); }
    // HCL / HOCON block "name { … }" (no separator before the brace): every assignment inside goes. Each brace on the
    // line is tried, since the block name may follow an outer brace.
    for (let bo = line.indexOf('{'); bo >= 0; bo = line.indexOf('{', bo + 1)) {
      const head = line.slice(0, bo);
      if (/[:=][ \t]*$/.test(head) || !(m = BLOCK_NAME.exec(head)) || !isCredentialName(resolve(m[2]))) continue;
      const open = i + bo, close = braceEnd(s, open), body = s.slice(open + 1, close); GENERIC_ASSIGN.lastIndex = 0;
      for (let g; (g = GENERIC_ASSIGN.exec(body));) { const vs = open + 1 + g.index + g[0].length; if (s[vs] !== '{') ivs.push([vs, Math.min(valueEnd(s, vs), close), 'SECRET']); }
      break;
    }
    // A YAML block map under a credential key (an OpenAPI ApiKeyAuth: block, a credentials: record) is a credential
    // record: every scalar inside it goes, at any depth. A nested map head (`nested:`) stays as structure and its
    // children are walked; a block scalar (`blob: |`) takes its indented block; a list item loses its scalar or the
    // value after `- key:`. A nested map used to turn the whole scope back into a container (PR #16 review).
    if ((m = YAML_MAP_KEY.exec(line)) && isCredentialName(resolve(m[4])) && nl < s.length) {
      // A list-item key's children sit at the key's own column, after the marker; the next "- " item ends the record.
      const base = m[1].length + (m[2] ? m[2].length : 0); let j = nl;
      while (j < s.length) {
        const ls = j + 1; let le = s.indexOf('\n', ls); if (le < 0) le = s.length; const l2 = s.slice(ls, le);
        // A blank line inside the record does not end it (PR #16 review); only a line at or above the key's indent does.
        if (!l2.trim()) { j = le; continue; } { const ind2 = (l2.match(/^[ \t]*/) || [''])[0].length; if (ind2 < base || (ind2 === base && !/^[ \t]*-(?:[ \t]|$)/.test(l2))) break; }
        const c = YAML_CHILD.exec(l2);
        if (c && c[0].length < l2.replace(/[ \t\r]+$/, '').length) { const vs = ls + c[0].length, ve = valueEnd(s, vs); ivs.push([vs, ve, 'SECRET']); j = Math.max(le, ve); }
        else j = le;
      }
    }
    // Flow-style maps under data:/stringData: ({username: admin, db: x}) lose every scalar too (viaknox PR #27 review).
    if (k8s) { const FM = /(?:^|[\s{,])(["']?)(?:data|stringData)\1[ \t]*:[ \t]*\{/g; for (let f; (f = FM.exec(line));) { const open = i + f.index + f[0].length - 1; objectScalars(s, open, braceEnd(s, open), ivs); } }
    if (k8s && (m = /^([ \t]*)(data|stringData):[ \t]*$/.exec(line))) {
      const ind = m[1].length; let j = nl;
      while (j < s.length) {
        const ls = j + 1; let le = s.indexOf('\n', ls); if (le < 0) le = s.length;
        const l2 = s.slice(ls, le); if (l2.trim() === '') { j = le; continue; }
        if ((l2.match(/^[ \t]*/) || [''])[0].length <= ind) break;
        const km = /^[ \t]*[^\s:]+:[ \t]*/.exec(l2);
        if (km && km[0].length < l2.length) { const vs = ls + km[0].length, ve = valueEnd(s, vs); ivs.push([vs, ve, 'SECRET']); j = Math.max(le, ve); } else j = le;
      }
    }
    i = nl + 1;
  }
  return applyIntervals(s, ivs, label);
}

// Table columns: a header that names a credential column marks that column in every row. SQL INSERT … VALUES (…),
// SQL COPY … FROM stdin rows up to "\.", Markdown tables (header, rule row, rows) and HTML tables (<th> index → <td>).
const SQL_INSERT = /\bINSERT[ \t]+INTO[ \t]+[\w."\x60\[\]]+[ \t]*\(([^()\n]{1,2000})\)[ \t]*VALUES[ \t]*/gi;
const SQL_COPY = /\bCOPY[ \t]+[\w."]+[ \t]*\(([^()\n]{1,2000})\)[ \t]+FROM[ \t]+stdin[^\n]*\n/gi;
const colIndexes = (list, resolve) => list.split(',').map(c => c.trim().replace(/^["'\x60\[]|["'\x60\]]$/g, '')).map((c, k) => (isCredentialName(resolve(c)) ? k : -1)).filter(k => k >= 0);
function scrubTables(s, label, resolve) {
  const ivs = [];
  if (/\bVALUES\b/i.test(s)) {
    SQL_INSERT.lastIndex = 0;
    for (let m; (m = SQL_INSERT.exec(s));) {
      const cols = colIndexes(m[1], resolve); if (!cols.length) continue;
      let p = m.index + m[0].length;
      while (p < s.length) {
        while (p < s.length && (s[p] === ' ' || s[p] === ',' || s[p] === '\n' || s[p] === '\r' || s[p] === '\t')) p++;
        if (s[p] !== '(') break;
        let depth = 0, k = 0, cellStart = p + 1, i = p + 1, done = false;
        for (; i < s.length; i++) {
          const c = s[i];
          if (c === "'" || c === '"') { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; continue; }
          // PostgreSQL dollar quotes ($$…$$, $tag$…$tag$) and array brackets keep their commas (PR #27 review).
          if (c === '$') { const dq = /^\$[A-Za-z_]?\w{0,30}\$/.exec(s.slice(i, i + 34)); if (dq) { const e = s.indexOf(dq[0], i + dq[0].length); i = e < 0 ? s.length : e + dq[0].length - 1; continue; } }
          if (c === '[' || c === '{') { depth++; continue; }
          if (c === ']' || c === '}') { depth--; continue; }
          if (c === '(') depth++;
          else if (c === ')') { if (depth === 0) { if (cols.includes(k)) ivs.push([cellStart, i, 'SECRET']); done = true; break; } depth--; }
          else if (c === ',' && depth === 0) { if (cols.includes(k)) ivs.push([cellStart, i, 'SECRET']); k++; cellStart = i + 1; }
        }
        if (!done) break; p = i + 1;
      }
    }
  }
  if (/\bstdin\b/i.test(s)) {
    SQL_COPY.lastIndex = 0;
    for (let m; (m = SQL_COPY.exec(s));) {
      const cols = colIndexes(m[1], resolve); if (!cols.length) continue;
      let i = m.index + m[0].length;
      while (i < s.length) {
        let nl = s.indexOf('\n', i); if (nl < 0) nl = s.length;
        const line = s.slice(i, nl); if (/^\\\.[ \t\r]*$/.test(line)) break;
        let pos = i; line.split('\t').forEach((cell, k) => { if (cols.includes(k) && cell.trim()) ivs.push([pos, pos + cell.length, 'SECRET']); pos += cell.length + 1; });
        i = nl + 1;
      }
    }
  }
  if (s.includes('|')) {
    // Markdown: a "| a | b |" header, a rule row of dashes, then rows with the same number of cells.
    let i = 0, cols = null, n = 0;
    while (i < s.length) {
      let nl = s.indexOf('\n', i); if (nl < 0) nl = s.length;
      // The judge's role label ("USER: | user | password |") is not a cell (PR #16 review).
      const line0 = s.slice(i, nl).replace(/\r$/, ''), rp = ROLE_PREFIX.exec(line0), base = i + (rp ? rp[0].length : 0), line = rp ? line0.slice(rp[0].length) : line0;
      // A pipe-less row only counts inside a table already found or right above a rule row, so ordinary lines with a
      // stray "|" (YAML block scalars) cost nothing.
      const ruleNext = () => { let n2 = s.indexOf('\n', nl + 1); if (n2 < 0) n2 = s.length; return /^[ \t]*(?:\|[ \t]*)?:?-{3,}/.test(s.slice(nl + 1, n2)); };
      if (/^[ \t]*\|.*\|[ \t]*$/.test(line) || (line.includes('|') && (cols !== null || ruleNext()))) {
        // A backslash-escaped pipe (`a\|b`) is cell text, not a boundary (PR #16 review). Outer pipes are optional in
        // Markdown ("user | password"), so the text before the first and after the last pipe is a cell when it is not
        // blank (viaknox PR #27 review).
        const pipes = []; for (let k = line.indexOf('|'); k >= 0; k = line.indexOf('|', k + 1)) if (!(k > 0 && line[k - 1] === '\\')) pipes.push(k);
        const bounds = [-1, ...pipes, line.length], cells = [];
        for (let q = 0; q + 1 < bounds.length; q++) { const a = bounds[q] + 1, b = bounds[q + 1]; if ((q === 0 || q === bounds.length - 2) && !line.slice(a, b).trim()) continue; cells.push([base + a, base + b]); }
        if (cols === null) {
          let nl2 = s.indexOf('\n', nl + 1); if (nl2 < 0) nl2 = s.length;
          if (/^[ \t]*(?:\|[ \t]*)?:?-{3,}/.test(s.slice(nl + 1, nl2))) { const found = cells.map(([a, b], k) => (isCredentialName(resolve(s.slice(a, b).trim())) ? k : -1)).filter(k => k >= 0); if (found.length) { cols = new Set(found); n = cells.length; } }
        } else if (cells.length === n && !/^[ \t]*(?:\|[ \t]*)?:?-{3,}/.test(line)) {
          for (const k of cols) if (cells[k]) { const [a, b] = cells[k], cell = s.slice(a, b), lead = cell.length - cell.trimStart().length; if (cell.trim()) ivs.push([a + lead, a + lead + cell.trim().length, 'SECRET']); }
        }
      } else if (line.trim() === '') cols = null;
      i = nl + 1;
    }
  }
  if (/<th\b/i.test(s)) {
    // A cell may hold inline markup (<td><code>…</code></td>); the header text is read with tags removed (PR #27 review).
    const CELL = /<t([hd])\b[^<>]*>((?:[^<]|<(?!\/?t[hdr]\b|\/table))*)<\/t[hd]>/gi;
    // Tag names are case-insensitive (<TR>, </Table>; PR #16 review): searched on an ASCII-lower-cased copy, same length.
    const lc = s.replace(/[A-Z]+/g, (c) => c.toLowerCase());
    for (let t = lc.indexOf('<table'); t >= 0; t = lc.indexOf('<table', t + 6)) {
      let end = lc.indexOf('</table>', t); if (end < 0) end = s.length; end = Math.min(end, t + 65536);
      let cols = null; const ROW = /<tr\b[^<>]*>/gi; ROW.lastIndex = t;
      for (let r; (r = ROW.exec(s)) && r.index < end;) {
        let rowEnd = lc.indexOf('</tr>', r.index); if (rowEnd < 0 || rowEnd > end) rowEnd = end;
        const cells = []; CELL.lastIndex = r.index + r[0].length;
        for (let c; (c = CELL.exec(s)) && c.index < rowEnd;) cells.push({ th: c[1].toLowerCase() === 'h', a: c.index + c[0].length - c[2].length - 5 - 0, text: c[2], start: c.index + c[0].indexOf('>') + 1 });
        if (cells.some(c => c.th)) { const found = cells.map((c, k) => (isCredentialName(resolve(c.text.replace(/<[^<>]*>/g, '').trim())) ? k : -1)).filter(k => k >= 0); cols = found.length ? new Set(found) : null; }
        else if (cols) for (const k of cols) if (cells[k] && cells[k].text.trim()) ivs.push([cells[k].start, cells[k].start + cells[k].text.length, 'SECRET']);
        ROW.lastIndex = rowEnd;
      }
    }
  }
  return applyIntervals(s, ivs, label);
}

// HTML attributes: in a tag whose name=, id= or http-equiv= attribute is a credential name or a credential header
// (<input name="password" value="…">, <meta http-equiv="Set-Cookie" content="…">), the value= and content= attribute
// values go. One bounded scan per tag.
// Quoted attribute values may contain ">" (value="a>b"; PR #16 review).
const TAG = /<[A-Za-z](?:"[^"\n]{0,2000}"|'[^'\n]{0,2000}'|[^<>"']){0,2000}>/g;
// Attributes that say what a field IS (name, id, http-equiv, aria-label, placeholder, data-field, data-name,
// data-key, title, for): when one of them names a credential, the element's other attribute values and text go.
const CUE_ATTR = /^(?:name|id|http-equiv|aria-label|placeholder|data-field|data-name|data-key|title|for)$/i;
const IDENT_ATTR = /^(?:name|id|http-equiv|type|class|aria-label|placeholder|data-field|data-name|data-key|title|for)$/i;
const ATTR_VALUE = /\b(value|content)([ \t]*=[ \t]*)("[^"]*"|'[^']*'|[^\s>]+)/gi;
const ATTR_ANY = /([A-Za-z_:][\w:.\-]{0,60})([ \t]*=[ \t]*)("[^"]*"|'[^']*'|[^\s>"']+)/g;
const CHILD_VALUE = /^[\s]*<([\w:.\-]*Value)\b[^<>]*>([^<]{1,4000})<\//i;
function scrubHtmlAttrs(s, label, resolve) {
  if (!s.includes('<')) return s;
  const ivs = []; TAG.lastIndex = 0;
  // HTML tag names are case-insensitive (</TEXTAREA> closes <textarea>), so the closing tag is searched on a
  // length-preserving ASCII lower-casing of the text, built once per call and only when a credential element needs it;
  // indexOf keeps the scan linear (PR #16 review).
  // Tags are visited left to right, so the last search per name is remembered: a search that found nothing (or a hit
  // not yet passed) answers the next one without rescanning, which keeps 5000 unclosed <textarea name=password> linear.
  let lower = null; const lastClose = new Map();
  const closeOf = (name, from) => {
    if (lower === null) lower = s.replace(/[A-Z]+/g, (u) => u.toLowerCase());
    // The complete end-tag name, counting nested same-name elements (<x><x>…</x>secret</x>, and </xy> is not </x>;
    // PR #16 review). At most 256 tags of that name inside the 64 KB window; past that the window is taken (fail closed).
    const key = name.toLowerCase(), last = lastClose.get(key);
    if (last && from >= last.from && last.found < 0) return -1;
    const re = new RegExp('<(/?)' + key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?=[\\s>/])', 'g'); re.lastIndex = from;
    let depth = 1, steps = 0, m;
    for (; (m = re.exec(lower)) && m.index - from <= 65536 && steps < 256; steps++) { if (m[1]) { if (--depth === 0) return m.index; } else depth++; }
    if (steps >= 256 || (m && m.index - from > 65536)) return Math.min(s.length, from + 65536);
    lastClose.set(key, { from, found: -1 }); return -1;
  };
  for (let m; (m = TAG.exec(s));) {
    const tag = m[0], tagName = (tag.match(/^<([\w:.\-]+)/) || ['', ''])[1];
    let byAttr = false; ATTR_ANY.lastIndex = 0;
    // type="password" marks a password field on its own (PR #27 review).
    for (let a; (a = ATTR_ANY.exec(tag));) { if ((/^type$/i.test(a[1]) && /^["']?password["']?$/i.test(a[3])) || (/^autocomplete$/i.test(a[1]) && /^["']?(?:current-password|new-password|one-time-code|cc-csc)["']?$/i.test(a[3]))) { byAttr = true; break; } if (!CUE_ATTR.test(a[1])) continue; const n = resolve(decodeName(a[3].replace(/^["']|["']$/g, ''))); if (isCredentialName(n) || HEADER_CRED.test(n.trim())) { byAttr = true; break; } }
    const byTag = isCredentialName(resolve(tagName));
    if (!byAttr && !byTag) continue;
    // Every attribute value goes except the ones that identify the element (name, id, http-equiv, type, class).
    let hit = false; ATTR_ANY.lastIndex = 0;
    // A cue attribute keeps its value only when that value is itself a credential NAME (it is the label); an aria-label
    // or placeholder that carries the secret itself goes like any other attribute.
    for (let v; (v = ATTR_ANY.exec(tag));) {
      const raw = v[3].replace(/^["']|["']$/g, '');
      // An autocomplete token (current-password) names the field, it is not a value (PR #16 review).
      if (/^(?:name|id|http-equiv|type|class)$/i.test(v[1]) || (/^autocomplete$/i.test(v[1]) && /^["']?[a-z\- ]{1,60}["']?$/i.test(raw)) || (IDENT_ATTR.test(v[1]) && (isCredentialName(resolve(decodeName(raw))) || HEADER_CRED.test(raw.trim())))) continue;
      const vs = m.index + v.index + v[0].length - v[3].length; ivs.push([vs, vs + v[3].length, 'SECRET']); hit = true;
    }
    // <… Name="password"><…Value>text</…Value>: the next *Value child's text is the credential; and the element's own
    // text (<textarea name="password">…</textarea>) when the tag is not self-closing.
    if (!hit && byAttr) { const c = CHILD_VALUE.exec(s.slice(m.index + tag.length, m.index + tag.length + 4200)); if (c) { const vs = m.index + tag.length + c[0].length - c[2].length - 2; ivs.push([vs, vs + c[2].length, 'SECRET']); } }
    if (byAttr && !tag.endsWith('/>') && tagName) { const open = m.index + tag.length, close = closeOf(tagName, open); if (close > open && close - open <= 65536 && s.slice(open, close).trim()) ivs.push([open, close, 'SECRET']); }   // nested markup goes too (PR #27)
  }
  return applyIntervals(s, ivs, label);
}

// A name written as a concatenation of string literals in code ("pass" + "word": …, ['pass' + 'word']: …) is joined
// before the check; the value after the separator then goes like any assignment.
const CONCAT_NAME = /(?:\[[ \t]*)?(["'])([\w.\-]{1,60})\1(?:[ \t]*\+[ \t]*(["'])([\w.\-]{1,60})\3){1,4}[ \t]*\]?[ \t]*(:=|=>|[:=])[ \t]*/g;
function scrubConcatNames(s, label, resolve) {
  if (!s.includes('+')) return s;
  let out = '', at = 0; CONCAT_NAME.lastIndex = 0;
  for (let m; (m = CONCAT_NAME.exec(s));) {
    const joined = (m[0].match(/(["'])([\w.\-]{1,60})\1/g) || []).map(p => p.slice(1, -1)).join('');
    const sepEnd = m.index + m[0].length;
    if (sepEnd < at || !isCredentialName(resolve(joined)) || s[sepEnd] === '{') continue;
    const end = valueEnd(s, sepEnd), value = s.slice(sepEnd, end);
    if (!value.trim() || isPlaceholderValue(value)) continue;
    out += s.slice(at, sepEnd) + label('SECRET', value); at = end; CONCAT_NAME.lastIndex = end;
  }
  return out + s.slice(at);
}

// Code forms: a tuple ('password', 'x') / ("password", "x") inside parentheses or brackets, and a C++ designated
// initialiser `.password = "x"` (a leading dot before the name after "{", "," or whitespace).
const TUPLE_PAIR = /[(\[][ \t]*(["']?)([\p{L}_$][\p{L}\p{N}_$.\-]{0,60})\1[ \t]*,[ \t]*("[^"\n]*"|'[^'\n]*'|[^,\]\)}\n]+)/gu;
// Clojure/EDN keyword maps: {:password "x" :user "ada"}.
const EDN_PAIR = /(?<![\p{L}\p{N}:/]):([\p{L}_$][\p{L}\p{N}_$.\-]{0,60})[ \t]+("[^"\n]*"|'[^'\n]*')/gu;
// YAML aliases: password: *s means the anchored value "&s …" elsewhere in the document is the password.
const ALIAS_REF = /(?<![\p{L}\p{N}_$.\-])(["']?)([\p{L}_$][\p{L}\p{N}_$.\-]{0,160})\1[ \t]*:[ \t]*\*([\w.\-]{1,80})/gu;
const DESIGNATED = /(?<=[{,\s])\.([A-Za-z_]\w{0,60})[ \t]*=[ \t]*/g;
function scrubCodeForms(s, label, resolve) {
  const ivs = [];
  if (s.includes(',')) { TUPLE_PAIR.lastIndex = 0; for (let m; (m = TUPLE_PAIR.exec(s));) if (isCredentialName(resolve(m[2]))) ivs.push([m.index + m[0].length - m[3].length, m.index + m[0].length, 'SECRET']); }
  if (s.includes(':')) { EDN_PAIR.lastIndex = 0; for (let m; (m = EDN_PAIR.exec(s));) if (isCredentialName(resolve(m[1]))) ivs.push([m.index + m[0].length - m[2].length, m.index + m[0].length, 'SECRET']); }
  if (s.includes('*') && s.includes('&')) {
    const aliases = new Set(); ALIAS_REF.lastIndex = 0;
    for (let m; (m = ALIAS_REF.exec(s));) if (isCredentialName(resolve(m[2]))) aliases.add(m[3]);
    for (const a of aliases) { const re = new RegExp('(?<![\\w&])&' + a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![\\w.\\-])[ \\t]*', 'g'); for (let m; (m = re.exec(s));) { const vs = m.index + m[0].length; const ve = valueEnd(s, vs); if (s.slice(vs, ve).trim()) ivs.push([vs, ve, 'SECRET']); } }
  }
  if (s.includes('.')) { DESIGNATED.lastIndex = 0; for (let m; (m = DESIGNATED.exec(s));) if (isCredentialName(resolve(m[1])) && s[m.index + m[0].length] !== '{') { const vs = m.index + m[0].length; ivs.push([vs, valueEnd(s, vs), 'SECRET']); } }
  return applyIntervals(s, ivs, label);
}

// Name/value sibling pairs: when a field that SAYS WHAT A SETTING IS (name, key, label, field, var, variable, id, env,
// option, setting, property, param, parameter) holds a credential name as its value, the value-like sibling in the
// same entry (value, val, default, defaultValue, default_value, string, data, content, secret) is the secret. One
// rule covers YAML list items, JSON objects, TOML tables, INI sections, flow maps, Go struct tags, Java/C#/Rust
// attributes, PHP/Ruby/Python/JS literals, GraphQL and protobuf text. The look-ahead is bounded to the entry: it stops
// at the next name-like field, an unbalanced closing bracket, a less-indented line, or 20 lines.
const NAME_FIELD = /(?<![\p{L}\p{N}_$.\-])(["']?)(name|key|label|field|var|variable|id|env|option|setting|property|param|parameter)\1[ \t]*(?:=>|[:=])[ \t]*(["']?)(--?)?([\p{L}_$][\p{L}\p{N}_$.\-]{0,160})\3/giu;
const NAME_FIELD_NEXT = new RegExp(NAME_FIELD.source, 'giu');
const VALUE_FIELD = /(?<![\p{L}\p{N}_$.\-])(["']?)(value|val|default|defaultValue|default_value|string|data|content|secret)\1[ \t]*(?:=>|[:=])[ \t]*/giu;
// Indexed or suffixed variables whose key ends in NAME: env[0].name=DB_PASSWORD, app.env[0].name=TOKEN, ENV_0_NAME=PASSWORD;
// the line with the same prefix and a VALUE-like suffix holds the secret.
const INDEXED_NAME = /^[ \t]*([\w.\[\]\-]{0,120}?)([._]?)(name)[ \t]*[=:][ \t]*(["']?)([\w.\-]{1,160})\4[ \t]*$/im;
// A value inside an entry: a quoted string whole, or a bare run up to a comma, a closing bracket or the line end.
function entryValueEnd(s, vs, limit) {
  const q = s[vs];
  if (q === '"' || q === "'") { let i = vs + 1; while (i < limit && s[i] !== q) { if (s[i] === '\\') i++; i++; } return Math.min(i + 1, limit); }
  let i = vs; while (i < limit && !',}])\n'.includes(s[i])) i++; return i;
}
// Where the entry that starts at `from` ends (see the rule above). `nameIndent` is the column of the name field.
function entryEnd(s, from, nameIndent) {
  let end = from; for (let k = 0; k < 20 && end < s.length; k++) { const nl = s.indexOf('\n', end + 1); end = nl < 0 ? s.length : nl; }
  NAME_FIELD_NEXT.lastIndex = from; const nx = NAME_FIELD_NEXT.exec(s); if (nx && nx.index < end) end = nx.index;
  let depth = 0;
  for (let j = from; j < end; j++) { const c = s[j]; if (c === '{' || c === '[' || c === '(') depth++; else if (c === '}' || c === ']' || c === ')') { if (depth === 0) { end = j; break; } depth--; } }
  for (let j = s.indexOf('\n', from); j >= 0 && j < end; j = s.indexOf('\n', j + 1)) {
    const ls = j + 1; let le = s.indexOf('\n', ls); if (le < 0) le = s.length; const l2 = s.slice(ls, le);
    if (l2.trim() && (l2.match(/^[ \t]*/) || [''])[0].length < nameIndent) { end = ls; break; }
  }
  return end;
}
function scrubNameValuePairs(s, label, resolve) {
  const ivs = [];
  NAME_FIELD.lastIndex = 0;
  // Names are visited left to right, so the last value-field search is remembered: the first value field at or after
  // `known.from` is `known.index` (-1: none). A name with no value field anywhere used to scan to the end of the text,
  // which made 4000 <input name="password"> lines quadratic (found with the PR #16 perf payloads).
  let known = null;
  for (let m; (m = NAME_FIELD.exec(s));) {
    if (!isCredentialName(resolve(m[5]))) continue;
    const from = m.index + m[0].length, nameIndent = m.index - (s.lastIndexOf('\n', m.index - 1) + 1);
    const end = entryEnd(s, from, nameIndent);
    // A value field may come BEFORE the name in the same entry ({"value": …, "name": "password"}, or a YAML list item
    // "- value: …" then "  name: password"); find the entry start and scrub those too (viaknox PR #27 review).
    // Looked up inside a bounded window behind the name, so thousands of names on one line stay linear.
    let start = -1;
    const win = Math.max(0, m.index - 4000), back = s.slice(win, m.index), obr = back.lastIndexOf('{'), ob = obr < 0 ? -1 : win + obr;
    if (ob >= 0 && !s.slice(ob, m.index).includes('}')) start = ob;
    else if (back.includes('\n')) {
      let ls = win + back.lastIndexOf('\n') + 1;
      for (let k = 0; k < 20 && ls > 0; k++) {
        const ps = s.lastIndexOf('\n', ls - 2) + 1, pl = s.slice(ps, ls - 1); if (!pl.trim()) break;
        const ind = (pl.match(/^[ \t]*/) || [''])[0].length;
        if (/^[ \t]*-[ \t]/.test(pl) && ind + 2 === nameIndent) { start = ps; break; }
        if (ind !== nameIndent) break; ls = ps;
      }
    }
    if (start >= 0) {
      const VB = new RegExp(VALUE_FIELD.source, 'giu'); VB.lastIndex = start;
      for (let v; (v = VB.exec(s)) && v.index < m.index;) { const vs = v.index + v[0].length, ve = entryValueEnd(s, vs, m.index); if (ve <= m.index && s.slice(vs, ve).trim()) ivs.push([vs, ve, 'SECRET']); VB.lastIndex = Math.max(ve, vs + 1); }
    }
    let at = from;
    if (known && from >= known.from) { if (known.index < 0) continue; if (known.index >= from) at = known.index; }
    for (;;) {
      VALUE_FIELD.lastIndex = at; const v = VALUE_FIELD.exec(s); known = { from: at, index: v ? v.index : -1 };
      if (!v || v.index >= end) break;
      const vs = v.index + v[0].length, ve = entryValueEnd(s, vs, end); if (s.slice(vs, ve).trim()) ivs.push([vs, ve, 'SECRET']); at = ve;
    }
  }
  // Indexed / suffixed variables: the NAME line decides, the VALUE line with the same prefix (within 20 lines) goes.
  if (/name[ \t]*[=:]/i.test(s)) {
    const re = new RegExp(INDEXED_NAME.source, 'gim');
    for (let m; (m = re.exec(s));) {
      if (!m[1] || !isCredentialName(resolve(m[5]))) continue;
      const prefix = m[1].replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), sep = m[2] ? '[._]' : '';
      const vre = new RegExp('^[ \\t]*' + prefix + sep + '(?:value|val|default|defaultValue|default_value|data|content|secret)[ \\t]*[=:][ \\t]*', 'gim');
      let limit = m.index; for (let k = 0; k < 20 && limit < s.length; k++) { const nl = s.indexOf('\n', limit + 1); limit = nl < 0 ? s.length : nl; }
      // Searched inside those 20 lines only (a name with no value line used to scan to the end of the text: quadratic).
      const base = s.indexOf('\n', m.index + m[0].length); if (base < 0 || base >= limit) continue;
      const seg = s.slice(base, limit);
      for (let v; (v = vre.exec(seg));) { const vs = base + v.index + v[0].length; ivs.push([vs, valueEnd(s, vs), 'SECRET']); }
    }
  }
  // plist: <key>Password</key> followed by the next <string> or <data> element.
  if (s.includes('<key>')) { const re = /<key>([^<]{1,160})<\/key>\s*<(?:string|data)>([^<]*)</g; for (let m; (m = re.exec(s));) if (isCredentialName(resolve(m[1])) && m[2].trim()) { const ve = m.index + m[0].length - 1; ivs.push([ve - m[2].length, ve, 'SECRET']); } }
  // A call whose first argument is the option name ('--password', default='x'): click, argparse and friends.
  if (s.includes('(')) {
    const re = /\([ \t]*(["'])(--?[\p{L}\p{N}_\-]{1,60})\1/gu;
    for (let m; (m = re.exec(s));) {
      if (!isCredentialName(resolve(m[2].replace(/^-+/, '')))) continue;
      const from = m.index + m[0].length, close = Math.min(s.length, from + 2000);
      let depth = 0, end = close; for (let j = from; j < close; j++) { const c = s[j]; if (c === '(') depth++; else if (c === ')') { if (depth === 0) { end = j; break; } depth--; } }
      VALUE_FIELD.lastIndex = from;
      for (let v; (v = VALUE_FIELD.exec(s)) && v.index < end;) { const vs = v.index + v[0].length, ve = entryValueEnd(s, vs, end); if (s.slice(vs, ve).trim()) ivs.push([vs, ve, 'SECRET']); VALUE_FIELD.lastIndex = ve; }
    }
  }
  return applyIntervals(s, ivs, label);
}

// URL path segments: a segment that is a credential name (/token/, /password/, /api-key/) makes the next segment a
// secret (https://x/api/token/<x>/status).
function scrubPathSegments(s, label, resolve) {
  if (!s.includes('/')) return s;
  // The slash after the segment is only looked at, not consumed, so "/api/token/x" is retried at "token".
  const ivs = [], re = /\/([\p{L}\p{N}_\-]{1,40})(?=\/[^\/\s?#"'<>)]+)/gu;
  for (let m; (m = re.exec(s));) if (isCredentialName(resolve(m[1]))) { const vs = m.index + m[0].length + 1; let ve = vs; while (ve < s.length && !'/?#"\'<>) \t\r\n'.includes(s[ve])) ve++; ivs.push([vs, ve, 'SECRET']); }
  return applyIntervals(s, ivs, label);
}

// Multipart form data: a part whose Content-Disposition names a credential field; its body (after the blank line, up to
// the next boundary line starting with "--" or the end) goes.
// The whole quoted name is read ("api key"; PR #27 review); an unquoted one runs to a space or semicolon.
const PART_HEADER = /Content-Disposition:[^\n]*\bname=(?:"([^"\n]{1,160})"|'([^'\n]{1,160})'|([^"'\s;\n]{1,160}))/gi;
function scrubMultipart(s, label, resolve) {
  if (!/Content-Disposition/i.test(s)) return s;
  const ivs = []; PART_HEADER.lastIndex = 0;
  for (let m; (m = PART_HEADER.exec(s));) {
    if (!isCredentialName(resolve(m[1] ?? m[2] ?? m[3]))) continue;
    const blank = s.indexOf('\n\n', m.index), blankCr = s.indexOf('\r\n\r\n', m.index);
    const start = blank < 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? blankCr + 4 : blank + 2);
    if (start < 0 || start - m.index > 4000) continue;
    // Stop only at this part's own boundary line (the last "--x" line before the header); a body line that merely starts
    // with "--" is content. With no boundary in sight the body runs to the end of the input (PR #27 review).
    const before = s.slice(Math.max(0, m.index - 4000), m.index).split(/\r?\n/).reverse().find(l => /^--\S/.test(l));
    const boundary = before ? before.trim() : null;
    let end = start;
    while (end < s.length) { let le = s.indexOf('\n', end); if (le < 0) le = s.length; const ln = s.slice(end, le).replace(/\r$/, '').trim(); if (boundary && (ln === boundary || ln === boundary + '--')) break; end = le + 1; }
    if (end > s.length) end = s.length;
    const body = s.slice(start, end).replace(/\r?\n$/, ''); if (body.trim()) ivs.push([start, start + body.length, 'SECRET']);
  }
  return applyIntervals(s, ivs, label);
}

// XML/HTML elements whose tag name is a credential name (<ageToken>…</ageToken>, <snykToken>…</snykToken>): the content
// between the tags goes, the tags stay. Linear: each opening tag is found once and the closing tag with one indexOf;
// content is bounded at 64 KB so a tag never opened is not a quadratic scan.
const XML_OPEN = /<([\p{L}_\uE000][\p{L}\p{N}_.\-:\uE000\uE001]{0,80})(?:\s[^<>\n]{0,200})?>/gu;   // Unicode names too (<пароль>; PR #27 review)
function scrubXml(s, label, resolve) {
  if (!s.includes('</')) return s;
  // Every "</" position once, so each opening tag finds its closing tag by binary search instead of an indexOf that,
  // for a tag never closed, would scan to the end of the text (20000 unclosed tags made that quadratic).
  const closes = []; for (let k = s.indexOf('</'); k >= 0; k = s.indexOf('</', k + 2)) closes.push(k);
  const nextClose = (from) => { let lo = 0, hi = closes.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (closes[mid] < from) lo = mid + 1; else hi = mid; } return lo < closes.length ? closes[lo] : -1; };
  let out = '', at = 0; XML_OPEN.lastIndex = 0;
  for (let m; (m = XML_OPEN.exec(s));) {
    const name = resolve(m[1]);
    if (!isCredentialName(name)) continue;
    const open = m.index + m[0].length;
    // The matching closing tag may come after nested elements (<password><value>…</value></password>; PR #27 review):
    // walk the closing tags inside the 64 KB window until this element's own one.
    let ci = closes.length; { let lo = 0, hi = closes.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (closes[mid] < open) lo = mid + 1; else hi = mid; } ci = lo; }
    // XML allows whitespace before the end tag's ">" (</password >; PR #27 review).
    let close = -1; const want = '</' + m[1], isEnd = (at) => s.slice(at, at + want.length).toLowerCase() === want.toLowerCase() &&   // HTML tag names ignore case (<Password>…</PASSWORD>; PR #16 review)
       /^[ \t\r\n]*>/.test(s.slice(at + want.length, at + want.length + 40));
    let k = ci, n = 0;
    for (; k < closes.length && closes[k] - open <= 65536 && n < 256; k++, n++) if (isEnd(closes[k])) { close = closes[k]; break; }
    // Too many nested closing tags to walk: take the rest of the 64 KB window rather than risk leaving the value (PR #27).
    if (close < 0 && n >= 256) close = Math.min(s.length, open + 65536);
    if (close < 0) continue;
    const content = s.slice(open, close);
    if (content.trim() && !isPlaceholderValue(content)) { out += s.slice(at, open) + label('SECRET', content); at = close; }
    XML_OPEN.lastIndex = close;
  }
  return out + s.slice(at);
}

// A credential passed as a quoted call argument in code: std::string secret("…"), setPassword('…'). The name before the
// parenthesis is checked like a setting name; only the quoted literal goes.
function scrubCallArg(s, label, resolve) {
  // SMTP/IMAP "AUTH PLAIN <base64>" initial responses (RFC 4954; PR #27 review).
  s = s.replace(/^((?:[ \t]*(?:USER|AGENT|C|S|>>?|<<?):?)?[ \t]*(?:\w+[ \t]+)?AUTH(?:ENTICATE)?[ \t]+(?:PLAIN|LOGIN|XOAUTH2?|OAUTHBEARER|CRAM-MD5|DIGEST-MD5|SCRAM-SHA-\d+(?:-PLUS)?)[ \t]+)(\S+)/gim, (m, pre, v) =>
    v === '=' || isPlaceholderValue(v) ? m : pre + label('SECRET', v));
  // MongoDB db.auth("user", "pw") and similar (user, password) signatures: the second quoted argument goes too
  // (PR #27 review).
  s = s.replace(/\b(?:db\.auth|auth|login|signIn|authenticate)[ \t]*\([ \t]*("[^"\n]*"|'[^'\n]*')[ \t]*,[ \t]*("[^"\n]*"|'[^'\n]*')/gu, (m, u, v) =>
    isPlaceholderValue(v) ? m : m.slice(0, m.length - v.length) + label('SECRET', v));
  return s.replace(/\b([\p{L}_$\uE000][\p{L}\p{N}_$.\uE000\uE001]{0,60})[ \t]*\([ \t]*("[^"\n]*"|'[^'\n]*')/gu, (m, name, v) =>
    (!isCredentialName(resolve(name)) || isPlaceholderValue(v)) ? m : m.slice(0, m.length - v.length) + label('SECRET', v));
}

// SQL account statements: MySQL "IDENTIFIED [WITH plugin] BY [PASSWORD] 'x'", PostgreSQL "[WITH] [ENCRYPTED] PASSWORD 'x'"
// after CREATE/ALTER USER or ROLE, SQL Server "WITH PASSWORD = 'x'" (PR #27 review).
const SQL_IDENTIFIED = /\bIDENTIFIED[ \t]+(?:WITH[ \t]+\S+[ \t]+)?BY[ \t]+(?:PASSWORD[ \t]+)?('(?:''|[^'\n])*'|"[^"\n]*"|[^\s;,)]+)/gi;
const SQL_SET_PASSWORD = /\bSET[ \t]+PASSWORD\b[^;\n]{0,200}?=[ \t]*(?:PASSWORD[ \t]*\([ \t]*)?('(?:''|[^'\n])*'|"[^"\n]*")/gi;   // MySQL SET PASSWORD [FOR u] = '…' (PR #27)
const SQL_PASSWORD = /\b(?:CREATE|ALTER)[ \t]+(?:USER|ROLE|LOGIN)\b[^;\n]{0,200}?\bPASSWORD[ \t]*=?[ \t]*('(?:''|[^'\n])*'|"[^"\n]*")/gi;
function scrubSqlAuth(s, label) {
  if (!/IDENTIFIED|PASSWORD/i.test(s)) return s;
  const f = (m, v) => isPlaceholderValue(v) ? m : m.slice(0, m.length - v.length) + label('SECRET', v);
  return s.replace(SQL_IDENTIFIED, f).replace(SQL_PASSWORD, f).replace(SQL_SET_PASSWORD, f);
}

// PostgreSQL password file lines: hostname:port:database:username:password, fields may hold \: escapes; the fifth field
// goes (PR #27 review). The port must be a number or *, which keeps times and IPv6 out.
const PGPASS = /^((?:\\.|[^:\\\s])+):(\d{1,5}|\*):((?:\\.|[^:\\\n])*):((?:\\.|[^:\\\n])*):((?:\\.|[^\\\n])+)$/gm;
function scrubPgpass(s, label) {
  if (!s.includes(':')) return s;
  return s.replace(PGPASS, (m, h, p, d, u, pw) => isPlaceholderValue(pw) ? m : m.slice(0, m.length - pw.length) + label('SECRET', pw));
}

// netrc: "password <value>" / "account <value>" with no separator. Applied only when the text is actually a netrc file
// (it has a line starting with "machine" or "default"), and only to a value that is not itself a separator — so prose
// like "Password requirements: 12 characters" and the assignment "password = x" are left for the other passes.
const NETRC_ANCHOR = /^[ \t]*(?:machine|default)\b/im;
function scrubNetrc(s, label) {
  if (!NETRC_ANCHOR.test(s)) return s;
  return s.replace(/^[ \t]*(?:machine|default|login|password|account)\b[^\n]*$/gim,
    (line) => line.replace(/\b(password|account)[ \t]+(?![=:])("(?:\\.|[^"\\\n])*"?|(?:\\.|\S)+)/gi,   // a quoted token or backslash-escaped spaces (PR #16 review)
       (m, k, v) => isPlaceholderValue(v) ? m : `${k} ${label('SECRET', v)}`));
}

// Credential words and phrases that appear in prose: "the password is X", "your recovery code is X". The copula "is"
// is the only link accepted, so "I forgot my password yesterday" is left alone.
// Credential words and phrases in prose, in English and the other languages the scrubber knows. Guards are
// Unicode-aware lookarounds (JS \b only knows ASCII letters, so "пароль" or "密码" would never sit at a \b).
const MULTI_CRED = 'mot[ \\t]+de[ \\t]+passe|mdp|cl[eé][ \\t]+(?:api|secr[eè]te)|cl[eé]|jeton|passw[oö]rter|passwort|kennwort|geheimnis|schl[uü]ssel|zugangsdaten|contrase[ñn]a|clave|secreto|credenciales|senha|chave|chiave|segreto|wachtwoord|sleutel|пароль|секрет|ключ|токен|パスワード|秘密鍵|トークン|密码|密钥|口令|令牌|비밀번호|암호';
const PROSE_CRED = '(?:(?:seed|recovery|mnemonic|secret|wallet)[ _-]?phrases?|mnemonics?|cvv2?|cvc2?|passwords?|passphrases?|passwd|pwd|pw|passcodes?|pins?|otp|secrets?|creds?|credentials?|tokens?|api[ _-]?keys?|auth[ _-]?tokens?|access[ _-]?tokens?|(?:recovery|backup|verification|security|auth|2fa|mfa)[ _-]?codes?|' + MULTI_CRED + ')';
const NOT_L = '(?![\\p{L}\\p{N}])', NOT_L_BEHIND = '(?<![\\p{L}\\p{N}])';
// "password is X", "creds are user:pass", "pw's X", "le mot de passe est X", "das Passwort ist X", "la contraseña es X":
// a copula (is/are/est/ist/lautet/es/é/è/это/—) or a possessive 's, then the value.
// Up to two plain words may sit between the noun and the copula ("the secret phrase is X", "my api key here is X") when
// the value carries a digit or a symbol, so "Our API key rotation policy is documented" (a plain word) is left alone.
// Words that describe a password rather than spell it ("is not working", "is too short") never extend a value.
const EXT_WORD = '(?!(?:not|no|wrong|incorrect|invalid|expired|too|missing|required|empty|blank|weak|strong|short|long|working|broken|locked|reset|changed|the|a|an|my|your|our|their|in|on|at|for|to|of|and|but|or|so|very|still|now|again|anymore|i|it|that|this|please|help|me|you|we|they)(?![\\p{L}\\p{N}]))[\\p{L}\\p{N}]+';
// An unquoted value takes the following lowercase words too when they run to the end of the clause, so a passphrase
// ("correct horse battery staple") or a 24-word recovery phrase goes whole (PR #27 review).
const COPULA_RE = new RegExp(NOT_L_BEHIND + PROSE_CRED + NOT_L + '(?:[ \\t]+(?:is|are|est|ist|lautet|es|é|è|это|—)[ \\t]+|[\'’]s[ \\t]+)("[^"\\n]*"|\'[^\'\\n]*\'|\\S+(?:(?:[ \\t]+' + EXT_WORD + '){1,23}(?=[ \\t]*(?:[.,;!?\\n]|$)))?)', 'giu');
// "recovery phrase: abandon ability …", "seed phrase = …": a wallet phrase cue with a separator takes the rest of the line.
const WALLET_RE = new RegExp(NOT_L_BEHIND + '(?:(?:seed|recovery|mnemonic|secret|wallet)[ _-]?phrases?|mnemonics?)' + NOT_L + '[ \\t]*(?:[:=\\uFF1A][ \\t]*)([^\\n]+)', 'giu');
// "aws configure set aws_secret_access_key X", "npm config set _authToken X": a config command naming a credential.
const CONFIG_SET_RE = /\b(?:configure|config)[ \t]+set[ \t]+(["']?)([\w.\-:\/]{1,80})\1[ \t]+([^\n]+)/g;
// Past and changed forms ("was", "will be", "changed to") take a value only when it is quoted or token-like (has a digit,
// punctuation or symbol), so "the password was reset yesterday" keeps its words (PR #27 review).
const PAST_RE = new RegExp(NOT_L_BEHIND + PROSE_CRED + NOT_L + '[ \\t]+(?:was|were|will[ \\t]+be|(?:has|had|have)[ \\t]+been|(?:is|was)[ \\t]+now|(?:changed|set|reset|updated)[ \\t]+to)[ \\t]+("[^"\\n]+"|\'[^\'\\n]+\'|(?=\\S*[\\p{N}\\p{S}]|\\S*\\p{P}\\S)\\S+)', 'giu');
const QUAL_COPULA_RE = new RegExp(NOT_L_BEHIND + PROSE_CRED + NOT_L + '(?:[ \\t]+\\p{L}{1,20}){1,2}' + '[ \\t]+(?:is|are|est|ist|lautet|es|é|è|это|—)[ \\t]+("[^"\\n]+"|\'[^\'\\n]+\'|(?=\\S*[\\p{N}\\p{P}\\p{S}]\\S)\\S+)', 'giu');
// A credential noun, after a prose word ("use the password", "enter api key"), followed directly by its value: a quoted
// token that carries a digit or a symbol before its last character ("use password x9k2"), so "my password yesterday."
// is left alone (letters only, and a final full stop does not count).
// The gap before the noun is bounded (1-4 blanks): an unbounded [ \t]+ lookbehind re-scanned every blank of a long
// indent at each position and made 2000 growing-indent YAML lines take 1.8 s on Node 22 (PR #16 CI on Linux).
const NOUN_VALUE_RE = new RegExp('(?<=\\p{L}[ \\t]{1,4})' + PROSE_CRED + NOT_L + '[ \\t]+("[^"\\n]+"|\'[^\'\\n]+\'|(?=\\S*[\\p{N}\\p{P}\\p{S}]\\S)[\\p{L}\\p{N}][^\\s"\']*)', 'giu');
// A multi-word foreign name before a separator: "Mot de passe: X", "clé API = X".
const PHRASE2_RE = new RegExp(NOT_L_BEHIND + '(?:mot[ \\t]+de[ \\t]+passe|cl[eé][ \\t]+(?:api|secr[eè]te)|chave[ \\t]+(?:de[ \\t]+)?api)' + NOT_L + '[ \\t]*(?:->|[:=\\u2236\\uFF1D\\uFF1A\\u2192])[ \\t]*("[^"\\n]*"|\'[^\'\\n]*\'|[^\\n]+)', 'giu');
// "I changed the password to …", "set my PIN to …" (PR #27 review).
const CHANGE_RE = new RegExp(NOT_L_BEHIND + '(?:changed|set|reset|updated|switched)[ \\t]+(?:(?:the|my|our|your|his|her|their)[ \\t]+)?(?:\\p{L}{1,20}[ \\t]+)?' + PROSE_CRED + NOT_L + '[ \\t]+to[ \\t]+("[^"\\n]*"|\'[^\'\\n]*\'|\\S+)', 'giu');
function scrubCopula(s, label) {
  s = s.replace(WALLET_RE, (m, v) => isPlaceholderValue(v) ? m : m.slice(0, m.length - v.length) + label('SECRET', v));
  s = s.replace(CONFIG_SET_RE, (m, q, name, v) => !isCredentialName(name) || isPlaceholderValue(v) ? m : m.slice(0, m.length - v.length) + label('SECRET', v));
  s = s.replace(CHANGE_RE, (m, v) => isPlaceholderValue(v) ? m : m.slice(0, m.length - v.length) + label('SECRET', v));
  s = s.replace(PAST_RE, (m, v) => isPlaceholderValue(v) ? m : m.slice(0, m.length - v.length) + label('SECRET', v));
  const out = s.replace(COPULA_RE, (m, v) => isPlaceholderValue(v) ? m : m.slice(0, m.length - v.length) + label('SECRET', v));
  const mid = out.replace(QUAL_COPULA_RE, (m, v) => isPlaceholderValue(v) ? m : m.slice(0, m.length - v.length) + label('SECRET', v));
  return mid.replace(NOUN_VALUE_RE, (m, v) => isPlaceholderValue(v) ? m : m.slice(0, m.length - v.length) + label('SECRET', v));
}

// A credential phrase written as separate words before a colon or equals: "api key: X", "openai api key = X",
// "recovery code: X". One or more qualifier words then key/token/secret/password/credential/code, then the value. A
// colon or equals is required, so prose like "Our API key rotation policy" (no separator) is left alone. At least one
// qualifier word followed by a space, so a single-word "password:" is left to the assignment pass (which also handles
// its continuation lines).
const PHRASE_RE = /\b(?:(?:api|access|secret|private|client|auth|refresh|session|bearer|recovery|backup|verification|security|2fa|mfa)[ \t]+)+(?:key|token|secret|password|credential|codes?)\b(?:[ \t]*(?:\([^()\n]{1,40}\)|\[[^\[\]\n]{1,40}\]|\/[\p{L}\p{N}_\-]{1,40}))?[ \t]*[:=][ \t]*("[^"\n]*"|'[^'\n]*'|[^\n]+)/giu;
function scrubPhrase(s, label) {
  const out = s.replace(PHRASE_RE, (m, v) => isPlaceholderValue(v) ? m : m.slice(0, m.length - v.length) + label('SECRET', v));
  return out.replace(PHRASE2_RE, (m, v) => isPlaceholderValue(v) ? m : m.slice(0, m.length - v.length) + label('SECRET', v));
}

// Command-line credential flags, matched on the folded view (PowerShell's -Client`Secret is -ClientSecret there): any
// -flag or --flag whose name is a credential name takes the next value, bare or quoted, after "=" or ":" (spaces allowed
// around them: --password = x, Java -Dpassword:x) or a space (-Password x). A bare value may continue on the next line
// after a backslash. curl's -u / --user take the whole user:pass. mysql's glued -pVALUE is handled first so its "p" is
// not read as a flag name.
const FLAG_P = /(^|\s)(-p)([^\s'"]+)/g; // no minimum: -pX is a password too (PR #16 review)
const FLAG_USER = /(^|\s)(-u|-U|--user|--proxy-user)(=|[ \t]+)((?:"[^"\n]*"|'[^'\n]*'|[^\s'"])+)/g;
const FLAG_ANY = /(^|[\s'"(])(--?)([A-Za-z][\w.\-]{0,60})([ \t]*[=:][ \t]*|[ \t]+)("(?:\\.|[^"\\\n])*"|'[^'\n]*'|(?:\\\r?\n|[^\s'"])+)/g;   // escaped quotes stay inside a "…" value (PR #16 review)
// SQL Server tools take the password as -P (sqlcmd -S db -U alice -P x, or -Px); only on a line naming one of them,
// since -P is a port elsewhere (PR #27 review).
const SQLCMD_LINE = /^.*\b(?:sqlcmd|osql|isql|bcp)\b.*$/gim;
function scrubFlags(s, label, V) {
  if (!s.includes('-')) return s;
  s = s.replace(/^.*\bsshpass\b.*$/gim, (line) => line.replace(/(^|\s)-p[ \t]+("[^"\n]*"|'[^'\n]*'|[^\s"']+)/g, (m, pre, v) => isPlaceholderValue(v) ? m : `${pre}-p ${label('SECRET', v)}`));   // sshpass -p x (PR #27)
  s = s.replace(/^.*\bredis-cli\b.*$/gim, (line) => line.replace(/(^|\s)-a[ \t]+("[^"\n]*"|'[^'\n]*'|[^\s"']+)/g, (m, pre, v) => isPlaceholderValue(v) ? m : `${pre}-a ${label('SECRET', v)}`));   // redis-cli -a x (PR #27)
  s = s.replace(/^.*\bvault[ \t]+login\b.*$/gim, (line) => line.replace(/(\bvault[ \t]+login(?:[ \t]+-\S+)*[ \t]+)("[^"\n]*"|'[^'\n]*'|[^\s"'=-][^\s"'=]*)(?=[ \t]*$)/i, (m, pre, v) => isPlaceholderValue(v) ? m : pre + label('SECRET', v)));   // vault login <token> (PR #27)
  s = s.replace(SQLCMD_LINE, (line) => line.replace(/(^|\s)-P(?:[ \t]+)?("[^"\n]*"|'[^'\n]*'|[^\s"']+)/g, (m, pre, v) => isPlaceholderValue(v) ? m : `${pre}-P ${label('SECRET', v)}`));
  s = applyOnView(s, V(s), FLAG_P, label, (m) => ({ from: m.index + m[1].length + 2, to: m.index + m[0].length, kind: 'SECRET' }));
  s = applyOnView(s, V(s), FLAG_USER, label, (m) => m[4].includes(':') ? { from: m.index + m[0].length - m[4].length, to: m.index + m[0].length, kind: 'SECRET' } : null);
  return applyOnView(s, V(s), FLAG_ANY, label, (m) => isCredentialName(m[3]) ? { from: m.index + m[0].length - m[5].length, to: m.index + m[0].length, kind: 'SECRET' } : null);
}

// Command forms: Windows `net use … /user:DOMAIN\\alice <pass>` (the token after the /user: token) and PowerShell
// `ConvertTo-SecureString '<x>' -AsPlainText` (the quoted argument). A credential header name followed by a space
// instead of a colon inside a bracket list ([Set-Cookie sessionid=x; Path=/, …]) takes the value up to the "," or "]".
function scrubCommands(s, label) {
  let out = s.replace(/(\/user:\S+[ \t]+)([^\s/][^\s]*)/gi, (m, pre, v) => isPlaceholderValue(v) ? m : pre + label('SECRET', v));
  out = out.replace(/(ConvertTo-SecureString[ \t]+)("[^"\n]*"|'[^'\n]*')/gi, (m, pre, v) => isPlaceholderValue(v) ? m : pre + label('SECRET', v));
  // New-Object pscredential 'user', '<x>' / PSCredential('user', '<x>') / [pscredential]::new('user', '<x>'): the second
  // quoted argument is the password.
  out = out.replace(/(pscredential\b[^\n(]{0,40}\(?[ \t]*(?:"[^"\n]*"|'[^'\n]*')[ \t]*,[ \t]*)("[^"\n]*"|'[^'\n]*')/gi, (m, pre, v) => isPlaceholderValue(v) ? m : pre + label('SECRET', v));
  return out.replace(/\b(Set-Cookie|Cookie|Authorization|Proxy-Authorization)([ \t]+)((?:Basic|Bearer|Digest)\b[^,\]\n]*|[^,\]\n]*=[^,\]\n]*)/gi, (m, h, sp, v) => isPlaceholderValue(v) ? m : h + sp + label('SECRET', v));
}

// URL query parameters whose name is a credential (code, auth, sig, token, session, …, or anything isCredentialName
// accepts) have their value replaced.
const QUERY_NAMES = new Set(['code', 'auth', 'sig', 'signature', 'key', 'token', 'secret', 'password', 'pwd', 'pass', 'access_token', 'refresh_token', 'id_token', 'apikey', 'api_key', 'session', 'sid', 'jwt', 'otp']);
function scrubQuery(s, label, resolve) {
  if (!s.includes('=')) return s;
  // Percent escapes anywhere in the name are decoded before the check (?%70assword=…; PR #27 review), and "+" is a space
  // as in form encoding (?api+key=…; PR #27 review).
  return s.replace(/([?&]((?:[A-Za-z0-9_.\-+]|%[0-9A-Fa-f]{2}){1,60})=)([^&\s#\]]+)/g, (m, pre, name, v) => {
    const n = decodeName(name.replace(/\+/g, ' '));
    return (!QUERY_NAMES.has(n.toLowerCase()) && !isCredentialName(resolve(n))) || isPlaceholderValue(v) ? m : pre + label('SECRET', v);
  });
}

// URL userinfo scheme://user:pass@host — the whole user:pass is replaced (a token-as-user form too). No length ceiling:
// a 300-character generated password must go too, and the classes exclude whitespace, slash and @, so the scan stays
// linear without one (PR #16 review).
const URL_USERINFO = /([a-z][a-z0-9+.\-]{0,30}:\/\/|(?<![\w:\/])\/\/(?=[^\s/@:]*:[^\s/@]+@))([^\s/@:]*:[^\s/@]+|[^\s/@:]{8,})@/gi;   // and scheme-relative //user:pass@host (RFC 3986 network-path; PR #27 review)   // a scheme may be one letter (x://) (PR #16 review)

const SCHEME_PROSE = /^(?:authentication|authorization|authorisation|credentials|tokens?|headers?|scheme|schemes|access|support|supported|login|logins)$/i;
// Bare auth scheme tokens anywhere (inside a value or a curl -H string): Basic/Bearer + token, or Digest + its params.
// Named header lines (Authorization:, Cookie:) are removed by scrubAssignments to the end of the line first; this is the
// safety net for a scheme token that is not introduced by a header name.
// After a lowercase scheme word, these plain words are prose ("basic understanding", "bearer instruments"); any other
// lowercase value is treated as a token (send bearer correcthorse now; PR #16 review).
const SCHEME_LOWER_PROSE = /^(?:understanding|knowledge|instruments?|bonds?|configuration|config|information|info|usage|idea|ideas|setup|version|plan|plans|account|level|training|rules?|needs|features?|principles?|functionality|structure|requirements?|skills?|questions?|steps?|stuff|things?|example|examples|form|format|search|support|package|tier|mode|level|policy|checks?|tests?|test|syntax|concepts?|terms|operations?|of|and|or|for|to|the|a|an|in|on|with|is|was)$/i;
function scrubBareAuth(s, label) {
  // No minimum length (`Basic YTpi` is a:b in base64; PR #16 review); a short plain lowercase word ("Bearer token",
  // "Basic auth") is prose about the scheme, not a token, and stays.
  // Words that name the scheme in prose ("Basic authentication", "Bearer tokens") stay too, at any length; a Digest
  // credential always carries name=value parameters, so Digest without an "=" is prose (PR #27 review).
  // Scheme names are case-insensitive (bearer, BASIC; PR #16 review). After a scheme not written as "Basic"/"Bearer", a
  // plain lowercase word of any length is prose ("basic understanding"), so only a token-looking value goes.
  let out = s.replace(/\b(basic|bearer)[ \t]+([A-Za-z0-9._~+/\-]+={0,2})/gi, (m, sch, v) => (isPlaceholderValue(v) || (v.length < 8 && /^[a-z]+$/.test(v)) || (!/^(?:Basic|Bearer)$/.test(sch) && SCHEME_LOWER_PROSE.test(v.replace(/\.+$/, ''))) || SCHEME_PROSE.test(v.replace(/\.+$/, ''))) ? m : `${sch} ${label('KEY', v)}`);
  return out.replace(/\b(digest)[ \t]+(?=[^\n]*=)([^\n]*=[^\n]*)/gi, (m, sch, v) => isPlaceholderValue(v) ? m : `${sch} ${label('KEY', v)}`);
}

// Known token shapes, shared by the main pass (KEY, matched on the folded view) and the residual scan. Assembled from
// pieces where a literal would trip the repo's own secret gate. Sources for the shapes: gitleaks (MIT) and
// detect-secrets (Apache-2.0) rule sets.
const KEY_SHAPES = [
  'sk-or-v1-[A-Za-z0-9]{20,}', 'sk-ant-[A-Za-z0-9_-]{10,}', 'sk-[A-Za-z0-9_-]{16,}', 'gh[pousr]_[A-Za-z0-9]{20,}',
  'xox' + '[a-z]-[A-Za-z0-9-]{10,}', '(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}', 'AIza[0-9A-Za-z_-]{30,}',
  'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{6,}', 'AGE-SECRET-KEY-1[A-Z0-9]{58}',
  'ABSK[A-Za-z0-9+/]{100,}={0,2}', 'gl(?:pat|rt|dt|ptt|soat|ft|oas|cbt|agent)-[A-Za-z0-9_-]{16,}',
  '[0-9a-f]{32}-us\\d{1,2}', 'v1\\.0-[a-f0-9]{24}-[a-f0-9]{146}',
  '[A-Za-z0-9_~.]{3}\\dQ~[A-Za-z0-9_~.-]{31,34}', 'api\\.softlayer\\.com/soap/v3(?:\\.1)?/[a-z0-9]{64}',
  '(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}', 'whsec_[A-Za-z0-9]{10,}', 'npm_[A-Za-z0-9]{20,}', 'ya29\\.[A-Za-z0-9_-]{20,}', 'pypi-[A-Za-z0-9_-]{20,}',
];
const KEY_SHAPE_RE = new RegExp('\\b(?:' + KEY_SHAPES.join('|') + ')', 'g');

const PATTERNS = [
  // Internationalised addresses too (usér@exämple.com, δοκιμή@παράδειγμα.δοκιμή): letters of any script, bounded classes.
  ['EMAIL', /"[^"\n]{1,64}"@[\p{L}\p{M}\p{N}.-]{1,253}\.[\p{L}\p{M}]{2,63}(?![\p{L}\p{M}\p{N}])/gu],   // quoted local part ("john doe"@x.com; PR #27)
  // Combining marks count as letters, so a decomposed exa\u0301mple.com is still one address (PR #16 review).
  ['EMAIL', /(?<![\p{L}\p{M}\p{N}])[\p{L}\p{M}\p{N}._%+-]{1,64}@[\p{L}\p{M}\p{N}.-]{1,253}\.[\p{L}\p{M}]{2,63}(?![\p{L}\p{M}\p{N}])/gu],
  ['CARD', /\b(?:\d[ -]?){12,18}\d\b/g],
  ['SSN', /(?<![\p{L}\p{N}-])\d{3}-\d{2}-\d{4}(?![\p{N}-])/gu],   // not \b: "id_123-45-6789" must match (PR #16 review)
  // A nine-digit SSN with no dashes counts after an SSN cue ("SSN: 123456789"; PR #27 review).
  ['SSN', /(?<=\b(?:ssn|SSN|social[ \t]+security(?:[ \t]+(?:number|no\.?|#))?)[ \t]*[:#=-]?[ \t]*)\d{9}\b/gi],
  ['PHONE', /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\b\d{2,4}[\s.-])\d{3,4}[\s.-]\d{3,4}\b/g],
  // Compact numbers: E.164 (+14155552671) anywhere, and 10–15 digits after a phone cue (PR #27 review).
  ['PHONE', /(?<![\w+])\+\d{10,15}\b/g],
  ['PHONE', /(?<=\b(?:phone|tel|telephone|mobile|cell|call|text|whatsapp|sms)[ \t]*[:#=]?[ \t]*)\d{10,15}\b/gi],
  // …and after "phone (number) is/was" (my phone is 4155552671; PR #27 review).
  ['PHONE', /(?<=\b(?:phone|tel|telephone|mobile|cell|whatsapp)(?:[ \t]+(?:number|no\.?|#))?[ \t]+(?:is|was|are)[ \t]+)\+?\d{10,15}\b/gi],
  ['IP', /\b(?:\d{1,3}\.){3}\d{1,3}\b/g],
  // IPv6, full or compressed; the callback keeps short look-alikes such as times (10:30:00) and C++ scopes (PR #27).
  ['IP', /(?<![\w:])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?![\w:])|(?<![\w:])(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?(?![\w:])/gi],
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

// --- Residual scan: a SECOND, independent mechanism (brief item 6), by shape and entropy rather than by context, so a
// secret the main pass missed is still caught and the whole text is held back. Pure function; returns only the reason,
// never the value.
const PREFIX_SHAPES = [
  ['known key shape', new RegExp('\\b(?:' + KEY_SHAPES.join('|') + ')')],
  ['pem private key', new RegExp('-----BEGIN[ \\t]+(?:[A-Z0-9]+[ \\t]+){0,32}PRIVATE[ \\t]+KEY')],
  ['http auth header', /\b(?:Authorization|Proxy-Authorization)[ \t]*:[ \t]*(?![\-\uE000])[^\s"'()\[\]{},;\uE000]{6,}/i],
  ['auth scheme token', /\b(?:Basic|Bearer)[ \t]+[A-Za-z0-9._~+/\-]{12,}/],
  ['credential assignment', new RegExp('(?<![\\p{L}\\p{N}])(?:password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|mot de passe|mdp|passwort|kennwort|contrase[ñn]a|senha|wachtwoord|пароль|パスワード|密码|비밀번호)(?![\\p{L}\\p{N}])[ \\t]*["\']?[ \\t]*[:=][ \\t]*["\']?(?![\\-\\uE000])[^\\s"\'()\\[\\]{},;\\uE000]{3,}', 'iu')],
  ['spaced hex groups', /\b(?:[0-9a-f]{4}[ -]){5,}[0-9a-f]{4}\b/i],   // recovery codes written as groups of four
];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function shannon(str) {
  const freq = Object.create(null);
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0; const len = str.length;
  for (const k in freq) { const p = freq[k] / len; h -= p * Math.log2(p); }
  return h;
}
export function residual(text, { terms = [] } = {}) {
  // Our own placeholders are safe. Each becomes a sentinel character (not a space) so "PASSWORD=[SECRET_1]" is not
  // mistaken for a live credential and, after "--password=[SECRET_1] --api-key=[SECRET_2]", the next flag is not read
  // as the first one's value: the value classes below exclude the sentinel and refuse a leading "-".
  const s = String(text ?? '').replace(PUB, OPEN);
  const reasons = [];
  for (const [why, re] of PREFIX_SHAPES) if (re.test(s)) reasons.push(why);
  // Entropy runs, looked at token by token so the whole string is never re-scanned per position. A hex run needs a
  // letter and at least 3 bits/char of entropy; a base64-class run needs at least two of {upper, lower, digit} (which keeps
  // lowercase URL paths and camelCase identifiers out) and entropy over 4 bits/char.
  for (const run of s.match(/[A-Za-z0-9+/=_-]{20,}/g) || []) {
    if (UUID.test(run) || run.startsWith(OPEN)) continue;
    if (/^[0-9a-fA-F]+$/.test(run)) { if (/[a-fA-F]/.test(run) && shannon(run) >= 3.0) { reasons.push('high-entropy hex run'); break; } continue; }
    const classes = (/[A-Z]/.test(run) ? 1 : 0) + (/[a-z]/.test(run) ? 1 : 0) + (/[0-9]/.test(run) ? 1 : 0);
    if (classes >= 2 && shannon(run) > 4.0) { reasons.push('high-entropy token'); break; }
  }
  // A generated password full of symbols (N7!qP2@vL9#sR4$x) breaks into short runs above, so whole tokens are looked at
  // too: upper, lower, digit and at least two symbols, 10-64 characters, not a URL or an email (PR #27 review).
  if (!reasons.includes('high-entropy token')) for (const tok of s.match(/[^\s"'`<>()\[\]{},;\uE000\uE001]{10,64}/g) || []) {
    if (tok.includes('://') || /^[^@]+@[\w.-]+\.[A-Za-z]{2,}$/.test(tok) || !/[a-z]/.test(tok) || !/[A-Z]/.test(tok) || !/[0-9]/.test(tok)) continue;
    if ((tok.match(/[!@#$%^&*~?+=]/g) || []).length >= 2 && shannon(tok) >= 3.3) { reasons.push('high-entropy token'); break; }
  }
  if (terms.length) {
    // The same folding as the main pass, so a term hidden with invisible characters or look-alike forms is still seen.
    const folded = foldName(foldStr(s)).toLowerCase();
    // Whole words only, as the scrubber matches them ("Ann" is not in "announce"; PR #27 review); plurals still count.
    for (const t of terms) {
      const tt = foldName(foldStr(t)).trim().toLowerCase();
      if (tt && new RegExp(`(?<![\\p{L}\\p{N}])${tt.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:['’]s|es|s)?(?![\\p{L}\\p{N}])`, 'u').test(folded)) { reasons.push('never-send term'); break; }
    }
  }
  return { held: reasons.length > 0, reasons };
}

// A sanitized value: the only thing allowed past the outbound boundary. Frozen and brand-checked (a plain object with
// the same keys is NOT a Sanitized), so a caller cannot hand the judge un-scrubbed text. It carries only safe fields and
// never the real values (the scrubber keeps the restore map; a Sanitized never does).
// Only this module holds MINT, so only sanitize() can make one; `new Sanitized(...)` elsewhere throws (PR #16 review).
const MINT = Symbol('sanitized');
export class Sanitized {
  #brand = true;
  constructor({ text, held, reasons, version }, mint) {
    if (mint !== MINT) throw new TypeError('Sanitized values are made only by scrubber().sanitize()');
    this.text = text; this.held = held; this.reasons = reasons; this.version = version;
    Object.freeze(this);
  }
  static is(x) { try { return x instanceof Sanitized && x.#brand === true; } catch { return false; } }
}
export class ScrubError extends Error { constructor(m) { super(m); this.name = 'ScrubError'; } }

// Returns a scrubber that keeps one placeholder per distinct value across every text it sees, so the judge can tell the
// same secret recurred without seeing it.
export function scrubber({ terms = [] } = {}) {
  const esc = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // A term that folds to nothing (only zero-width or combining characters) is dropped: it would make an empty regex
  // alternative that matches at every offset (PR #27 review).
  const own = terms.map(t => String(t).trim()).filter(t => t && foldStr(t).trim()).sort((a, b) => b.length - a.length);
  // Never-send words: whole-word, any case, not inside another word and not inside an email/host (so a one-letter term
  // can't eat the "x" in jo@x.example). Matched on the folded view with folded terms, so "A\u200Dcme", "Ａｃｍｅ",
  // "ıstanbul" and a decomposed "Café" are all the term.
  // The \uE000 in the lookbehind stops a term from matching inside a placeholder already made (a PEM block labelled
  // [KEY_1] must not have its "KEY" re-matched by never-send term "KEY").
  // A plural or possessive of the term ("Acmes", "Acme's") is still the term; "Ivory" for "Ivo" and "ACMEcorp" are not.
  const ownBody = `(?:${own.map(t => esc(foldStr(t))).join('|')})(?:['’]s|es|s)?`;
  const ownRe = own.length ? new RegExp(`(?<![\\p{L}\\p{N}@\\uE000])${ownBody}(?![\\p{L}\\p{N}@])`, 'giu') : null;
  // The same words with "@" allowed beside them, for a second sweep after the email rule has run (see scrubOnce).
  const ownAtRe = own.length ? new RegExp(`(?<![\\p{L}\\p{N}\\uE000])${ownBody}(?![\\p{L}\\p{N}])`, 'giu') : null;
  let deadline = Infinity;           // set by sanitize() for its run, so long loops can stop early
  const seen = new Map();            // kind\u0000value -> sentinel-wrapped placeholder
  const real = new Map();            // public [KIND_n] -> real value, for unscrub and echoes
  const counts = {};                 // distinct values found, per kind (what counts() reports)
  const next = {};                   // last placeholder number handed out, per kind
  const reserved = new Map();        // kind -> numbers that already appeared as literal [KIND_n] text in some input
  const inventory = [];              // { kind, value } of every value scrubbed, for echoes()
  const ambiguous = new Set();       // public [KIND_n] we minted that later also arrived as literal text: never restored
  // Why numbers are reserved: if the input already holds a literal "[SECRET_1]", our own first SECRET must not also be
  // "[SECRET_1]", or unscrub would map one placeholder to a value that contains itself and the two would be
  // indistinguishable. counts() still reports distinct values only; numbering just skips the reserved ones.
  const label = (kind, value) => {
    const k = kind + '\u0000' + value;
    if (!seen.has(k)) {
      let n = (next[kind] || 0) + 1; while (reserved.has(kind) && reserved.get(kind).has(n)) n++;
      next[kind] = n; counts[kind] = (counts[kind] || 0) + 1;
      const pub = `[${kind}_${n}]`;
      seen.set(k, OPEN + kind + '_' + n + CLOSE);
      // A SECRET value may already hold a PRIVATE sentinel; store the value in public [KIND_n] form so unscrub nests.
      real.set(pub, value.replace(SENT, (m, kk, nn) => `[${kk}_${nn}]`));
      inventory.push({ kind, value });
      if (kind === 'SECRET') {
        const core = value.trim().replace(/^["']|["']$/g, ''); if (core && core !== value) inventory.push({ kind, value: core });
        // The token itself, without a trailing comment or sibling setting ("hunter2 # temporary"), so an echo of just
        // the token is still found (viaknox PR #27 review).
        // Only when a comment or a sibling setting really follows: spaces alone may be part of the credential
        // ("correct horse battery staple" must not make "correct" a secret; PR #16 review).
        const tm = /^([^\s,;#]+)(?:[ \t]+#|[ \t]*[,;][ \t]*[\p{L}_][\p{L}\p{N}_.\-]*[ \t]*[=:])/u.exec(core), tok = tm && tm[1];
        if (tok && tok !== core) inventory.push({ kind, value: tok });
      }
    }
    return seen.get(k);
  };
  const resolve = (name) => name.replace(SENT, (m, kind, n) => real.get(`[${kind}_${n}]`) ?? m);

  function scrubOnce(text) {
    let s = String(text ?? '').replace(/[\uE000\uE001]/g, '');
    // Protect placeholders that were ALREADY in the input: wrap them so no rule re-matches them, and reserve their
    // numbers so a placeholder this scrubber makes can never equal them. They reveal back unchanged and are not counted.
    // A literal that equals a placeholder we already minted can no longer be told apart from it, so unscrub leaves that
    // placeholder as text from now on rather than risk turning a literal into the real value (PR #16 review).
    s = s.replace(PUB, (m, kind, n) => { if (real.has(m)) ambiguous.add(m); if (!reserved.has(kind)) reserved.set(kind, new Set()); reserved.get(kind).add(Number(n)); return OPEN + kind + '_' + n + CLOSE; });
    const V = viewer();
    s = scrubPem(s, label);
    if (ownRe) s = applyOnView(s, V(s), ownRe, label, (m) => ({ from: m.index, to: m.index + m[0].length, kind: 'PRIVATE' }));
    s = scrubPgpass(s, label);
    s = scrubSqlAuth(s, label);
    s = scrubNetrc(s, label);
    s = scrubCopula(s, label);
    s = scrubPhrase(s, label);
    s = scrubFlags(s, label, V);
    s = scrubCommands(s, label);
    s = s.replace(URL_USERINFO, (m, scheme, userinfo) => scheme + label('KEY', userinfo) + '@');
    s = scrubQuery(s, label, resolve);
    s = scrubXml(s, label, resolve);
    s = scrubHtmlAttrs(s, label, resolve);
    s = scrubMultipart(s, label, resolve);
    s = scrubNameValuePairs(s, label, resolve);
    s = scrubPathSegments(s, label, resolve);
    s = scrubScopes(s, label, resolve);
    s = scrubTables(s, label, resolve);
    s = scrubCodeForms(s, label, resolve);
    s = scrubConcatNames(s, label, resolve);
    s = scrubQuotedKeys(s, label, resolve);
    s = scrubAssignments(s, V(s), label, resolve);
    s = scrubLineForms(s, label, resolve);
    s = scrubCallArg(s, label, resolve);
    s = scrubBareAuth(s, label);
    // Any quoted string carrying an escaped quote (\") is a smuggling attempt: scrub the whole string. Benign values
    // like "jo" have no escaped quote and stay. The pattern is the classic linear JSON-string match.
    s = s.replace(/"(?:\\.|[^"\\\n])*"/g, (m) => (/\\"/.test(m) ? label('SECRET', m) : m));
    // Known key shapes on the folded view (a soft hyphen inside "ghp_…" does not hide it), then the plain PII shapes.
    s = applyOnView(s, V(s), KEY_SHAPE_RE, label, (m) => ({ from: m.index, to: m.index + m[0].length, kind: 'KEY' }));
    for (const [kind, re] of PATTERNS) {
      s = s.replace(re, (m) => {
        if (kind === 'CARD') { const d = m.replace(/\D/g, ''); if (d.length < 13 || !luhn(d)) return m; }
        // A two-group compressed address counts when its first group is a real IPv6 prefix (fe80::1 link-local, fd00::,
        // 2001::, ff02::; RFC 4291), so times (10::30) and short scopes still stay (PR #27 review).
        if (kind === 'IP' && m.includes(':') && !(m.split(':').filter(Boolean).length >= 3 && /[0-9a-f]{3,4}/i.test(m)) && !(m.includes('::') && /^(?:fe[89ab][0-9a-f]|f[cd][0-9a-f]{2}|2[0-9a-f]{3}|ff[0-9a-f]{2})$/i.test(m.split(':')[0]))) return m;
        return label(kind, m.trim());
      });
    }
    // A term beside "@" that the email rule did not consume (`user@Acme`, `jo@acme`: a handle or a single-label host) is
    // still the term. The first sweep keeps "@" out so a one-letter term cannot eat a host label inside a real address
    // (jo@x.example); real addresses are [EMAIL_n] by now, so this sweep may touch "@" freely (PR #16 review).
    if (ownAtRe) s = applyOnView(s, V(s), ownAtRe, label, (m) => ({ from: m.index, to: m.index + m[0].length, kind: 'PRIVATE' }));
    // A secret already recognised anywhere (in this text or an earlier one) is replaced wherever it recurs bare, e.g. an
    // agent repeating "CorrectHorse9!" after the user's PASSWORD=CorrectHorse9! (viaknox PR #27 review).
    const known = [...new Set(inventory.filter(e => (e.kind === 'SECRET' || e.kind === 'KEY') && e.value.trim().length >= 4 && !/[\uE000\uE001\n]/.test(e.value)).map(e => `${e.kind}\u0000${e.value.trim()}`))]
      .map(k => k.split('\u0000')).sort((a, b) => b[1].length - a[1].length);
    // One forward pass looking values up by length (not a full-text scan per secret, which was quadratic with thousands of
    // settings), and
    // only whole occurrences: a value that begins or ends with a letter or digit is not taken out of a longer word, so
    // password=pass does not turn "compass" into "com[SECRET_1]" (PR #16 review).
    if (known.length) {
      const kindOf = new Map(); for (const [kind, v] of known) if (!kindOf.has(v)) kindOf.set(v, kind);
      // Candidate lengths are indexed by the value's first four characters (every value has at least four), so a
      // position is only tried against values that can start there.
      const byPre = new Map(); for (const v of kindOf.keys()) { const p = v.slice(0, 4); if (!byPre.has(p)) byPre.set(p, new Set()); byPre.get(p).add(v.length); }
      for (const [p, set] of byPre) byPre.set(p, [...set].sort((a, b) => b - a));
      const firsts = new Set([...kindOf.keys()].map(v => v[0]));
      const word = (c) => c !== undefined && /[\p{L}\p{N}]/u.test(c);
      let out = '', at = 0;
      for (let i = 0; i < s.length; i++) {
        // The sanitize deadline is checked inside the loop: many distinct lengths sharing a first character could
        // otherwise run far past it before the check after scrubbing (PR #16 review). Past it, sanitize holds.
        if ((i & 1023) === 0 && Date.now() > deadline) throw new ScrubError('scrubbing took too long; holding back');
        if (!firsts.has(s[i])) continue;
        const lens = byPre.get(s.substr(i, 4)); if (!lens) continue;
        for (const L of lens) {
          const v = s.substr(i, L), kind = kindOf.get(v);
          if (kind === undefined || (word(v[0]) && word(s[i - 1])) || (word(v[L - 1]) && word(s[i + L]))) continue;
          out += s.slice(at, i) + label(kind, v); at = i + L; i = at - 1; break;
        }
      }
      s = out + s.slice(at);
    }
    // Card and SSN numbers recur with other separators (123-45-6789 echoed as 123456789; PR #27 review): match the digits
    // with any of space, dot or dash between them and reuse the same placeholder.
    for (const { kind, value } of inventory) {
      if (kind !== 'SSN' && kind !== 'CARD') continue;
      const d = value.replace(/\D/g, ''); if (d.length < 9) continue;
      const re = new RegExp(`(?<![\\d\\uE000])${d.split('').join('[ .-]?')}(?!\\d)`, 'g');
      s = s.replace(re, () => label(kind, value));
    }
    return s.replace(SENT, (m, kind, n) => `[${kind}_${n}]`);
  }

  return {
    scrub(text) { return scrubOnce(text); },
    // Puts the real values back into text returned by a model, locally. One pass in REVERSE insertion order: a
    // placeholder's value can only contain placeholders created before it (a SECRET made after a PRIVATE may wrap
    // it, never the other way round), so restoring newest first is dependency order and no fixed-point loop is needed
    // (a loop could run forever if a value ever contained its own placeholder).
    unscrub(text) {
      let s = String(text ?? '');
      for (const [ph, v] of [...real].reverse()) if (!ambiguous.has(ph)) s = s.split(ph).join(v);
      return s;
    },
    counts: () => ({ ...counts }),
    // True if the raw text holds a never-send term anywhere, even inside a value another rule replaced first (an email
    // like employee@acme.example becomes [EMAIL_1] before the term sweep, so counts().PRIVATE alone misses it).
    mentionsTerm(text) {
      if (!ownAtRe) return false;
      const view = foldStr(String(text ?? '').replace(/[\uE000\uE001]/g, ''));
      ownAtRe.lastIndex = 0; const hit = ownAtRe.test(view); ownAtRe.lastIndex = 0; return hit;
    },
    // scrub + the independent residual scan, returned as a frozen Sanitized. Throws ScrubError past the caps so a stuck
    // or enormous input means "no call", never a silent partial scrub.
    sanitize(text, { maxMs = 2000, maxChars = 4_000_000 } = {}) {
      const s = String(text ?? '');
      if (s.length > maxChars) throw new ScrubError(`input of ${s.length} characters is over the ${maxChars} cap; holding back`);
      const t0 = Date.now();
      // Any unexpected failure inside the scrubber is a ScrubError, so callers hold the text back instead of crashing.
      let scrubbed;
      deadline = t0 + maxMs;
      try { scrubbed = scrubOnce(s); } catch (e) { throw new ScrubError(`scrubber failed (${e && e.name}); holding back`); } finally { deadline = Infinity; }
      // The residual scan is inside the time budget too (PR #16 review).
      let r; try { r = residual(scrubbed, { terms: own }); } catch (e) { throw new ScrubError(`residual scan failed (${e && e.name}); holding back`); }
      if (Date.now() - t0 > maxMs) throw new ScrubError(`scrubbing took longer than ${maxMs} ms; holding back`);
      return new Sanitized({ text: scrubbed, held: r.held, reasons: r.reasons, version: SCRUBBER_VERSION }, MINT);
    },
    // Kinds whose inventoried user-side values appear verbatim in `text` (brief item 9: an exact echo, not a re-scan).
    // Values shorter than 4 characters are ignored. Never returns the values themselves.
    echoes(text) {
      const s = String(text ?? ''), kinds = new Set();
      // Contact details are compared normalised: emails without case, phones by their last ten digits, so a reformatted
      // echo ((415) 555-2671 -> 415-555-2671, Alice@ -> alice@) still counts (PR #27 review).
      const lower = s.toLowerCase();
      const phones = (s.match(/\+?\d[\d\s().-]{6,}\d/g) || []).map(x => x.replace(/\D/g, '').slice(-10));
      for (const { kind, value } of inventory) {
        if (!value || value.length < 4) continue;
        // A value that begins or ends with a letter or digit counts only as a whole occurrence, so PASSWORD=pass is not
        // echoed by "compass" or "passed" (PR #27 review).
        if (kind !== 'EMAIL' && s.includes(value) && (!/^[\p{L}\p{N}]|[\p{L}\p{N}]$/u.test(value) || new RegExp((/^[\p{L}\p{N}]/u.test(value) ? '(?<![\\p{L}\\p{N}])' : '') + value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + (/[\p{L}\p{N}]$/u.test(value) ? '(?![\\p{L}\\p{N}])' : ''), 'u').test(s))) kinds.add(kind);
        else if (kind === 'EMAIL' && new RegExp(`(?<![\\p{L}\\p{M}\\p{N}._%+-])${value.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\p{L}\\p{M}\\p{N}])`, 'u').test(lower)) kinds.add(kind);   // the whole address, not a suffix of data@… (PR #16 review)
        else if (kind === 'PHONE') { const d = value.replace(/\D/g, '').slice(-10); if (d.length >= 7 && phones.includes(d)) kinds.add(kind); }
      }
      return [...kinds];
    },
  };
}
