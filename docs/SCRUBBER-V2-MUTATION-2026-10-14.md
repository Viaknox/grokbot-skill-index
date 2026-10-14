# Mutation report: src/redact.js

- Mutants generated: 843
- Killed: 432
- Killed by timeout: 17
- Survivors: 394
- Run time: 5057.8 s

## Survivors

| Line | Operator | Snippet |
| --- | --- | --- |
| 26 | regex | const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF\u00AD]/g; |
| 33 | and-or | tr) => (CONFUSABLE[c] && (LATIN.test(str[idx - 1] \|\| '') \|\| LATIN.test(str[idx + 1] \|\| ''))) ? CONFU |
| 36 | regex | return s.replace(/[\u0400-\u04FF\u0370-\u03FF]/g, confusableAt); |
| 40 | regex | return name.replace(/\\u([0-9a-fA-F]{4})/g, (m, h) => String.fromCharCode(parseInt(h, 16))).replac |
| 40 | int | {4})/g, (m, h) => String.fromCharCode(parseInt(h, 16))).replace(/%([0-9a-fA-F]{2})/g, (m, h) => Stri |
| 40 | regex | => String.fromCharCode(parseInt(h, 16))).replace(/%([0-9a-fA-F]{2})/g, (m, h) => String.fromCharCod |
| 40 | int | de(parseInt(h, 16))).replace(/%([0-9a-fA-F]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16))); |
| 64 | and-or | const k = r.normalize('NFKC'); if (k.length >= 1 && k.length <= 4) r = k; |
| 64 | cmp | const k = r.normalize('NFKC'); if (k.length >= 1 && k.length <= 4) r = k; |
| 64 | int | const k = r.normalize('NFKC'); if (k.length >= 1 && k.length <= 4) r = k; |
| 67 | cmp | if (FOLD_CACHE.size < 8192) FOLD_CACHE.set(c, r); |
| 67 | int | if (FOLD_CACHE.size < 8192) FOLD_CACHE.set(c, r); |
| 79 | cmp | if (code < 0x80) { |
| 82 | eq | (code === 0x5C && (s[i + 1] === '\n' \|\| (s[i + 1] === '\r' && s[i + 2] === '\n'))) { i += s[i + 1] = |
| 82 | and-or | 0x5C && (s[i + 1] === '\n' \|\| (s[i + 1] === '\r' && s[i + 2] === '\n'))) { i += s[i + 1] === '\r' ? |
| 82 | int | (s[i + 1] === '\n' \|\| (s[i + 1] === '\r' && s[i + 2] === '\n'))) { i += s[i + 1] === '\r' ? 2 : 1; r |
| 82 | eq | i + 1] === '\n' \|\| (s[i + 1] === '\r' && s[i + 2] === '\n'))) { i += s[i + 1] === '\r' ? 2 : 1; rev[ |
| 82 | int | = '\r' && s[i + 2] === '\n'))) { i += s[i + 1] === '\r' ? 2 : 1; rev[i] = parts.length; continue; } |
| 85 | cmp | parts.push(code < 0x20 && code !== 0x0A && code !== 0x0D && code !== 0x09 \|\| code === 0x7F ? ' |
| 87 | cmp | if (code >= 0x80 && code <= 0x9F) { parts.push(' '); map.push(i); continue; } |
| 87 | cmp | if (code >= 0x80 && code <= 0x9F) { parts.push(' '); map.push(i); continue; } |
| 88 | cmp | if (code >= 0xD800 && code <= 0xDBFF && i + 1 < n) { parts.push(s[i], s[i + 1]); map.push(i, i + |
| 88 | cmp | if (code >= 0xD800 && code <= 0xDBFF && i + 1 < n) { parts.push(s[i], s[i + 1]); map.push(i, i + |
| 88 | cmp | if (code >= 0xD800 && code <= 0xDBFF && i + 1 < n) { parts.push(s[i], s[i + 1]); map.push(i, i + |
| 120 | cmp | for (let i = 0; i < joined.length; i++) { |
| 150 | and-or | t glued = parts.reduce((a, p) => (/^\d+$/.test(p) && a.length ? (a[a.length - 1] += p, a) : (a.push( |
| 152 | cmp | if (parts.length >= 2 && /^keys?$/.test(parts[parts.length - 1]) && !STRUCTURAL_KEY.has(parts[part |
| 152 | int | if (parts.length >= 2 && /^keys?$/.test(parts[parts.length - 1]) && !STRUCTURAL_KEY.has(parts[part |
| 152 | regex | if (parts.length >= 2 && /^keys?$/.test(parts[parts.length - 1]) && !STRUCTURAL_KEY.has(parts[part |
| 152 | ret | keys?$/.test(parts[parts.length - 1]) && !STRUCTURAL_KEY.has(parts[parts.length - 2])) return true; |
| 152 | bool | keys?$/.test(parts[parts.length - 1]) && !STRUCTURAL_KEY.has(parts[parts.length - 2])) return true; |
| 163 | regex | const HEADER_CRED = /^(?:set-cookie\|cookie\|authorization\|proxy-authorization)$/i; |
| 173 | regex | new RegExp('-----END[ \\t]+' + label.trim().split(/[ \t]+/).filter(Boolean).map(w => w + '[ \\t]+'). |
| 180 | and-or | if (s[afterHead] === '\\' && s[afterHead + 1] === 'n') { |
| 185 | cmp | while (q < s.length) { if (s[q] === '"' && s[q - 1] !== '\\') break; q++; } |
| 222 | cmp | for (let i = start; i < s.length; i++) { |
| 224 | eq | if (c === '"' \|\| c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; |
| 224 | and-or | if (c === '"' \|\| c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; |
| 224 | eq | if (c === '"' \|\| c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; |
| 224 | cmp | if (c === '"' \|\| c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; |
| 224 | eq | '"' \|\| c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; continue; } |
| 224 | eq | '"' \|\| c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; continue; } |
| 225 | eq | if (c === '[') depth++; |
| 226 | eq | else if (c === ']' && --depth === 0) return i + 1; |
| 240 | int | === '"""' \|\| tq === "'''") { const e = s.indexOf(tq, start + 3); return e < 0 ? s.length : e + 3; } |
| 240 | cmp | === '"""' \|\| tq === "'''") { const e = s.indexOf(tq, start + 3); return e < 0 ? s.length : e + 3; } |
| 240 | int | === '"""' \|\| tq === "'''") { const e = s.indexOf(tq, start + 3); return e < 0 ? s.length : e + 3; } |
| 241 | cmp | if (s[start] === ''') { for (let i = start + 1; i < s.length; i++) { if (s[i] === '\\') { i++; conti |
| 241 | eq | (let i = start + 1; i < s.length; i++) { if (s[i] === '\\') { i++; continue; } if (s[i] === ''') ret |
| 241 | eq | ; i++) { if (s[i] === '\\') { i++; continue; } if (s[i] === ''') return i + 1; } return s.length; } |
| 242 | int | const hd = /^<<[-~]?[ \t]*(["']?)([A-Za-z_]\w{0,40})\1/.exec(s.slice(start, start + 60)); |
| 244 | cmp | for (let ls = s.indexOf('\n', start); ls >= 0; ) { const le0 = s.indexOf('\n', ls + 1), le = le0 |
| 244 | cmp | ) { const le0 = s.indexOf('\n', ls + 1), le = le0 < 0 ? s.length : le0; if (s.slice(ls + 1, le).trim |
| 244 | cmp | .length : le0; if (s.slice(ls + 1, le).trim() === hd[2]) return le; if (le0 < 0) break; ls = le0; } |
| 250 | cmp | for (; i < s.length; i++) { if (s[i] === '\\') { i++; continue; } if (s[i] === q) return i + 1; |
| 254 | cmp | if (nl < 0) nl = s.length; |
| 266 | cmp | let lineEnd = s.indexOf('\n', lineStart); if (lineEnd < 0) lineEnd = s.length; |
| 269 | eq | /^\s*/) \|\| [''])[0].length <= indent && !(trimmed === '' && (line.match(/^\s*/) \|\| [''])[0].length = |
| 269 | regex | ngth <= indent && !(trimmed === '' && (line.match(/^\s*/) \|\| [''])[0].length === indent && /^\s*-(?: |
| 269 | and-or | indent && !(trimmed === '' && (line.match(/^\s*/) \|\| [''])[0].length === indent && /^\s*-(?:\s\|$)/.t |
| 269 | eq | === '' && (line.match(/^\s*/) \|\| [''])[0].length === indent && /^\s*-(?:\s\|$)/.test(line))) break; |
| 269 | regex | === '' && (line.match(/^\s*/) \|\| [''])[0].length === indent && /^\s*-(?:\s\|$)/.test(line))) break; |
| 277 | cmp | while (/\\\r?$/.test(line) && nl < s.length) { |
| 279 | cmp | nl = s.indexOf('\n', from); if (nl < 0) nl = s.length; |
| 291 | cmp | for (const [a, b, kind] of ivs) { if (a < at \|\| b <= a) continue; const v = s.slice(a, b); if (!v. |
| 291 | and-or | for (const [a, b, kind] of ivs) { if (a < at \|\| b <= a) continue; const v = s.slice(a, b); if (!v. |
| 291 | cmp | for (const [a, b, kind] of ivs) { if (a < at \|\| b <= a) continue; const v = s.slice(a, b); if (!v.tr |
| 291 | and-or | continue; const v = s.slice(a, b); if (!v.trim() \|\| isPlaceholderValue(v)) continue; out += s.slice |
| 306 | cmp | if (re.lastIndex < r.to) re.lastIndex = r.to; |
| 332 | cmp | if (sepEnd < at) continue; |
| 339 | regex | && (() => { const e = braceEnd(s, sepEnd); return /[:=]/.test(s.slice(sepEnd + 1, e)) && /^[ \t]*(?: |
| 339 | and-or | pEnd); return /[:=]/.test(s.slice(sepEnd + 1, e)) && /^[ \t]*(?:[,;}\]\r\n]\|$)/.test(s.slice(e + 1, |
| 339 | regex | d); return /[:=]/.test(s.slice(sepEnd + 1, e)) && /^[ \t]*(?:[,;}\]\r\n]\|$)/.test(s.slice(e + 1, e + |
| 339 | int | [:=]/.test(s.slice(sepEnd + 1, e)) && /^[ \t]*(?:[,;}\]\r\n]\|$)/.test(s.slice(e + 1, e + 3)); })(); |
| 348 | cmp | let nl = s.indexOf('\n', sepEnd); if (nl < 0) nl = s.length; |
| 349 | int | :]{0,160}:(?:[ \t]\|$)/m.test(s.slice(nl + 1, nl + 200).split(/\n(?=[ \t]*\S)/)[0] \|\| '')) { ASSIGN_S |
| 360 | int | ASSIGN_START.lastIndex = m.index + m[1].length + m[2].length; |
| 372 | regex | if (/^[\p{L}\p{N}_$.\-]+$/u.test(name) \|\| !isCredentialName(name)) continue; |
| 372 | and-or | if (/^[\p{L}\p{N}_$.\-]+$/u.test(name) \|\| !isCredentialName(name)) continue; |
| 374 | eq | const ve = s[vs] === '[' ? bracketEnd(s, vs) : valueEnd(s, vs), v = s.slice(vs, ve); |
| 393 | regex | const ENV_LINE = /^[ \t]*(?:ENV\|ARG\|export\|set\|setenv\|env)[ \t]+/; |
| 403 | cmp | for (; j < s.length; j++) { const c = s[j]; if (c === '"') { q = !q; continue; } if (!q && c === ' |
| 406 | regex | const trailingName = (tok) => (tok.replace(/[:=]+$/, '').replace(/["']$/, '').match(/[\p{L}\p{N}_$. |
| 406 | regex | ame = (tok) => (tok.replace(/[:=]+$/, '').replace(/["']$/, '').match(/[\p{L}\p{N}_$.\-]+$/u) \|\| [''] |
| 409 | cmp | while (i < s.length) { |
| 410 | cmp | let nl = s.indexOf('\n', i); if (nl < 0) nl = s.length; |
| 411 | regex | const line = s.slice(i, nl).replace(/\r$/, ''); |
| 414 | cmp | if ((m = BARE_KEY_LINE.exec(line)) && line.length > m[0].length) { |
| 416 | cmp | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) |
| 416 | and-or | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) |
| 416 | and-or | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) { ou |
| 419 | regex | const toks = []; const TOK = /\S+/g; TOK.lastIndex = m[0].length; |
| 421 | cmp | for (let k = 0; k + 1 < toks.length; k++) { |
| 423 | regex | if (!/[=:]/.test(t.text) && isCredentialName(resolve(t.text)) && !/[=:]/.test(v.text) && v.a |
| 423 | and-or | test(t.text) && isCredentialName(resolve(t.text)) && !/[=:]/.test(v.text) && v.at >= at && !isPlaceh |
| 423 | regex | (t.text) && isCredentialName(resolve(t.text)) && !/[=:]/.test(v.text) && v.at >= at && !isPlaceholde |
| 423 | and-or | tialName(resolve(t.text)) && !/[=:]/.test(v.text) && v.at >= at && !isPlaceholderValue(v.text)) { ou |
| 423 | cmp | (resolve(t.text)) && !/[=:]/.test(v.text) && v.at >= at && !isPlaceholderValue(v.text)) { out += s.s |
| 423 | and-or | ve(t.text)) && !/[=:]/.test(v.text) && v.at >= at && !isPlaceholderValue(v.text)) { out += s.slice(a |
| 427 | cmp | if (vStart >= at && !isPlaceholderValue(m[2])) { out += s.slice(at, vStart) + label('SECRET', |
| 430 | cmp | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) |
| 430 | and-or | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) |
| 430 | and-or | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) { ou |
| 431 | cmp | } else if ((m = YAML_Q.exec(line)) && isCredentialName(resolve(m[1])) && nl < s.length) { |
| 432 | cmp | let nl2 = s.indexOf('\n', nl + 1); if (nl2 < 0) nl2 = s.length; |
| 434 | cmp | [0].length, end = valueEnd(s, vStart); if (vStart >= at && s.slice(vStart, end).trim()) { out += s.s |
| 434 | and-or | ngth, end = valueEnd(s, vStart); if (vStart >= at && s.slice(vStart, end).trim()) { out += s.slice(a |
| 435 | cmp | } else if ((m = BARE_NAME.exec(line)) && isCredentialName(resolve(m[2])) && nl < s.length) { |
| 438 | cmp | let nl2 = s.indexOf('\n', nl + 1); if (nl2 < 0) nl2 = s.length; |
| 441 | and-or | let vStart = nl + 1 + c[0].length; if (vStart >= nl2 && nl2 < s.length) vStart = nl2 + 1; |
| 441 | cmp | let vStart = nl + 1 + c[0].length; if (vStart >= nl2 && nl2 < s.length) vStart = nl2 + 1; |
| 443 | cmp | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end)) |
| 443 | and-or | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end)) |
| 443 | and-or | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) { ou |
| 447 | regex | const nameIndent = (line.match(/^[ \t]*/) \|\| [''])[0].length, next = s.slice(nl + 1, nl2), n |
| 447 | and-or | const nameIndent = (line.match(/^[ \t]*/) \|\| [''])[0].length, next = s.slice(nl + 1, nl2), n |
| 448 | and-or | if (next.trim() && nextIndent > nameIndent) { |
| 448 | cmp | if (next.trim() && nextIndent > nameIndent) { |
| 450 | cmp | while (end < s.length) { let e2 = s.indexOf('\n', end + 1); if (e2 < 0) e2 = s.length; con |
| 450 | cmp | ngth) { let e2 = s.indexOf('\n', end + 1); if (e2 < 0) e2 = s.length; const l2 = s.slice(end + 1, e2 |
| 450 | and-or | ; const l2 = s.slice(end + 1, e2); if (!l2.trim() \|\| (l2.match(/^[ \t]*/) \|\| [''])[0].length <= name |
| 450 | regex | s.slice(end + 1, e2); if (!l2.trim() \|\| (l2.match(/^[ \t]*/) \|\| [''])[0].length <= nameIndent) break |
| 450 | and-or | + 1, e2); if (!l2.trim() \|\| (l2.match(/^[ \t]*/) \|\| [''])[0].length <= nameIndent) break; end = e2; |
| 450 | cmp | 1, e2); if (!l2.trim() \|\| (l2.match(/^[ \t]*/) \|\| [''])[0].length <= nameIndent) break; end = e2; } |
| 452 | cmp | if (vStart >= at && !isPlaceholderValue(s.slice(vStart, end))) { out += s.slice(at, vStart |
| 452 | and-or | if (vStart >= at && !isPlaceholderValue(s.slice(vStart, end))) { out += s.slice(at, vStart |
| 461 | and-or | if (csv.cols.has(k) && core && a + lead >= at && !isPlaceholderValue(core)) { out += s.sli |
| 461 | and-or | if (csv.cols.has(k) && core && a + lead >= at && !isPlaceholderValue(core)) { out += s.sli |
| 461 | cmp | if (csv.cols.has(k) && core && a + lead >= at && !isPlaceholderValue(core)) { out += s.sli |
| 461 | and-or | if (csv.cols.has(k) && core && a + lead >= at && !isPlaceholderValue(core)) { out += s.slice(at, |
| 465 | and-or | } else if (line.includes(',') && !csv) { |
| 468 | regex | h((c, k) => { if (isCredentialName(resolve(c.trim().replace(/^["']\|["']$/g, '')))) cols.add(k); }); |
| 498 | cmp | for (let m; (m = KV.exec(s)) && m.index < close;) { |
| 503 | eq | if (c === '[') { const ae = Math.min(bracketEnd(s, vs), close); if (s.slice(vs + 1, ae - 1).trim |
| 506 | eq | if (c === '"' \|\| c === "'") { ve = vs + 1; while (ve < close && s[ve] !== c) { if (s[ve] === '\ |
| 506 | and-or | if (c === '"' \|\| c === "'") { ve = vs + 1; while (ve < close && s[ve] !== c) { if (s[ve] === '\ |
| 506 | eq | if (c === '"' \|\| c === "'") { ve = vs + 1; while (ve < close && s[ve] !== c) { if (s[ve] === '\ |
| 506 | cmp | (c === '"' \|\| c === "'") { ve = vs + 1; while (ve < close && s[ve] !== c) { if (s[ve] === '\\') ve++ |
| 507 | cmp | else { ve = vs; while (ve < close && !',}]\n'.includes(s[ve])) ve++; } |
| 507 | and-or | else { ve = vs; while (ve < close && !',}]\n'.includes(s[ve])) ve++; } |
| 518 | int | let d = 0; const lim = Math.min(s.length, open + 65536); |
| 519 | cmp | for (let i = open; i < lim; i++) { |
| 521 | and-or | if (c === '"' \|\| c === "'") { for (i++; i < lim && s[i] !== c; i++) if (s[i] === '\\') i++; cont |
| 521 | cmp | if (c === '"' \|\| c === "'") { for (i++; i < lim && s[i] !== c; i++) if (s[i] === '\\') i++; cont |
| 521 | eq | c === '"' \|\| c === "'") { for (i++; i < lim && s[i] !== c; i++) if (s[i] === '\\') i++; continue; } |
| 532 | cmp | while (i < s.length) { |
| 533 | cmp | let nl = s.indexOf('\n', i); if (nl < 0) nl = s.length; |
| 539 | cmp | for (let bo = line.indexOf('{'); bo >= 0; bo = line.indexOf('{', bo + 1)) { |
| 541 | regex | if (/[:=][ \t]*$/.test(head) \|\| !(m = BLOCK_NAME.exec(head)) \|\| !isCredentialName(resolve(m[2] |
| 550 | cmp | if ((m = YAML_MAP_KEY.exec(line)) && isCredentialName(resolve(m[3])) && nl < s.length) { |
| 553 | cmp | st ls = j + 1; let le = s.indexOf('\n', ls); if (le < 0) le = s.length; const l2 = s.slice(ls, le); |
| 555 | cmp | (l2.match(/^[ \t]*/) \|\| [''])[0].length; if (ind2 < base \|\| (ind2 === base && !/^[ \t]*-(?:[ \t]\|$)/ |
| 555 | regex | \|\| [''])[0].length; if (ind2 < base \|\| (ind2 === base && !/^[ \t]*-(?:[ \t]\|$)/.test(l2))) break; } |
| 557 | regex | if (c && c[0].length < l2.replace(/[ \t\r]+$/, '').length) { const vs = ls + c[0].length, ve |
| 566 | cmp | const ls = j + 1; let le = s.indexOf('\n', ls); if (le < 0) le = s.length; |
| 568 | cmp | if ((l2.match(/^[ \t]*/) \|\| [''])[0].length <= ind) break; |
| 570 | and-or | if (km && km[0].length < l2.length) { const vs = ls + km[0].length, ve = valueEnd(s, vs); iv |
| 570 | cmp | if (km && km[0].length < l2.length) { const vs = ls + km[0].length, ve = valueEnd(s, vs); iv |
| 582 | regex | lve) => list.split(',').map(c => c.trim().replace(/^["'\x60\[]\|["'\x60\]]$/g, '')).map((c, k) => (is |
| 582 | cmp | \[]\|["'\x60\]]$/g, '')).map((c, k) => (isCredentialName(resolve(c)) ? k : -1)).filter(k => k >= 0); |
| 590 | cmp | while (p < s.length) { |
| 591 | cmp | while (p < s.length && (s[p] === ' ' \|\| s[p] === ',' \|\| s[p] === '\n' \|\| s[p] === '\r' \|\| s[ |
| 591 | and-or | while (p < s.length && (s[p] === ' ' \|\| s[p] === ',' \|\| s[p] === '\n' \|\| s[p] === '\r' \|\| s[ |
| 591 | and-or | le (p < s.length && (s[p] === ' ' \|\| s[p] === ',' \|\| s[p] === '\n' \|\| s[p] === '\r' \|\| s[p] === '\t' |
| 591 | and-or | s.length && (s[p] === ' ' \|\| s[p] === ',' \|\| s[p] === '\n' \|\| s[p] === '\r' \|\| s[p] === '\t')) p++; |
| 591 | and-or | s.length && (s[p] === ' ' \|\| s[p] === ',' \|\| s[p] === '\n' \|\| s[p] === '\r' \|\| s[p] === '\t')) p++; |
| 593 | bool | let depth = 0, k = 0, cellStart = p + 1, i = p + 1, done = false; |
| 594 | cmp | for (; i < s.length; i++) { |
| 596 | and-or | if (c === "'" \|\| c === '"') { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\' |
| 596 | cmp | if (c === "'" \|\| c === '"') { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') |
| 598 | int | q = /^\$[A-Za-z_]?\w{0,30}\$/.exec(s.slice(i, i + 34)); if (dq) { const e = s.indexOf(dq[0], i + dq[ |
| 598 | cmp | nst e = s.indexOf(dq[0], i + dq[0].length); i = e < 0 ? s.length : e + dq[0].length - 1; continue; } |
| 599 | and-or | if (c === '[' \|\| c === '{') { depth++; continue; } |
| 600 | and-or | if (c === ']' \|\| c === '}') { depth--; continue; } |
| 602 | bool | === 0) { if (cols.includes(k)) ivs.push([cellStart, i, 'SECRET']); done = true; break; } depth--; } |
| 614 | cmp | while (i < s.length) { |
| 615 | cmp | let nl = s.indexOf('\n', i); if (nl < 0) nl = s.length; |
| 616 | regex | const line = s.slice(i, nl); if (/^\\\.[ \t\r]*$/.test(line)) break; |
| 617 | and-or | '\t').forEach((cell, k) => { if (cols.includes(k) && cell.trim()) ivs.push([pos, pos + cell.length, |
| 625 | cmp | while (i < s.length) { |
| 626 | cmp | let nl = s.indexOf('\n', i); if (nl < 0) nl = s.length; |
| 627 | regex | const line = s.slice(i, nl).replace(/\r$/, ''); |
| 630 | cmp | () => { let n2 = s.indexOf('\n', nl + 1); if (n2 < 0) n2 = s.length; return /^[ \t]*(?:\\|[ \t]*)?:? |
| 631 | regex | if (/^[ \t]*\\|.*\\|[ \t]*$/.test(line) \|\| (line.includes('\|') && (cols !== null \|\| ruleNext())) |
| 631 | and-or | if (/^[ \t]*\\|.*\\|[ \t]*$/.test(line) \|\| (line.includes('\|') && (cols !== null \|\| ruleNext()))) { |
| 635 | cmp | Of('\|'); k >= 0; k = line.indexOf('\|', k + 1)) if (!(k > 0 && line[k - 1] === '\\')) pipes.push(k); |
| 637 | cmp | for (let q = 0; q + 1 < bounds.length; q++) { const a = bounds[q] + 1, b = bounds[q + 1]; if |
| 637 | eq | onst a = bounds[q] + 1, b = bounds[q + 1]; if ((q === 0 \|\| q === bounds.length - 2) && !line.slice(a |
| 637 | and-or | = bounds[q] + 1, b = bounds[q + 1]; if ((q === 0 \|\| q === bounds.length - 2) && !line.slice(a, b).t |
| 637 | eq | unds[q] + 1, b = bounds[q + 1]; if ((q === 0 \|\| q === bounds.length - 2) && !line.slice(a, b).trim() |
| 637 | int | nds[q + 1]; if ((q === 0 \|\| q === bounds.length - 2) && !line.slice(a, b).trim()) continue; cells.pu |
| 639 | cmp | let nl2 = s.indexOf('\n', nl + 1); if (nl2 < 0) nl2 = s.length; |
| 640 | cmp | e(s.slice(a, b).trim())) ? k : -1)).filter(k => k >= 0); if (found.length) { cols = new Set(found); |
| 641 | and-or | } else if (cells.length === n && !/^[ \t]*(?:\\|[ \t]*)?:?-{3,}/.test(line)) { |
| 641 | regex | } else if (cells.length === n && !/^[ \t]*(?:\\|[ \t]*)?:?-{3,}/.test(line)) { |
| 644 | eq | } else if (line.trim() === '') cols = null; |
| 651 | int | for (let t = s.indexOf('<table'); t >= 0; t = s.indexOf('<table', t + 6)) { |
| 652 | cmp | let end = s.indexOf('</table>', t); if (end < 0) end = s.length; end = Math.min(end, t + 65536 |
| 652 | int | let end = s.indexOf('</table>', t); if (end < 0) end = s.length; end = Math.min(end, t + 65536); |
| 654 | cmp | for (let r; (r = ROW.exec(s)) && r.index < end;) { |
| 655 | cmp | let rowEnd = s.indexOf('</tr>', r.index); if (rowEnd < 0 \|\| rowEnd > end) rowEnd = end; |
| 655 | and-or | let rowEnd = s.indexOf('</tr>', r.index); if (rowEnd < 0 \|\| rowEnd > end) rowEnd = end; |
| 655 | cmp | let rowEnd = s.indexOf('</tr>', r.index); if (rowEnd < 0 \|\| rowEnd > end) rowEnd = end; |
| 657 | cmp | for (let c; (c = CELL.exec(s)) && c.index < rowEnd;) cells.push({ th: c[1].toLowerCase() === |
| 657 | int | === 'h', a: c.index + c[0].length - c[2].length - 5 - 0, text: c[2], start: c.index + c[0].indexOf(' |
| 658 | regex | c, k) => (isCredentialName(resolve(c.text.replace(/<[^<>]*>/g, '').trim())) ? k : -1)).filter(k => k |
| 659 | and-or | else if (cols) for (const k of cols) if (cells[k] && cells[k].text.trim()) ivs.push([cells[k].start, |
| 674 | regex | const IDENT_ATTR = /^(?:name\|id\|http-equiv\|type\|class\|aria-label\|placeholder\|data-field\|data-name\|da |
| 675 | regex | const ATTR_VALUE = /\b(value\|content)([ \t]*=[ \t]*)("[^"]*"\|'[^']*'\|[^\s>]+)/gi; |
| 690 | cmp | if (last && from >= last.from && (last.found < 0 \|\| last.found >= from)) return last.found; |
| 690 | cmp | if (last && from >= last.from && (last.found < 0 \|\| last.found >= from)) return last.found; |
| 690 | and-or | if (last && from >= last.from && (last.found < 0 \|\| last.found >= from)) return last.found; |
| 690 | cmp | if (last && from >= last.from && (last.found < 0 \|\| last.found >= from)) return last.found; |
| 695 | bool | let byAttr = false; ATTR_ANY.lastIndex = 0; |
| 697 | and-or | ATTR_ANY.exec(tag));) { if ((/^type$/i.test(a[1]) && /^["']?password["']?$/i.test(a[3])) \|\| (/^autoc |
| 697 | and-or | ?$/i.test(a[3])) \|\| (/^autocomplete$/i.test(a[1]) && /^["']?(?:current-password\|new-password\|one-tim |
| 697 | regex | t(a[1])) continue; const n = resolve(a[3].replace(/^["']\|["']$/g, '')); if (isCredentialName(n) \|\| H |
| 705 | regex | const raw = v[3].replace(/^["']\|["']$/g, ''); |
| 706 | regex | if (/^(?:name\|id\|http-equiv\|type\|class)$/i.test(v[1]) \|\| (IDENT_ATTR.test(v[1]) && (isCredenti |
| 706 | and-or | /^(?:name\|id\|http-equiv\|type\|class)$/i.test(v[1]) \|\| (IDENT_ATTR.test(v[1]) && (isCredentialName(res |
| 706 | and-or | ENT_ATTR.test(v[1]) && (isCredentialName(resolve(raw)) \|\| HEADER_CRED.test(raw.trim())))) continue; |
| 707 | bool | ndex + v.index + v[0].length - v[3].length; ivs.push([vs, vs + v[3].length, 'SECRET']); hit = true; |
| 711 | and-or | if (!hit && byAttr) { const c = CHILD_VALUE.exec(s.slice(m.index + tag.length, m.index + tag.len |
| 711 | int | lice(m.index + tag.length, m.index + tag.length + 4200)); if (c) { const vs = m.index + tag.length + |
| 711 | int | .index + tag.length + c[0].length - c[2].length - 2; ivs.push([vs, vs + c[2].length, 'SECRET']); } } |
| 712 | and-or | if (byAttr && !tag.endsWith('/>') && tagName) { const open = m.index + tag.length, close = close |
| 712 | and-or | if (byAttr && !tag.endsWith('/>') && tagName) { const open = m.index + tag.length, close = close |
| 712 | cmp | length, close = closeOf(tagName, open); if (close > open && close - open <= 65536 && !s.slice(open, |
| 712 | and-or | close = closeOf(tagName, open); if (close > open && close - open <= 65536 && !s.slice(open, close). |
| 712 | cmp | (tagName, open); if (close > open && close - open <= 65536 && !s.slice(open, close).includes('<') && |
| 712 | int | gName, open); if (close > open && close - open <= 65536 && !s.slice(open, close).includes('<') && s. |
| 712 | and-or | open); if (close > open && close - open <= 65536 && !s.slice(open, close).includes('<') && s.slice( |
| 712 | and-or | n <= 65536 && !s.slice(open, close).includes('<') && s.slice(open, close).trim()) ivs.push([open, cl |
| 726 | cmp | if (sepEnd < at \|\| !isCredentialName(resolve(joined)) \|\| s[sepEnd] === '{') continue; |
| 726 | and-or | if (sepEnd < at \|\| !isCredentialName(resolve(joined)) \|\| s[sepEnd] === '{') continue; |
| 726 | and-or | if (sepEnd < at \|\| !isCredentialName(resolve(joined)) \|\| s[sepEnd] === '{') continue; |
| 728 | and-or | if (!value.trim() \|\| isPlaceholderValue(value)) continue; |
| 746 | and-or | if (s.includes('*') && s.includes('&')) { |
| 749 | regex | const re = new RegExp('(?<![\\w&])&' + a.replace(/[.*+?^${}()\|[\]\\]/g, '\\$&') + '(?![\\w.\\-])[  |
| 751 | and-or | ED.exec(s));) if (isCredentialName(resolve(m[1])) && s[m.index + m[0].length] !== '{') { const vs = |
| 770 | eq | if (q === '"' \|\| q === "'") { let i = vs + 1; while (i < limit && s[i] !== q) { if (s[i] === '\\') |
| 770 | and-or | if (q === '"' \|\| q === "'") { let i = vs + 1; while (i < limit && s[i] !== q) { if (s[i] === '\\') |
| 770 | eq | if (q === '"' \|\| q === "'") { let i = vs + 1; while (i < limit && s[i] !== q) { if (s[i] === '\\') |
| 770 | cmp | === '"' \|\| q === "'") { let i = vs + 1; while (i < limit && s[i] !== q) { if (s[i] === '\\') i++; i |
| 770 | eq | s + 1; while (i < limit && s[i] !== q) { if (s[i] === '\\') i++; i++; } return Math.min(i + 1, limit |
| 771 | cmp | let i = vs; while (i < limit && !',}])\n'.includes(s[i])) i++; return i; |
| 775 | cmp | let end = from; for (let k = 0; k < 20 && end < s.length; k++) { const nl = s.indexOf('\n', end + |
| 775 | int | let end = from; for (let k = 0; k < 20 && end < s.length; k++) { const nl = s.indexOf('\n', end + |
| 775 | and-or | let end = from; for (let k = 0; k < 20 && end < s.length; k++) { const nl = s.indexOf('\n', end + |
| 775 | cmp | let end = from; for (let k = 0; k < 20 && end < s.length; k++) { const nl = s.indexOf('\n', end + |
| 775 | cmp | < 20 && end < s.length; k++) { const nl = s.indexOf('\n', end + 1); end = nl < 0 ? s.length : nl; } |
| 776 | cmp | EXT.lastIndex = from; const nx = NAME_FIELD_NEXT.exec(s); if (nx && nx.index < end) end = nx.index; |
| 778 | cmp | for (let j = from; j < end; j++) { const c = s[j]; if (c === '{' \|\| c === '[' \|\| c === '(') depth+ |
| 778 | eq | t j = from; j < end; j++) { const c = s[j]; if (c === '{' \|\| c === '[' \|\| c === '(') depth++; else i |
| 778 | and-or | om; j < end; j++) { const c = s[j]; if (c === '{' \|\| c === '[' \|\| c === '(') depth++; else if (c === |
| 778 | eq | < end; j++) { const c = s[j]; if (c === '{' \|\| c === '[' \|\| c === '(') depth++; else if (c === '}' |
| 778 | and-or | j++) { const c = s[j]; if (c === '{' \|\| c === '[' \|\| c === '(') depth++; else if (c === '}' \|\| c === |
| 778 | eq | { const c = s[j]; if (c === '{' \|\| c === '[' \|\| c === '(') depth++; else if (c === '}' \|\| c === ']' |
| 778 | and-or | === '[' \|\| c === '(') depth++; else if (c === '}' \|\| c === ']' \|\| c === ')') { if (depth === 0) { en |
| 778 | and-or | === '(') depth++; else if (c === '}' \|\| c === ']' \|\| c === ')') { if (depth === 0) { end = j; break; |
| 778 | eq | ; else if (c === '}' \|\| c === ']' \|\| c === ')') { if (depth === 0) { end = j; break; } depth--; } } |
| 779 | cmp | for (let j = s.indexOf('\n', from); j >= 0 && j < end; j = s.indexOf('\n', j + 1)) { |
| 779 | cmp | for (let j = s.indexOf('\n', from); j >= 0 && j < end; j = s.indexOf('\n', j + 1)) { |
| 780 | cmp | st ls = j + 1; let le = s.indexOf('\n', ls); if (le < 0) le = s.length; const l2 = s.slice(ls, le); |
| 800 | int | const win = Math.max(0, m.index - 4000), back = s.slice(win, m.index), obr = back.lastIndexOf('{ |
| 804 | cmp | for (let k = 0; k < 20 && ls > 0; k++) { |
| 804 | int | for (let k = 0; k < 20 && ls > 0; k++) { |
| 804 | and-or | for (let k = 0; k < 20 && ls > 0; k++) { |
| 804 | cmp | for (let k = 0; k < 20 && ls > 0; k++) { |
| 805 | int | const ps = s.lastIndexOf('\n', ls - 2) + 1, pl = s.slice(ps, ls - 1); if (!pl.trim()) break; |
| 806 | regex | const ind = (pl.match(/^[ \t]*/) \|\| [''])[0].length; |
| 806 | and-or | const ind = (pl.match(/^[ \t]*/) \|\| [''])[0].length; |
| 807 | and-or | if (/^[ \t]*-[ \t]/.test(pl) && ind + 2 === nameIndent) { start = ps; break; } |
| 808 | eq | if (ind !== nameIndent) break; ls = ps; |
| 813 | cmp | for (let v; (v = VB.exec(s)) && v.index < m.index;) { const vs = v.index + v[0].length, ve = e |
| 813 | cmp | ength, ve = entryValueEnd(s, vs, m.index); if (ve <= m.index && s.slice(vs, ve).trim()) ivs.push([vs |
| 813 | and-or | entryValueEnd(s, vs, m.index); if (ve <= m.index && s.slice(vs, ve).trim()) ivs.push([vs, ve, 'SECR |
| 816 | cmp | if (known && from >= known.from) { if (known.index < 0) continue; if (known.index >= from) at = |
| 816 | cmp | f (known && from >= known.from) { if (known.index < 0) continue; if (known.index >= from) at = known |
| 816 | cmp | & from >= known.from) { if (known.index < 0) continue; if (known.index >= from) at = known.index; } |
| 819 | cmp | if (!v \|\| v.index >= end) break; |
| 827 | and-or | if (!m[1] \|\| !isCredentialName(resolve(m[5]))) continue; |
| 828 | int | const prefix = m[1].replace(/[.*+?^${}()\|[\]\\]/g, '\\$&'), sep = m[2] ? '[._]' : ''; |
| 830 | cmp | let limit = m.index; for (let k = 0; k < 20 && limit < s.length; k++) { const nl = s.indexOf(' |
| 830 | int | let limit = m.index; for (let k = 0; k < 20 && limit < s.length; k++) { const nl = s.indexOf(' |
| 830 | and-or | let limit = m.index; for (let k = 0; k < 20 && limit < s.length; k++) { const nl = s.indexOf(' |
| 830 | cmp | limit = m.index; for (let k = 0; k < 20 && limit < s.length; k++) { const nl = s.indexOf('\n', limi |
| 830 | cmp | & limit < s.length; k++) { const nl = s.indexOf('\n', limit + 1); limit = nl < 0 ? s.length : nl; } |
| 832 | cmp | const base = s.indexOf('\n', m.index + m[0].length); if (base < 0 \|\| base >= limit) continue; |
| 832 | and-or | const base = s.indexOf('\n', m.index + m[0].length); if (base < 0 \|\| base >= limit) continue; |
| 832 | cmp | const base = s.indexOf('\n', m.index + m[0].length); if (base < 0 \|\| base >= limit) continue; |
| 838 | and-or | re.exec(s));) if (isCredentialName(resolve(m[1])) && m[2].trim()) { const ve = m.index + m[0].length |
| 843 | regex | if (!isCredentialName(resolve(m[2].replace(/^-+/, '')))) continue; |
| 844 | int | const from = m.index + m[0].length, close = Math.min(s.length, from + 2000); |
| 845 | cmp | let depth = 0, end = close; for (let j = from; j < close; j++) { const c = s[j]; if (c === '(') dep |
| 845 | eq | j = from; j < close; j++) { const c = s[j]; if (c === '(') depth++; else if (c === ')') { if (depth |
| 845 | eq | j]; if (c === '(') depth++; else if (c === ')') { if (depth === 0) { end = j; break; } depth--; } } |
| 847 | cmp | for (let v; (v = VALUE_FIELD.exec(s)) && v.index < end;) { const vs = v.index + v[0].length, ve = e |
| 859 | cmp | m.index + m[0].length + 1; let ve = vs; while (ve < s.length && !'/?#"\'<>) \t\r\n'.includes(s[ve])) |
| 872 | cmp | const start = blank < 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? |
| 872 | cmp | const start = blank < 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? |
| 872 | int | start = blank < 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? blankCr + |
| 872 | cmp | < 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? blankCr + 4 : blank + 2) |
| 872 | and-or | 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? blankCr + 4 : blank + 2); |
| 872 | cmp | 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? blankCr + 4 : blank + 2); |
| 872 | int | 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? blankCr + 4 : blank + 2); |
| 872 | int | 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? blankCr + 4 : blank + 2); |
| 873 | cmp | if (start < 0 \|\| start - m.index > 4000) continue; |
| 873 | and-or | if (start < 0 \|\| start - m.index > 4000) continue; |
| 873 | cmp | if (start < 0 \|\| start - m.index > 4000) continue; |
| 873 | int | if (start < 0 \|\| start - m.index > 4000) continue; |
| 876 | int | const before = s.slice(Math.max(0, m.index - 4000), m.index).split(/\r?\n/).reverse().find(l => |
| 876 | regex | s.slice(Math.max(0, m.index - 4000), m.index).split(/\r?\n/).reverse().find(l => /^--\S/.test(l)); |
| 876 | regex | s.slice(Math.max(0, m.index - 4000), m.index).split(/\r?\n/).reverse().find(l => /^--\S/.test(l)); |
| 879 | cmp | while (end < s.length) { let le = s.indexOf('\n', end); if (le < 0) le = s.length; const ln = s. |
| 879 | cmp | s.length) { let le = s.indexOf('\n', end); if (le < 0) le = s.length; const ln = s.slice(end, le).re |
| 879 | regex | e = s.length; const ln = s.slice(end, le).replace(/\r$/, '').trim(); if (boundary && (ln === boundar |
| 879 | and-or | r$/, '').trim(); if (boundary && (ln === boundary \|\| ln === boundary + '--')) break; end = le + 1; } |
| 880 | cmp | if (end > s.length) end = s.length; |
| 881 | regex | const body = s.slice(start, end).replace(/\r?\n$/, ''); if (body.trim()) ivs.push([start, start |
| 894 | cmp | onst closes = []; for (let k = s.indexOf('</'); k >= 0; k = s.indexOf('</', k + 2)) closes.push(k); |
| 894 | int | onst closes = []; for (let k = s.indexOf('</'); k >= 0; k = s.indexOf('</', k + 2)) closes.push(k); |
| 895 | cmp | m) => { let lo = 0, hi = closes.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (closes[mid |
| 895 | cmp | hi) { const mid = (lo + hi) >> 1; if (closes[mid] < from) lo = mid + 1; else hi = mid; } return lo < |
| 895 | ret | (closes[mid] < from) lo = mid + 1; else hi = mid; } return lo < closes.length ? closes[lo] : -1; }; |
| 895 | cmp | (closes[mid] < from) lo = mid + 1; else hi = mid; } return lo < closes.length ? closes[lo] : -1; }; |
| 903 | cmp | hi) { const mid = (lo + hi) >> 1; if (closes[mid] < open) lo = mid + 1; else hi = mid; } ci = lo; } |
| 906 | cmp | for (; k < closes.length && closes[k] - open <= 65536 && n < 256; k++, n++) if (s.startsWith(wan |
| 906 | and-or | for (; k < closes.length && closes[k] - open <= 65536 && n < 256; k++, n++) if (s.startsWith(wan |
| 906 | cmp | for (; k < closes.length && closes[k] - open <= 65536 && n < 256; k++, n++) if (s.startsWith(wan |
| 906 | int | for (; k < closes.length && closes[k] - open <= 65536 && n < 256; k++, n++) if (s.startsWith(want, |
| 906 | and-or | (; k < closes.length && closes[k] - open <= 65536 && n < 256; k++, n++) if (s.startsWith(want, close |
| 906 | cmp | < closes.length && closes[k] - open <= 65536 && n < 256; k++, n++) if (s.startsWith(want, closes[k]) |
| 906 | int | closes.length && closes[k] - open <= 65536 && n < 256; k++, n++) if (s.startsWith(want, closes[k])) |
| 908 | cmp | if (close < 0 && n >= 256) close = Math.min(s.length, open + 65536); |
| 908 | and-or | if (close < 0 && n >= 256) close = Math.min(s.length, open + 65536); |
| 908 | int | if (close < 0 && n >= 256) close = Math.min(s.length, open + 65536); |
| 909 | cmp | if (close < 0) continue; |
| 911 | and-or | if (content.trim() && !isPlaceholderValue(content)) { out += s.slice(at, open) + label('SECRET', |
| 921 | and-or | (!isCredentialName(resolve(name)) \|\| isPlaceholderValue(v)) ? m : m.slice(0, m.length - v.length |
| 927 | regex | const NETRC_ANCHOR = /^[ \t]*(?:machine\|default)\b/im; |
| 930 | regex | return s.replace(/^[ \t]*(?:machine\|default\|login\|password\|account)\b[^\n]*$/gim, |
| 931 | regex | (line) => line.replace(/\b(password\|account)[ \t]+(?![=:])(\S+)/gi, (m, k, v) => isPlaceholderVa |
| 989 | int | P, label, (m) => ({ from: m.index + m[1].length + 2, to: m.index + m[0].length, kind: 'SECRET' })); |
| 1003 | regex | return out.replace(/\b(Set-Cookie\|Cookie\|Authorization\|Proxy-Authorization)([ \t]+)((?:Basic\|Beare |
| 1012 | and-or | LowerCase()) && !isCredentialName(resolve(name))) \|\| isPlaceholderValue(v) ? m : pre + label('SECRET |
| 1029 | cmp | m, sch, v) => (isPlaceholderValue(v) \|\| (v.length < 8 && /^[a-z]+$/.test(v)) \|\| SCHEME_PROSE.test(v. |
| 1029 | int | sch, v) => (isPlaceholderValue(v) \|\| (v.length < 8 && /^[a-z]+$/.test(v)) \|\| SCHEME_PROSE.test(v.re |
| 1030 | regex | return out.replace(/\b(Digest)[ \t]+([^\n]*=[^\n]*)/g, (m, sch, v) => isPlaceholderValue(v) ? m : |
| 1068 | cmp | if (alt) { d *= 2; if (d > 9) d -= 9; } |
| 1068 | int | if (alt) { d *= 2; if (d > 9) d -= 9; } |
| 1080 | regex | ['http auth header', /\b(?:Authorization\|Proxy-Authorization)[ \t]*:[ \t]*(?![\-\uE000])[^\s"'()\[ |
| 1081 | regex | ['auth scheme token', /\b(?:Basic\|Bearer)[ \t]+[A-Za-z0-9._~+/\-]{12,}/], |
| 1083 | regex | ['spaced hex groups', /\b(?:[0-9a-f]{4}[ -]){5,}[0-9a-f]{4}\b/i],   // recovery codes written as g |
| 1085 | regex | const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i; |
| 1104 | and-or | if (UUID.test(run) \|\| run.startsWith(OPEN)) continue; |
| 1105 | and-or | 9a-fA-F]+$/.test(run)) { if (/[a-fA-F]/.test(run) && shannon(run) >= 3.0) { reasons.push('high-entro |
| 1105 | cmp | (run)) { if (/[a-fA-F]/.test(run) && shannon(run) >= 3.0) { reasons.push('high-entropy hex run'); br |
| 1107 | cmp | if (classes >= 2 && shannon(run) > 4.0) { reasons.push('high-entropy token'); break; } |
| 1115 | regex | tt && new RegExp('(?<![\\p{L}\\p{N}])${tt.replace(/[.*+?^${}()\|[\]\\]/g, '\\$&')}(?:['’]s\|es\|s)?(?![ |
| 1140 | regex | const esc = (t) => t.replace(/[.*+?^${}()\|[\]\\]/g, '\\$&'); |
| 1173 | regex | const core = value.trim().replace(/^["']\|["']$/g, ''); if (core && core !== value) inventory |
| 1173 | and-or | alue.trim().replace(/^["']\|["']$/g, ''); if (core && core !== value) inventory.push({ kind, value: c |
| 1173 | eq | m().replace(/^["']\|["']$/g, ''); if (core && core !== value) inventory.push({ kind, value: core }); |
| 1176 | and-or | const tok = core.split(/[\s,;#]/)[0]; if (tok && tok !== core) inventory.push({ kind, value: tok |
| 1184 | regex | let s = String(text ?? '').replace(/[\uE000\uE001]/g, ''); |
| 1216 | regex | s = s.replace(/"(?:\\.\|[^"\\\n])*"/g, (m) => (/\\"/.test(m) ? label('SECRET', m) : m)); |
| 1216 | regex | s = s.replace(/"(?:\\.\|[^"\\\n])*"/g, (m) => (/\\"/.test(m) ? label('SECRET', m) : m)); |
| 1221 | cmp | if (kind === 'CARD') { const d = m.replace(/\D/g, ''); if (d.length < 13 \|\| !luhn(d)) return m; } |
| 1221 | int | if (kind === 'CARD') { const d = m.replace(/\D/g, ''); if (d.length < 13 \|\| !luhn(d)) return m; } |
| 1222 | eq | if (kind === 'IP' && m.includes(':') && !(m.split(':').filter(Boolean).length >= 3 && /[0-9a |
| 1222 | cmp | includes(':') && !(m.split(':').filter(Boolean).length >= 3 && /[0-9a-f]{3,4}/i.test(m))) return m; |
| 1222 | int | includes(':') && !(m.split(':').filter(Boolean).length >= 3 && /[0-9a-f]{3,4}/i.test(m))) return m; |
| 1222 | and-or | includes(':') && !(m.split(':').filter(Boolean).length >= 3 && /[0-9a-f]{3,4}/i.test(m))) return m; |
| 1232 | eq | entory.filter(e => (e.kind === 'SECRET' \|\| e.kind === 'KEY') && e.value.trim().length >= 4 && !/[\uE |
| 1232 | and-or | er(e => (e.kind === 'SECRET' \|\| e.kind === 'KEY') && e.value.trim().length >= 4 && !/[\uE000\uE001\n |
| 1232 | cmp | ET' \|\| e.kind === 'KEY') && e.value.trim().length >= 4 && !/[\uE000\uE001\n]/.test(e.value)).map(e = |
| 1232 | int | \|\| e.kind === 'KEY') && e.value.trim().length >= 4 && !/[\uE000\uE001\n]/.test(e.value)).map(e => ' |
| 1232 | regex | kind === 'KEY') && e.value.trim().length >= 4 && !/[\uE000\uE001\n]/.test(e.value)).map(e => '${e.ki |
| 1253 | ret | if (!ownAtRe) return false; |
| 1253 | bool | if (!ownAtRe) return false; |
| 1254 | regex | const view = foldStr(String(text ?? '').replace(/[\uE000\uE001]/g, '')); |
| 1259 | int | sanitize(text, { maxMs = 2000, maxChars = 4_000_000 } = {}) { |
| 1261 | cmp | if (s.length > maxChars) throw new ScrubError('input of ${s.length} characters is over the ${m |
| 1265 | and-or | rubOnce(s); } catch (e) { throw new ScrubError('scrubber failed (${e && e.name}); holding back'); } |
| 1266 | cmp | if (Date.now() - t0 > maxMs) throw new ScrubError('scrubbing took longer than ${maxMs} ms; hol |
| 1277 | int | const phones = (s.match(/\+?\d[\d\s().-]{6,}\d/g) \|\| []).map(x => x.replace(/\D/g, '').slice(-10)); |
| 1279 | and-or | if (!value \|\| value.length < 4) continue; |
| 1279 | cmp | if (!value \|\| value.length < 4) continue; |
| 1279 | int | if (!value \|\| value.length < 4) continue; |
| 1282 | int | ONE') { const d = value.replace(/\D/g, '').slice(-10); if (d.length >= 7 && phones.includes(d)) kind |
| 1282 | cmp | = value.replace(/\D/g, '').slice(-10); if (d.length >= 7 && phones.includes(d)) kinds.add(kind); } |
| 1282 | int | = value.replace(/\D/g, '').slice(-10); if (d.length >= 7 && phones.includes(d)) kinds.add(kind); } |
| 1282 | and-or | = value.replace(/\D/g, '').slice(-10); if (d.length >= 7 && phones.includes(d)) kinds.add(kind); } |

## By operator

| Operator | Mutants | Survivors |
| --- | --- | --- |
| regex | 185 | 60 |
| and-or | 219 | 96 |
| int | 94 | 49 |
| eq | 129 | 33 |
| cmp | 174 | 147 |
| ret | 19 | 3 |
| bool | 23 | 6 |
