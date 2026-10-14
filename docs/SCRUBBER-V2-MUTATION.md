# Mutation report: src/redact.js

- Mutants generated: 645
- Killed: 350
- Killed by timeout: 15
- Survivors: 280
- Run time: 3761.2 s

## Survivors

| Line | Operator | Snippet |
| --- | --- | --- |
| 24 | regex | const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF\u00AD]/g; |
| 31 | and-or | tr) => (CONFUSABLE[c] && (LATIN.test(str[idx - 1] \|\| '') \|\| LATIN.test(str[idx + 1] \|\| ''))) ? CONFU |
| 34 | regex | return s.replace(/[\u0400-\u04FF\u0370-\u03FF]/g, confusableAt); |
| 38 | regex | return name.replace(/\\u([0-9a-fA-F]{4})/g, (m, h) => String.fromCharCode(parseInt(h, 16))).replac |
| 38 | int | {4})/g, (m, h) => String.fromCharCode(parseInt(h, 16))).replace(/%([0-9a-fA-F]{2})/g, (m, h) => Stri |
| 38 | regex | => String.fromCharCode(parseInt(h, 16))).replace(/%([0-9a-fA-F]{2})/g, (m, h) => String.fromCharCod |
| 38 | int | de(parseInt(h, 16))).replace(/%([0-9a-fA-F]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16))); |
| 62 | and-or | const k = r.normalize('NFKC'); if (k.length >= 1 && k.length <= 4) r = k; |
| 62 | cmp | const k = r.normalize('NFKC'); if (k.length >= 1 && k.length <= 4) r = k; |
| 62 | int | const k = r.normalize('NFKC'); if (k.length >= 1 && k.length <= 4) r = k; |
| 65 | cmp | if (FOLD_CACHE.size < 8192) FOLD_CACHE.set(c, r); |
| 65 | int | if (FOLD_CACHE.size < 8192) FOLD_CACHE.set(c, r); |
| 77 | cmp | if (code < 0x80) { |
| 80 | eq | (code === 0x5C && (s[i + 1] === '\n' \|\| (s[i + 1] === '\r' && s[i + 2] === '\n'))) { i += s[i + 1] = |
| 80 | and-or | 0x5C && (s[i + 1] === '\n' \|\| (s[i + 1] === '\r' && s[i + 2] === '\n'))) { i += s[i + 1] === '\r' ? |
| 80 | int | (s[i + 1] === '\n' \|\| (s[i + 1] === '\r' && s[i + 2] === '\n'))) { i += s[i + 1] === '\r' ? 2 : 1; r |
| 80 | eq | i + 1] === '\n' \|\| (s[i + 1] === '\r' && s[i + 2] === '\n'))) { i += s[i + 1] === '\r' ? 2 : 1; rev[ |
| 80 | int | = '\r' && s[i + 2] === '\n'))) { i += s[i + 1] === '\r' ? 2 : 1; rev[i] = parts.length; continue; } |
| 83 | cmp | parts.push(code < 0x20 && code !== 0x0A && code !== 0x0D && code !== 0x09 \|\| code === 0x7F ? ' |
| 85 | cmp | if (code >= 0x80 && code <= 0x9F) { parts.push(' '); map.push(i); continue; } |
| 85 | cmp | if (code >= 0x80 && code <= 0x9F) { parts.push(' '); map.push(i); continue; } |
| 86 | cmp | if (code >= 0xD800 && code <= 0xDBFF && i + 1 < n) { parts.push(s[i], s[i + 1]); map.push(i, i + |
| 86 | cmp | if (code >= 0xD800 && code <= 0xDBFF && i + 1 < n) { parts.push(s[i], s[i + 1]); map.push(i, i + |
| 86 | cmp | if (code >= 0xD800 && code <= 0xDBFF && i + 1 < n) { parts.push(s[i], s[i + 1]); map.push(i, i + |
| 136 | regex | const HEADER_CRED = /^(?:set-cookie\|cookie\|authorization\|proxy-authorization)$/i; |
| 151 | and-or | if (s[afterHead] === '\\' && s[afterHead + 1] === 'n') { |
| 153 | int | let q = afterHead; const lim = Math.min(s.length, afterHead + 65536); |
| 154 | cmp | while (q < lim) { if (s[q] === '"' && s[q - 1] !== '\\') break; q++; } |
| 188 | cmp | for (let i = start; i < s.length; i++) { |
| 190 | eq | if (c === '"' \|\| c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; |
| 190 | and-or | if (c === '"' \|\| c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; |
| 190 | eq | if (c === '"' \|\| c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; |
| 190 | cmp | if (c === '"' \|\| c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; |
| 190 | and-or | (c === '"' \|\| c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; contin |
| 190 | eq | '"' \|\| c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; continue; } |
| 190 | eq | '"' \|\| c === "'") { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') i++; continue; } |
| 191 | eq | if (c === '[') depth++; |
| 192 | eq | else if (c === ']' && --depth === 0) return i + 1; |
| 206 | cmp | for (; i < s.length; i++) { if (s[i] === '\\') { i++; continue; } if (s[i] === q) return i + 1; |
| 210 | cmp | if (nl < 0) nl = s.length; |
| 221 | cmp | let lineEnd = s.indexOf('\n', lineStart); if (lineEnd < 0) lineEnd = s.length; |
| 229 | cmp | if (/\\\r?$/.test(firstLine) && nl < s.length) return valueEnd(s, nl + 1); |
| 239 | cmp | for (const [a, b, kind] of ivs) { if (a < at \|\| b <= a) continue; const v = s.slice(a, b); if (!v. |
| 239 | and-or | for (const [a, b, kind] of ivs) { if (a < at \|\| b <= a) continue; const v = s.slice(a, b); if (!v. |
| 239 | cmp | for (const [a, b, kind] of ivs) { if (a < at \|\| b <= a) continue; const v = s.slice(a, b); if (!v.tr |
| 239 | and-or | continue; const v = s.slice(a, b); if (!v.trim() \|\| isPlaceholderValue(v)) continue; out += s.slice |
| 254 | cmp | if (re.lastIndex < r.to) re.lastIndex = r.to; |
| 280 | cmp | if (sepEnd < at) continue; |
| 291 | cmp | let nl = s.indexOf('\n', sepEnd); if (nl < 0) nl = s.length; |
| 292 | int | :]{0,160}:(?:[ \t]\|$)/m.test(s.slice(nl + 1, nl + 200).split(/\n(?=[ \t]*\S)/)[0] \|\| '')) { ASSIGN_S |
| 303 | int | ASSIGN_START.lastIndex = m.index + m[1].length + m[2].length; |
| 330 | cmp | for (; j < s.length; j++) { const c = s[j]; if (c === '"') { q = !q; continue; } if (!q && c === ' |
| 333 | regex | const trailingName = (tok) => (tok.replace(/[:=]+$/, '').replace(/["']$/, '').match(/[\p{L}\p{N}_$. |
| 333 | regex | ame = (tok) => (tok.replace(/[:=]+$/, '').replace(/["']$/, '').match(/[\p{L}\p{N}_$.\-]+$/u) \|\| [''] |
| 336 | cmp | while (i < s.length) { |
| 337 | cmp | let nl = s.indexOf('\n', i); if (nl < 0) nl = s.length; |
| 338 | regex | const line = s.slice(i, nl).replace(/\r$/, ''); |
| 341 | cmp | if ((m = BARE_KEY_LINE.exec(line)) && line.length > m[0].length) { |
| 343 | cmp | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) |
| 343 | and-or | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) |
| 343 | and-or | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) { ou |
| 348 | cmp | for (let k = 0; k + 1 < toks.length; k++) { |
| 350 | regex | if (!/[=:]/.test(t.text) && isCredentialName(resolve(t.text)) && !/[=:]/.test(v.text) && v.a |
| 350 | regex | (t.text) && isCredentialName(resolve(t.text)) && !/[=:]/.test(v.text) && v.at >= at && !isPlaceholde |
| 350 | cmp | (resolve(t.text)) && !/[=:]/.test(v.text) && v.at >= at && !isPlaceholderValue(v.text)) { out += s.s |
| 354 | cmp | if (vStart >= at && !isPlaceholderValue(m[2])) { out += s.slice(at, vStart) + label('SECRET', |
| 357 | cmp | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) |
| 357 | and-or | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) |
| 357 | and-or | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) { ou |
| 358 | cmp | } else if ((m = YAML_Q.exec(line)) && isCredentialName(resolve(m[1])) && nl < s.length) { |
| 359 | cmp | let nl2 = s.indexOf('\n', nl + 1); if (nl2 < 0) nl2 = s.length; |
| 361 | cmp | [0].length, end = valueEnd(s, vStart); if (vStart >= at && s.slice(vStart, end).trim()) { out += s.s |
| 361 | and-or | ngth, end = valueEnd(s, vStart); if (vStart >= at && s.slice(vStart, end).trim()) { out += s.slice(a |
| 362 | cmp | } else if ((m = BARE_NAME.exec(line)) && isCredentialName(resolve(m[2])) && nl < s.length) { |
| 365 | cmp | let nl2 = s.indexOf('\n', nl + 1); if (nl2 < 0) nl2 = s.length; |
| 368 | and-or | let vStart = nl + 1 + c[0].length; if (vStart >= nl2 && nl2 < s.length) vStart = nl2 + 1; |
| 368 | cmp | let vStart = nl + 1 + c[0].length; if (vStart >= nl2 && nl2 < s.length) vStart = nl2 + 1; |
| 370 | cmp | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end)) |
| 370 | and-or | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end)) |
| 370 | and-or | if (vStart >= at && s.slice(vStart, end).trim() && !isPlaceholderValue(s.slice(vStart, end))) { ou |
| 374 | regex | const nameIndent = (line.match(/^[ \t]*/) \|\| [''])[0].length, next = s.slice(nl + 1, nl2), n |
| 374 | and-or | const nameIndent = (line.match(/^[ \t]*/) \|\| [''])[0].length, next = s.slice(nl + 1, nl2), n |
| 375 | and-or | if (next.trim() && nextIndent > nameIndent) { |
| 375 | cmp | if (next.trim() && nextIndent > nameIndent) { |
| 377 | cmp | while (end < s.length) { let e2 = s.indexOf('\n', end + 1); if (e2 < 0) e2 = s.length; con |
| 377 | cmp | ngth) { let e2 = s.indexOf('\n', end + 1); if (e2 < 0) e2 = s.length; const l2 = s.slice(end + 1, e2 |
| 377 | and-or | ; const l2 = s.slice(end + 1, e2); if (!l2.trim() \|\| (l2.match(/^[ \t]*/) \|\| [''])[0].length <= name |
| 377 | regex | s.slice(end + 1, e2); if (!l2.trim() \|\| (l2.match(/^[ \t]*/) \|\| [''])[0].length <= nameIndent) break |
| 377 | and-or | + 1, e2); if (!l2.trim() \|\| (l2.match(/^[ \t]*/) \|\| [''])[0].length <= nameIndent) break; end = e2; |
| 377 | cmp | 1, e2); if (!l2.trim() \|\| (l2.match(/^[ \t]*/) \|\| [''])[0].length <= nameIndent) break; end = e2; } |
| 379 | cmp | if (vStart >= at && !isPlaceholderValue(s.slice(vStart, end))) { out += s.slice(at, vStart |
| 379 | and-or | if (vStart >= at && !isPlaceholderValue(s.slice(vStart, end))) { out += s.slice(at, vStart |
| 388 | and-or | if (csv.cols.has(k) && core && a + lead >= at && !isPlaceholderValue(core)) { out += s.sli |
| 388 | and-or | if (csv.cols.has(k) && core && a + lead >= at && !isPlaceholderValue(core)) { out += s.sli |
| 388 | cmp | if (csv.cols.has(k) && core && a + lead >= at && !isPlaceholderValue(core)) { out += s.sli |
| 388 | and-or | if (csv.cols.has(k) && core && a + lead >= at && !isPlaceholderValue(core)) { out += s.slice(at, |
| 392 | and-or | } else if (line.includes(',') && !csv) { |
| 395 | regex | h((c, k) => { if (isCredentialName(resolve(c.trim().replace(/^["']\|["']$/g, '')))) cols.add(k); }); |
| 423 | cmp | for (let m; (m = KV.exec(s)) && m.index < close;) { |
| 425 | and-or | if (c === '{' \|\| c === '[') continue; |
| 427 | eq | if (c === '"' \|\| c === "'") { ve = vs + 1; while (ve < close && s[ve] !== c) { if (s[ve] === '\ |
| 427 | and-or | if (c === '"' \|\| c === "'") { ve = vs + 1; while (ve < close && s[ve] !== c) { if (s[ve] === '\ |
| 427 | eq | if (c === '"' \|\| c === "'") { ve = vs + 1; while (ve < close && s[ve] !== c) { if (s[ve] === '\ |
| 427 | cmp | (c === '"' \|\| c === "'") { ve = vs + 1; while (ve < close && s[ve] !== c) { if (s[ve] === '\\') ve++ |
| 428 | cmp | else { ve = vs; while (ve < close && !',}]\n'.includes(s[ve])) ve++; } |
| 428 | and-or | else { ve = vs; while (ve < close && !',}]\n'.includes(s[ve])) ve++; } |
| 437 | int | let d = 0; const lim = Math.min(s.length, open + 65536); |
| 438 | cmp | for (let i = open; i < lim; i++) { |
| 440 | and-or | if (c === '"' \|\| c === "'") { for (i++; i < lim && s[i] !== c; i++) if (s[i] === '\\') i++; cont |
| 440 | cmp | if (c === '"' \|\| c === "'") { for (i++; i < lim && s[i] !== c; i++) if (s[i] === '\\') i++; cont |
| 440 | eq | c === '"' \|\| c === "'") { for (i++; i < lim && s[i] !== c; i++) if (s[i] === '\\') i++; continue; } |
| 451 | cmp | while (i < s.length) { |
| 452 | cmp | let nl = s.indexOf('\n', i); if (nl < 0) nl = s.length; |
| 458 | cmp | for (let bo = line.indexOf('{'); bo >= 0; bo = line.indexOf('{', bo + 1)) { |
| 460 | regex | if (/[:=][ \t]*$/.test(head) \|\| !(m = BLOCK_NAME.exec(head)) \|\| !isCredentialName(resolve(m[2] |
| 468 | cmp | if ((m = YAML_MAP_KEY.exec(line)) && isCredentialName(resolve(m[3])) && nl < s.length) { |
| 470 | cmp | while (j < s.length) { const ls = j + 1; let le = s.indexOf('\n', ls); if (le < 0) le = s.leng |
| 470 | cmp | ls = j + 1; let le = s.indexOf('\n', ls); if (le < 0) le = s.length; const l2 = s.slice(ls, le); if |
| 476 | cmp | const ls = j + 1; let le = s.indexOf('\n', ls); if (le < 0) le = s.length; |
| 478 | cmp | if ((l2.match(/^[ \t]*/) \|\| [''])[0].length <= ind) break; |
| 480 | and-or | if (km && km[0].length < l2.length) { const vs = ls + km[0].length, ve = valueEnd(s, vs); iv |
| 480 | cmp | if (km && km[0].length < l2.length) { const vs = ls + km[0].length, ve = valueEnd(s, vs); iv |
| 492 | regex | lve) => list.split(',').map(c => c.trim().replace(/^["'\x60\[]\|["'\x60\]]$/g, '')).map((c, k) => (is |
| 492 | cmp | \[]\|["'\x60\]]$/g, '')).map((c, k) => (isCredentialName(resolve(c)) ? k : -1)).filter(k => k >= 0); |
| 500 | cmp | while (p < s.length) { |
| 501 | cmp | while (p < s.length && (s[p] === ' ' \|\| s[p] === ',' \|\| s[p] === '\n' \|\| s[p] === '\r' \|\| s[ |
| 501 | and-or | while (p < s.length && (s[p] === ' ' \|\| s[p] === ',' \|\| s[p] === '\n' \|\| s[p] === '\r' \|\| s[ |
| 501 | and-or | le (p < s.length && (s[p] === ' ' \|\| s[p] === ',' \|\| s[p] === '\n' \|\| s[p] === '\r' \|\| s[p] === '\t' |
| 501 | and-or | s.length && (s[p] === ' ' \|\| s[p] === ',' \|\| s[p] === '\n' \|\| s[p] === '\r' \|\| s[p] === '\t')) p++; |
| 501 | and-or | s.length && (s[p] === ' ' \|\| s[p] === ',' \|\| s[p] === '\n' \|\| s[p] === '\r' \|\| s[p] === '\t')) p++; |
| 503 | bool | let depth = 0, k = 0, cellStart = p + 1, i = p + 1, done = false; |
| 504 | cmp | for (; i < s.length; i++) { |
| 506 | and-or | if (c === "'" \|\| c === '"') { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\' |
| 506 | cmp | if (c === "'" \|\| c === '"') { for (i++; i < s.length && s[i] !== c; i++) if (s[i] === '\\') |
| 508 | bool | === 0) { if (cols.includes(k)) ivs.push([cellStart, i, 'SECRET']); done = true; break; } depth--; } |
| 509 | eq | else if (c === ',' && depth === 0) { if (cols.includes(k)) ivs.push([cellStart, i, 'SECRET |
| 520 | cmp | while (i < s.length) { |
| 521 | cmp | let nl = s.indexOf('\n', i); if (nl < 0) nl = s.length; |
| 522 | regex | const line = s.slice(i, nl); if (/^\\\.[ \t\r]*$/.test(line)) break; |
| 523 | and-or | '\t').forEach((cell, k) => { if (cols.includes(k) && cell.trim()) ivs.push([pos, pos + cell.length, |
| 531 | cmp | while (i < s.length) { |
| 532 | cmp | let nl = s.indexOf('\n', i); if (nl < 0) nl = s.length; |
| 533 | regex | const line = s.slice(i, nl).replace(/\r$/, ''); |
| 535 | cmp | ; k >= 0; prev = k, k = line.indexOf('\|', k + 1)) if (prev >= 0) cells.push([i + prev + 1, i + k]); |
| 537 | cmp | let nl2 = s.indexOf('\n', nl + 1); if (nl2 < 0) nl2 = s.length; |
| 538 | cmp | e(s.slice(a, b).trim())) ? k : -1)).filter(k => k >= 0); if (found.length) { cols = new Set(found); |
| 539 | and-or | } else if (cells.length === n && !/^[ \t]*\\|?[ \t]*:?-{3,}/.test(line)) { |
| 539 | regex | } else if (cells.length === n && !/^[ \t]*\\|?[ \t]*:?-{3,}/.test(line)) { |
| 542 | eq | } else if (line.trim() === '') cols = null; |
| 548 | int | for (let t = s.indexOf('<table'); t >= 0; t = s.indexOf('<table', t + 6)) { |
| 549 | cmp | let end = s.indexOf('</table>', t); if (end < 0) end = s.length; end = Math.min(end, t + 65536 |
| 549 | int | let end = s.indexOf('</table>', t); if (end < 0) end = s.length; end = Math.min(end, t + 65536); |
| 551 | cmp | for (let r; (r = ROW.exec(s)) && r.index < end;) { |
| 552 | cmp | let rowEnd = s.indexOf('</tr>', r.index); if (rowEnd < 0 \|\| rowEnd > end) rowEnd = end; |
| 552 | and-or | let rowEnd = s.indexOf('</tr>', r.index); if (rowEnd < 0 \|\| rowEnd > end) rowEnd = end; |
| 552 | cmp | let rowEnd = s.indexOf('</tr>', r.index); if (rowEnd < 0 \|\| rowEnd > end) rowEnd = end; |
| 554 | cmp | for (let c; (c = CELL.exec(s)) && c.index < rowEnd;) cells.push({ th: c[1].toLowerCase() === |
| 554 | int | === 'h', a: c.index + c[0].length - c[2].length - 5 - 0, text: c[2], start: c.index + c[0].indexOf(' |
| 555 | cmp | (resolve(c.text.trim())) ? k : -1)).filter(k => k >= 0); cols = found.length ? new Set(found) : null |
| 556 | and-or | else if (cols) for (const k of cols) if (cells[k] && cells[k].text.trim()) ivs.push([cells[k].start, |
| 571 | regex | const IDENT_ATTR = /^(?:name\|id\|http-equiv\|type\|class\|aria-label\|placeholder\|data-field\|data-name\|da |
| 572 | regex | const ATTR_VALUE = /\b(value\|content)([ \t]*=[ \t]*)("[^"]*"\|'[^']*'\|[^\s>]+)/gi; |
| 581 | regex | t(a[1])) continue; const n = resolve(a[3].replace(/^["']\|["']$/g, '')); if (isCredentialName(n) \|\| H |
| 589 | regex | const raw = v[3].replace(/^["']\|["']$/g, ''); |
| 590 | regex | if (/^(?:name\|id\|http-equiv\|type\|class)$/i.test(v[1]) \|\| (IDENT_ATTR.test(v[1]) && (isCredenti |
| 590 | and-or | /^(?:name\|id\|http-equiv\|type\|class)$/i.test(v[1]) \|\| (IDENT_ATTR.test(v[1]) && (isCredentialName(res |
| 590 | and-or | ENT_ATTR.test(v[1]) && (isCredentialName(resolve(raw)) \|\| HEADER_CRED.test(raw.trim())))) continue; |
| 591 | bool | ndex + v.index + v[0].length - v[3].length; ivs.push([vs, vs + v[3].length, 'SECRET']); hit = true; |
| 595 | and-or | if (!hit && byAttr) { const c = CHILD_VALUE.exec(s.slice(m.index + tag.length, m.index + tag.len |
| 595 | int | lice(m.index + tag.length, m.index + tag.length + 4200)); if (c) { const vs = m.index + tag.length + |
| 595 | int | .index + tag.length + c[0].length - c[2].length - 2; ivs.push([vs, vs + c[2].length, 'SECRET']); } } |
| 596 | cmp | lose = s.indexOf('</' + tagName, open); if (close > open && close - open <= 65536 && !s.slice(open, |
| 596 | and-or | s.indexOf('</' + tagName, open); if (close > open && close - open <= 65536 && !s.slice(open, close). |
| 596 | cmp | tagName, open); if (close > open && close - open <= 65536 && !s.slice(open, close).includes('<') && |
| 596 | int | gName, open); if (close > open && close - open <= 65536 && !s.slice(open, close).includes('<') && s. |
| 596 | and-or | open); if (close > open && close - open <= 65536 && !s.slice(open, close).includes('<') && s.slice( |
| 596 | and-or | n <= 65536 && !s.slice(open, close).includes('<') && s.slice(open, close).trim()) ivs.push([open, cl |
| 610 | cmp | if (sepEnd < at \|\| !isCredentialName(resolve(joined)) \|\| s[sepEnd] === '{') continue; |
| 610 | and-or | if (sepEnd < at \|\| !isCredentialName(resolve(joined)) \|\| s[sepEnd] === '{') continue; |
| 610 | and-or | if (sepEnd < at \|\| !isCredentialName(resolve(joined)) \|\| s[sepEnd] === '{') continue; |
| 612 | and-or | if (!value.trim() \|\| isPlaceholderValue(value)) continue; |
| 630 | and-or | if (s.includes('*') && s.includes('&')) { |
| 633 | regex | const re = new RegExp('(?<![\\w&])&' + a.replace(/[.*+?^${}()\|[\]\\]/g, '\\$&') + '(?![\\w.\\-])[  |
| 635 | and-or | ED.exec(s));) if (isCredentialName(resolve(m[1])) && s[m.index + m[0].length] !== '{') { const vs = |
| 654 | eq | if (q === '"' \|\| q === "'") { let i = vs + 1; while (i < limit && s[i] !== q) { if (s[i] === '\\') |
| 654 | and-or | if (q === '"' \|\| q === "'") { let i = vs + 1; while (i < limit && s[i] !== q) { if (s[i] === '\\') |
| 654 | eq | if (q === '"' \|\| q === "'") { let i = vs + 1; while (i < limit && s[i] !== q) { if (s[i] === '\\') |
| 654 | cmp | === '"' \|\| q === "'") { let i = vs + 1; while (i < limit && s[i] !== q) { if (s[i] === '\\') i++; i |
| 654 | eq | s + 1; while (i < limit && s[i] !== q) { if (s[i] === '\\') i++; i++; } return Math.min(i + 1, limit |
| 655 | cmp | let i = vs; while (i < limit && !',}])\n'.includes(s[i])) i++; return i; |
| 659 | cmp | let end = from; for (let k = 0; k < 20 && end < s.length; k++) { const nl = s.indexOf('\n', end + |
| 659 | int | let end = from; for (let k = 0; k < 20 && end < s.length; k++) { const nl = s.indexOf('\n', end + |
| 659 | and-or | let end = from; for (let k = 0; k < 20 && end < s.length; k++) { const nl = s.indexOf('\n', end + |
| 659 | cmp | let end = from; for (let k = 0; k < 20 && end < s.length; k++) { const nl = s.indexOf('\n', end + |
| 659 | cmp | < 20 && end < s.length; k++) { const nl = s.indexOf('\n', end + 1); end = nl < 0 ? s.length : nl; } |
| 660 | cmp | EXT.lastIndex = from; const nx = NAME_FIELD_NEXT.exec(s); if (nx && nx.index < end) end = nx.index; |
| 662 | cmp | for (let j = from; j < end; j++) { const c = s[j]; if (c === '{' \|\| c === '[' \|\| c === '(') depth+ |
| 662 | eq | t j = from; j < end; j++) { const c = s[j]; if (c === '{' \|\| c === '[' \|\| c === '(') depth++; else i |
| 662 | and-or | om; j < end; j++) { const c = s[j]; if (c === '{' \|\| c === '[' \|\| c === '(') depth++; else if (c === |
| 662 | eq | < end; j++) { const c = s[j]; if (c === '{' \|\| c === '[' \|\| c === '(') depth++; else if (c === '}' |
| 662 | and-or | j++) { const c = s[j]; if (c === '{' \|\| c === '[' \|\| c === '(') depth++; else if (c === '}' \|\| c === |
| 662 | eq | { const c = s[j]; if (c === '{' \|\| c === '[' \|\| c === '(') depth++; else if (c === '}' \|\| c === ']' |
| 662 | and-or | === '[' \|\| c === '(') depth++; else if (c === '}' \|\| c === ']' \|\| c === ')') { if (depth === 0) { en |
| 662 | and-or | === '(') depth++; else if (c === '}' \|\| c === ']' \|\| c === ')') { if (depth === 0) { end = j; break; |
| 662 | eq | ; else if (c === '}' \|\| c === ']' \|\| c === ')') { if (depth === 0) { end = j; break; } depth--; } } |
| 663 | cmp | for (let j = s.indexOf('\n', from); j >= 0 && j < end; j = s.indexOf('\n', j + 1)) { |
| 663 | cmp | for (let j = s.indexOf('\n', from); j >= 0 && j < end; j = s.indexOf('\n', j + 1)) { |
| 664 | cmp | st ls = j + 1; let le = s.indexOf('\n', ls); if (le < 0) le = s.length; const l2 = s.slice(ls, le); |
| 677 | cmp | for (let v; (v = VALUE_FIELD.exec(s)) && v.index < end;) { const vs = v.index + v[0].length, ve = e |
| 683 | and-or | if (!m[1] \|\| !isCredentialName(resolve(m[5]))) continue; |
| 684 | int | const prefix = m[1].replace(/[.*+?^${}()\|[\]\\]/g, '\\$&'), sep = m[2] ? '[._]' : ''; |
| 686 | cmp | let limit = m.index; for (let k = 0; k < 20 && limit < s.length; k++) { const nl = s.indexOf(' |
| 686 | int | let limit = m.index; for (let k = 0; k < 20 && limit < s.length; k++) { const nl = s.indexOf(' |
| 686 | and-or | let limit = m.index; for (let k = 0; k < 20 && limit < s.length; k++) { const nl = s.indexOf(' |
| 686 | cmp | limit = m.index; for (let k = 0; k < 20 && limit < s.length; k++) { const nl = s.indexOf('\n', limi |
| 686 | cmp | & limit < s.length; k++) { const nl = s.indexOf('\n', limit + 1); limit = nl < 0 ? s.length : nl; } |
| 688 | cmp | for (let v; (v = vre.exec(s)) && v.index < limit;) { const vs = v.index + v[0].length; ivs.pus |
| 692 | and-or | re.exec(s));) if (isCredentialName(resolve(m[1])) && m[2].trim()) { const ve = m.index + m[0].length |
| 697 | regex | if (!isCredentialName(resolve(m[2].replace(/^-+/, '')))) continue; |
| 698 | int | const from = m.index + m[0].length, close = Math.min(s.length, from + 2000); |
| 699 | cmp | let depth = 0, end = close; for (let j = from; j < close; j++) { const c = s[j]; if (c === '(') dep |
| 699 | eq | j = from; j < close; j++) { const c = s[j]; if (c === '(') depth++; else if (c === ')') { if (depth |
| 699 | eq | j]; if (c === '(') depth++; else if (c === ')') { if (depth === 0) { end = j; break; } depth--; } } |
| 701 | cmp | for (let v; (v = VALUE_FIELD.exec(s)) && v.index < end;) { const vs = v.index + v[0].length, ve = e |
| 713 | cmp | m.index + m[0].length + 1; let ve = vs; while (ve < s.length && !'/?#"\'<>) \t\r\n'.includes(s[ve])) |
| 726 | cmp | const start = blank < 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? |
| 726 | cmp | const start = blank < 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? |
| 726 | int | start = blank < 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? blankCr + |
| 726 | cmp | < 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? blankCr + 4 : blank + 2) |
| 726 | cmp | 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? blankCr + 4 : blank + 2); |
| 726 | int | 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? blankCr + 4 : blank + 2); |
| 726 | int | 0 ? (blankCr < 0 ? -1 : blankCr + 4) : (blankCr >= 0 && blankCr < blank ? blankCr + 4 : blank + 2); |
| 727 | cmp | if (start < 0 \|\| start - m.index > 4000) continue; |
| 727 | and-or | if (start < 0 \|\| start - m.index > 4000) continue; |
| 727 | cmp | if (start < 0 \|\| start - m.index > 4000) continue; |
| 727 | int | if (start < 0 \|\| start - m.index > 4000) continue; |
| 729 | cmp | while (end < s.length) { let le = s.indexOf('\n', end); if (le < 0) le = s.length; if (s.slice(e |
| 729 | cmp | s.length) { let le = s.indexOf('\n', end); if (le < 0) le = s.length; if (s.slice(end, le).startsWit |
| 730 | cmp | if (end > s.length) end = s.length; |
| 731 | regex | const body = s.slice(start, end).replace(/\r?\n$/, ''); if (body.trim()) ivs.push([start, start |
| 744 | cmp | onst closes = []; for (let k = s.indexOf('</'); k >= 0; k = s.indexOf('</', k + 2)) closes.push(k); |
| 744 | int | onst closes = []; for (let k = s.indexOf('</'); k >= 0; k = s.indexOf('</', k + 2)) closes.push(k); |
| 745 | cmp | hi) { const mid = (lo + hi) >> 1; if (closes[mid] < from) lo = mid + 1; else hi = mid; } return lo < |
| 745 | cmp | (closes[mid] < from) lo = mid + 1; else hi = mid; } return lo < closes.length ? closes[lo] : -1; }; |
| 751 | cmp | if (close < 0 \|\| close - open > 65536 \|\| !s.startsWith('</' + m[1] + '>', close)) continue; |
| 751 | and-or | if (close < 0 \|\| close - open > 65536 \|\| !s.startsWith('</' + m[1] + '>', close)) continue; |
| 751 | cmp | if (close < 0 \|\| close - open > 65536 \|\| !s.startsWith('</' + m[1] + '>', close)) continue; |
| 751 | int | if (close < 0 \|\| close - open > 65536 \|\| !s.startsWith('</' + m[1] + '>', close)) continue; |
| 751 | and-or | if (close < 0 \|\| close - open > 65536 \|\| !s.startsWith('</' + m[1] + '>', close)) continue; |
| 753 | and-or | if (content.trim() && !isPlaceholderValue(content)) { out += s.slice(at, open) + label('SECRET', |
| 763 | and-or | (!isCredentialName(resolve(name)) \|\| isPlaceholderValue(v)) ? m : m.slice(0, m.length - v.length |
| 813 | int | P, label, (m) => ({ from: m.index + m[1].length + 2, to: m.index + m[0].length, kind: 'SECRET' })); |
| 827 | regex | return out.replace(/\b(Set-Cookie\|Cookie\|Authorization\|Proxy-Authorization)([ \t]+)((?:Basic\|Beare |
| 836 | and-or | LowerCase()) && !isCredentialName(resolve(name))) \|\| isPlaceholderValue(v) ? m : pre + label('SECRET |
| 847 | regex | return out.replace(/\b(Digest)[ \t]+([^\n]*)/g, (m, sch, v) => isPlaceholderValue(v) ? m : '${sch} |
| 876 | cmp | if (alt) { d *= 2; if (d > 9) d -= 9; } |
| 876 | int | if (alt) { d *= 2; if (d > 9) d -= 9; } |
| 876 | int | if (alt) { d *= 2; if (d > 9) d -= 9; } |
| 888 | regex | ['http auth header', /\b(?:Authorization\|Proxy-Authorization)[ \t]*:[ \t]*(?![\-\uE000])[^\s"'()\[ |
| 889 | regex | ['auth scheme token', /\b(?:Basic\|Bearer)[ \t]+[A-Za-z0-9._~+/\-]{12,}/], |
| 891 | regex | ['spaced hex groups', /\b(?:[0-9a-f]{4}[ -]){5,}[0-9a-f]{4}\b/i],   // recovery codes written as g |
| 893 | regex | const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i; |
| 912 | and-or | if (UUID.test(run) \|\| run.startsWith(OPEN)) continue; |
| 913 | and-or | 9a-fA-F]+$/.test(run)) { if (/[a-fA-F]/.test(run) && shannon(run) >= 3.0) { reasons.push('high-entro |
| 915 | cmp | if (classes >= 2 && shannon(run) > 4.0) { reasons.push('high-entropy token'); break; } |
| 941 | regex | const esc = (t) => t.replace(/[.*+?^${}()\|[\]\\]/g, '\\$&'); |
| 969 | eq | if (kind === 'SECRET') { const core = value.trim().replace(/^["']\|["']$/g, ''); if (core && co |
| 969 | regex | === 'SECRET') { const core = value.trim().replace(/^["']\|["']$/g, ''); if (core && core !== value) i |
| 969 | and-or | alue.trim().replace(/^["']\|["']$/g, ''); if (core && core !== value) inventory.push({ kind, value: c |
| 969 | eq | m().replace(/^["']\|["']$/g, ''); if (core && core !== value) inventory.push({ kind, value: core }); |
| 976 | regex | let s = String(text ?? '').replace(/[\uE000\uE001]/g, ''); |
| 1005 | regex | s = s.replace(/"(?:\\.\|[^"\\\n])*"/g, (m) => (/\\"/.test(m) ? label('SECRET', m) : m)); |
| 1005 | regex | s = s.replace(/"(?:\\.\|[^"\\\n])*"/g, (m) => (/\\"/.test(m) ? label('SECRET', m) : m)); |
| 1010 | cmp | if (kind === 'CARD') { const d = m.replace(/\D/g, ''); if (d.length < 13 \|\| !luhn(d)) return m; } |
| 1010 | int | if (kind === 'CARD') { const d = m.replace(/\D/g, ''); if (d.length < 13 \|\| !luhn(d)) return m; } |
| 1031 | int | sanitize(text, { maxMs = 2000, maxChars = 4_000_000 } = {}) { |
| 1033 | cmp | if (s.length > maxChars) throw new ScrubError('input of ${s.length} characters is over the ${m |
| 1036 | cmp | if (Date.now() - t0 > maxMs) throw new ScrubError('scrubbing took longer than ${maxMs} ms; hol |
| 1044 | cmp | { kind, value } of inventory) if (value && value.length >= 4 && s.includes(value)) kinds.add(kind); |
| 1044 | int | { kind, value } of inventory) if (value && value.length >= 4 && s.includes(value)) kinds.add(kind); |

## By operator

| Operator | Mutants | Survivors |
| --- | --- | --- |
| regex | 144 | 37 |
| and-or | 166 | 68 |
| int | 70 | 32 |
| eq | 97 | 24 |
| cmp | 138 | 116 |
| ret | 12 | 0 |
| bool | 18 | 3 |
