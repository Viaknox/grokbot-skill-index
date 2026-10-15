// Scrubber v2 contract tests, written before the v2 redact.js (docs/SCRUBBER-V2-BRIEF.md, docs/SCRUBBER-V2-PLAN.md).
// Every test asserts that the secret's own characters are gone (no 8-character window survives), not merely that a
// placeholder appeared. Fixtures are templates expanded at run time, so no secret shape sits in the repo.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scrubber, Sanitized, isCredentialName, residual, ScrubError } from '../src/redact.js';
import { fixture, expand, gen, makeRng, seedOf, attackRounds } from './corpus/expand.js';

const V2 = () => import('../src/redact.js');   // new exports are reached dynamically so a missing one fails one test, not the file
const windows = (s, w = 8) => (s.length <= w ? [s] : Array.from({ length: s.length - w + 1 }, (_, i) => s.slice(i, i + w)));
// Fails if any 8-character window of any secret is still in `out` (reports only the window, never the whole value).
function assertGone(out, secrets, label = '') {
  for (const sec of secrets) { const hit = windows(sec).find(w => out.includes(w)); assert.equal(hit, undefined, `${label} "${hit}" of a secret survived`); }
}
const assertKept = (out, keeps, label = '') => { for (const k of keeps) assert.ok(out.includes(k), `${label} expected "${k}" to stay`); };
const rng = makeRng(20261012);
const sec = (n) => gen.secret(rng, n);
const PEM_HEAD = (l) => gen.pemHead(l), PEM_FOOT = (l) => gen.pemFoot(l);

// ---- corpus families (engine/test/corpus/README.md) ----

test('[promised] corpus dotenv: every credential value is gone, usage settings stay', () => {
  const { text, secrets } = fixture('dotenv.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'dotenv'); assert.ok(!out.includes('LEAKED_SUFFIX'), 'suffix after 200 characters survived');
  assert.ok(!out.includes('abcde'), 'text before an escaped quote survived');
  assertKept(out, ['APP_NAME=tuneup', 'PORT=3000', 'tokenLimit=100000', 'max_tokens=128000', 'tokenizer=enabled'], 'dotenv');
});

test('[promised] corpus json-compact: secret fields are gone, neighbouring fields on the same line stay', () => {
  const { text, secrets } = fixture('json-compact.json'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'json-compact'); assert.ok(!out.includes('PRIVATE' + ' KEY'), 'PEM header survived inside a JSON string');
  assertKept(out, ['"user":"jo"', '"tokenLimit":100000', '"after":"still here"'], 'json-compact');
});

test('[promised] corpus json-pretty: nested credential fields, headers and escaped quotes are gone', () => {
  const { text, secrets } = fixture('json-pretty.json'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'json-pretty'); assert.ok(!out.includes('LEAKED_SUFFIX'));
  assertKept(out, ['"service": "api"', '"tokenLimit": 100000', '"max_tokens": 128000', 'the secretary will call about the session'], 'json-pretty');
});

test('[promised] corpus yaml: block scalars and deeper-indented continuation lines go with their key', () => {
  const { text, secrets } = fixture('yaml.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'yaml'); assert.ok(!out.includes('LEAKED_SUFFIX'));
  assertKept(out, ['name: api', 'max_tokens: 128000', 'region: eu-west-1', 'secretary: Jonathan Smith', 'note: the session timed out'], 'yaml');
});

test('[promised] corpus npmrc: _authToken, _password and _auth values are gone', () => {
  const { text, secrets } = fixture('npmrc.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'npmrc'); assertKept(out, ['registry=https://registry.npmjs.org/', 'username=jo', 'save-exact=true'], 'npmrc');
});

test('[promised] corpus pypirc: "password = value" lines are gone, repositories stay', () => {
  const { text, secrets } = fixture('pypirc.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'pypirc'); assertKept(out, ['repository = https://upload.pypi.org/legacy/', '[testpypi]'], 'pypirc');
});

test('[best-effort] corpus netrc: "password value" with no separator is gone in netrc shape, machine names stay', () => {
  const { text, secrets } = fixture('netrc.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'netrc'); assertKept(out, ['machine api.example.com', 'machine github.com'], 'netrc');
});

test('[promised] corpus headers: Basic, Bearer, Digest, Proxy-Authorization, Cookie, Set-Cookie and X-Api-Key values are gone', () => {
  const { text, secrets } = fixture('headers.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'headers'); assertKept(out, ['GET /api/v1/rooms HTTP/1.1', 'Host: api.example.com', 'Content-Type: application/json'], 'headers');
});

test('[promised] corpus urls: userinfo is gone, hosts and ordinary long URLs stay', () => {
  const { text, secrets } = fixture('urls.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'urls');
  assertKept(out, ['db.example.com:5432/app', 'cache.example.com:6379', 'https://docs.example.com/guide/getting-started/installation-and-configuration'], 'urls');
});

test('[promised] corpus pem: plain, RSA, EC, DSA, OPENSSH and ENCRYPTED keys go header to footer, text after stays', () => {
  const { text, secrets } = fixture('pem.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'pem');
  for (const leak of ['BEGIN', 'Proc-Type', 'DEK-Info', 'PRIVATE' + ' KEY']) assert.ok(!out.includes(leak), `pem: "${leak}" survived`);
  assertKept(out, ['after the keys, this text stays'], 'pem');
});

test('[promised] corpus pem-truncated: a key with Proc-Type, DEK-Info, a blank line and no footer is removed to the end of input', () => {
  const { text, secrets } = fixture('pem-truncated.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'pem-truncated');
  for (const leak of ['Proc-Type', 'DEK-Info', 'BEGIN']) assert.ok(!out.includes(leak), `pem-truncated: "${leak}" survived`);
  assertKept(out, ['some notes before the key'], 'pem-truncated');
});

test('[promised] corpus pem-big: a block over 16 KB is removed whole, the line after it stays, and a 70 KB block with no footer goes to the end', () => {
  const { text, secrets } = fixture('pem-big.txt'); assert.ok(text.length > 64 * 1024);
  const out = scrubber().scrub(text); assertGone(out, secrets, 'pem-big');
  assert.ok(out.length < 200, 'a key body survived'); assertKept(out, ['this line follows a key of more than 16 KB'], 'pem-big');
});

test('[promised] corpus prose: ordinary chat about passwords, sessions, cookies and tokens is left exactly as written', () => {
  const { text } = fixture('prose.txt'); assert.equal(scrubber().scrub(text), text);
});

test('[promised] corpus never-send: terms inside brackets, as name prefixes, in any case and inside values are all gone', () => {
  const { text, secrets } = fixture('never-send.txt'); const s = scrubber({ terms: ['Acme', 'Acme Corp', 'OpenAI'] }); const out = s.scrub(text);
  assertGone(out, secrets, 'never-send');
  assert.ok(!/acme|openai/i.test(out), 'a never_send term survived: ' + out.match(/.{0,10}(acme|openai).{0,10}/i));
  assertKept(out, ['welcome message', 'signed by', 'again, in lower case'], 'never-send');
  assert.equal(s.unscrub(out), text, 'round trip');
});

test('[promised] corpus chat: a .env pasted mid-conversation is scrubbed, the rest of the chat is untouched', () => {
  const { text, secrets } = fixture('chat.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'chat');
  assertKept(out, ['User: hi, the connector fails', 'DB_HOST=db.example.com', 'Bot: Thanks, the session is working now. Your password was fine.', 'see [EMAIL_1] above'], 'chat');
});

// ---- 1. line-level redaction ----

test('[promised] known bypass: PASSWORD= plus 200 characters plus LEAKED_SUFFIX, quoted and unquoted', () => {
  for (const q of ['', '"', "'"]) {
    const v = sec(200) + 'LEAKED_SUFFIX'; const out = scrubber().scrub(`PASSWORD=${q}${v}${q}\nNEXT=1`);
    assertGone(out, [v], q || 'bare'); assert.ok(!out.includes('LEAKED_SUFFIX'), `${q || 'bare'}: suffix survived`); assertKept(out, ['NEXT=1']);
  }
});

test('[promised] line level: a trailing backslash carries the value onto the next line', () => {
  const a = sec(20), b = sec(20); const out = scrubber().scrub(`PASSWORD=${a}\\\n${b}\nNEXT=1`);
  assertGone(out, [a, b]); assertKept(out, ['NEXT=1']);
});

test('[promised] line level: an unterminated quote carries the value onto the following lines until it closes', () => {
  const a = sec(20), b = sec(20), c = sec(20); const out = scrubber().scrub(`API_KEY="${a}\n${b}\n${c}"\nNEXT=1`);
  assertGone(out, [a, b, c]); assertKept(out, ['NEXT=1']);
});

test('[promised] line level: a YAML block scalar and an indented block under an empty key go with the key', () => {
  const a = sec(40), b = sec(40), c = sec(40); const out = scrubber().scrub(`creds:\n  token: |\n    ${a}\n    ${b}\n  private_key:\n    ${c}\n  region: eu\nname: x`);
  assertGone(out, [a, b, c]); assert.match(out, /region: \[SECRET_\d+\]/); assertKept(out, ['name: x']);   // every scalar under creds: goes, nested or not (PR #16 review, plan D16)
});

test('[promised] line level: a comment after a long value goes with the value', () => {
  const v = sec(220); const out = scrubber().scrub(`PASSWORD=${v} # rotate monthly\nNEXT=1`);
  assertGone(out, [v]); assert.ok(!out.includes('rotate monthly')); assertKept(out, ['NEXT=1']);
});

test('[promised] line level: CRLF input is scrubbed the same as LF and the other lines survive', () => {
  const a = sec(220), b = sec(30); const out = scrubber().scrub(`PASSWORD=${a}\r\nPORT=3000\r\nAPI_KEY="${b}"\r\n`);
  assertGone(out, [a, b]); assertKept(out, ['PORT=3000']);
});

test('[promised] line level: command-line flags --password, --token= and -p carry a credential', () => {
  const a = sec(16), b = sec(16), c = sec(16); const out = scrubber().scrub(`deploy --password ${a} --retries 3\nlogin --token=${b}\nmysql -u root -p${c} app`);
  assertGone(out, [a, b, c]);
});

test('[promised] line level: a value longer than 200 characters inside pretty JSON goes to the end of the field only', () => {
  const v = sec(260); const out = scrubber().scrub(`{\n  "password": "${v}",\n  "tokenLimit": 5\n}`);
  assertGone(out, [v]); assertKept(out, ['"tokenLimit": 5']);
});

// ---- 2. signals with word boundaries and context ----

test('[promised] signals: secretary, tokenizer, tokenLimit, max_tokens and "Password requirements:" are not credentials', () => {
  const lines = ['secretary: Jonathan Smith', 'tokenizer=enabled', 'tokenLimit=100000', 'max_tokens: 128000', 'Password requirements: 12 characters minimum', 'token_count: 42'];
  for (const l of lines) assert.equal(scrubber().scrub(l), l, l);
});

test('[promised] signals: password, secret, api_key and token as whole name parts are credentials in every spelling', () => {
  for (const name of ['password', 'PASSWD', 'Secret', 'api-key', 'apiKey', 'API_KEY', 'token', 'AUTH_TOKEN', 'accessToken', 'credential', 'x-api-key', 'db.password', 'secretSanta']) {
    const v = sec(210); const out = scrubber().scrub(`${name}: ${v}`); assertGone(out, [v], name);
  }
});

test('[promised] signals: Authorization Digest and Proxy-Authorization values are gone, even mid-line inside quotes', () => {
  const n = gen.hex(rng, 32), r = gen.hex(rng, 32), b = gen.b64(rng, 40), c = gen.b64(rng, 40);
  const out = scrubber().scrub(`Authorization: Digest username="jo", realm="api", nonce="${n}", response="${r}"\nProxy-Authorization: Basic ${b}\ncurl -H "Authorization: Bearer ${c}" https://x.example`);
  assertGone(out, [n, r, b, c]);
});

test('[promised] signals: Cookie and Set-Cookie values are gone, but "cookie" and "session" in prose stay', () => {
  const a = gen.hex(rng, 32), b = gen.b64(rng, 40);
  const out = scrubber().scrub(`Cookie: session=${a}; theme=dark\nSet-Cookie: sid=${b}; Path=/; HttpOnly\nCan you clear the cookie so the session restarts?`);
  assertGone(out, [a, b]); assertKept(out, ['Can you clear the cookie so the session restarts?']);
});

test('[best-effort] signals: "password value" with no separator counts only in netrc shape, not in chat', () => {
  const v = sec(20); const out = scrubber().scrub(`machine api.example.com login jo password ${v}`); assertGone(out, [v]);
  const chat = 'I forgot my password yesterday and the reset mail never came'; assert.equal(scrubber().scrub(chat), chat);
});

test('[promised] signals: URL userinfo with an empty user, a long password or a token as the user is gone', () => {
  const a = sec(18), b = sec(210), c = gen.prefix(rng, 'ghp');
  const out = scrubber().scrub(`redis://:${a}@cache.example.com:6379\namqp://guest:${b}@mq.example.com/v\nhttps://${c}@github.com/org/repo.git`);
  assertGone(out, [a, b, c]); assertKept(out, ['cache.example.com:6379', 'mq.example.com/v', 'github.com/org/repo.git']);
});

test('[best-effort] signals: a credential name written with zero-width or look-alike characters is still a signal', () => {
  const cases = [['pass​word=', 'zero-width space'], ['pass‍word: ', 'zero-width joiner'], ['pаssword=', 'Cyrillic a'], ['ＰＡＳＳＷＯＲＤ=', 'fullwidth letters'], ['api⁠_key=', 'word joiner'], ['﻿PASSWORD=', 'byte-order mark']];
  for (const [name, why] of cases) { const v = sec(16); assertGone(scrubber().scrub(name + v), [v], why); }
});

test('[best-effort] signals: zero-width characters inside a value do not let any fragment survive', () => {
  const v = sec(220); const spaced = v.match(/.{1,50}/g).join('​');
  const out = scrubber().scrub(`PASSWORD=${spaced}\nNEXT=1`).replace(/[​-‍⁠﻿]/g, '');
  assertGone(out, [v]); assertKept(out, ['NEXT=1']);
});

// ---- 3. PEM ----

test('[promised] known bypass: truncated RSA key with Proc-Type, DEK-Info and a blank line after the header', () => {
  const lines = gen.pemLines(rng, 5), iv = gen.hex(rng, 16);
  const block = `${PEM_HEAD('RSA')}\nProc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC,${iv}\n\n${lines.join('\n')}`;
  for (const [name, text] of [['no footer', 'before\n' + block], ['with footer', 'before\n' + block + '\n' + PEM_FOOT('RSA') + '\nafter']]) {
    const out = scrubber().scrub(text); assertGone(out, [...lines, iv], name);
    for (const leak of ['Proc-Type', 'DEK-Info', 'BEGIN']) assert.ok(!out.includes(leak), `${name}: "${leak}" survived`);
    assertKept(out, ['before'], name); if (name === 'with footer') assertKept(out, ['after'], name);
  }
});

test('[promised] pem: a key inside a JSON string with escaped newlines and no footer ends at the closing quote', () => {
  const lines = gen.pemLines(rng, 5);
  const out = scrubber().scrub(`{"private_key":"${PEM_HEAD('')}\\n${lines.join('\\n')}\\n","next":"x"}`);
  assertGone(out, lines); assert.ok(!out.includes('BEGIN')); assertKept(out, ['"next":"x"']);
});

test('[promised] pem: a blank line and a Comment header inside an OPENSSH block do not end it early, with or without a footer', () => {
  const lines = gen.pemLines(rng, 4);
  const block = `${PEM_HEAD('OPENSSH')}\n${lines[0]}\n\n${lines[1]}\nComment: work laptop\n${lines[2]}\n${lines[3]}`;
  const out = scrubber().scrub(`${block}\n${PEM_FOOT('OPENSSH')}\ntail`);
  assertGone(out, lines, 'footer'); assert.ok(!out.includes('Comment: work laptop')); assertKept(out, ['tail']);
  const cut = scrubber().scrub(`head\n${block}`); assertGone(cut, lines, 'no footer'); assert.ok(!cut.includes('Comment: work laptop')); assertKept(cut, ['head']);
});

// ---- 4. never_send terms ----

test('[promised] known bypass: [Acme] and [Acme Corp] with never_send terms', () => {
  const s = scrubber({ terms: ['Acme', 'Acme Corp'] }); const text = 'Welcome [Acme] and [Acme Corp] and [ACME CORP]!';
  const out = s.scrub(text); assert.ok(!/acme/i.test(out), out); assert.equal(s.unscrub(out), text);
});

test('[promised] known bypass: OPENAI-API-KEY=CorrectHorse9! with never_send OpenAI', () => {
  const s = scrubber({ terms: ['OpenAI'] }); const out = s.scrub('OPENAI-API-KEY=CorrectHorse9!\nOPENAI_API_KEY: CorrectHorse8!');
  assert.ok(!/openai/i.test(out), out); assert.ok(!/CorrectHorse/.test(out), out);
});

test('[promised] never_send: terms match case-insensitively and inside values, and whole-word guards still hold', () => {
  const s = scrubber({ terms: ['Acme Corp', 'Ivo'] }); const out = s.scrub('Acme corp terms apply. Ivo said yes. Ivory and ACMEcorp stay. note=ACME CORP rules');
  assert.ok(!/acme corp/i.test(out)); assert.ok(!/\bIvo\b/.test(out)); assertKept(out, ['Ivory', 'ACMEcorp stay']);
  assert.equal(s.unscrub(out), 'Acme corp terms apply. Ivo said yes. Ivory and ACMEcorp stay. note=ACME CORP rules');
});

test('[promised] never_send: a term that is also a credential word (KEY, PRIVATE, SECRET) cannot break key or setting scrubbing', () => {
  const lines = gen.pemLines(rng, 2), v = sec(16);
  const s = scrubber({ terms: ['KEY', 'PRIVATE', 'SECRET'] });
  const out = s.scrub(`${PEM_HEAD('')}\n${lines.join('\n')}\n${PEM_FOOT('')}\nSECRET_KEY=${v}`);
  assertGone(out, [...lines, v]); assert.ok(!/\bkey\b|\bprivate\b|\bsecret\b/i.test(out.replace(/\[[A-Z]+_\d+\]/g, '')), out);
});

// ---- 5. placeholders are reserved tokens ----

test('[promised] known bypass: a credential value containing a never_send term restores ([SECRET_1] wrapping [PRIVATE_1])', () => {
  const v = sec(10); const text = `PASSWORD=Acme-${v}\nclient_secret: my Acme pass\nhello Acme`;
  const s = scrubber({ terms: ['Acme'] }); const out = s.scrub(text);
  assert.ok(!out.includes('Acme') && !out.includes(v), out);
  assert.equal(s.unscrub(out), text, 'dependency-ordered restore');
  assert.deepEqual(s.counts(), { PRIVATE: 1, SECRET: 2 });
});

test('[promised] placeholders: scrubbing is idempotent on every fixture and never nests a placeholder in another', () => {
  for (const f of ['dotenv.txt', 'headers.txt', 'never-send.txt', 'urls.txt', 'pem.txt', 'chat.txt']) {
    const s = scrubber({ terms: ['Acme', 'Acme Corp', 'OpenAI'] }); const once = s.scrub(fixture(f).text), twice = s.scrub(once);
    assert.equal(twice, once, f); assert.ok(!/\[[A-Z]+_\d*\[/.test(once), f + ': nested placeholder');
  }
});

test('[promised] placeholders: text that already looks like [KIND_n] is left alone and not counted', () => {
  const s = scrubber(); const text = 'see [EMAIL_1] and [SECRET_2] and [KEY_3] above';
  assert.equal(s.scrub(text), text); assert.deepEqual(s.counts(), {});
});

test('[promised] placeholders: counts stay accurate with repeats and nesting, and numbering is stable across texts', () => {
  const s = scrubber({ terms: ['Acme'] }); const v = sec(12);
  s.scrub(`PASSWORD=Acme${v}\nPASSWORD=Acme${v}\nmail jo@x.example`); s.scrub('again jo@x.example and Acme');
  assert.deepEqual(s.counts(), { PRIVATE: 1, SECRET: 1, EMAIL: 1 });
  assert.equal(s.scrub('jo@x.example'), '[EMAIL_1]');
});

// ---- 6. residual scan, sanitize ----

test('[promised] v2 api: SCRUBBER_VERSION is 2.0.0 and the public shape is unchanged', async () => {
  const mod = await V2(); assert.equal(mod.SCRUBBER_VERSION, '2.0.0');
  const s = scrubber({ terms: ['x'] }); for (const k of ['scrub', 'unscrub', 'counts', 'sanitize', 'echoes']) assert.equal(typeof s[k], 'function', k);
  assert.match(s.scrub('mail jo@x.example'), /^mail \[EMAIL_1\]$/);
});

test('[promised] residual: a high-entropy run, a known prefix shape and a leftover never_send term each hold the text back', async () => {
  const { residual } = await V2();
  const cases = [['bare base64', 'deploy key ' + gen.b64(rng, 40)], ['bare hex', 'sha ' + gen.hex(rng, 40)], ['prefix shape', 'id ' + 'AKIA' + 'Q'.repeat(16)],
    ['prefix shape sk', 'try ' + 'sk-' + 'a1'.repeat(12)], ['pem header', 'x ' + PEM_HEAD('EC') + ' y'], ['jwt', gen.prefix(rng, 'jwt')]];
  for (const [why, text] of cases) { const r = residual(text); assert.equal(r.held, true, why); assert.ok(r.reasons.length, why); }
  const t = residual('hello [Acme] and [acme corp]', { terms: ['Acme Corp'] }); assert.equal(t.held, true, 'leftover term inside brackets');
});

test('[promised] residual: ordinary prose, long URLs, identifiers, UUIDs and placeholders are not held', async () => {
  const { residual } = await V2();
  for (const text of [fixture('prose.txt').text, '[SECRET_1] and [KEY_2] remain, id 123e4567-e89b-12d3-a456-426614174000', 'https://docs.example.com/guide/getting-started/installation-and-configuration',
    'The quick brown fox jumps over the lazy dog, again and again and again.']) {
    const r = residual(text, { terms: ['Acme'] }); assert.equal(r.held, false, text.slice(0, 40) + ' ' + r.reasons.join(','));
  }
});

test('[promised] sanitize: returns a frozen Sanitized whose text equals scrub(text), carries the version, and is idempotent', async () => {
  const { Sanitized, SCRUBBER_VERSION } = await V2(); const s = scrubber({ terms: ['Acme'] }); const text = 'Acme mail jo@x.example PASSWORD=' + sec(12);
  const san = s.sanitize(text);
  assert.ok(san instanceof Sanitized); assert.ok(Object.isFrozen(san)); assert.equal(san.text, s.scrub(text)); assert.equal(san.held, false); assert.deepEqual(san.reasons, []);
  assert.equal(san.version, SCRUBBER_VERSION); assert.equal(s.sanitize(san.text).text, san.text);
  assert.ok(!JSON.stringify(san).includes('jo@x.example'), 'a Sanitized never carries the real values');
});

test('[promised] sanitize: held is true and nothing secret is in the text when only the residual scan catches it', async () => {
  const s = scrubber({ terms: ['Acme'] }); const b = gen.b64(rng, 48); const san = s.sanitize('deploy key ' + b + ' for [Acme]');
  assert.ok(san.held || !san.text.includes(b), 'bare entropy neither scrubbed nor held');
  assert.ok(!/acme/i.test(san.text) || san.held, 'leftover term neither scrubbed nor held');
});

test('[promised] sanitize: throws ScrubError over the size cap and makes no Sanitized', async () => {
  const { ScrubError } = await V2(); const s = scrubber(); assert.equal(typeof ScrubError, 'function');
  assert.throws(() => s.sanitize('a'.repeat(10), { maxChars: 5 }), (e) => e instanceof ScrubError);
});

test('[promised] echoes: reports the kinds of user-side values found verbatim in following text, never the values', () => {
  const s = scrubber({ terms: ['Acme'] }); const k = gen.prefix(rng, 'sk'), v = sec(14);
  s.scrub(`card 4111 1111 1111 1111, key ${k}, PASSWORD=${v}
mail jo@x.example, Acme`);
  assert.deepEqual([...s.echoes(`your card 4111 1111 1111 1111 is updated, ${v} noted`)].sort(), ['CARD', 'SECRET']);
  assert.deepEqual(s.echoes('nothing here'), []);
  assert.deepEqual([...s.echoes(`key ${k} and jo@x.example and acme`)].sort(), ['EMAIL', 'KEY']);
  assert.ok(!JSON.stringify(s.echoes(`${k}`)).includes(k.slice(0, 8)));
});

// ---- remaining known bypasses ----

test('[promised] known bypass: Authorization: Basic dXNlcjpwYXNzd29yZA==', () => {
  const out = scrubber().scrub('Authorization: Basic dXNlcjpwYXNzd29yZA==\nnext line');
  assert.ok(!out.includes('dXNlcjpwYXNzd29yZA'), out); assertKept(out, ['next line']);
});

test('[promised] known bypass: API_KEY="abcde\\"CorrectHorse9!"', () => {
  const out = scrubber().scrub('API_KEY="abcde\\"CorrectHorse9!"\nNEXT=1');
  assert.ok(!out.includes('CorrectHorse9') && !out.includes('abcde'), out); assertKept(out, ['NEXT=1']);
});

// ---- regression guards: v1 behaviour that must survive ----

test('[promised] regression guard: emails, phones, keys, valid cards, SSNs and IPs still become stable placeholders', () => {
  const s = scrubber(); const k = gen.prefix(rng, 'skor');
  const out = s.scrub(`Mail jo@acme.com or jo@acme.com, call +1 336-555-0142, key ${k}, card 4111 1111 1111 1111, ssn 123-45-6789, ip 10.0.0.12`);
  for (const leak of ['jo@acme.com', '555-0142', k, '4111', '123-45-6789', '10.0.0.12']) assert.ok(!out.includes(leak), leak);
  assert.equal(out.match(/\[EMAIL_1\]/g).length, 2);
  assert.deepEqual(Object.keys(s.counts()).sort(), ['CARD', 'EMAIL', 'IP', 'KEY', 'PHONE', 'SSN']);
});

test('[promised] regression guard: order numbers, prices, dates, public keys and simple unscrub round trips are unchanged', () => {
  const plain = 'Order 1234567890123 shipped on 2026-10-11 for $49.99, room B at 3pm.'; assert.equal(scrubber().scrub(plain), plain);
  const pub = '-----BEGIN PUBLIC KEY-----\nAAAAB3NzaC1yc2E\n-----END PUBLIC KEY-----'; assert.equal(scrubber().scrub(pub), pub);
  const s = scrubber(); const sent = s.scrub('Escalate to help@viaknox.test.');
  assert.equal(s.unscrub(sent.replace('Escalate', 'Always escalate')), 'Always escalate to help@viaknox.test.');
});

// ---- known bypasses from the second review round on #14, #15 and viaknox #25 ----

test('[promised] known bypass (review 2): short credential values go whole, there is no minimum length', () => {
  for (const l of ['PASSWORD=abcde', 'API_KEY=12345', 'token: 7', "secret='x'"]) { const out = scrubber().scrub(l); assert.match(out, /^[A-Za-z_]+[=:] ?\[SECRET_1\]$/, l); }
});

test('[promised] known bypass (review 2): a multi-line quoted dotenv value is consumed through the closing quote', () => {
  const out = scrubber().scrub('PASSWORD="alphaX\nbravo\ncharlie"\nNEXT=1');
  assertGone(out, ['alphaX', 'bravo', 'charlie'].map(x => x.padEnd(8, x))); assert.ok(!/alphaX|bravo|charlie/.test(out), out); assertKept(out, ['NEXT=1']);
});

test('[promised] known bypass (review 2): a never_send term as a name prefix (ACME-PASSWORD=) still loses its value', () => {
  const s = scrubber({ terms: ['Acme'] }); const out = s.scrub('ACME-PASSWORD=CorrectHorse9!');
  assert.ok(!/acme|CorrectHorse/i.test(out), out); assert.equal(s.unscrub(out), 'ACME-PASSWORD=CorrectHorse9!');
});

test('[promised] known bypass (review 2): --password=x, --api-key=x and --token x flags, and the result is not falsely held', () => {
  const a = sec(12), b = sec(12), c = sec(12); const s = scrubber(); const text = `run --password=${a} --api-key=${b} --token ${c} now`;
  const out = s.scrub(text); assertGone(out, [a, b, c]); assertKept(out, ['run ', ' now']);
  assert.equal(s.sanitize(text).held, false, 'a fully scrubbed flag line must not be held by the residual scan');
});

test('[promised] known bypass (review 2): bare key= in dotenv form is scrubbed; key: labels in YAML and JSON stay', () => {
  for (const l of ['key=CorrectHorseBatteryStaple', 'export key=CorrectHorseBatteryStaple', 'api key=CorrectHorseBatteryStaple']) assert.ok(!scrubber().scrub(l).includes('CorrectHorse'), l);
  for (const l of ['key: user_id', '{"key": "user_id", "value": 1}', '- key: name']) assert.equal(scrubber().scrub(l), l, l);
});

// ---- known bypasses from the review of PR #16 ----

test('[best-effort] known bypass (review 3): a credential noun followed by a quoted or bare value in prose', () => {
  for (const [text, v] of [["Use the password 'cat123' to log in.", 'cat123'], ['use password "x9k2"', 'x9k2'], ['Use the password cat123 to log in.', 'cat123'], ['enter api key Zz8def when asked', 'Zz8def']]) {
    const out = scrubber().scrub(text); assert.ok(!out.includes(v), text + ' -> ' + out);
  }
  for (const keep of ['I forgot my password yesterday and the reset mail never came', 'my password yesterday.']) assert.equal(scrubber().scrub(keep), keep, keep);
});

test('[best-effort] known bypass (review 3): a credential noun with qualifier words before the copula', () => {
  for (const [text, v] of [['The secret phrase is secret12345.', 'secret12345'], ['my api key here is abc123xyz', 'abc123xyz'], ['the db password for staging is Qq7ghi.', 'Qq7ghi']]) {
    const out = scrubber().scrub(text); assert.ok(!out.includes(v), text + ' -> ' + out);
  }
});

test('[promised] known bypass (review 3): internationalised email addresses become [EMAIL_n]', () => {
  const s = scrubber(); const out = s.scrub('mail usér@exämple.com or δοκιμή@παράδειγμα.δοκιμή or jo@x.example today');
  assert.equal(out, 'mail [EMAIL_1] or [EMAIL_2] or [EMAIL_3] today', out);
  assert.equal(s.unscrub(out), 'mail usér@exämple.com or δοκιμή@παράδειγμα.δοκιμή or jo@x.example today');
});

// ---- PR #16 review (Codex, head 87b3b71): fixtures written before their fixes ----

test('[promised] known bypass (review 4): URL userinfo has no length ceiling', () => {
  const pw = 'a'.repeat(300), user = 'b'.repeat(300);
  for (const text of ['see https://user:' + pw + '@example.com ok', 'https://' + user + '@h.example']) {
    const s = scrubber(); const out = s.scrub(text);
    assert.ok(!out.includes('a'.repeat(8)) && !out.includes('b'.repeat(8)), out.slice(0, 80));
    assert.equal(s.counts().KEY, 1, out.slice(0, 80));
  }
});

test('[best-effort] known bypass (review 4): HTML closing tags match case-insensitively', () => {
  for (const text of ['<textarea name="password">hunter2</TEXTAREA>', '<TextArea Name="password">hunter2</TeXtArEa>']) {
    const out = scrubber().scrub(text); assert.ok(!out.includes('hunter2'), out);
  }
});

test('[promised] known bypass (review 4): only real placeholder kinds are reserved; [ATTACK_1] as a value is scrubbed', () => {
  const s = scrubber();
  assert.equal(s.scrub('password=[ATTACK_1]'), 'password=[SECRET_1]');
  assert.equal(s.scrub('password=[SECRET_1]'), 'password=[SECRET_1]');   // a real placeholder in the input is left alone
  assert.equal(s.scrub('PASSWORD=x9k2'), 'PASSWORD=[SECRET_2]');         // and its number stays reserved
  assert.equal(s.scrub('note [FOO_1] here'), 'note [FOO_1] here');       // plain text is not a credential value
  assert.deepEqual(s.counts(), { SECRET: 2 });
});

test('[best-effort] known bypass (review 4): nested YAML maps, block scalars and lists under a credential key', () => {
  const text = 'credentials:\n  username: admin\n  nested:\n    account: hunter2\n    deeper:\n      token: abc\n  blob: |\n    line1\n    line2\n  list:\n    - item9\n    - name: n1\n  note: plain\nother: keepme\n';
  const out = scrubber().scrub(text);
  for (const v of ['admin', 'hunter2', 'abc', 'line1', 'line2', 'item9', 'n1', 'plain']) assert.ok(!out.includes(v), v + ' survived: ' + out);
  for (const k of ['credentials:', 'nested:', 'deeper:', 'other: keepme']) assert.ok(out.includes(k), k + ' missing: ' + out);
});

test('[best-effort] known bypass (review 4): an escaped pipe inside a Markdown cell is not a cell boundary', () => {
  const text = '| note | password |\n|---|---|\n| a\\|b | hunter2 |\n| c | p2x |\n';
  const out = scrubber().scrub(text);
  assert.ok(!out.includes('hunter2') && !out.includes('p2x'), out);
  assert.ok(out.includes('a\\|b') && out.includes('| c |'), out);
});

test('[promised] known bypass (review 4): data trailing a placeholder is scrubbed; closers and sibling fields still count as complete', () => {
  for (const [text, v] of [['PASSWORD=[SECRET_1])CorrectHorse9!', 'CorrectHorse9!'], ['PASSWORD=[SECRET_1]; CorrectHorse9!', 'CorrectHorse9!'], ['password: [KEY_1], CorrectHorse9!', 'CorrectHorse9!']]) {
    const out = scrubber().scrub(text); assert.ok(!out.includes(v), text + ' -> ' + out);
  }
  for (const keep of ['(agent said: "Authorization: [SECRET_1]")', '{"password":"[SECRET_1]","after":"x"}', 'tokens: [SECRET_1], [SECRET_2]', 'PASSWORD=[SECRET_1]; next=1']) {
    const s = scrubber(); assert.equal(s.scrub(keep), keep, keep); assert.deepEqual(s.counts(), {}, keep);
  }
});

test('[promised] known bypass (review 4): a never_send term next to @ is still scrubbed when it is not an email', () => {
  const s = scrubber({ terms: ['Acme'] });
  assert.equal(s.scrub('ping user@Acme please'), 'ping user@[PRIVATE_1] please');
  assert.equal(s.scrub('jo@Acme'), 'jo@[PRIVATE_1]');
  assert.equal(s.scrub('jo@acme.example'), '[EMAIL_1]');            // a real address goes whole, term included
  assert.equal(scrubber({ terms: ['x'] }).scrub('mail jo@x.example'), 'mail [EMAIL_1]');   // a one-letter term never eats a host label
  for (const t of ['user@Acme', 'jo@acme', 'mail to jo@acme.example now']) assert.ok(!/acme/i.test(scrubber({ terms: ['Acme'] }).scrub(t)), t);
});

// ---- PR #16 review round 6 (promised tier): fixtures written before their fixes ----

test('[promised] known bypass (review 5): a YAML credential scope continues across blank lines', () => {
  const out = scrubber().scrub('credentials:\n  username: admin\n\n  nested:\n    account: hunter2\n\nother: keepme\n');
  for (const v of ['admin', 'hunter2']) assert.ok(!out.includes(v), v + ' survived: ' + out);
  assertKept(out, ['credentials:', 'nested:', 'other: keepme']);
});

test('[promised] known bypass (review 5): Basic and Bearer tokens have no minimum length; a plain lowercase word stays', () => {
  for (const [text, v] of [['curl -H "Basic YTpi" https://h.example', 'YTpi'], ['send Bearer Ab1 with it', 'Ab1'], ['Basic dXNlcjpwdw==', 'dXNlcjpwdw==']]) {
    const s = scrubber(); const out = s.scrub(text); assert.ok(!out.includes(v), text + ' -> ' + out); assert.equal(s.counts().KEY, 1, out);
  }
  for (const keep of ['Basic auth is fine and the Bearer token header is set', 'use the Bearer scheme here']) assert.equal(scrubber().scrub(keep), keep, keep);
});

test('[promised] known bypass (review 5): a PEM footer ends the block only when its type matches the header', () => {
  const body = gen.pemLines(rng, 3), tail = gen.pemLines(rng, 2);
  const text = PEM_HEAD('RSA') + '\n' + body.join('\n') + '\n' + PEM_FOOT('EC') + '\n' + tail.join('\n') + '\nTRAILING TEXT';
  const out = scrubber().scrub(text);
  assertGone(out, [...body, ...tail], 'mismatched footer'); assert.ok(!out.includes('TRAILING TEXT'), 'text after a mismatched footer survived (no footer means to the end of input): ' + out);
  const ok = scrubber().scrub(PEM_HEAD('RSA') + '\n' + body.join('\n') + '\n' + PEM_FOOT('RSA') + '\nAFTER');
  assertGone(ok, body); assertKept(ok, ['AFTER']);
});

test('[promised] known bypass (review 5): URL userinfo with a one-character scheme', () => {
  const s = scrubber(); const out = s.scrub('x://alice:hunter2@db/app and a://tok8chars@h');
  assert.ok(!out.includes('hunter2') && !out.includes('alice') && !out.includes('tok8chars'), out);
  assert.equal(s.counts().KEY, 2, out);
});

// ---- mutation survivors (engine/scripts/mutate.mjs): each test kills one mutant that the suite missed ----

test('[promised] mutation: names split at letter/digit boundaries, so token2 and v2token are credentials', () => {
  const a = sec(16), b = sec(16); const out = scrubber().scrub(`token2: ${a}\nv2token=${b}`); assertGone(out, [a, b]);
});

test('[promised] mutation: a name with no word parts (__=) is not a credential and key after a structural word stays', () => {
  for (const l of ['__=keep this', 'public_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 host', 'foreign_key = user_id', 'sort-key: created_at']) assert.equal(scrubber().scrub(l), l, l);
});

// ---- Phase 3 self-attack fixtures: corpus/attack-round-N.json ----
for (const { file, cases } of attackRounds()) {
  for (const c of cases) {
    assert.ok(c.tier === 'promised' || c.tier === 'best-effort', `${file} ${c.name}: every fixture carries a tier (contract "Tiers")`);
    test(`[${c.tier}] ${file.replace('.json', '')}: ${c.name}`, () => {
      const { text, secrets } = expand(c.input, seedOf(file + c.name)); const s = scrubber({ terms: c.terms || [] }); const out = s.scrub(text);
      assertGone(out, [...secrets, ...(c.gone || [])], c.name); assertKept(out, c.keep || [], c.name);
      if (c.terms && c.terms.length) assert.ok(!c.terms.some(t => out.toLowerCase().includes(String(t).toLowerCase())), c.name + ': never_send term survived');
    });
  }
}

// PR #16 review, round on d96c996.
test('[promised] glued -p passwords of any length are scrubbed', () => {
  for (const x of ['mysql -pX', 'mysql -pab']) { const r = scrubber().sanitize(x); assert.ok(!/-p(?:X|ab)$/.test(r.text), r.text); }
});
test('[promised] YAML block scalars accept indicators in either order', () => {
  for (const h of ['|2-', '|2+', '>2-', '>2+', '|-2']) { const r = scrubber().sanitize(`password: ${h}\n  hunter2\n`); assert.ok(!r.text.includes('hunter2'), h + ' ' + r.text); }
});
test('[promised] a JSON-escaped private key longer than 64 KB is scrubbed whole', () => {
  const big = '{"k":"-----BEGIN PRIVATE KEY-----\\n' + 'A'.repeat(66000) + 'stillsecret\\n-----END PRIVATE KEY-----"}';
  const r = scrubber().sanitize(big); assert.ok(!r.text.includes('stillsecret'));
});
test('[promised] thousands of backslash-continued lines do not overflow the stack', () => {
  const r = scrubber().sanitize('password=a\\\n' + 'b\\\n'.repeat(6000) + 'end\nnext=ok');
  assert.ok(r.text.endsWith('next=ok') && !r.text.includes('end'), r.text.slice(-40));
});
test('[promised] only sanitize() can make a Sanitized', () => {
  assert.throws(() => new Sanitized({ text: 'raw', held: false, reasons: [], version: 'x' }), TypeError);
  assert.ok(Sanitized.is(scrubber().sanitize('hi')));
});
test('[promised] a literal placeholder equal to one already minted is never restored to the real value', () => {
  const s = scrubber(); const out = s.scrub('password=hunter2'); assert.equal(s.unscrub(out), 'password=hunter2');
  s.scrub('the user typed [SECRET_1] literally'); assert.ok(!s.unscrub('echo [SECRET_1]').includes('hunter2'));
});
test('[promised] a never-send term inside an email address is still detected', () => {
  const s = scrubber({ terms: ['Acme'] }); s.scrub('mail employee@acme.example');
  assert.ok(s.mentionsTerm('mail employee@acme.example'));
  assert.ok(!scrubber({ terms: ['Acme'] }).mentionsTerm('mail jo@x.example'));
});

// viaknox PR #27 review, on the engine vendored at d96c996.
test('[promised] compact names with a storage suffix are credentials (DBPASSWORDHASH, MYSECRETVALUE)', () => {
  for (const x of ['DBPASSWORDHASH=CorrectHorse9!', 'MYSECRETVALUE=CorrectHorse9!']) assert.ok(!scrubber().sanitize(x).text.includes('CorrectHorse'), x);
  for (const n of ['secretary', 'passage', 'author', 'tokenizer']) assert.equal(isCredentialName(n), false, n);
});
test('[promised] a credential-named array of objects goes whole', () => {
  for (const x of ['credentials: [{value: hunter2}]', 'api_keys: [{key: hunter2}]', 'credentials: [\n  {value: hunter2}\n]', '{"credentials": [{"user":"a","value":"hunter2"}]}'])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter2'), x);
});
test('[best-effort] type="password" marks an HTML field as a credential', () => {
  assert.ok(!scrubber().sanitize('<input type="password" value="hunter2">').text.includes('hunter2'));
});
test('[promised] prose about auth schemes stays; real Basic and Digest credentials go', () => {
  for (const x of ['Does Basic authentication work here?', 'Digest authentication is supported by the server.', 'We accept Bearer tokens.']) assert.equal(scrubber().scrub(x), x);
  assert.ok(!scrubber().scrub('use Basic YWxhZGRpbjpvcGVuc2VzYW1l').includes('YWxhZGRp'));
  assert.ok(!scrubber().scrub('Authorization: Digest username="a", response="zz9secret"').includes('zz9secret'));
});
test('[promised] a compact name ending in b64 is a credential (DBPASSWORDB64)', () => {
  const r = scrubber().sanitize('DBPASSWORDB64: "aHVudGVyMg=="'); assert.ok(!r.text.includes('aHVudGVyMg'), r.text);
  assert.equal(isCredentialName('secretary2'), false);
});
test('[promised] a plain-value array inside a credential object goes whole', () => {
  assert.ok(!scrubber().sanitize('{"credentials":{"items":["hunter2"]}}').text.includes('hunter2'));
});
test('[best-effort] compound credential names need part boundaries (cookiecutter, monkeyvalue stay plain)', () => {
  for (const n of ['cookiecutter', 'monkeyvalue', 'hockeyname']) assert.equal(isCredentialName(n), false, n);
  for (const n of ['DBAPIKEY', 'OPENAI_API_KEY', 'cookies', 'Set-Cookie', 'KeyValue', 'DBAPIKEYHASH', 'PHPSESSID', 'mysessionid']) assert.equal(isCredentialName(n), true, n);
});
test('[promised] the residual term check is whole-word, like the scrubber', async () => {
  const { residual } = await V2();
  assert.equal(scrubber({ terms: ['Ann'] }).sanitize('Please announce the result').held, false);
  assert.equal(residual('ask Ann today', { terms: ['Ann'] }).held, true);
  assert.equal(residual('the Anns agreed', { terms: ['Ann'] }).held, true);
});
test('[promised] any quoted key inside a credential object has its value scrubbed', () => {
  for (const x of ['{"credentials":{"alice@example.com":"hunter2"}}', '{"credentials":{"my key":"hunter2"}}', '{"credentials":{"1st":"hunter2"}}'])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter2'), x);
});
test('[promised] a brace-prefixed credential value ({noop}, {bcrypt}) goes whole', () => {
  for (const x of ['PASSWORD={noop}hunter2', 'PASSWORD={bcrypt}$2a$10$abcdefghijklmnopqrstuv']) {
    const t = scrubber().sanitize(x).text; assert.ok(!/hunter2|abcdefghij/.test(t), t);
  }
  assert.ok(!scrubber().sanitize('"credentials": {"user": "a", "password": "hunter2"}, "host": "db"').text.includes('hunter2'));
});
test('[best-effort] an echo of just the token is found after a credential with a trailing comment', () => {
  const s = scrubber(); s.scrub('PASSWORD=hunter2 # temporary'); assert.deepEqual(s.echoes('your password is hunter2'), ['SECRET']);
});
test('[promised] a recognised secret is replaced wherever it recurs bare, in this text or a later one', () => {
  assert.equal(scrubber().sanitize('USER: PASSWORD=CorrectHorse9!\nAGENT: CorrectHorse9!').text, 'USER: PASSWORD=[SECRET_1]\nAGENT: [SECRET_1]');
  const s = scrubber(); s.scrub('PASSWORD=CorrectHorse9!'); assert.ok(!s.scrub('the bot said CorrectHorse9! again').includes('CorrectHorse'));
});
test('[promised] digit-leading credential keys ({"2facode": …}) are scrubbed', () => {
  assert.ok(!scrubber().sanitize('{"2facode":"654321"}').text.includes('654321'));
});
test('[best-effort] flow-style Kubernetes Secret maps, value-before-name records and pipe-less Markdown tables', () => {
  for (const x of ['kind: Secret\nstringData: {username: admin, db: hunter2}', '{"value":"hunter2","name":"password"}', '- value: hunter2\n  name: password', 'user | password\n--- | ---\nalice | hunter2'])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter2'), x);
});
test('[promised] compound names with a digit suffix (APIKEYB64) and mixed arrays in credential objects', () => {
  assert.ok(!scrubber().sanitize('APIKEYB64: "aHVudGVyMg=="').text.includes('aHVudGVyMg'));
  assert.ok(!scrubber().sanitize('{"credentials":{"items":["hunter2",{"note":"legacy"}]}}').text.includes('hunter2'));
});
test('[promised] viaknox PR #27 round 7: quoted multiword keys, numeric keys, heredocs and multi-line literals', () => {
  for (const x of ['{"api key":"hunter2"}', '"password field": hunter2', 'credentials: {123: hunter2}', 'password = <<EOF\nhunter2\nEOF', 'password = """\nhunter2\n"""', "password = '''\nhunter2\n'''"])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter2'), x);
  assert.equal(scrubber().sanitize('password = <<EOF\nhunter2\nEOF\nnext=ok').text, 'password = [SECRET_1]\nnext=ok');
});
test('[best-effort] viaknox PR #27 round 7: HTML cells with markup, decorated k8s kinds, Unicode XML names, prose verbs, SQL dollar quotes', () => {
  for (const x of ['<table><tr><th>password</th></tr><tr><td><code>hunter2</code></td></tr></table>', 'kind: Secret # prod\nstringData: {db: hunter2}', 'kind: "Secret"\nstringData: {db: hunter2}',
    '<пароль>hunter2</пароль>', '<密码>hunter2</密码>', 'the password was hunter2', 'I changed the password to hunter2', "INSERT INTO users(note,password) VALUES ($$a,b$$,'hunter2')"])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter2'), x);
  assert.equal(scrubber().sanitize('The password was reset yesterday by IT').text, 'The password was reset yesterday by IT');
});
test('[promised] viaknox PR #27 round 8: indentless YAML lists, compound token names, proxy-user, nested XML, seed phrases', () => {
  for (const x of ['password:\n- hunter2', 'credentials:\n  password:\n  - hunter2', 'BEARERTOKEN=hunter2', 'curl --proxy-user alice:hunter2 https://x', 'curl -U alice:hunter2 https://x',
    '<password><value>hunter2</value></password>', 'mnemonic: "abandon hunter2 about"', 'seed_phrase: abandon hunter2 about', '<input autocomplete="current-password" value="hunter2">'])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter2'), x);
  assert.equal(scrubber().sanitize('random_seed: 42').text, 'random_seed: 42');
});
test('[promised] viaknox PR #27 round 8: compact SSNs and phones after a cue, E.164, IPv6; times and C++ scopes stay', () => {
  for (const [x, bad] of [['SSN: 123456789', '123456789'], ['call +14155552671', '4155552671'], ['phone: 4155552671', '4155552671'], ['client at 2001:db8:85a3::8a2e:370:7334', '8a2e']])
    assert.ok(!scrubber().sanitize(x).text.includes(bad), x);
  for (const x of ['meeting at 10:30:00 today', 'use std::string here', 'order 1234567890 shipped']) assert.equal(scrubber().sanitize(x).text, x);
});
test('[best-effort] reformatted contact echoes are found', () => {
  const s = scrubber(); s.scrub('mail Alice@Example.com, call (415) 555-2671');
  assert.deepEqual(s.echoes('ok alice@example.com and 415-555-2671').sort(), ['EMAIL', 'PHONE']);
});
test('[promised] viaknox PR #27 round 9: environment-suffixed compact names, multipart boundaries, quoted-local emails, deep XML', () => {
  for (const x of ['APIKEYPROD=hunter22', 'PASSWORDPROD=hunter22', 'CLIENTSECRETTEST=hunter22', '--real\nContent-Disposition: form-data; name="password"\n\nnote\n---\nhunter22\n--real--', '<password>' + '<x>a</x>'.repeat(300) + 'hunter22</password>'])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter22'), x.slice(0, 40));
  assert.ok(!scrubber().sanitize('"john doe"@example.com wrote').text.includes('john doe'));
});
test('[promised] viaknox PR #27 round 10: quoted multipart names, percent-encoded query names, XML end-tag whitespace, nested credential elements, reformatted SSN echoes, sqlcmd -P, pgpass', () => {
  for (const x of ['--b\nContent-Disposition: form-data; name="api key"\n\nhunter22\n--b--', 'https://x/?%70assword=hunter22&a=1', '<password>hunter22</password >',
    '<div data-field="password"><span>hunter22</span></div>', '<textarea name="password"><b>hunter22</b></textarea>', 'sqlcmd -S db -U alice -P hunter22', 'sqlcmd -S db -Phunter22',
    'db.example.com:5432:mydb:alice:hunter22'])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter22'), x);
  assert.ok(!scrubber().sanitize('User: 123-45-6789\nBot: got 123456789').text.includes('123456789'));
  assert.equal(scrubber().sanitize('mysql -h db -P 3306 -u x').text, 'mysql -h db -P 3306 -u x');
  assert.equal(scrubber().sanitize('meeting 10:30:00').text, 'meeting 10:30:00');
});
test('[promised] viaknox PR #27 round 11: sshpass -p, HTML-entity cue names, SQL account passwords, role-prefixed line forms', () => {
  for (const x of ['sshpass -p hunter22 ssh host', '<input name="p&#97;ssword" value="hunter22">', "CREATE USER 'alice'@'localhost' IDENTIFIED BY 'hunter22';",
    "ALTER USER bob WITH PASSWORD 'hunter22';", "CREATE LOGIN x WITH PASSWORD = 'hunter22'", 'USER: AUTH hunter22\nAGENT: ok'])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter22'), x);
  assert.equal(scrubber().sanitize('ssh -p 22 host').text, 'ssh -p 22 host');
});
test('[promised] computed keys inside a credential container lose their values (viaknox PR #27 round 12)', () => {
  assert.ok(!scrubber().sanitize('const credentials = { [provider]: "hunter22" }').text.includes('hunter22'));
});
test('[promised] viaknox PR #27 round 13: named HTML references, WPA psk, MySQL SET PASSWORD; non-Latin names still work', () => {
  for (const x of ['<input name="p&aacute;ssword" value="hunter22">', 'psk="hunter22"', 'WIFI_PSK="hunter22"', "SET PASSWORD FOR 'alice'@'localhost' = 'hunter22';",
    'contraseña: hunter22', '비밀번호: hunter22', 'パスワード: hunter22', 'Schlüssel: hunter22'])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter22'), x);
});
test('[promised] viaknox PR #27 round 14: multiword CSV headers, UTF-8 query names, zugangsdaten; empty-folding terms do not hang', () => {
  for (const x of ['Title,Website,Login Name,Password,Comment\nX,https://x,alice,hunter22,n', 'https://x/?contrase%C3%B1a=hunter22&a=1', 'zugangsdaten=hunter22'])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter22'), x);
  const s = scrubber({ terms: ['​', '́', 'Acme'] });
  assert.equal(s.scrub(''), '');
  assert.ok(!s.sanitize('Acme ok').text.includes('Acme'));
  assert.equal(scrubber().sanitize('I said hi, then left\nok, fine').text, 'I said hi, then left\nok, fine');
});
test('[promised] tune-up PR #16 review backlog: plurals, PEM labels, schemes, YAML comments, JSON newlines, escaped flags, brace strings, decomposed emails', () => {
  const pem = (l) => `-----BEGIN ${l} PRIVATE KEY-----\nhunter22\n-----END ${l} PRIVATE KEY-----`;
  for (const x of ['sessions=hunter22', 'sids=hunter22', pem('VENDOR HARDWARE SECURITY MODULE WRAPPED'), 'curl -H "basic YTpiOmhl22"', 'send bearer Ab1hunter22 now',
    'proxy digest username="a", response="hunter22"', 'password: # production\n  hunter22', '{"password":\n"hunter22"}', 'cmd --password "abc\\"hunter22"',
    'export PASSWORD={hunter22:}', 'Authorization: Bearer\r\n hunter22hunter22', 'mail hunter22@exámple.com'])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter22'), x);
  assert.equal(scrubber().sanitize('a basic understanding of bearer instruments').text, 'a basic understanding of bearer instruments');
});
test('[best-effort] tune-up PR #16 review backlog: PowerShell, JSON k8s Secrets, HTML/XML case, role-prefixed tables, netrc quotes, oversized credential objects', () => {
  for (const x of ['$token = hunter22', '{"kind":"Secret","stringData":{"db":"hunter22"}}', '<table><TR><TH>password</TH></TR><TR><TD>hunter22</TD></TR></table>',
    '<Password>hunter22</PASSWORD>', 'USER: | user | password |\n| --- | --- |\n| alice | hunter22 |', 'machine x.example\nlogin a\npassword "correct hunter22"',
    '{"credentials":{"padding":"' + 'a'.repeat(66000) + '","value":"hunter22"}}'])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter22'), x.slice(0, 50));
});
test('[best-effort] tune-up PR #16 review backlog: no over-scrub of compass/bypass, autocomplete cues, recurrences inside words; echoes are whole', () => {
  assert.equal(scrubber().sanitize('compass: north\nbypass: on').text, 'compass: north\nbypass: on');
  assert.equal(scrubber().sanitize('<input autocomplete="current-password">').text, '<input autocomplete="current-password">');
  const s = scrubber(); s.sanitize('password=pass'); assert.equal(s.sanitize('bypass the compass').text, 'bypass the compass');
  const e = scrubber(); e.sanitize('password=correct horse battery staple'); assert.deepEqual(e.echoes('That is correct.'), []);
  const m = scrubber(); m.sanitize('a@example.com'); assert.deepEqual(m.echoes('data@example.com'), []);
});
test('[promised] viaknox PR #27 round 15: scheme-relative URL userinfo; a ConfigMap after a Secret keeps its data', () => {
  assert.ok(!scrubber().sanitize('see //alice:CorrectHorse22!@db.example/app').text.includes('CorrectHorse22'));
  const t = scrubber().sanitize('kind: Secret\nstringData:\n  db: hunter22\n---\nkind: ConfigMap\ndata:\n  greeting: hello world\n').text;
  assert.ok(!t.includes('hunter22')); assert.ok(t.includes('greeting: hello world'), t);
  assert.equal(scrubber().sanitize('// TODO: ping bob\nx // y').text, '// TODO: ping bob\nx // y');
});
test('[promised] viaknox PR #27 round 16: compact version suffixes (PASSWORDV2, APIKEYV3, TOKENV2)', () => {
  for (const x of ['PASSWORDV2=hunter22', 'APIKEYV3=hunter22', 'CLIENTSECRETV2=hunter22', 'TOKENV2=hunter22'])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter22'), x);
});
test('[promised] viaknox PR #27 round 17: adjacent look-alikes in a Latin name; [best-effort] two-group IPv6 with a real prefix', () => {
  assert.ok(!scrubber().sanitize('ѕесret=hunter22').text.includes('hunter22'));
  assert.ok(!scrubber().sanitize('пароль: hunter22').text.includes('hunter22'));
  assert.ok(!scrubber().sanitize('connect fe80::1 now').text.includes('fe80'));
  assert.equal(scrubber().sanitize('meet 10::30 then std::vector').text, 'meet 10::30 then std::vector');
});
test('[promised] viaknox PR #27 round 18: form-encoded query names (?api+key=)', () => {
  for (const x of ['https://x.example/?api+key=hunter22&a=1', 'https://x.example/?a=1&access+token=hunter22'])
    assert.ok(!scrubber().sanitize(x).text.includes('hunter22'), x);
  assert.equal(scrubber().sanitize('https://x.example/?q=a+b&page=2').text, 'https://x.example/?q=a+b&page=2');
});
test('[best-effort] viaknox PR #27 round 19: card codes, multiword passphrases, wallet phrases, config set commands, symbol-rich passwords held', () => {
  for (const x of ['cvv=922', 'CVC: 922', 'my password is correct horse battery staple', 'recovery phrase: abandon ability able about above',
    'seed phrase is abandon ability able about', 'aws configure set aws_secret_access_key hunter22'])
    assert.ok(!/922|horse|ability|hunter22/.test(scrubber().sanitize(x).text), x);
  assert.equal(scrubber().sanitize('N7!qP2@vL9#sR4$x').held, true);
  assert.equal(scrubber().sanitize('npm config set registry https://x.example').text, 'npm config set registry https://x.example');
  assert.match(scrubber().sanitize('my password is not working, can you help').text, /working, can you help/);
});
test('[best-effort] viaknox PR #27 round 20: YAML list-item credential containers, redis-cli -a', () => {
  const y = scrubber().sanitize('- credentials:\n    value: hunter22\n- other:\n    value: keepme').text;
  assert.ok(!y.includes('hunter22')); assert.ok(y.includes('keepme'), y);
  assert.ok(!scrubber().sanitize('redis-cli -a hunter22 PING').text.includes('hunter22'));
  assert.equal(scrubber().sanitize('tar -a x.tar').text, 'tar -a x.tar');
});
test('[promised] tune-up PR #16 round 2 backlog: Digest any case, SSN after underscore; [best-effort] lowercase-scheme tokens, TOML escapes, HTML quoted >, nested end tags, YAML "...", token-indexed keys', () => {
  for (const x of ['Digest username="bob", response="hunter22"', 'id_123-45-6789', 'send bearer correcthorse now', 'password = """abc\\"""hunter22"""',
    '<input name="password" value="hunter\\">two">', '<textarea name="password"><textarea>in</textarea>outersecret</textarea>', '{"api_keys":{"hunter22":{"owner":"alice"}}}'])
    assert.ok(!/hunter22|6789|correcthorse|two|outersecret/.test(scrubber().sanitize(x).text), x);
  assert.equal(scrubber().sanitize('a basic understanding').text, 'a basic understanding');
  assert.ok(scrubber().sanitize('kind: Secret\nstringData:\n  db: hunter22\n...\nkind: ConfigMap\ndata:\n  greeting: hello world\n').text.includes('hello world'));
});
test('[promised] perf: 800 distinct-length recurrences over a shared first character stay fast (PR #16 review)', () => {
  const lines = []; for (let i = 0; i < 800; i++) lines.push('password=a' + 'b'.repeat(i + 4));
  const t = Date.now(); scrubber().sanitize(lines.join('\n') + '\n' + 'a '.repeat(20000)); assert.ok(Date.now() - t < 2000);
});
test('[best-effort] viaknox PR #27 round 21: db.auth, SMTP AUTH, BOM CSV, phone after copula, JSON Secret whitespace; whole-value echoes', () => {
  for (const x of ['db.auth("alice", "hunter22")', 'AUTH PLAIN AHVudGVyMjI=', '\uFEFFTitle,Username,Password\nsite,alice,hunter22', 'my phone is 4155552671',
    '{"kind":"Secret","data"\n:\n{"foo":"aHVudGVyMjI="}}'])
    assert.ok(!/hunter22|AHVudGVyMjI|4155552671|aHVudGVyMjI/.test(scrubber().sanitize(x).text), x);
  const s = scrubber(); s.sanitize('PASSWORD=pass'); assert.deepEqual(s.echoes('the compass passed'), []); assert.deepEqual(s.echoes('use pass now'), ['SECRET']);
});
test('[best-effort] viaknox PR #27 round 22: vault login token, cc-csc fields; token-usage settings stay', () => {
  for (const x of ['vault login dev-only-token', '<input autocomplete="cc-csc" value="922">', 'API_TOKEN=hunter22'])
    assert.ok(!/dev-only-token|922|hunter22/.test(scrubber().sanitize(x).text), x);
  for (const x of ['max_output_tokens=1024', 'max_completion_tokens=1024', 'cached_input_tokens=500']) assert.equal(scrubber().sanitize(x).text, x);
});
test('[promised] viaknox PR #27 round 23: a name ending in token is a credential unless a count word says otherwise', () => {
  for (const x of ['ROTATION_TOKEN=hunter22', 'RESPONSE_TOKEN=hunter22']) assert.ok(!scrubber().sanitize(x).text.includes('hunter22'), x);
  for (const x of ['max_output_tokens=1024', 'usage_tokens=5', 'token_rotation_policy=30d', 'tokenLimit=10']) assert.equal(scrubber().sanitize(x).text, x);
});
test('[best-effort] viaknox PR #27 round 24: IMAP LOGIN, SSN after copula, one-time codes, punctuation-rich passwords held, public PEM not held', () => {
  for (const x of ['C: a001 LOGIN alice hunter22', 'my SSN is 123456789', 'one_time_code=654321', 'my one-time code is 654321', 'TOTP=654321'])
    assert.ok(!/hunter22|123456789|654321/.test(scrubber().sanitize(x).text), x);
  assert.equal(scrubber().sanitize('N7:qP2-vL9:sR4-x').held, true);
  assert.equal(scrubber().sanitize('-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0\n-----END PUBLIC KEY-----').held, false);
});
test('[promised] auth-scheme prose is not held by the residual scan (viaknox PR #27 round 25)', () => {
  for (const x of ['Use Basic authentication for this endpoint', 'The API uses Bearer authentication']) assert.equal(scrubber().sanitize(x).held, false, x);
  assert.equal(scrubber().sanitize('x Bearer abcdefghijklmnopQRS12').held || !scrubber().sanitize('x Bearer abcdefghijklmnopQRS12').text.includes('QRS12'), true);
});
test('[promised] round 26: key shapes after _, hyphenated PEM labels, JSON non-string values after a newline, CRLF scopes, comments after quoted values; RFC local parts; labelled commit hashes not held', () => {
  for (const x of ['id_sk-' + 'x'.repeat(40), '-----BEGIN ACME-HSM PRIVATE KEY-----\nhuntertwo\n-----END ACME-HSM PRIVATE KEY-----', '{"password":\n["huntertwo"]}',
    '{"pin":\n654321}', '[credentials]\r\nuser = huntertwo', 'credentials:\r\n  user: huntertwo', 'password: "foo" # backup huntertwo',
    '<password><password>in</password>huntertwo</password>', "mail o'huntertwo@example.com"])
    assert.ok(!/huntertwo|654321|xxxxxxxxxx/.test(scrubber().sanitize(x).text), x);
  assert.equal(scrubber().sanitize('merged commit e79bc9f0d7039e11a1e0258fd217cb109c397329 today').held, false);
});
test('[best-effort] round 27: role-prefixed Secret manifests, htpasswd -b, smbclient user%pass; card/SSN echoes by digits', () => {
  for (const x of ['USER: kind: Secret\ndata:\n  foo: aHVudGVyMjI=', 'htpasswd -b .htpasswd alice hunter22', 'smbclient //server/share -U alice%hunter22'])
    assert.ok(!/aHVudGVyMjI|hunter22/.test(scrubber().sanitize(x).text), x);
  const s = scrubber(); s.sanitize('my ssn 123-45-6789'); assert.deepEqual(s.echoes('got 123 45 6789'), ['SSN']);
});
test('[best-effort] round 28: recurrences wrapping a private term, escaped JSON Secret keys, cards after _, doubled PowerShell quotes, multiword terms across whitespace', () => {
  const p = scrubber({ terms: ['Acme'] }); p.sanitize('password=Acme-huntertwo');
  assert.ok(!/huntertwo/.test(p.sanitize('send Acme-huntertwo now').text));
  for (const x of ['{"kind":"\\u0053ecret","stringData":{"db":"huntertwo"}}', '{"kind":"Secret","\\u0073tringData":{"db":"huntertwo"}}', "cmd -Password 'foo''huntertwo'"])
    assert.ok(!/huntertwo/.test(scrubber().sanitize(x).text), x);
  assert.ok(!/4111111111111111/.test(scrubber().sanitize('id_4111111111111111').text));
  for (const x of ['Acme  Corp', 'Acme\tCorp', 'Acme\nCorp']) {
    assert.ok(!/Acme|Corp/.test(scrubber({ terms: ['Acme Corp'] }).sanitize(x).text), x);
    assert.equal(residual(x, { terms: ['Acme Corp'] }).held, true, x);
  }
});
test('[best-effort] round 29: Redis AUTH [user] password, Oracle JDBC user/password URLs', () => {
  for (const x of ['redis-cli AUTH alice hunter22', '127.0.0.1:6379> AUTH alice hunter22', 'AUTH hunter22', 'jdbc:oracle:thin:scott/hunter22@//db.example:1521/orcl'])
    assert.ok(!/hunter22/.test(scrubber().sanitize(x).text), x);
  assert.equal(scrubber().sanitize('auth is hard to get right').text, 'auth is hard to get right');
  assert.equal(scrubber().sanitize('jdbc:oracle:thin:@//db.example:1521/orcl').text, 'jdbc:oracle:thin:@//db.example:1521/orcl');
});
test('[best-effort] round 30: unclosed credential elements, echo | --password-stdin, labelled HCL credential blocks', () => {
  for (const x of ['<password>hunter22', '<password>hunter22</foo>', '<password>\n  hunter22', 'echo hunter22 | docker login --username alice --password-stdin registry.example.com', 'credentials "prod" { value = "hunter22" }'])
    assert.ok(!/hunter22/.test(scrubber().sanitize(x).text), x);
  assert.ok(scrubber().sanitize('echo hunter22 | docker login --password-stdin registry.example.com').text.includes('registry.example.com'));
  assert.equal(scrubber().sanitize('<password /> stays').text, '<password /> stays');
});
test('[best-effort] round 31: scalar token-map keys, 3-character recurrences, ";" comments, quoted Secret keys, POSIX-concatenated flags, folded multipart headers, HTML values past the window', () => {
  const big = '<textarea name="password">' + 'a'.repeat(65537) + 'hunter22</textarea>';
  for (const x of ['{"api_keys":{"hunter22":"alice"}}', 'password = "foo" ; backup hunter22', 'kind: Secret\n"stringData":\n  db: hunter22', "cmd --password 'foo'\\''hunter22'", 'Content-Disposition: form-data;\r\n name="password"\r\n\r\nhunter22\r\n--b--', big])
    assert.ok(!/hunter22/.test(scrubber().sanitize(x).text), x.slice(0, 60));
  assert.ok(scrubber().sanitize('{"credentials":{"username":"bob","password":"x"}}').text.includes('"username"'));
  const s = scrubber(); assert.equal(s.sanitize('USER: PASSWORD=abc\nAGENT: abc').text, 'USER: PASSWORD=[SECRET_1]\nAGENT: [SECRET_1]');
  assert.deepEqual(s.echoes('it was abc'), ['SECRET']);
});
test('[best-effort] round 32: docker login -p with a space', () => {
  assert.ok(!/hunter22/.test(scrubber().sanitize('docker login -u alice -p hunter22 registry.example.com').text));
  assert.equal(scrubber().sanitize('psql -h db -p 5432').text, 'psql -h db -p 5432');
});
test('[best-effort] round 34: kubectl create secret --from-literal, SASL challenge-response lines', () => {
  for (const x of ['kubectl create secret generic db --from-literal=foo=hunter22', 'C: AUTH LOGIN\nS: 334 VXNlcm5hbWU6\nC: dXNlcg==\nS: 334 UGFzc3dvcmQ6\nC: aHVudGVyMjI=\nS: 235 ok', 'a1 AUTHENTICATE PLAIN\n+ \nAGh1bnRlcjIy'])
    assert.ok(!/hunter22|aHVudGVyMjI|AGh1bnRlcjIy/.test(scrubber().sanitize(x).text), x);
  assert.equal(scrubber().sanitize('kubectl get secret db').text, 'kubectl get secret db');
});
test('[best-effort] round 36: PAT fields, HTML attributes with line breaks around "="', () => {
  for (const x of ['GITHUB_PAT=hunter22', 'PAT=hunter22', '<input name\n=\n"password" value\n=\n"hunter22">'])
    assert.ok(!/hunter22/.test(scrubber().sanitize(x).text), x);
  assert.equal(scrubber().sanitize('a pat on the back').text, 'a pat on the back');
});
test('[best-effort] round 37: glued repeat/confirm password fields', () => {
  for (const x of ['passwordrepeat=letmein22', 'passwordconfirm=letmein22', 'PASSWORDCURRENT=letmein22'])
    assert.ok(!/letmein22/.test(scrubber().sanitize(x).text), x);
});
test('[best-effort] round 38: distinctive compounds with any tail, multiline values after a placeholder, commented YAML block headers, oversized JSON Secret maps, explicit YAML keys in Secrets, self-closing same-name tags, schemes and IPv4 after "_", array-style names', () => {
  const big = '{"kind":"Secret","stringData":{' + ' '.repeat(65540) + '"foo":"hunter22"}}';
  for (const x of ['AUTHTOKENJWT = hunter22', 'password="[SECRET_1]\nhunter22"', 'password: >- # folded\n  hunter22', big, 'kind: Secret\nstringData:\n  ? foo\n  : hunter22',
    '<password><password/>hunter22</password>', '<textarea name="password"><textarea/>hunter22</textarea>', 'id_Digest username="bob", response="hunter22"',
    'https://x.test/?password[]=hunter22', 'password[]=hunter22'])
    assert.ok(!/hunter22/.test(scrubber().sanitize(x).text), x.slice(0, 60));
  assert.ok(!/YTpiYzEy/.test(scrubber().sanitize('id_Basic YTpiYzEy').text));
  assert.ok(!/192\.168\.1\.1/.test(scrubber().sanitize('host_192.168.1.1').text));
  assert.equal(isCredentialName('cookiecutter'), false);
  assert.equal(scrubber().sanitize('items[]=apple').text, 'items[]=apple');
});
test('[best-effort] round 39: vault login without a hyphen, rabbitmqctl passwords, spaced/dotted SSNs, logical-assignment operators, qualified prose values ending in a digit', () => {
  for (const x of ['vault login hunter22', 'rabbitmqctl add_user alice hunter22', 'rabbitmqctl change_password alice hunter22', 'password ??= "hunter22"', 'token ||= "hunter22"', 'my password here is hunter22'])
    assert.ok(!/hunter22/.test(scrubber().sanitize(x).text), x);
  for (const x of ['SSN: 123 45 6789', 'SSN = 123.45.6789']) assert.ok(!/6789/.test(scrubber().sanitize(x).text), x);
  assert.equal(scrubber().sanitize('the password for production is ready.').text, 'the password for production is ready.');
});
test('[best-effort] round 40: mosquitto -P, credential names starting with an escape', () => {
  for (const x of ['mosquitto_pub -u alice -P hunter22 -t alerts -m hi', '{"\\u0070assword":"hunter22"}', '{"\\u0074oken":"hunter22"}'])
    assert.ok(!/hunter22/.test(scrubber().sanitize(x).text), x);
});
test('[best-effort] round 40: echoes() of a very long value does not build an oversized RegExp', () => {
  const s = scrubber(); const v = '{"data":{"a":'.repeat(4000); s.sanitize('kind: Secret\n' + v);
  assert.doesNotThrow(() => s.echoes('kind: Secret\n' + v));
});
test('[best-effort] round 41: \\xNN names, unindented assignment continuations, CSV/DELIMITER COPY rows, quoted TOML tables with spaces, sibling HOCON blocks', () => {
  for (const x of ['{"\\x70assword":"hunter22"}', 'const password =\n"hunter22";', 'COPY users (username,password) FROM stdin WITH (FORMAT csv);\nalice,hunter22\n\\.',
    "COPY users (username, password) FROM stdin DELIMITER '|';\nalice|hunter22\n\\.", '["database credentials"]\nvalue = "hunter22"', 'credentials { value = "x1" }, auth { value = "hunter22" }'])
    assert.ok(!/hunter22/.test(scrubber().sanitize(x).text), x);
});
test('[best-effort] round 42: SSN before a full stop, +E.164 after "_", PowerShell quote escapes, comments of any length, JSON whitespace runs, quoted multiword objects, quoted kind keys, header comments, oversized HCL blocks, attached curl -u, long credential tags held, inventory of quoted-then-commented values and URL passwords, quote-bounded placeholder siblings, PEM backslash parity', () => {
  assert.equal(scrubber().sanitize('The SSN is 123-45-6789.').text, 'The SSN is [SSN_1].');
  assert.ok(!/4155552671/.test(scrubber().sanitize('record id_+14155552671').text));
  for (const x of ["$password = 'foo''hunter22'", '$password = "foo`"hunter22"', 'password="foo" #' + ' '.repeat(5000) + 'hunter22', '{"password":' + ' '.repeat(300) + '\n"hunter22"}',
    '{"api key":{"user":"hunter22"}}', '"kind": Secret\nstringData:\n  db: hunter22', '[credentials] # prod\nuser = hunter22', 'credentials {' + ' '.repeat(65540) + 'user = hunter22',
    'curl -ualice:hunter22 https://x.test', 'password="[SECRET_1], next:hunter22"'])
    assert.ok(!/hunter22/.test(scrubber().sanitize(x).text), x.slice(0, 50));
  assert.throws(() => scrubber().sanitize('<textarea name="password" data-pad="' + 'a'.repeat(2001) + '">hunter22</textarea>'), (e) => e.name === 'ScrubError');
  const a = scrubber(); a.sanitize('password="hunter22" # backup'); assert.ok(!/hunter22/.test(a.sanitize('AGENT: try hunter22').text));
  assert.ok(!/hunter22/.test(scrubber().sanitize('USER: connect https://alice:hunter22@db.test\nAGENT: Use hunter22 to connect').text));
  const pem = '{"key":"-----BEGIN PRIVATE KEY-----\\nMIIB\\n-----END PRIVATE KEY-----\\\\","after":"KEEP"}';
  assert.ok(scrubber().sanitize(pem).text.includes('"after":"KEEP"'));
});
test('[best-effort] round 43: \\u{…} identifier escapes, C++ brace initializers, XML key= attributes, comments before the assignment operator', () => {
  for (const x of ['const p\\u{61}ssword = "hunter22";', 'std::string password{"hunter22"};', '<entry key="password">hunter22</entry>', 'const password /* production */ = "hunter22";'])
    assert.ok(!/hunter22/.test(scrubber().sanitize(x).text), x);
  assert.equal(scrubber().sanitize('<entry key="color">blue</entry>').text, '<entry key="color">blue</entry>');
});

// Round 44 (viaknox PR #27 review of b0af78e).
const r44s = scrubber({ terms: [] });
const sshKey = (type) => type + ' ' + Buffer.concat([
  Buffer.from([0, 0, 0, type.length]), Buffer.from(type), Buffer.from([0, 0, 0, 32]),
  Buffer.alloc(32).map((_, i) => (i * 37) % 251),
]).toString('base64');

test('r44: a line comment between the name and the operator on the next line does not leak the value', () => {
  for (const t of ['const password // production\n= "hunter2";', 'let api_key // rotated monthly\n  = "hunter2"']) {
    const r = r44s.sanitize(t);
    assert.ok(!r.text.includes('hunter2'), r.text);
  }
});

test('r44: genuine OpenSSH public keys are not held as high-entropy tokens', () => {
  for (const type of ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'sk-ssh-ed25519@openssh.com', 'ssh-ed25519-cert-v01@openssh.com']) {
    const r = r44s.sanitize('authorized_keys: ' + sshKey(type) + ' user@host');
    assert.equal(r.held, false, type + ' ' + JSON.stringify(r));
  }
});

test('r44: a random token after an ssh key-type word still counts (body must encode the named type)', () => {
  const r = r44s.sanitize('key: ssh-rsa AAAAx9Qk3sXcXc1wRk2b0m1vQ4mYt8X9ZpQ2r3s4t5u6');
  assert.equal(r.held, true);
  const mismatch = r44s.sanitize('key: ' + sshKey('ssh-ed25519').replace(/^ssh-ed25519/, 'ssh-rsa'));
  assert.equal(mismatch.held, true);
});

// Round 45 (viaknox PR #27 review of f8e0634).
const r45s = scrubber({ terms: [] });
test('r45: a Secret kind on a YAML list item (kind: List) scrubs its data', () => {
  for (const t of ['apiVersion: v1\nkind: List\nitems:\n  - kind: Secret\n    data:\n      foo: dGVzdA==', 'items:\n- kind: Secret\n  data:\n    foo: dGVzdA==']) {
    assert.ok(!r45s.sanitize(t).text.includes('dGVzdA=='), t);
  }
});
test('r45: an escaped credential container name is decoded', () => {
  assert.ok(!r45s.sanitize('{"cred\\u0065ntials":{"foo":"hunter2"}}').text.includes('hunter2'));
  assert.ok(!r45s.sanitize('{"x":1, "cred\\u0065ntials":{"foo":"hunter2"}}').text.includes('hunter2'));
});
test('r45: COPY CSV with a custom delimiter honours quotes', () => {
  const r = r45s.sanitize("COPY users (note,password) FROM stdin WITH (FORMAT csv, DELIMITER '|');\n\"a|b\"|hunter2\n\\.");
  assert.ok(!r.text.includes('hunter2'), r.text); assert.ok(r.text.includes('"a|b"'), r.text);
});
test('r45: --password-stdin fed by a here-string or a heredoc', () => {
  for (const t of ['docker login --password-stdin <<< hunter2', "docker login --password-stdin <<<'hunter2'", 'docker login -u me --password-stdin <<EOF\nhunter2\nEOF', "cat <<'END' | helm registry login reg.example.com --password-stdin\nhunter2\nEND\nok", 'docker login --password-stdin <<EOF\nhunter2']) {
    assert.ok(!r45s.sanitize(t).text.includes('hunter2'), t);
  }
  assert.ok(r45s.sanitize('docker login --password-stdin <<EOF\nhunter2\nEOF\nafter').text.endsWith('EOF\nafter'));
});

// Round 46 (viaknox PR #27 security review of f8e0634).
test('r46: a literal inside an assignment wrapper is inventoried, so a bare repeat is scrubbed', () => {
  const sc = scrubber({ terms: [] });
  for (const t of ['password = ("hunter2")\nThen use hunter2', 'password = ["hunter2"]\nuse hunter2', 'password = String("hunter2")\nuse hunter2', 'password = (hunter2)\nuse hunter2']) {
    assert.ok(!sc.sanitize(t).text.includes('hunter2'), t);
  }
});

// Round 47 (tune-up PR #16 review threads from 08:29-08:42).
test('r47: leaks found on tune-up #16 are scrubbed', () => {
  const cases = {
    json_nl: '{"password"\n:"huntertwo"}',
    strong_suffix: 'DB_PASSWORDJWT = huntertwo',
    tag_long: '<input data-x="' + 'a'.repeat(300) + '" name="password">huntertwo</input>',
    tag_cue: '<input title=">" name="password">huntertwo</input>',
    yaml_tag: 'password: !!str\n  huntertwo',
    yaml_anchor: 'password: &pw\n  huntertwo',
    json_esc: 'USER: {"password":"hunter\\u0074wo"}\nAGENT: huntertwo',
    toml_quoted: '[credentials]\n"login name" = huntertwo',
    hcl_hash: 'credentials {\n  # } not the closer\n  user = huntertwo\n}',
    hcl_slash: 'credentials {\n  // }\n  user = huntertwo\n}',
    hcl_block: 'credentials {\n  /* } */\n  user = huntertwo\n}',
    xml_comment: '<password><!-- </password> -->huntertwo</password>',
    xml_cdata: '<password><![CDATA[</password>]]>huntertwo</password>',
    cookie_fold: 'Cookie: sid=abc;\n foo=huntertwo',
    auth_fold: 'Authorization: Custom\n huntertwo',
  };
  for (const [k, t] of Object.entries(cases)) {
    const r = scrubber({ terms: [] }).sanitize(t);
    assert.ok(r.held || !r.text.includes('huntertwo'), k + ': ' + r.text);
  }
  assert.ok(!scrubber({ terms: [] }).sanitize('passwordless = true').text.includes('['), 'passwordless stays a setting');
});

// Round 48 (viaknox PR #27 review of a801ac1).
test('r48: TSV password columns, JSX expression attributes and leading-compressed IPv6', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x).text;
  assert.ok(!t('username\tpassword\nalice\thunter2').includes('hunter2'));
  assert.ok(!t('<input type="password" defaultValue={"hunter2"} />').includes('hunter2'));
  assert.ok(!t('<input name="password" value={`hunter2`} />').includes('hunter2'));
  assert.ok(!t('from ::ffff:c000:0280 today').includes('c000'));
  assert.ok(t('std::max and ::1').includes('std::max'));
});

// Round 49 (viaknox PR #27 security review of f9d2491).
test('r49: secret/credential/bearer stems take any glued tail; ordinary words stay', () => {
  for (const n of ['SECRETJWT', 'CREDENTIALJSON', 'BEARERJWT']) assert.ok(isCredentialName(n), n);
  for (const n of ['secretary', 'SECRETARY_NAME', 'secretion', 'secretive']) assert.ok(!isCredentialName(n), n);
  assert.ok(!scrubber({ terms: [] }).sanitize('SECRETJWT=hunter2').text.includes('hunter2'));
});

// Round 50 (tune-up PR #16 review of 4fa89e9).
test('r50: multiword JSON key before a newline colon, anchored Secret kinds, long URL schemes, INI continuations, PWD tails', () => {
  for (const t of ['{"api key"\n:"huntertwo"}', 'kind: &k Secret\nstringData:\n  db: huntertwo', 'kind: !!str &k Secret\ndata:\n  db: huntertwo',
    'a1111111111111111111111111111111111111111://alice:huntertwo@localhost', '[credentials]\nuser = alice\n  huntertwo', 'db_pwdjwt=huntertwo']) {
    const r = scrubber({ terms: [] }).sanitize(t);
    assert.ok(r.held || !r.text.includes('huntertwo'), t + ' -> ' + r.text);
  }
});

// Round 51 (viaknox PR #27 security review of bfc5077).
test('r51: an SSN after a label hyphen is scrubbed; longer numeric IDs stay', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x).text;
  assert.ok(!t('SSN-123-45-6789').includes('6789'));
  assert.equal(t('id 987-123-45-6789'), 'id 987-123-45-6789');
});

// Round 52 (viaknox PR #27 review of bfc5077).
test('r52: copula punctuation, dotted TOML headers, Java escapes, multiline block comments, aliased Secret kinds', () => {
  for (const t of ['The password is: hunter2.', '["database credentials".prod]\nvalue = "hunter2"', 'p\\assword=hunter2',
    'const password /* production\nvalue */ = "hunter2";', 'x: &s Secret\nkind: *s\ndata:\n  foo: hunter2']) {
    const r = scrubber({ terms: [] }).sanitize(t);
    assert.ok(r.held || !r.text.includes('hunter2'), t + ' -> ' + r.text);
  }
});

// Round 53 (viaknox PR #27 review of 6e07d33; follow-up PR).
test('r53: credential-first CSV headers, C# auto-property initializers, camel-case identifiers', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  const csv = t('password,username\nhunter2,alice\nhunter3,bob');
  assert.ok(!csv.text.includes('hunter2') && !csv.text.includes('hunter3'), csv.text);
  assert.ok(!t('public string Password { get; set; } = "hunter2";').text.includes('hunter2'));
  assert.equal(t('at java.util.concurrent.locks.AbstractQueuedSynchronizer.acquire(AbstractQueuedSynchronizer.java:1)').held, false);
  assert.equal(t('var s = new AbstractQueuedSynchronizer();').held, false);
  const rnd = t('token kQzPbXwRtYmNvLsDfGhJkLzXcVbNm'); assert.ok(rnd.held || !rnd.text.includes('kQzPbXwR'), rnd.text);
});

// Round 54 (tune-up PR #16 review of 3f71d4f / 866e473).
test('r54: long JSON whitespace before a colon, international phones with long groups, unbounded URL schemes, list-hyphen SSNs', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['{"password"' + '\n'.repeat(41) + ':"huntertwo"}', 'a' + '1'.repeat(129) + '://alice:huntertwo@localhost']) {
    const r = t(x); assert.ok(r.held || !r.text.includes('huntertwo'), r.text);
  }
  for (const x of ['Phone: +91-98765-43210', 'Phone: +49 1512 3456789']) assert.ok(t(x).text.includes('[PHONE_'), x);
  assert.equal(t('version +1.2.3').text, 'version +1.2.3');
  assert.ok(!t('-123-45-6789').text.includes('6789'));
});

test('r54: a credential word followed by a long run of whitespace stays fast (was cubic)', () => {
  for (const x of ['"password"' + ' '.repeat(300000), 'password' + ' '.repeat(300000) + 'x', 'phone' + ' '.repeat(5000) + '4155552671', 'secret' + '\t'.repeat(300000) + ':']) {
    const t0 = Date.now(); scrubber({ terms: [] }).sanitize(x); assert.ok(Date.now() - t0 < 1500, String(Date.now() - t0));
  }
});

// Round 55 (tune-up PR #16 review of 6d939a4).
test('r55: underscore-prefixed international phones, long gaps after SSN/phone cues, URLs after a hyphen', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x).text;
  assert.ok(t('id_+91-98765-43210').includes('[PHONE_'));
  assert.ok(t('SSN:' + ' '.repeat(30) + '123456789').includes('[SSN_'));
  assert.ok(t('Phone:' + ' '.repeat(30) + '4155552671').includes('[PHONE_'));
  assert.ok(!t('-https://alice:hunter2@host').includes('hunter2'));
  for (const x of ['phone' + ' '.repeat(300000) + '4155552671', 'a-'.repeat(200000) + 'x', '1'.repeat(300000) + '://a:b@c']) {
    const t0 = Date.now(); scrubber({ terms: [] }).sanitize(x); assert.ok(Date.now() - t0 < 1500, String(Date.now() - t0));
  }
});

// Round 56 (tune-up PR #19 / viaknox PR #28 Codex review of f3870f0).
test('r56: bare camel-case passphrases still count, quoted commas in credential-first CSV headers, multi-line C# accessors', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['value PurpleMonkeyDishwasherSatellite', 'VelvetQuartzDragonNimbusCipher', 'value PurpleMonkeyDishwasherSatellite.']) {
    const r = t(x); assert.ok(r.held || !/PurpleMonkey|VelvetQuartz/.test(r.text), x);
  }
  const csv = t('password,"last,name"\nhunter2,"smith, j"\nhunter3,doe');
  assert.ok(!csv.text.includes('hunter2') && !csv.text.includes('hunter3'), csv.text);
  for (const x of ['public string Password {\n  get;\n  set;\n} = "hunter2";', 'public string Password\n{\n    get; private set;\n}\n= "hunter2";']) {
    assert.ok(!t(x).text.includes('hunter2'), x);
  }
});

test('r56: long whitespace inside and after a C# accessor block stays fast', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['Password {' + ' \n'.repeat(100000) + 'get;}', 'Password { get; }' + ' '.repeat(300000) + 'x', 'Password { get;' + '\n '.repeat(100000)]) {
    const t0 = Date.now(); try { t(x); } catch {} assert.ok(Date.now() - t0 < 1500, `${Date.now() - t0} ms`);
  }
});

test('r57: camel-case type positions stay unheld; prose after a passphrase still counts', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['private AbstractQueuedSynchronizer synchronizer;', 'List<AbstractQueuedSynchronizer> values;', 'Map<String, AbstractQueuedSynchronizer> m;',
    'public AbstractQueuedSynchronizer getSync() {', 'AbstractQueuedSynchronizer[] all;', 'void run(AbstractQueuedSynchronizer sync, int n) {']) {
    assert.equal(t(x).held, false, x);
  }
  for (const x of ['PurpleMonkeyDishwasherSatellite is my password', 'use PurpleMonkeyDishwasherSatellite tonight', 'PurpleMonkeyDishwasherSatellite',
    'my password PurpleMonkeyDishwasherSatellite thanks,', 'PurpleMonkeyDishwasherSatellite works, right?', 'it is PurpleMonkeyDishwasherSatellite (new)']) {
    const r = t(x); assert.ok(r.held || !r.text.includes('PurpleMonkey'), x);
  }
});

test('r58: comments between C# accessors, escaped quotes in credential-first CSV headers', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['public string Password { get; /* note */ set; } = "hunter2";', 'public string Password {\n  get; // read\n  set;\n} = "hunter2";',
    'public string Password\n{\n  /* a */ get;\n  // b\n  private set;\n}\n= "hunter2";']) {
    assert.ok(!t(x).text.includes('hunter2'), x);
  }
  const csv = t('password,"last,""name"""\nhunter2,"smith"\nhunter3,doe');
  assert.ok(!csv.text.includes('hunter2') && !csv.text.includes('hunter3'), csv.text);
});

test('r58: long comment and whitespace runs inside a C# accessor block stay fast', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['Password {' + ' /**/'.repeat(60000) + 'get;', 'Password { get;' + ' // x\n'.repeat(60000), 'Password {' + '/*'.repeat(100000)]) {
    const t0 = Date.now(); try { t(x); } catch {} assert.ok(Date.now() - t0 < 1500, `${Date.now() - t0} ms`);
  }
});

test('r59: CSV rows wider or narrower than a credential header fail closed', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['password,"last,name"\nhuntertwo,Doe,Jane', '"last,name",password\nDoe,Jane,huntertwo', 'user,password,role\nalice,huntertwo']) {
    const r = t(x); assert.ok(r.held || !r.text.includes('huntertwo'), `${x} -> ${r.text}`);
  }
  const ok = t('password,user\nhuntertwo,alice\n\nhope that helps');
  assert.ok(ok.text.includes('hope that helps') && !ok.text.includes('huntertwo'), ok.text);
});

test('r60: camel-case exemption needs a code line with no credential word; prose passphrase shapes still count', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  const W = 'PurpleMonkeyDishwasherSatellite';
  for (const x of [`ok so ${W}#2024 is it`, `with ${W}#`, `ok ${W}(2024) works`, `${W}<3`, `${W}::1`, `ok ${W}.Xx`, `x.${W}`,
    `bob, ${W}, admin`, `(${W} admin)`, `pw catch ${W}`, `password import ${W}`, `password = new ${W}();`, `token: x.${W};`, `use ${W}#1;`]) {
    const r = t(x); assert.ok(r.held || !r.text.includes(W), x);
  }
  for (const x of ['at java.util.concurrent.locks.AbstractQueuedSynchronizer.acquire(AbstractQueuedSynchronizer.java:1)', 'List<AbstractQueuedSynchronizer> values;',
    'class Foo extends AbstractQueuedSynchronizer {', 'private AbstractQueuedSynchronizer synchronizer;']) {
    assert.equal(t(x).held, false, x);
  }
});

test('r60: CSV trailing commas from spreadsheet exports and stray quotes inside values', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['password,username,\nHunter2xyz!,bob,\n', 'user,password\nbob,Hun"ter2xyz!\nalice,Second1pass\n', 'password,username\nHunt"er2xyz!,bob\nOther1pass,amy\n']) {
    const r = t(x); assert.ok(r.held || !/Hunter2xyz|Hun"ter2xyz|Hunt"er2xyz|Second1pass|Other1pass/.test(r.text), `${x} -> ${r.text}`);
  }
  const keep = t('password,username,\nHunter2xyz!,bob,\n');
  assert.ok(keep.text.includes('bob'), keep.text);
  const q = t('password,note\nhunter2,"a, b"\nhunter3,"say ""hi"""\n');
  assert.ok(!/hunter2|hunter3/.test(q.text) && q.text.includes('"a, b"'), q.text);
});

test('r61: prose with a trailing semicolon, long accessor comments, one-cell rows, quoted credential headers, Allman methods', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  const W = 'PurpleMonkeyDishwasherSatellite';
  for (const x of [`use ${W} tonight;`, `bob ${W} admin;`, `user=bob ${W} ok;`]) { const r = t(x); assert.ok(r.held || !r.text.includes(W), x); }
  for (const x of ['public string Password { get; /*' + 'x'.repeat(2000) + '*/ set; } = "huntertwo";', 'public string Password {\n get; //' + 'y'.repeat(500) + '\n set;\n} = "huntertwo";',
    'password,user\nhuntertwo', 'user,"access,token"\nbob,huntertwo']) {
    const r = t(x); assert.ok(r.held || !r.text.includes('huntertwo'), x.slice(0, 60));
  }
  for (const x of ['public AbstractQueuedSynchronizer getSync()\n{', 'private AbstractQueuedSynchronizer synchronizer;', 'public AbstractQueuedSynchronizer getSync() {']) assert.equal(t(x).held, false, x);
});

test('r61: repeated unclosed comment starts in accessor blocks stay fast', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['pw\n{/* '.repeat(50000), 'key{/*'.repeat(55000), 'Password\n{ /* '.repeat(25000)]) {   // ~350 KB: quadratic would be minutes
    const t0 = Date.now(); try { t(x); } catch {} assert.ok(Date.now() - t0 < 1500, `${Date.now() - t0} ms`);
  }
});

test('r61: let/var/val before a word are not type positions', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['let PurpleMonkeyDishwasherSatellite go;', 'I will let PurpleMonkeyDishwasherSatellite stay; thanks', 'var PurpleMonkeyDishwasherSatellite x;']) {
    const r = t(x); assert.ok(r.held || !r.text.includes('PurpleMonkey'), x);
  }
});

test('r62: module-qualified Java stack frames and nullable type positions stay unheld', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['at java.base/java.util.concurrent.locks.AbstractQueuedSynchronizer.acquire(AbstractQueuedSynchronizer.java:1)',
    'private AbstractQueuedSynchronizer? synchronizer;', 'void Run(AbstractQueuedSynchronizer? sync) {']) assert.equal(t(x).held, false, x);
  const r = t('use PurpleMonkeyDishwasherSatellite? tonight;'); assert.ok(r.held || !r.text.includes('PurpleMonkey'));
});

test('r62: bare PascalCase calls are not a code context; many quotes in one CSV cell stay fast', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['PurpleMonkeyDishwasherSatellite();', 'x = PurpleMonkeyDishwasherSatellite#;']) { const r = t(x); assert.ok(r.held || !r.text.includes('PurpleMonkey'), x); }
  const big = 'password,user\nab' + 'c"'.repeat(150000) + ',bob\n';
  const t0 = Date.now(); try { t(big); } catch {} assert.ok(Date.now() - t0 < 1500, `${Date.now() - t0} ms`);
});

test('r63: IDs in links to known sharing sites are not secrets; query strings, other hosts and key formats still are', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['see https://claude.ai/artifact/6sAkHYbhygfFtdDg7z4Yy8 please', 'https://claude.ai/code/artifact/2f7ee35f-0e3b-4c1c-a8fc-4feb0f36789b',
    'doc: https://docs.google.com/document/d/1aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdEf/edit', 'https://drive.google.com/file/d/1QwErTyUiOpAsDfGhJkLzXcVbNm123456/view',
    'https://www.notion.so/Launch-Plan-8f2a9c4b7e1d4a6b9c3e5f7a1b2c4d6e', 'https://www.figma.com/design/Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op/Home', 'https://chatgpt.com/share/68e0f1a2-9b3c-8000-a1b2-c3d4e5f60718']) {
    assert.equal(t(x).held, false, x);
  }
  for (const x of ['https://docs.google.com/document/d/abc/edit?resourcekey=0-Xk9QpL2mZr7TvB4nWc8YsJ1d', 'https://example.com/share/kQzPbXwRtYmNvLsDfGhJkLzXcVbNm',
    'https://claude.ai.evil.example/artifact/kQzPbXwRtYmNvLsDfGhJkLzXcVbNm', 'token kQzPbXwRtYmNvLsDfGhJkLzXcVbNm']) {
    const r = t(x); assert.ok(r.held || !r.text.includes('kQzPbXwR') && !r.text.includes('Xk9QpL2m'), x);
  }
  const key = t('https://claude.ai/artifact/sk-proj-AbCdEf1234567890GhIjKlMnOpQrStUvWx');
  assert.ok(key.held || !key.text.includes('AbCdEf1234567890'), key.text);
});

test('r64: share links with %-escapes, Claude Code sessions, upper-case hosts, Markdown underscores and long slugs', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['https://www.notion.so/Caf%C3%A9-8f2a9c4b7e1d4a6b9c3e5f7a1b2c4d6e', 'https://claude.ai/code/session_01A2mqnwASb4jTHXiQoNPzPE',
    'HTTPS://claude.ai/artifact/6sAkHYbhygfFtdDg7z4Yy8', 'https://CLAUDE.AI/artifact/6sAkHYbhygfFtdDg7z4Yy8', '_https://claude.ai/artifact/6sAkHYbhygfFtdDg7z4Yy8_',
    'https://www.notion.so/' + 'a-'.repeat(160) + '8f2a9c4b7e1d4a6b9c3e5f7a1b2c4d6e']) {
    assert.equal(t(x).held, false, x.slice(0, 80));
  }
  for (const x of ['https://claude.ai/code/settings?token=kQzPbXwRtYmNvLsDfGhJkLzXcVbNm', 'xhttps://claude.ai/artifact/kQzPbXwRtYmNvLsDfGhJkLzXcVbNm']) {
    const r = t(x); assert.ok(r.held || !r.text.includes('kQzPbXwR'), x);
  }
  const t0 = Date.now(); try { t('https://www.notion.so/' + '%41'.repeat(60000) + ' x'); } catch {} assert.ok(Date.now() - t0 < 1500);   // ~180 KB; quadratic would be minutes
});

test('r65: only the ID segment of a share link is exempt; extra segments and Notion workspaces are still scanned', () => {
  const t = (x) => scrubber({ terms: [] }).sanitize(x);
  for (const x of ['https://acme.notion.site/Launch-Plan-8f2a9c4b7e1d4a6b9c3e5f7a1b2c4d6e', 'https://www.notion.so/acme/Launch-Plan-8f2a9c4b7e1d4a6b9c3e5f7a1b2c4d6e',
    'https://docs.google.com/spreadsheets/d/1aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdEf/edit', 'https://www.figma.com/design/Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op/Viaknox-Website-v2',
    'https://chatgpt.com/g/g-Ab1Cd2Ef3-trip-planner/c/68e0f1a2-9b3c-8000-a1b2-c3d4e5f60718', 'https://www.loom.com/share/8f2a9c4b7e1d4a6b9c3e5f7a1b2c4d6e?sid=1', 'https://chatgpt.com/s/t_6aa37d6d2cf08191a58f07a61903307a',
    'https://www.figma.com/deck/abttA1F3GxZdZlkI9t5s99/Example', 'https://www.figma.com/make/abttA1F3GxZdZlkI9t5s99/Example']) {
    assert.equal(t(x).held, false, x);
  }
  for (const x of ['https://claude.ai/artifact/public-id/kQzPbXwRtYmNvLsDfGhJkLzXcVbNm', 'https://www.notion.so/kQzPbXwRtYmNvLsDfGhJkLzXcVbNm/Page-8f2a9c4b7e1d4a6b9c3e5f7a1b2c4d6e',
    'https://www.notion.so/kQzPbXwRtYmNvLsDfGhJkLzXcVbNm', 'https://docs.google.com/document/d/abc/kQzPbXwRtYmNvLsDfGhJkLzXcVbNm',
    'https://claude.ai/ARTIFACT/kQzPbXwRtYmNvLsDfGhJkLzXcVbNm', 'https://docs.google.com/DOCUMENT/d/kQzPbXwRtYmNvLsDfGhJkLzXcVbNm',
    'https://kQzPbXwRtYmNvLsDfGhJkLzXcVbNm.notion.site/page-8f2a9c4b7e1d4a6b9c3e5f7a1b2c4d6e', 'éhttps://claude.ai/artifact/kQzPbXwRtYmNvLsDfGhJkLzXcVbNm',
    '٣https://claude.ai/artifact/kQzPbXwRtYmNvLsDfGhJkLzXcVbNm']) {
    const r = t(x); assert.ok(r.held || !r.text.includes('kQzPbXwR'), x);
  }
});

test('r66: share links are replaced whole by [LINK_n], so the ID never reaches the checker (viaknox PR #31 security review)', () => {
  const s = scrubber({ terms: [] });
  for (const [x, id] of [['open https://docs.google.com/document/d/1aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdEf/edit now', '1aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdEf'],
    ['https://docs.google.com/videos/d/1Y9zTG21uMxHmqs7EG0nQubcJKpkhwXax3WcIZkv9Cvw/edit', '1Y9zTG21uMxHmqs7EG0nQubcJKpkhwXax3WcIZkv9Cvw'],
    ['https://drive.google.com/file/u/0/d/1tQe2R9a3ERgXUWuyYiJbjKGA4uT16tmV/view', '1tQe2R9a3ERgXUWuyYiJbjKGA4uT16tmV'],
    ['https://app.notion.com/p/Scratchpad-91e1838c7bae82319d990137ca5ef7b6', '91e1838c7bae82319d990137ca5ef7b6'],
    ['https://www.notion.so/Plan-8F2A9C4B7E1D4A6B9C3E5F7A1B2C4D6E', '8F2A9C4B7E1D4A6B9C3E5F7A1B2C4D6E'],
    ['https://acme.notion.site/k9f3m7q2x8c4v6b1n5z7p2r8t4w6y9', 'k9f3m7q2x8c4v6b1n5z7p2r8t4w6y9'],
    ['see https://claude.ai/artifact/6sAkHYbhygfFtdDg7z4Yy8.', '6sAkHYbhygfFtdDg7z4Yy8']]) {
    const r = s.sanitize(x);
    assert.equal(r.held, false, x); assert.ok(!r.text.includes(id), r.text); assert.match(r.text, /\[LINK_\d+\]/);
  }
  assert.ok(s.counts().LINK >= 7);
  const r = s.sanitize('éhttps://claude.ai/artifact/kQzPbXwRtYmNvLsDfGhJkLzXcVbNm');
  assert.ok(r.held || !r.text.includes('kQzPbXwR'), r.text);
});

test('r67: [LINK_n] is a reserved placeholder: a literal one is never restored to the real link (tune-up PR #21 review, P1)', () => {
  const s = scrubber(); const url = 'https://docs.google.com/document/d/1aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdEf/edit';
  assert.equal(s.unscrub(s.scrub('see ' + url)), 'see ' + url);
  s.scrub('the user typed [LINK_1] literally');
  assert.ok(!s.unscrub('echo [LINK_1]').includes('1aBcDeFg'));
  assert.ok(!scrubber().scrub('[LINK_1] then ' + url).includes('[LINK_1] then [LINK_1]'));   // our own numbering skips a literal one
});

test('r68: whole links even with a never-send term inside; ChatGPT workspace shares; trailing punctuation stays out; cap vs failure (tune-up PR #21 review)', () => {
  const s = scrubber({ terms: ['Acme'] });
  const a = s.sanitize('https://www.notion.so/Acme-8f2a9c4b7e1d4a6b9c3e5f7a1b2c4d6e');
  assert.ok(a.held || !a.text.includes('8f2a9c4b'), a.text);
  const b = scrubber().sanitize('see https://chatgpt.com/share/e/6741e46b-82d0-8005-90a2-27780552fe70 ok');
  assert.ok(!b.text.includes('6741e46b'), b.text);
  const c = scrubber(); const out = c.scrub('Open https://claude.ai/artifact/6sAkHYbhygfFtdDg7z4Yy8. Then https://docs.google.com/document/d/1aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcd_');
  assert.match(out, /^Open \[LINK_1\]\. Then \[LINK_2\]$/);
  assert.equal(c.unscrub('[LINK_1]'), 'https://claude.ai/artifact/6sAkHYbhygfFtdDg7z4Yy8');
  assert.equal(c.unscrub('[LINK_2]'), 'https://docs.google.com/document/d/1aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcd_');   // a trailing "_" is part of an opaque ID
  let capErr; try { scrubber().sanitize('a'.repeat(10), { maxChars: 5 }); } catch (e) { capErr = e; }
  assert.equal(capErr.cap, true);
  assert.equal(new ScrubError('scrubber failed (TypeError); holding back').cap, false);
  for (const u of ['https://www.notion.so/Café-8f2a9c4b7e1d4a6b9c3e5f7a1b2c4d6e', 'https://www.notion.so/Cafe\u0301-8f2a9c4b7e1d4a6b9c3e5f7a1b2c4d6e', 'https://www.notion.so/計画-8f2a9c4b7e1d4a6b9c3e5f7a1b2c4d6e']) {
    const r = scrubber().sanitize(u); assert.ok(!r.text.includes('8f2a9c4b'), r.text);
  }
  let tagErr; try { scrubber().sanitize('<input type="password" value="hunter2'); } catch (e) { tagErr = e; }
  assert.equal(tagErr.cap, false);   // an unclosed tag is not a size cap
  const d = scrubber().sanitize('old link https://chat.openai.com/share/68e0f1a2-9b3c-8000-a1b2-c3d4e5f60718x9Q ok');
  assert.ok(!d.text.includes('68e0f1a2'), d.text); assert.match(d.text, /\[LINK_1\]/);
});
