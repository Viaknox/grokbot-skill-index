// Scrubber v2 contract tests, written before the v2 redact.js (docs/SCRUBBER-V2-BRIEF.md, docs/SCRUBBER-V2-PLAN.md).
// Every test asserts that the secret's own characters are gone (no 8-character window survives), not merely that a
// placeholder appeared. Fixtures are templates expanded at run time, so no secret shape sits in the repo.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scrubber } from '../src/redact.js';
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

test('corpus dotenv: every credential value is gone, usage settings stay', () => {
  const { text, secrets } = fixture('dotenv.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'dotenv'); assert.ok(!out.includes('LEAKED_SUFFIX'), 'suffix after 200 characters survived');
  assert.ok(!out.includes('abcde'), 'text before an escaped quote survived');
  assertKept(out, ['APP_NAME=tuneup', 'PORT=3000', 'tokenLimit=100000', 'max_tokens=128000', 'tokenizer=enabled'], 'dotenv');
});

test('corpus json-compact: secret fields are gone, neighbouring fields on the same line stay', () => {
  const { text, secrets } = fixture('json-compact.json'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'json-compact'); assert.ok(!out.includes('PRIVATE' + ' KEY'), 'PEM header survived inside a JSON string');
  assertKept(out, ['"user":"jo"', '"tokenLimit":100000', '"after":"still here"'], 'json-compact');
});

test('corpus json-pretty: nested credential fields, headers and escaped quotes are gone', () => {
  const { text, secrets } = fixture('json-pretty.json'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'json-pretty'); assert.ok(!out.includes('LEAKED_SUFFIX'));
  assertKept(out, ['"service": "api"', '"tokenLimit": 100000', '"max_tokens": 128000', 'the secretary will call about the session'], 'json-pretty');
});

test('corpus yaml: block scalars and deeper-indented continuation lines go with their key', () => {
  const { text, secrets } = fixture('yaml.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'yaml'); assert.ok(!out.includes('LEAKED_SUFFIX'));
  assertKept(out, ['name: api', 'max_tokens: 128000', 'region: eu-west-1', 'secretary: Jonathan Smith', 'note: the session timed out'], 'yaml');
});

test('corpus npmrc: _authToken, _password and _auth values are gone', () => {
  const { text, secrets } = fixture('npmrc.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'npmrc'); assertKept(out, ['registry=https://registry.npmjs.org/', 'username=jo', 'save-exact=true'], 'npmrc');
});

test('corpus pypirc: "password = value" lines are gone, repositories stay', () => {
  const { text, secrets } = fixture('pypirc.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'pypirc'); assertKept(out, ['repository = https://upload.pypi.org/legacy/', '[testpypi]'], 'pypirc');
});

test('corpus netrc: "password value" with no separator is gone in netrc shape, machine names stay', () => {
  const { text, secrets } = fixture('netrc.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'netrc'); assertKept(out, ['machine api.example.com', 'machine github.com'], 'netrc');
});

test('corpus headers: Basic, Bearer, Digest, Proxy-Authorization, Cookie, Set-Cookie and X-Api-Key values are gone', () => {
  const { text, secrets } = fixture('headers.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'headers'); assertKept(out, ['GET /api/v1/rooms HTTP/1.1', 'Host: api.example.com', 'Content-Type: application/json'], 'headers');
});

test('corpus urls: userinfo is gone, hosts and ordinary long URLs stay', () => {
  const { text, secrets } = fixture('urls.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'urls');
  assertKept(out, ['db.example.com:5432/app', 'cache.example.com:6379', 'https://docs.example.com/guide/getting-started/installation-and-configuration'], 'urls');
});

test('corpus pem: plain, RSA, EC, DSA, OPENSSH and ENCRYPTED keys go header to footer, text after stays', () => {
  const { text, secrets } = fixture('pem.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'pem');
  for (const leak of ['BEGIN', 'Proc-Type', 'DEK-Info', 'PRIVATE' + ' KEY']) assert.ok(!out.includes(leak), `pem: "${leak}" survived`);
  assertKept(out, ['after the keys, this text stays'], 'pem');
});

test('corpus pem-truncated: a key with Proc-Type, DEK-Info, a blank line and no footer is removed to the end of input', () => {
  const { text, secrets } = fixture('pem-truncated.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'pem-truncated');
  for (const leak of ['Proc-Type', 'DEK-Info', 'BEGIN']) assert.ok(!out.includes(leak), `pem-truncated: "${leak}" survived`);
  assertKept(out, ['some notes before the key'], 'pem-truncated');
});

test('corpus pem-big: a block over 16 KB is removed whole, the line after it stays, and a 70 KB block with no footer goes to the end', () => {
  const { text, secrets } = fixture('pem-big.txt'); assert.ok(text.length > 64 * 1024);
  const out = scrubber().scrub(text); assertGone(out, secrets, 'pem-big');
  assert.ok(out.length < 200, 'a key body survived'); assertKept(out, ['this line follows a key of more than 16 KB'], 'pem-big');
});

test('corpus prose: ordinary chat about passwords, sessions, cookies and tokens is left exactly as written', () => {
  const { text } = fixture('prose.txt'); assert.equal(scrubber().scrub(text), text);
});

test('corpus never-send: terms inside brackets, as name prefixes, in any case and inside values are all gone', () => {
  const { text, secrets } = fixture('never-send.txt'); const s = scrubber({ terms: ['Acme', 'Acme Corp', 'OpenAI'] }); const out = s.scrub(text);
  assertGone(out, secrets, 'never-send');
  assert.ok(!/acme|openai/i.test(out), 'a never_send term survived: ' + out.match(/.{0,10}(acme|openai).{0,10}/i));
  assertKept(out, ['welcome message', 'signed by', 'again, in lower case'], 'never-send');
  assert.equal(s.unscrub(out), text, 'round trip');
});

test('corpus chat: a .env pasted mid-conversation is scrubbed, the rest of the chat is untouched', () => {
  const { text, secrets } = fixture('chat.txt'); const out = scrubber().scrub(text);
  assertGone(out, secrets, 'chat');
  assertKept(out, ['User: hi, the connector fails', 'DB_HOST=db.example.com', 'Bot: Thanks, the session is working now. Your password was fine.', 'see [EMAIL_1] above'], 'chat');
});

// ---- 1. line-level redaction ----

test('known bypass: PASSWORD= plus 200 characters plus LEAKED_SUFFIX, quoted and unquoted', () => {
  for (const q of ['', '"', "'"]) {
    const v = sec(200) + 'LEAKED_SUFFIX'; const out = scrubber().scrub(`PASSWORD=${q}${v}${q}\nNEXT=1`);
    assertGone(out, [v], q || 'bare'); assert.ok(!out.includes('LEAKED_SUFFIX'), `${q || 'bare'}: suffix survived`); assertKept(out, ['NEXT=1']);
  }
});

test('line level: a trailing backslash carries the value onto the next line', () => {
  const a = sec(20), b = sec(20); const out = scrubber().scrub(`PASSWORD=${a}\\\n${b}\nNEXT=1`);
  assertGone(out, [a, b]); assertKept(out, ['NEXT=1']);
});

test('line level: an unterminated quote carries the value onto the following lines until it closes', () => {
  const a = sec(20), b = sec(20), c = sec(20); const out = scrubber().scrub(`API_KEY="${a}\n${b}\n${c}"\nNEXT=1`);
  assertGone(out, [a, b, c]); assertKept(out, ['NEXT=1']);
});

test('line level: a YAML block scalar and an indented block under an empty key go with the key', () => {
  const a = sec(40), b = sec(40), c = sec(40); const out = scrubber().scrub(`creds:\n  token: |\n    ${a}\n    ${b}\n  private_key:\n    ${c}\n  region: eu\nname: x`);
  assertGone(out, [a, b, c]); assertKept(out, ['region: eu', 'name: x']);
});

test('line level: a comment after a long value goes with the value', () => {
  const v = sec(220); const out = scrubber().scrub(`PASSWORD=${v} # rotate monthly\nNEXT=1`);
  assertGone(out, [v]); assert.ok(!out.includes('rotate monthly')); assertKept(out, ['NEXT=1']);
});

test('line level: CRLF input is scrubbed the same as LF and the other lines survive', () => {
  const a = sec(220), b = sec(30); const out = scrubber().scrub(`PASSWORD=${a}\r\nPORT=3000\r\nAPI_KEY="${b}"\r\n`);
  assertGone(out, [a, b]); assertKept(out, ['PORT=3000']);
});

test('line level: command-line flags --password, --token= and -p carry a credential', () => {
  const a = sec(16), b = sec(16), c = sec(16); const out = scrubber().scrub(`deploy --password ${a} --retries 3\nlogin --token=${b}\nmysql -u root -p${c} app`);
  assertGone(out, [a, b, c]);
});

test('line level: a value longer than 200 characters inside pretty JSON goes to the end of the field only', () => {
  const v = sec(260); const out = scrubber().scrub(`{\n  "password": "${v}",\n  "tokenLimit": 5\n}`);
  assertGone(out, [v]); assertKept(out, ['"tokenLimit": 5']);
});

// ---- 2. signals with word boundaries and context ----

test('signals: secretary, tokenizer, tokenLimit, max_tokens and "Password requirements:" are not credentials', () => {
  const lines = ['secretary: Jonathan Smith', 'tokenizer=enabled', 'tokenLimit=100000', 'max_tokens: 128000', 'Password requirements: 12 characters minimum', 'token_count: 42'];
  for (const l of lines) assert.equal(scrubber().scrub(l), l, l);
});

test('signals: password, secret, api_key and token as whole name parts are credentials in every spelling', () => {
  for (const name of ['password', 'PASSWD', 'Secret', 'api-key', 'apiKey', 'API_KEY', 'token', 'AUTH_TOKEN', 'accessToken', 'credential', 'x-api-key', 'db.password', 'secretSanta']) {
    const v = sec(210); const out = scrubber().scrub(`${name}: ${v}`); assertGone(out, [v], name);
  }
});

test('signals: Authorization Digest and Proxy-Authorization values are gone, even mid-line inside quotes', () => {
  const n = gen.hex(rng, 32), r = gen.hex(rng, 32), b = gen.b64(rng, 40), c = gen.b64(rng, 40);
  const out = scrubber().scrub(`Authorization: Digest username="jo", realm="api", nonce="${n}", response="${r}"\nProxy-Authorization: Basic ${b}\ncurl -H "Authorization: Bearer ${c}" https://x.example`);
  assertGone(out, [n, r, b, c]);
});

test('signals: Cookie and Set-Cookie values are gone, but "cookie" and "session" in prose stay', () => {
  const a = gen.hex(rng, 32), b = gen.b64(rng, 40);
  const out = scrubber().scrub(`Cookie: session=${a}; theme=dark\nSet-Cookie: sid=${b}; Path=/; HttpOnly\nCan you clear the cookie so the session restarts?`);
  assertGone(out, [a, b]); assertKept(out, ['Can you clear the cookie so the session restarts?']);
});

test('signals: "password value" with no separator counts only in netrc shape, not in chat', () => {
  const v = sec(20); const out = scrubber().scrub(`machine api.example.com login jo password ${v}`); assertGone(out, [v]);
  const chat = 'I forgot my password yesterday and the reset mail never came'; assert.equal(scrubber().scrub(chat), chat);
});

test('signals: URL userinfo with an empty user, a long password or a token as the user is gone', () => {
  const a = sec(18), b = sec(210), c = gen.prefix(rng, 'ghp');
  const out = scrubber().scrub(`redis://:${a}@cache.example.com:6379\namqp://guest:${b}@mq.example.com/v\nhttps://${c}@github.com/org/repo.git`);
  assertGone(out, [a, b, c]); assertKept(out, ['cache.example.com:6379', 'mq.example.com/v', 'github.com/org/repo.git']);
});

test('signals: a credential name written with zero-width or look-alike characters is still a signal', () => {
  const cases = [['pass​word=', 'zero-width space'], ['pass‍word: ', 'zero-width joiner'], ['pаssword=', 'Cyrillic a'], ['ＰＡＳＳＷＯＲＤ=', 'fullwidth letters'], ['api⁠_key=', 'word joiner'], ['﻿PASSWORD=', 'byte-order mark']];
  for (const [name, why] of cases) { const v = sec(16); assertGone(scrubber().scrub(name + v), [v], why); }
});

test('signals: zero-width characters inside a value do not let any fragment survive', () => {
  const v = sec(220); const spaced = v.match(/.{1,50}/g).join('​');
  const out = scrubber().scrub(`PASSWORD=${spaced}\nNEXT=1`).replace(/[​-‍⁠﻿]/g, '');
  assertGone(out, [v]); assertKept(out, ['NEXT=1']);
});

// ---- 3. PEM ----

test('known bypass: truncated RSA key with Proc-Type, DEK-Info and a blank line after the header', () => {
  const lines = gen.pemLines(rng, 5), iv = gen.hex(rng, 16);
  const block = `${PEM_HEAD('RSA')}\nProc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC,${iv}\n\n${lines.join('\n')}`;
  for (const [name, text] of [['no footer', 'before\n' + block], ['with footer', 'before\n' + block + '\n' + PEM_FOOT('RSA') + '\nafter']]) {
    const out = scrubber().scrub(text); assertGone(out, [...lines, iv], name);
    for (const leak of ['Proc-Type', 'DEK-Info', 'BEGIN']) assert.ok(!out.includes(leak), `${name}: "${leak}" survived`);
    assertKept(out, ['before'], name); if (name === 'with footer') assertKept(out, ['after'], name);
  }
});

test('pem: a key inside a JSON string with escaped newlines and no footer ends at the closing quote', () => {
  const lines = gen.pemLines(rng, 5);
  const out = scrubber().scrub(`{"private_key":"${PEM_HEAD('')}\\n${lines.join('\\n')}\\n","next":"x"}`);
  assertGone(out, lines); assert.ok(!out.includes('BEGIN')); assertKept(out, ['"next":"x"']);
});

test('pem: a blank line and a Comment header inside an OPENSSH block do not end it early, with or without a footer', () => {
  const lines = gen.pemLines(rng, 4);
  const block = `${PEM_HEAD('OPENSSH')}\n${lines[0]}\n\n${lines[1]}\nComment: work laptop\n${lines[2]}\n${lines[3]}`;
  const out = scrubber().scrub(`${block}\n${PEM_FOOT('OPENSSH')}\ntail`);
  assertGone(out, lines, 'footer'); assert.ok(!out.includes('Comment: work laptop')); assertKept(out, ['tail']);
  const cut = scrubber().scrub(`head\n${block}`); assertGone(cut, lines, 'no footer'); assert.ok(!cut.includes('Comment: work laptop')); assertKept(cut, ['head']);
});

// ---- 4. never_send terms ----

test('known bypass: [Acme] and [Acme Corp] with never_send terms', () => {
  const s = scrubber({ terms: ['Acme', 'Acme Corp'] }); const text = 'Welcome [Acme] and [Acme Corp] and [ACME CORP]!';
  const out = s.scrub(text); assert.ok(!/acme/i.test(out), out); assert.equal(s.unscrub(out), text);
});

test('known bypass: OPENAI-API-KEY=CorrectHorse9! with never_send OpenAI', () => {
  const s = scrubber({ terms: ['OpenAI'] }); const out = s.scrub('OPENAI-API-KEY=CorrectHorse9!\nOPENAI_API_KEY: CorrectHorse8!');
  assert.ok(!/openai/i.test(out), out); assert.ok(!/CorrectHorse/.test(out), out);
});

test('never_send: terms match case-insensitively and inside values, and whole-word guards still hold', () => {
  const s = scrubber({ terms: ['Acme Corp', 'Ivo'] }); const out = s.scrub('Acme corp terms apply. Ivo said yes. Ivory and ACMEcorp stay. note=ACME CORP rules');
  assert.ok(!/acme corp/i.test(out)); assert.ok(!/\bIvo\b/.test(out)); assertKept(out, ['Ivory', 'ACMEcorp stay']);
  assert.equal(s.unscrub(out), 'Acme corp terms apply. Ivo said yes. Ivory and ACMEcorp stay. note=ACME CORP rules');
});

test('never_send: a term that is also a credential word (KEY, PRIVATE, SECRET) cannot break key or setting scrubbing', () => {
  const lines = gen.pemLines(rng, 2), v = sec(16);
  const s = scrubber({ terms: ['KEY', 'PRIVATE', 'SECRET'] });
  const out = s.scrub(`${PEM_HEAD('')}\n${lines.join('\n')}\n${PEM_FOOT('')}\nSECRET_KEY=${v}`);
  assertGone(out, [...lines, v]); assert.ok(!/\bkey\b|\bprivate\b|\bsecret\b/i.test(out.replace(/\[[A-Z]+_\d+\]/g, '')), out);
});

// ---- 5. placeholders are reserved tokens ----

test('known bypass: a credential value containing a never_send term restores ([SECRET_1] wrapping [PRIVATE_1])', () => {
  const v = sec(10); const text = `PASSWORD=Acme-${v}\nclient_secret: my Acme pass\nhello Acme`;
  const s = scrubber({ terms: ['Acme'] }); const out = s.scrub(text);
  assert.ok(!out.includes('Acme') && !out.includes(v), out);
  assert.equal(s.unscrub(out), text, 'dependency-ordered restore');
  assert.deepEqual(s.counts(), { PRIVATE: 1, SECRET: 2 });
});

test('placeholders: scrubbing is idempotent on every fixture and never nests a placeholder in another', () => {
  for (const f of ['dotenv.txt', 'headers.txt', 'never-send.txt', 'urls.txt', 'pem.txt', 'chat.txt']) {
    const s = scrubber({ terms: ['Acme', 'Acme Corp', 'OpenAI'] }); const once = s.scrub(fixture(f).text), twice = s.scrub(once);
    assert.equal(twice, once, f); assert.ok(!/\[[A-Z]+_\d*\[/.test(once), f + ': nested placeholder');
  }
});

test('placeholders: text that already looks like [KIND_n] is left alone and not counted', () => {
  const s = scrubber(); const text = 'see [EMAIL_1] and [SECRET_2] and [KEY_3] above';
  assert.equal(s.scrub(text), text); assert.deepEqual(s.counts(), {});
});

test('placeholders: counts stay accurate with repeats and nesting, and numbering is stable across texts', () => {
  const s = scrubber({ terms: ['Acme'] }); const v = sec(12);
  s.scrub(`PASSWORD=Acme${v}\nPASSWORD=Acme${v}\nmail jo@x.example`); s.scrub('again jo@x.example and Acme');
  assert.deepEqual(s.counts(), { PRIVATE: 1, SECRET: 1, EMAIL: 1 });
  assert.equal(s.scrub('jo@x.example'), '[EMAIL_1]');
});

// ---- 6. residual scan, sanitize ----

test('v2 api: SCRUBBER_VERSION is 2.0.0 and the public shape is unchanged', async () => {
  const mod = await V2(); assert.equal(mod.SCRUBBER_VERSION, '2.0.0');
  const s = scrubber({ terms: ['x'] }); for (const k of ['scrub', 'unscrub', 'counts', 'sanitize', 'echoes']) assert.equal(typeof s[k], 'function', k);
  assert.match(s.scrub('mail jo@x.example'), /^mail \[EMAIL_1\]$/);
});

test('residual: a high-entropy run, a known prefix shape and a leftover never_send term each hold the text back', async () => {
  const { residual } = await V2();
  const cases = [['bare base64', 'deploy key ' + gen.b64(rng, 40)], ['bare hex', 'sha ' + gen.hex(rng, 40)], ['prefix shape', 'id ' + 'AKIA' + 'Q'.repeat(16)],
    ['prefix shape sk', 'try ' + 'sk-' + 'a1'.repeat(12)], ['pem header', 'x ' + PEM_HEAD('EC') + ' y'], ['jwt', gen.prefix(rng, 'jwt')]];
  for (const [why, text] of cases) { const r = residual(text); assert.equal(r.held, true, why); assert.ok(r.reasons.length, why); }
  const t = residual('hello [Acme] and [acme corp]', { terms: ['Acme Corp'] }); assert.equal(t.held, true, 'leftover term inside brackets');
});

test('residual: ordinary prose, long URLs, identifiers, UUIDs and placeholders are not held', async () => {
  const { residual } = await V2();
  for (const text of [fixture('prose.txt').text, '[SECRET_1] and [KEY_2] remain, id 123e4567-e89b-12d3-a456-426614174000', 'https://docs.example.com/guide/getting-started/installation-and-configuration',
    'The quick brown fox jumps over the lazy dog, again and again and again.']) {
    const r = residual(text, { terms: ['Acme'] }); assert.equal(r.held, false, text.slice(0, 40) + ' ' + r.reasons.join(','));
  }
});

test('sanitize: returns a frozen Sanitized whose text equals scrub(text), carries the version, and is idempotent', async () => {
  const { Sanitized, SCRUBBER_VERSION } = await V2(); const s = scrubber({ terms: ['Acme'] }); const text = 'Acme mail jo@x.example PASSWORD=' + sec(12);
  const san = s.sanitize(text);
  assert.ok(san instanceof Sanitized); assert.ok(Object.isFrozen(san)); assert.equal(san.text, s.scrub(text)); assert.equal(san.held, false); assert.deepEqual(san.reasons, []);
  assert.equal(san.version, SCRUBBER_VERSION); assert.equal(s.sanitize(san.text).text, san.text);
  assert.ok(!JSON.stringify(san).includes('jo@x.example'), 'a Sanitized never carries the real values');
});

test('sanitize: held is true and nothing secret is in the text when only the residual scan catches it', async () => {
  const s = scrubber({ terms: ['Acme'] }); const b = gen.b64(rng, 48); const san = s.sanitize('deploy key ' + b + ' for [Acme]');
  assert.ok(san.held || !san.text.includes(b), 'bare entropy neither scrubbed nor held');
  assert.ok(!/acme/i.test(san.text) || san.held, 'leftover term neither scrubbed nor held');
});

test('sanitize: throws ScrubError over the size cap and makes no Sanitized', async () => {
  const { ScrubError } = await V2(); const s = scrubber(); assert.equal(typeof ScrubError, 'function');
  assert.throws(() => s.sanitize('a'.repeat(10), { maxChars: 5 }), (e) => e instanceof ScrubError);
});

test('echoes: reports the kinds of user-side values found verbatim in following text, never the values', () => {
  const s = scrubber({ terms: ['Acme'] }); const k = gen.prefix(rng, 'sk'), v = sec(14);
  s.scrub(`card 4111 1111 1111 1111, key ${k}, PASSWORD=${v}
mail jo@x.example, Acme`);
  assert.deepEqual([...s.echoes(`your card 4111 1111 1111 1111 is updated, ${v} noted`)].sort(), ['CARD', 'SECRET']);
  assert.deepEqual(s.echoes('nothing here'), []);
  assert.deepEqual([...s.echoes(`key ${k} and jo@x.example and acme`)].sort(), ['EMAIL', 'KEY']);
  assert.ok(!JSON.stringify(s.echoes(`${k}`)).includes(k.slice(0, 8)));
});

// ---- remaining known bypasses ----

test('known bypass: Authorization: Basic dXNlcjpwYXNzd29yZA==', () => {
  const out = scrubber().scrub('Authorization: Basic dXNlcjpwYXNzd29yZA==\nnext line');
  assert.ok(!out.includes('dXNlcjpwYXNzd29yZA'), out); assertKept(out, ['next line']);
});

test('known bypass: API_KEY="abcde\\"CorrectHorse9!"', () => {
  const out = scrubber().scrub('API_KEY="abcde\\"CorrectHorse9!"\nNEXT=1');
  assert.ok(!out.includes('CorrectHorse9') && !out.includes('abcde'), out); assertKept(out, ['NEXT=1']);
});

// ---- regression guards: v1 behaviour that must survive ----

test('regression guard: emails, phones, keys, valid cards, SSNs and IPs still become stable placeholders', () => {
  const s = scrubber(); const k = gen.prefix(rng, 'skor');
  const out = s.scrub(`Mail jo@acme.com or jo@acme.com, call +1 336-555-0142, key ${k}, card 4111 1111 1111 1111, ssn 123-45-6789, ip 10.0.0.12`);
  for (const leak of ['jo@acme.com', '555-0142', k, '4111', '123-45-6789', '10.0.0.12']) assert.ok(!out.includes(leak), leak);
  assert.equal(out.match(/\[EMAIL_1\]/g).length, 2);
  assert.deepEqual(Object.keys(s.counts()).sort(), ['CARD', 'EMAIL', 'IP', 'KEY', 'PHONE', 'SSN']);
});

test('regression guard: order numbers, prices, dates, public keys and simple unscrub round trips are unchanged', () => {
  const plain = 'Order 1234567890123 shipped on 2026-10-11 for $49.99, room B at 3pm.'; assert.equal(scrubber().scrub(plain), plain);
  const pub = '-----BEGIN PUBLIC KEY-----\nAAAAB3NzaC1yc2E\n-----END PUBLIC KEY-----'; assert.equal(scrubber().scrub(pub), pub);
  const s = scrubber(); const sent = s.scrub('Escalate to help@viaknox.test.');
  assert.equal(s.unscrub(sent.replace('Escalate', 'Always escalate')), 'Always escalate to help@viaknox.test.');
});

// ---- known bypasses from the second review round on #14, #15 and viaknox #25 ----

test('known bypass (review 2): short credential values go whole, there is no minimum length', () => {
  for (const l of ['PASSWORD=abcde', 'API_KEY=12345', 'token: 7', "secret='x'"]) { const out = scrubber().scrub(l); assert.match(out, /^[A-Za-z_]+[=:] ?\[SECRET_1\]$/, l); }
});

test('known bypass (review 2): a multi-line quoted dotenv value is consumed through the closing quote', () => {
  const out = scrubber().scrub('PASSWORD="alphaX\nbravo\ncharlie"\nNEXT=1');
  assertGone(out, ['alphaX', 'bravo', 'charlie'].map(x => x.padEnd(8, x))); assert.ok(!/alphaX|bravo|charlie/.test(out), out); assertKept(out, ['NEXT=1']);
});

test('known bypass (review 2): a never_send term as a name prefix (ACME-PASSWORD=) still loses its value', () => {
  const s = scrubber({ terms: ['Acme'] }); const out = s.scrub('ACME-PASSWORD=CorrectHorse9!');
  assert.ok(!/acme|CorrectHorse/i.test(out), out); assert.equal(s.unscrub(out), 'ACME-PASSWORD=CorrectHorse9!');
});

test('known bypass (review 2): --password=x, --api-key=x and --token x flags, and the result is not falsely held', () => {
  const a = sec(12), b = sec(12), c = sec(12); const s = scrubber(); const text = `run --password=${a} --api-key=${b} --token ${c} now`;
  const out = s.scrub(text); assertGone(out, [a, b, c]); assertKept(out, ['run ', ' now']);
  assert.equal(s.sanitize(text).held, false, 'a fully scrubbed flag line must not be held by the residual scan');
});

test('known bypass (review 2): bare key= in dotenv form is scrubbed; key: labels in YAML and JSON stay', () => {
  for (const l of ['key=CorrectHorseBatteryStaple', 'export key=CorrectHorseBatteryStaple', 'api key=CorrectHorseBatteryStaple']) assert.ok(!scrubber().scrub(l).includes('CorrectHorse'), l);
  for (const l of ['key: user_id', '{"key": "user_id", "value": 1}', '- key: name']) assert.equal(scrubber().scrub(l), l, l);
});

// ---- mutation survivors (engine/scripts/mutate.mjs): each test kills one mutant that the suite missed ----

test('mutation: names split at letter/digit boundaries, so token2 and v2token are credentials', () => {
  const a = sec(16), b = sec(16); const out = scrubber().scrub(`token2: ${a}\nv2token=${b}`); assertGone(out, [a, b]);
});

test('mutation: a name with no word parts (__=) is not a credential and key after a structural word stays', () => {
  for (const l of ['__=keep this', 'public_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 host', 'foreign_key = user_id', 'sort-key: created_at']) assert.equal(scrubber().scrub(l), l, l);
});

// ---- Phase 3 self-attack fixtures: corpus/attack-round-N.json ----
for (const { file, cases } of attackRounds()) {
  for (const c of cases) {
    test(`${file.replace('.json', '')}: ${c.name}`, () => {
      const { text, secrets } = expand(c.input, seedOf(file + c.name)); const s = scrubber({ terms: c.terms || [] }); const out = s.scrub(text);
      assertGone(out, [...secrets, ...(c.gone || [])], c.name); assertKept(out, c.keep || [], c.name);
      if (c.terms && c.terms.length) assert.ok(!c.terms.some(t => out.toLowerCase().includes(String(t).toLowerCase())), c.name + ': never_send term survived');
    });
  }
}
