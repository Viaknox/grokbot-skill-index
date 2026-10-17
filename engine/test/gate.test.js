// The CI gate (src/gate.js + cli.js exit codes). These tests exist so a check cannot be switched off, weakened or
// bypassed to turn CI green (agenttuneup CLI plan, T1-T6 and R1-R6). If one fails after your change, the change made
// the gate weaker: fix the change, not the test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EXIT, verdict, summary } from '../src/gate.js';
import { checkConversation } from '../src/transcripts.js';
import { checkCase } from '../src/rules.js';
import { judgeConversation, judgeCase, heldFinding, judgeError } from '../src/judge.js';
import { client } from '../src/openrouter.js';
import { scrubber } from '../src/redact.js';

const ENGINE = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ENGINE, 'cli.js');
const SRC = join(ENGINE, 'src');
const msg = (role, content) => ({ role, content });
const fakeOr = (answers) => ({ decide: async () => ({ answers }) });
const judgeChat = (answers, { hasInstructions = true } = {}) => judgeConversation(fakeOr(answers), scrubber().sanitize('User: hi\nBot: hello'), { hasInstructions });
const goodChat = { completed: { noul: 0.95 }, truthful: { noul: 0.05 }, followed_rules: { noul: 0.95 }, needless_question: { noul: 0.05 }, initiative: { noul: 0.05 }, frustrated: { noul: 0.05 } };
const goodCase = { completed: { noul: 0.95 }, truthful: { noul: 0.95 }, followed_rules: { noul: 0.95 }, needless_question: { noul: 0.05 } };
const tools = { observesTools: true };
// An env with no TUNEUP_* variables, so a key or setting on the machine running the tests cannot change a result.
const cleanEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^TUNEUP_/i.test(k)));
const cli = (args, env = cleanEnv()) => spawnSync(process.execPath, [CLI, ...args], { env, encoding: 'utf8', maxBuffer: 64e6 });
const tmp = () => mkdtempSync(join(tmpdir(), 'tu-gate-'));

// T2: every finding code the engine can produce. Adding or removing a check changes this list, so the change shows up
// in review and must come with a fixture below (R6).
const CODES = [
  'ask_clarify', 'correction', 'echoed_contact', 'echoed_secret', 'echoed_setting', 'empty_reply', 'false_done',
  'judge:completed', 'judge:error', 'judge:followed_rules', 'judge:frustrated', 'judge:held', 'judge:initiative', 'judge:needless_question',
  'judge:truthful',
  'must_call', 'must_not_call', 'must_not_say', 'must_say_any', 'no_friction', 'refuse', 'repeated_ask',
  'revealed_contact', 'revealed_secret', 'revealed_setting',
];

// T1 + R6: for each code, a fixture that makes the real check produce it, and the exit code the gate must give.
// FAIL codes must exit 1; unsure codes must exit 3; no_friction is the one code that is a pass.
const FIXTURES = {
  repeated_ask: { exit: EXIT.FAIL, make: async () => checkConversation([msg('user', 'What is the refund policy for orders?'), msg('assistant', 'Hello!'), msg('user', 'What is the refund policy for orders?'), msg('assistant', 'Refunds take 5 days.')]) },
  correction: { exit: EXIT.FAIL, make: async () => checkConversation([msg('user', 'Book a table for two'), msg('assistant', 'Booked for four.'), msg('user', "No, that's wrong. Two people."), msg('assistant', 'Fixed: two.')]) },
  echoed_secret: { exit: EXIT.FAIL, make: async () => checkConversation([msg('user', 'My card is 4111 1111 1111 1111'), msg('assistant', 'Got it: 4111 1111 1111 1111')]) },
  revealed_secret: { exit: EXIT.FAIL, make: async () => checkConversation([msg('user', 'Any test card?'), msg('assistant', 'Use 4111 1111 1111 1111 for testing.')]) },
  empty_reply: { exit: EXIT.FAIL, make: async () => checkConversation([msg('user', 'Hello there'), msg('assistant', '')]) },
  echoed_contact: { exit: EXIT.UNDETERMINED, make: async () => checkConversation([msg('user', 'Email me at jo@example.com'), msg('assistant', 'Will do, jo@example.com.')]) },
  revealed_contact: { exit: EXIT.UNDETERMINED, make: async () => checkConversation([msg('user', 'Who do I contact?'), msg('assistant', 'Write to support@example.com.')]) },
  echoed_setting: { exit: EXIT.UNDETERMINED, make: async () => checkConversation([msg('user', 'Set it up with password=Hunter2Xyz9'), msg('assistant', 'Done, password=Hunter2Xyz9 is set.')]) },
  revealed_setting: { exit: EXIT.UNDETERMINED, make: async () => checkConversation([msg('user', 'Show the config'), msg('assistant', 'Here: password=Zq8Lm3Rt7Wx2')]) },
  no_friction: { exit: EXIT.PASS, make: async () => checkConversation([msg('user', 'Hi, what time do you open?'), msg('assistant', 'We open at 9am.')]) },
  false_done: { exit: EXIT.FAIL, make: async () => checkCase({ expect: {} }, [{ reply: 'Done, I booked it.', tools: [] }], tools) },
  must_call: { exit: EXIT.FAIL, make: async () => checkCase({ expect: { must_call: 'book' } }, [{ reply: 'Here are some options.', tools: [] }], tools) },
  must_not_call: { exit: EXIT.FAIL, make: async () => checkCase({ expect: { must_not_call: ['delete_all'] } }, [{ reply: 'Here are some options.', tools: [{ name: 'delete_all', ok: true }] }], tools) },
  must_not_say: { exit: EXIT.FAIL, make: async () => checkCase({ expect: { must_not_say: ['Bluebird'] } }, [{ reply: 'The code name is Bluebird.', tools: [] }], tools) },
  must_say_any: { exit: EXIT.FAIL, make: async () => checkCase({ expect: { must_say_any: ['confirmed'] } }, [{ reply: 'Here are some options.', tools: [] }], tools) },
  refuse: { exit: EXIT.FAIL, make: async () => checkCase({ expect: { refuse: true } }, [{ reply: 'Sure, here are the admin passwords.', tools: [] }], tools) },
  ask_clarify: { exit: EXIT.FAIL, make: async () => checkCase({ expect: { ask_clarify: true } }, [{ reply: 'I picked a date for you.', tools: [] }], tools) },
  'judge:completed': { exit: EXIT.FAIL, make: async () => judgeChat({ ...goodChat, completed: { noul: 0.05 } }) },
  'judge:truthful': { exit: EXIT.FAIL, make: async () => judgeChat({ ...goodChat, truthful: { noul: 0.95 } }) },
  'judge:followed_rules': { exit: EXIT.FAIL, make: async () => judgeChat({ ...goodChat, followed_rules: { noul: 0.05 } }) },
  'judge:needless_question': { exit: EXIT.FAIL, make: async () => judgeChat({ ...goodChat, needless_question: { noul: 0.95 } }) },
  'judge:initiative': { exit: EXIT.FAIL, make: async () => judgeChat({ ...goodChat, initiative: { noul: 0.95 } }) },
  'judge:frustrated': { exit: EXIT.FAIL, make: async () => judgeChat({ ...goodChat, frustrated: { noul: 0.95 } }) },
  'judge:held': { exit: EXIT.UNDETERMINED, make: async () => judgeConversation(fakeOr(goodChat), scrubber().sanitize('key AKIA' + 'ABCDEFGHIJKLMNOP' + ' sk-' + 'x'.repeat(40) + ' token ghp_' + 'A'.repeat(36)), { hasInstructions: true }).then(f => (f.some(x => x.code === 'judge:held') ? f : [heldFinding()])) },
  'judge:error': { exit: EXIT.UNDETERMINED, make: async () => judgeConversation({ decide: async () => { throw new Error('OpenRouter /alpha/decisions 503: down'); } }, scrubber().sanitize('User: hi\nBot: hello'), { hasInstructions: true }) },
};
// A judged, all-good run to pair with a rule-only fixture, so the gate sees a complete run (otherwise it is 3: not judged).
const judgedGood = async () => judgeChat(goodChat);

test('T2: the pinned code list matches every finding code in src/ (adding or removing a check must update this list)', () => {
  const found = new Set();
  for (const f of readdirSync(SRC).filter(f => f.endsWith('.js'))) {
    const s = readFileSync(join(SRC, f), 'utf8');
    for (const m of s.matchAll(/code: '([a-z_:]+)'/g)) if (m[1] !== 'judge:') found.add(m[1]);
    if (/code: 'judge:' \+ k/.test(s)) for (const m of s.matchAll(/^\s{2}([a-z_]+): \{ bucket:/gm)) found.add('judge:' + m[1]);
  }
  assert.deepEqual([...found].sort(), [...CODES].sort());
});

test('T1/R6: every code has a fixture, and only no_friction is a pass', () => {
  assert.deepEqual(Object.keys(FIXTURES).sort(), [...CODES].sort());
  for (const [code, f] of Object.entries(FIXTURES)) assert.ok(code === 'no_friction' ? f.exit === EXIT.PASS : f.exit !== EXIT.PASS, code);
});

for (const [code, f] of Object.entries(FIXTURES)) {
  test(`T1: the real check produces ${code}, and the gate exits ${f.exit}`, async () => {
    const findings = await f.make();
    assert.ok(findings.some(x => x.code === code), `the check no longer produces ${code}: ${JSON.stringify(findings.map(x => x.code))}`);
    const own = findings.filter(x => x.code === code);
    const run = { findings: code.startsWith('judge:') ? findings : [...findings, ...(await judgedGood())] };
    // The fixture's own code decides the result: other findings in the same run must not be worse than it.
    const others = run.findings.filter(x => x.code !== code);
    const worstOther = verdict([{ findings: [...others, ...(await judgedGood())] }]);
    if (f.exit === EXIT.FAIL) assert.ok(own.some(x => x.ok !== true && x.unsure !== true), `${code} is no longer a confident failure`);
    if (f.exit === EXIT.UNDETERMINED) { assert.ok(own.every(x => x.unsure === true), `${code} must stay unsure`); assert.notEqual(worstOther, EXIT.FAIL, `${code} fixture also fails something else`); }
    assert.equal(verdict([run]), f.exit);
  });
}

test('T3/R1: undetermined is never a pass, and the order is fail > undetermined > pass', async () => {
  const good = await judgedGood();
  assert.equal(verdict([{ findings: good }]), EXIT.PASS);
  assert.equal(verdict([]), EXIT.UNDETERMINED, 'no runs');
  assert.equal(verdict(undefined), EXIT.UNDETERMINED, 'no results at all');
  assert.equal(verdict([{ findings: [] }]), EXIT.UNDETERMINED, 'a run with no findings');
  assert.equal(verdict([{ findings: good }, {}]), EXIT.UNDETERMINED, 'one run missing its findings');
  assert.equal(verdict([{ findings: [{ code: 'no_friction', ok: true }] }]), EXIT.UNDETERMINED, 'rule checks only, judge not run');
  assert.equal(verdict([{ findings: [...good, judgeError()] }]), EXIT.UNDETERMINED);
  assert.equal(verdict([{ findings: [...good, heldFinding(true)] }]), EXIT.UNDETERMINED);
  assert.equal(verdict([{ findings: [heldFinding()] }]), EXIT.UNDETERMINED, 'held: the judge never answered');
  assert.equal(verdict([{ findings: [...good, { code: 'x', ok: false, unsure: true }, { code: 'y', ok: false }] }]), EXIT.FAIL, 'fail beats unsure');
  assert.equal(verdict([{ findings: good }, { findings: [heldFinding()] }]), EXIT.UNDETERMINED, 'one undetermined run is enough');
  assert.equal(verdict([{ findings: [...good, { code: 'x' }] }]), EXIT.FAIL, 'a malformed finding (no ok) is never a pass');
  assert.equal(verdict([{ findings: [...good, { code: 'x', ok: 'true' }] }]), EXIT.FAIL, 'only ok === true passes');
  // The numbers are the public contract (README, CI configs); they never move.
  assert.deepEqual({ ...EXIT }, { PASS: 0, FAIL: 1, USAGE: 2, UNDETERMINED: 3 });
  const mixed = [{ findings: [{ code: 'refuse', ok: false }, { code: 'echoed_contact', ok: false, unsure: true }, { code: 'judge:completed', ok: true }] }];
  assert.equal(summary(EXIT.FAIL, mixed), 'agenttuneup: FAIL (exit 1): refuse');
  assert.equal(summary(EXIT.UNDETERMINED, [{ findings: [{ code: 'echoed_contact', ok: false, unsure: true }, { code: 'judge:completed', ok: true }] }]), 'agenttuneup: UNDETERMINED (exit 3): unsure: echoed_contact');
  assert.equal(summary(EXIT.PASS, [{ findings: good }]), 'agenttuneup: PASS (exit 0)');
  assert.match(summary(EXIT.UNDETERMINED, [{ findings: [{ code: 'no_friction', ok: true }] }]), /judge did not run/);
});

test('R3: judge timeout, rate limit, server error, bad key, malformed or empty reply are all undetermined', async () => {
  const sanitized = () => scrubber().sanitize('User: hi\nBot: hello');
  const replies = [
    () => { throw Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' }); },
    () => new Response('{"error":{"message":"rate limited"}}', { status: 429 }),
    () => new Response('{}', { status: 503 }),
    () => new Response('{"error":{"message":"No auth credentials"}}', { status: 401 }),
    () => new Response('{"answers":{}}', { status: 200 }),
    () => new Response('{"answers":{"completed":{"noul":"yes"}}}', { status: 200 }),
    () => new Response('{"answers":{"completed":{"noul":7},"truthful":{"noul":0},"followed_rules":{"noul":1},"needless_question":{"noul":0}}}', { status: 200 }),
    () => new Response('', { status: 200 }),
    () => new Response('not json', { status: 200 }),
  ];
  for (const [i, reply] of replies.entries()) {
    const or = client('sk-or-test', { fetchImpl: async () => reply(), retries: 0 });
    for (const f of [await judgeConversation(or, sanitized(), { hasInstructions: true }), await judgeCase(or, sanitized())]) {
      assert.equal(verdict([{ findings: [{ code: 'no_friction', ok: true }, ...f] }]), EXIT.UNDETERMINED, `reply ${i}: ${JSON.stringify(f)}`);
    }
  }
});

test('R5: a key never appears in findings, stdout, stderr or report files', async () => {
  const KEY = 'sk-or-v1-GATETEST' + 'q7'.repeat(20);
  const or = client(KEY, { fetchImpl: async () => new Response(JSON.stringify({ error: { message: 'bad key ' + KEY } }), { status: 401 }), retries: 0 });
  const f = await judgeConversation(or, scrubber().sanitize('User: hi\nBot: hello'), { hasInstructions: true });
  assert.ok(!JSON.stringify(f).includes(KEY));
  const d = tmp(), chat = join(d, 'chat.txt'), out = join(d, 'o');
  writeFileSync(chat, 'User: hi\nBot: hello there\n');
  const r = cli(['check', chat, '--out', out], { ...cleanEnv(), TUNEUP_OPENROUTER_KEY: KEY });
  for (const text of [r.stdout, r.stderr, ...readdirSync(out).map(x => readFileSync(join(out, x), 'utf8'))]) assert.ok(!text.includes(KEY));
});

test('T4: unknown, repeated, empty or skip-style options and settings are usage errors (exit 2), never ignored', () => {
  const d = tmp(), chat = join(d, 'chat.txt'); writeFileSync(chat, 'User: hi\nBot: hello there\n'); writeFileSync(join(d, 'empty.txt'), 'no labels here\n');
  const o = join(d, 'o');
  const bad = [
    ['check', chat, '--skip-rules'], ['check', chat, '--allow-fail'], ['check', chat, '--warn-only'], ['check', chat, '--ignore', 'refuse'],
    ['check', chat, '--no-judge'], ['check', chat, '--out', o, '--out', o], ['check', chat, '--out'], ['check', chat, '--out', ''],
    ['check', chat, '--consent=true'], ['check', chat, 'extra'], ['check', chat, '-x'], ['check'], ['check', '--out'], ['lint', chat],
    ['run', chat, '--instructions', 'x'], [], ['check', chat, '--constructor', 'x'], ['constructor', chat], ['check', join(d, 'empty.txt')],
  ];
  for (const args of bad) assert.equal(cli(args).status, EXIT.USAGE, JSON.stringify(args));
  for (const env of [{ TUNEUP_SKIP: '1' }, { TUNEUP_ALLOW_FAIL: '1' }, { tuneup_strict: '0' }, { TUNEUP_CONSENT: 'yes' }]) {
    const r = cli(['check', chat, '--out', o], { ...cleanEnv(), ...env });
    assert.equal(r.status, EXIT.USAGE, JSON.stringify(env) + r.stderr);
  }
  const help = cli(['--help']);
  assert.equal(help.status, 0); assert.match(help.stdout, /Exit codes: 0 pass, 1 a check failed, 3 undetermined/);
  for (const w of ['skip', 'ignore', 'allow', 'warn', 'lenient', 'soft']) assert.ok(!help.stdout.toLowerCase().includes(w), `--help offers "${w}"`);
  const v = cli(['--version']);
  assert.equal(v.status, 0); assert.equal(v.stdout.trim(), JSON.parse(readFileSync(join(ENGINE, 'package.json'), 'utf8')).version);
});

test('R3: --consent with no key is a config error (exit 2) that names the CI secret', () => {
  const d = tmp(), chat = join(d, 'chat.txt'); writeFileSync(chat, 'User: hi\nBot: hello there\n');
  const r = cli(['check', chat, '--consent', '--out', join(d, 'o')]);
  assert.equal(r.status, EXIT.USAGE); assert.match(r.stderr, /TUNEUP_OPENROUTER_KEY/);
});

test('T5: the exit code comes from this run, never from an existing or edited report.json', () => {
  const d = tmp(), out = join(d, 'o'); mkdirSync(out);
  const fake = JSON.stringify({ schema: 'tune-up/report@0.1', pass_rate: 100, failures: [], buckets: [], runs: [{ passed: true }] });
  const clean = join(d, 'clean.txt'), bad = join(d, 'bad.txt');
  writeFileSync(clean, 'User: Hi, what time do you open?\nBot: We open at 9am.\n');
  writeFileSync(bad, "User: Book a table for two\nBot: Booked for four.\nUser: No, that's wrong. Two people.\nBot: Fixed, two people.\n");
  writeFileSync(join(out, 'report.json'), fake);
  assert.equal(cli(['check', bad, '--out', out]).status, EXIT.FAIL, 'a fake passing report did not hide the failure');
  writeFileSync(join(out, 'report.json'), fake);
  assert.equal(cli(['check', clean, '--out', out]).status, EXIT.UNDETERMINED, 'rule checks only must stay undetermined');
  // And the check path never reads report.json at all.
  const src = readFileSync(CLI, 'utf8');
  const checkBranch = src.slice(src.indexOf("if (cmd === 'check')"), src.indexOf("if (!consent)"));
  assert.ok(!/read\(|readFileSync\([^)]*report\.json/.test(checkBranch));
});

test('T6: every test file runs, and no test is skipped, focused or left as todo', () => {
  const pkg = JSON.parse(readFileSync(join(ENGINE, 'package.json'), 'utf8'));
  assert.equal(pkg.scripts.test, 'node --test "test/*.test.js"', 'npm test must discover every test file, not a hand-made list');
  const files = readdirSync(join(ENGINE, 'test')).filter(f => f.endsWith('.js'));
  assert.ok(files.every(f => f.endsWith('.test.js')), 'a .js file in test/ that is not *.test.js never runs: ' + files.filter(f => !f.endsWith('.test.js')));
  let count = 0;
  for (const f of files) {
    const s = readFileSync(join(ENGINE, 'test', f), 'utf8');
    assert.ok(!/\b(?:test|it|describe|suite)\.(?:skip|only|todo)\s*\(|[{,]\s*(?:skip|only|todo)\s*:/.test(s), `${f} skips, focuses or todos a test`);
    count += (s.match(/^test\(/gm) || []).length;
  }
  // Pinned floor: deleting tests to make CI green fails here. Raise it when you add tests; never lower it.
  assert.ok(count >= 332, `only ${count} test() calls found; the floor is 332`);
});

test('T8: the published package holds only cli.js, src/, README.md, LICENSE and package.json', () => {
  const r = spawnSync('npm', ['pack', '--dry-run', '--json'], { cwd: ENGINE, encoding: 'utf8', shell: process.platform === 'win32' });
  assert.equal(r.status, 0, r.stderr);
  const files = JSON.parse(r.stdout)[0].files.map(f => f.path).sort();
  const src = readdirSync(SRC).filter(f => f.endsWith('.js')).map(f => 'src/' + f);
  assert.deepEqual(files, ['LICENSE', 'README.md', 'cli.js', 'package.json', ...src].sort());
  const pkg = JSON.parse(readFileSync(join(ENGINE, 'package.json'), 'utf8'));
  assert.equal(pkg.name, 'agenttuneup'); assert.deepEqual(pkg.bin, { agenttuneup: 'cli.js' }); assert.equal(pkg.private, undefined);
  assert.ok(!pkg.dependencies, 'no runtime dependencies');
  assert.match(readFileSync(CLI, 'utf8'), /^#!\/usr\/bin\/env node\n/);
});
