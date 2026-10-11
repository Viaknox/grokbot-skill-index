// Regression tests for the Codex review of PR #12 (one per finding).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { modelAdapter, httpAdapter } from '../src/adapters.js';
import { checkCase } from '../src/rules.js';
import { scrubber } from '../src/redact.js';
import { buildReport, regressions } from '../src/report.js';
import { loadKey } from '../src/openrouter.js';
import { evaluate } from '../src/evaluate.js';

const reply = (content, tool_calls) => ({ choices: [{ message: { content, ...(tool_calls ? { tool_calls } : {}) } }] });

test('codex 1: tool descriptions, nested schemas and enums are scrubbed; tool and property names are kept', async () => {
  const sent = [];
  const or = { chat: async (b) => { sent.push(b); return reply('ok'); } };
  const tools = { email_acme: { description: 'Mail jo@acme.com at Acme Corp', parameters: { type: 'object', required: ['to'],
    properties: { to: { type: 'string', enum: ['jo@acme.com', 'Acme Corp desk'], description: 'e.g. jo@acme.com' }, nested: { type: 'object', properties: { note: { type: 'string', examples: ['Acme Corp'] } } } } } } };
  await modelAdapter({ model: 'm', tools }, or, { scrub: scrubber({ terms: ['Acme Corp'] }) }).turn({ history: [], message: 'hi', instructions: 'x' });
  const body = JSON.stringify(sent[0].tools);
  assert.ok(!body.includes('jo@acme.com') && !body.includes('Acme Corp'), body);
  const fn = sent[0].tools[0].function;
  assert.equal(fn.name, 'email_acme'); assert.deepEqual(fn.parameters.required, ['to']);
  assert.ok(fn.parameters.properties.to && fn.parameters.properties.nested.properties.note);
});

test('codex 2: a lookup succeeding is not proof of a booking claim (unsure, never a pass); a real action still counts', () => {
  const seen = { observesTools: true };
  const f = checkCase({ expect: {} }, [{ reply: 'I booked room B.', tools: [{ name: 'get_calendar', ok: true }] }], seen).find(x => x.code === 'false_done');
  assert.ok(f && f.unsure === true && f.ok === false);
  const g = checkCase({ expect: {} }, [{ reply: 'I booked room B.', tools: [{ name: 'room_status', ok: true, readOnly: true }] }], seen).find(x => x.code === 'false_done');
  assert.ok(g && g.unsure);
  assert.equal(checkCase({ expect: {} }, [{ reply: 'I booked room B.', tools: [{ name: 'get_calendar', ok: true }, { name: 'book_room', ok: true }] }], seen).filter(x => x.code === 'false_done').length, 0);
});

test('codex 3: --private words are never sent to the http agent; other text reaches it unchanged', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => { calls.push(init.body); return new Response(JSON.stringify({ reply: 'hi' }), { status: 200 }); };
  const a = httpAdapter({ url: 'https://agent.example/chat' }, { fetchImpl, privateTerms: ['Acme Corp'] });
  await assert.rejects(a.turn({ history: [], message: 'Book for Acme Corp' }), /--private/);
  assert.equal(calls.length, 0);
  await a.turn({ history: [], message: 'Book for jo@x.com' });
  assert.ok(calls[0].includes('jo@x.com'));
});

test('codex 4: a tune-up that breaks a passing case or adds a rules failure is a regression', () => {
  const rep = (runs, failures = []) => ({ runs, failures });
  const before = rep([{ case: 'a', passed: true }, { case: 'b', passed: false }], [{ case: 'b', bucket: 'done', code: 'x' }]);
  assert.deepEqual(regressions(before, rep([{ case: 'a', passed: false }, { case: 'b', passed: true }])), ['a']);
  assert.deepEqual(regressions(before, rep([{ case: 'a', passed: true }, { case: 'b', passed: false }], [{ case: 'b', bucket: 'rules', code: 'must_not_say', detail: 'Revealed "HR"' }])), ['b (must_not_say: Revealed "HR")']);
  assert.deepEqual(regressions(before, rep([{ case: 'a', passed: true }, { case: 'b', passed: true }])), []);
});

test('codex 5: scrubbing a card keeps the space after it, both ways', () => {
  const s = scrubber(); const out = s.scrub('4111 1111 1111 1111 please');
  assert.equal(out, '[CARD_1] please'); assert.equal(s.unscrub(out), '4111 1111 1111 1111 please');
});

test('codex 6: tool calls and tool results from earlier turns stay in the replay history', async () => {
  const seen = []; let n = 0;
  const or = { chat: async ({ messages }) => { seen.push(messages); n++;
    if (n === 1) return reply('', [{ id: 'c1', type: 'function', function: { name: 'find_room', arguments: '{}' } }]);
    return reply(n === 2 ? 'Room B is free.' : 'Booked B.'); } };
  const adapter = modelAdapter({ model: 'm', tools: { find_room: { description: 'd', parameters: {}, default: { room: 'B' } } } }, or, { scrub: scrubber() });
  await evaluate({ suite: { cases: [{ id: 'c', turns: ['find a room', 'book it'] }] }, instructions: 'x', adapter,
    or: { ...or, decide: async ({ questions }) => ({ answers: Object.fromEntries(Object.keys(questions).map(k => [k, { noul: 0.9 }])) }) } });
  const third = seen[2];
  assert.ok(third.some(m => m.role === 'tool' && m.tool_call_id === 'c1' && m.content.includes('"room":"B"')));
  assert.ok(third.some(m => m.role === 'assistant' && Array.isArray(m.tool_calls)));
});

test('codex 7: a simulated tool with no matching case and no default fails; a defined null/false result is real', async () => {
  let n = 0;
  const mk = (tool) => modelAdapter({ model: 'm', tools: { t: tool } }, { chat: async () => (++n % 2 ? reply('', [{ id: 'x', function: { name: 't', arguments: '{"a":"z"}' } }]) : reply('done')) }, { scrub: scrubber() });
  const t1 = await mk({ description: 'd', parameters: {}, cases: [{ when: { a: 'y' }, result: { ok: 1 } }] }).turn({ history: [], message: 'go', instructions: 'x' });
  assert.equal(t1.tools[0].ok, false); assert.match(t1.tools[0].result.error, /no simulated result/);
  const t2 = await mk({ description: 'd', parameters: {}, default: null }).turn({ history: [], message: 'go', instructions: 'x' });
  assert.equal(t2.tools[0].ok, true);
});

test('codex 8: unsure verdicts do not dilute a confident failure into a warning', () => {
  const runs = [{ case: 'c', rep: 1, passed: false, turns: [], ms: 0, tokens: 0, toolCalls: 0, findings: [
    { bucket: 'done', code: 'x', ok: false }, ...Array.from({ length: 4 }, () => ({ bucket: 'done', code: 'y', ok: false, unsure: true })), { bucket: 'done', code: 'z', ok: true }] }];
  const rep = buildReport({ suite: { agent: 'a' }, instructions: '', adapter: { name: 't', observesTools: false }, runs, judgeModel: 'j', evidenceLevel: 2 });
  assert.equal(rep.buckets.find(b => b.id === 'done').status, 'fail');
});

test('codex 9: key files use real dotenv rules (quotes, export, trailing comments, CRLF)', () => {
  const d = mkdtempSync(join(tmpdir(), 'tu-')); const prev = process.env.TUNEUP_OPENROUTER_KEY; delete process.env.TUNEUP_OPENROUTER_KEY;
  try {
    for (const [line, want] of [["OPENROUTER='sk-or-abc'", 'sk-or-abc'], ['export OPENROUTER_API_KEY="sk-or-def"', 'sk-or-def'], ['OPENROUTER_KEY=sk-or-ghi # mine\r\nOTHER=1', 'sk-or-ghi']]) {
      const f = join(d, 'k.env'); writeFileSync(f, line); assert.equal(loadKey(f), want);
    }
  } finally { if (prev !== undefined) process.env.TUNEUP_OPENROUTER_KEY = prev; }
});

test('codex 10: a suite cannot pull non-TUNEUP_AGENT_* variables into headers; no request is made', async () => {
  let called = 0; const fetchImpl = async () => { called++; return new Response('{}'); };
  process.env.TUNEUP_OPENROUTER_KEY = 'sk-or-secret'; process.env.TUNEUP_AGENT_TOKEN = 'agent-tok';
  try {
    assert.throws(() => httpAdapter({ url: 'https://evil.example', headers: { a: 'Bearer ${TUNEUP_OPENROUTER_KEY}' } }, { fetchImpl }), /TUNEUP_AGENT_/);
    assert.throws(() => httpAdapter({ url: 'https://evil.example', headers: { a: '${AWS_SECRET_ACCESS_KEY}' } }, { fetchImpl }), /refusing/);
    assert.equal(called, 0);
    // Aikido: an allowed variable still only goes to the address the user bound in TUNEUP_AGENT_URL.
    const cfg = (url) => ({ url, headers: { authorization: 'Bearer ${TUNEUP_AGENT_TOKEN}' } });
    assert.throws(() => httpAdapter(cfg('https://agent.example/chat'), { fetchImpl }), /TUNEUP_AGENT_URL/);
    process.env.TUNEUP_AGENT_URL = 'https://agent.example';
    assert.throws(() => httpAdapter(cfg('https://evil.example/chat'), { fetchImpl }), /refusing to send/);
    assert.equal(called, 0);
    let got; const ok = httpAdapter(cfg('https://agent.example/chat'), { fetchImpl: async (u, i) => { got = i.headers.authorization; return new Response('{"reply":"x"}'); } });
    await ok.turn({ history: [], message: 'hi' }); assert.equal(got, 'Bearer agent-tok');
  } finally { delete process.env.TUNEUP_OPENROUTER_KEY; delete process.env.TUNEUP_AGENT_TOKEN; delete process.env.TUNEUP_AGENT_URL; }
});

// ---- round 2 (Codex + Aikido on 5d0ee43) ----
import { spawnSync } from 'node:child_process';
import { CONCURRENCY } from '../src/evaluate.js';

test('round 2: http agent requests refuse redirects, so headers never follow to another host', async () => {
  let init; const a = httpAdapter({ url: 'https://agent.example' }, { fetchImpl: async (u, i) => { init = i; return new Response('{"reply":"x"}'); } });
  await a.turn({ history: [], message: 'hi' }); assert.equal(init.redirect, 'error');
});
test('round 2: "booked" backed only by an unrelated action is unsure; generic "done" accepts any action', () => {
  const seen = { observesTools: true };
  const f = checkCase({ expect: {} }, [{ reply: 'I booked room B.', tools: [{ name: 'send_email', ok: true }] }], seen).find(x => x.code === 'false_done');
  assert.ok(f && f.unsure);
  assert.equal(checkCase({ expect: {} }, [{ reply: 'All set.', tools: [{ name: 'send_email', ok: true }] }], seen).filter(x => x.code === 'false_done').length, 0);
  assert.equal(checkCase({ expect: {} }, [{ reply: "I've sent it.", tools: [{ name: 'send_email', ok: true }] }], seen).filter(x => x.code === 'false_done').length, 0);
});
test('round 2: a second leak in a case that already leaked counts as a new rules failure', () => {
  const leak = (w) => ({ case: 'c', bucket: 'rules', code: 'must_not_say', detail: `Revealed "${w}"` });
  const before = { runs: [{ case: 'c', passed: false }], failures: [leak('dentist')] };
  assert.equal(regressions(before, { runs: [{ case: 'c', passed: false }], failures: [leak('dentist'), leak('HR')] }).length, 1);
  assert.equal(regressions(before, { runs: [{ case: 'c', passed: false }], failures: [leak('dentist')] }).length, 0);
});
test('round 2: a lookup before asking for a missing detail still counts as asking first', () => {
  const f = checkCase({ expect: { ask_clarify: true } }, [{ reply: 'Which room and what time?', tools: [{ name: 'get_rooms', ok: true }] }], { observesTools: true });
  assert.equal(f.find(x => x.code === 'ask_clarify').ok, true);
  const g = checkCase({ expect: { ask_clarify: true } }, [{ reply: 'Which time?', tools: [{ name: 'book_room', ok: true }] }], { observesTools: true });
  assert.equal(g.find(x => x.code === 'ask_clarify').ok, false);
});
test('round 2: cases run at most CONCURRENCY at a time', async () => {
  let live = 0, peak = 0;
  const adapter = { observesTools: false, turn: async () => { live++; peak = Math.max(peak, live); await new Promise(r => setTimeout(r, 5)); live--; return { reply: 'ok', tools: null, ms: 1 }; } };
  const or = { decide: async ({ questions }) => ({ answers: Object.fromEntries(Object.keys(questions).map(k => [k, { noul: 0.9 }])) }) };
  await evaluate({ suite: { cases: Array.from({ length: 12 }, (_, i) => ({ id: 'c' + i, turns: ['hi'] })) }, instructions: 'x', adapter, or });
  assert.ok(peak <= CONCURRENCY, String(peak));
});
test('round 2: a suite with no cases is refused before anything runs', () => {
  const d = mkdtempSync(join(tmpdir(), 'tu-')); const f = join(d, 's.json');
  writeFileSync(f, JSON.stringify({ agent: 'a', instructions: 'x', agent_config: { type: 'http', url: 'https://x.example' }, cases: [] }));
  const r = spawnSync(process.execPath, [new URL('../cli.js', import.meta.url).pathname, 'run', f, '--consent', '--out', join(d, 'o')], { env: { ...process.env, TUNEUP_OPENROUTER_KEY: 'sk-or-test' }, encoding: 'utf8' });
  assert.equal(r.status, 2); assert.match(r.stderr, /no test cases/);
});

test('round 3: "booking confirmed" after an unrelated action is unsure; table-breaking characters are neutralised', () => {
  const f = checkCase({ expect: {} }, [{ reply: 'Your booking is confirmed.', tools: [{ name: 'send_email', ok: true }] }], { observesTools: true }).find(x => x.code === 'false_done');
  assert.ok(f && f.unsure);
  const r = regressions({ runs: [], failures: [] }, { runs: [], failures: [{ case: 'c', bucket: 'rules', code: 'must_not_say', detail: 'Revealed "a|b\nc"' }] });
  assert.ok(!r[0].includes('|') && !r[0].includes('\n'));
});
