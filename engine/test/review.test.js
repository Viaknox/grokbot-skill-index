import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildReport, toMarkdown } from '../src/report.js';
import { parseTranscripts } from '../src/transcripts.js';
import { proposeFix } from '../src/writer.js';

test('review: a | in a reason does not split the report table row', () => {
  const findings = [{ bucket: 'done', code: 'must_say_any', ok: false, detail: 'Final reply is missing any of: RB-1 | booked' }];
  const r = buildReport({ suite: { agent: 'x' }, instructions: '', adapter: { name: 'm', observesTools: true },
    runs: [{ case: 'c1', rep: 1, passed: false, findings, turns: [], ms: 0, tokens: 0, toolCalls: 0 }], judgeModel: 'j', evidenceLevel: 2 });
  assert.equal(r.repeats, 1);
  const row = toMarkdown(r).split('\n').find(l => l.startsWith('| Gets it done'));
  assert.equal(row.split('|').length, 5);
  assert.match(toMarkdown(r), /× 1 runs/);
});

test('review: JSON with no two-sided conversation yields nothing', () => {
  assert.equal(parseTranscripts('[]').length, 0);
  assert.equal(parseTranscripts(JSON.stringify([{ role: 'user', content: 'hi' }])).length, 0);
});

test('review: case ids are scrubbed before they reach the fix writer', async () => {
  let sent = '';
  const or = { chat: async ({ messages }) => { sent = messages[0].content; return { choices: [{ message: { content: JSON.stringify({ revised_instructions: 'You are a helpful booking agent. Always confirm.', changes: ['x'] }) } }] }; } };
  await proposeFix(or, { instructions: 'Book rooms.', failures: [{ case: 'leak-jo@acme.com', code: 'false_done', detail: 'd' }], cases: [{ id: 'leak-jo@acme.com', intent: 'i' }] });
  assert.ok(!sent.includes('jo@acme.com'));
});

import { scrubber } from '../src/redact.js';
test('never-send list: whole words, any case, restored locally; not inside other words', () => {
  const s = scrubber({ terms: ['Acme Corp', 'Ivo'] });
  const out = s.scrub('Acme corp terms apply. Ivo said yes. Ivory and ACMEcorp stay.');
  assert.equal(out, '[PRIVATE_1] terms apply. [PRIVATE_2] said yes. Ivory and ACMEcorp stay.');
  assert.equal(s.unscrub(out), 'Acme corp terms apply. Ivo said yes. Ivory and ACMEcorp stay.');
});
