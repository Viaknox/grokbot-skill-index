#!/usr/bin/env node
// Agent Tune-Up engine (v0.1).
//   node engine/cli.js run  <suite.json> [--keyfile path] [--out dir] [--repeats N]
//       Evaluate the agent: writes <out>/report.json and report.md.
//   node engine/cli.js check <chats.txt|chats.json> [--instructions file] [--agent name] [--private words.txt] [--consent] [--keyfile path] [--out dir]
//       Report card from real chats you paste or export (Level 1). Personal data is scrubbed locally first.
//       Without --consent only the local rule checks run and nothing leaves this machine.
//   node engine/cli.js tune <suite.json> [--keyfile path] [--out dir] [--repeats N]
//       One verified tune-up attempt: draft the smallest fix for the failures in <out>/report.json,
//       re-run the same tests on it, save <out>/attempt-N.json, and rewrite tune-up.md with the best attempt.
//       Run it again to try once more; earlier attempts that did not help are fed back to the writer.
// A fix is a proposal. This tool never applies it to a real agent.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { loadKey, client } from './src/openrouter.js';
import { httpAdapter, modelAdapter } from './src/adapters.js';
import { evaluate } from './src/evaluate.js';
import { proposeFix, WRITER_MODEL } from './src/writer.js';
import { toMarkdown, buildReport, runPassed } from './src/report.js';
import { scrubber } from './src/redact.js';
import { parseTranscripts, checkConversation } from './src/transcripts.js';
import { judgeConversation, chatState, JUDGE_MODEL } from './src/judge.js';

const [cmd, file, ...rest] = process.argv.slice(2);
const opt = (name, dflt) => { const i = rest.indexOf('--' + name); return i < 0 ? dflt : (rest[i + 1] && !rest[i + 1].startsWith('--') ? rest[i + 1] : true); };
if (!['run', 'tune', 'check'].includes(cmd) || !file) { console.error('usage: node engine/cli.js run|tune <suite.json> | check <chats> [--consent] [--keyfile path] [--out dir]'); process.exit(2); }
const consent = opt('consent', false) === true || process.env.TUNEUP_CONSENT === '1';
const NOTICE = 'Remote models: the judge (Jev, via OpenRouter) and, for tune-ups, the fix writer (Nemotron on a no-training endpoint). Text is scrubbed on this machine first of emails, phone numbers, API keys and tokens, card numbers, US Social Security numbers and IPv4 addresses (other IDs, such as passport numbers, are not detected). Turn on "no training" in your OpenRouter privacy settings.';
const out = opt('out', 'tune-up-report'); mkdirSync(out, { recursive: true });
// --private <file>: one never-send word or name per line (# starts a comment). Scrubbed before anything leaves.
const terms = opt('private') ? readFileSync(opt('private'), 'utf8').split(/\r?\n/).map(l => l.replace(/#.*/, '').trim()).filter(Boolean) : [];

if (cmd === 'check') {
  const scrub = scrubber({ terms });
  const instructions = opt('instructions') ? readFileSync(opt('instructions'), 'utf8').trim() : '';
  const convos = parseTranscripts(readFileSync(file, 'utf8'), { agentName: opt('agent') });
  if (!convos.length) { console.error('No conversations found. Label lines "User:" and "Bot:" (or your bot\'s name with --agent), and separate chats with a line of ---.'); process.exit(1); }
  const or = consent ? client(loadKey(opt('keyfile'))) : null;
  console.error(`Checking ${convos.length} conversation(s)` + (consent ? ' with the remote judge. ' + NOTICE : '. Rule checks only, nothing leaves this machine (add --consent to use the judge).'));
  const runs = await Promise.all(convos.map(async (msgs, i) => {
    const findings = [...checkConversation(msgs), ...(or ? await judgeConversation(or, scrub.scrub(chatState(instructions, msgs)), { hasInstructions: !!instructions }) : [])];
    return { case: `chat-${i + 1}`, rep: 1, passed: runPassed(findings), findings: findings.map(f => ({ ...f, quote: f.quote && scrub.scrub(f.quote) })),
      turns: msgs.map(m => ({ role: m.role, reply: scrub.scrub(m.content) })), ms: 0, tokens: 0, toolCalls: 0 };
  }));
  const rep = buildReport({ suite: { agent: opt('agent', 'Your agent'), repeats: 1 }, instructions, adapter: { name: 'paste', observesTools: false }, runs, judgeModel: or ? JUDGE_MODEL : 'none (rule checks only)', evidenceLevel: 1 });
  rep.scrubbed = scrub.counts();
  writeFileSync(join(out, 'report.json'), JSON.stringify(rep, null, 2));
  const md = toMarkdown(rep, { title: 'Report card' }) + `\nScrubbed before checking: ${Object.entries(rep.scrubbed).map(([k, v]) => `${v} ${k.toLowerCase()}`).join(', ') || 'nothing found'}.` + (or ? ` Model cost: $${or.spent().toFixed(5)}` : '') + '\n';
  writeFileSync(join(out, 'report.md'), md); console.log(md);
  process.exit(0);
}
if (!consent) { console.error(NOTICE + '\nAdd --consent to run with remote models.'); process.exit(2); }

const suite = JSON.parse(readFileSync(file, 'utf8'));
const repeats = Number(opt('repeats', suite.repeats ?? 1));
if (!Number.isInteger(repeats) || repeats < 1 || repeats > 20) { console.error('--repeats (or the suite\'s "repeats") must be a whole number from 1 to 20.'); process.exit(2); }
suite.repeats = repeats;
// Ties reports and tune-up attempts to the exact suite they came from, so stale files are never mixed in.
const suiteId = createHash('sha256').update(JSON.stringify(suite)).digest('hex').slice(0, 16);
const or = client(loadKey(opt('keyfile')));
const adapter = suite.agent_config.type === 'http' ? httpAdapter(suite.agent_config) : modelAdapter(suite.agent_config, or);
const log = (s) => console.error('  ' + s);
const scrub = scrubber({ terms });
const read = (f) => JSON.parse(readFileSync(join(out, f), 'utf8'));

if (cmd === 'run') {
  console.error(`Evaluating ${suite.agent}: ${suite.cases.length} cases × ${suite.repeats} runs`);
  const rep = await evaluate({ suite, instructions: suite.instructions, adapter, or, log, scrub });
  rep.suite_id = suiteId;
  writeFileSync(join(out, 'report.json'), JSON.stringify(rep, null, 2));
  const md = toMarkdown(rep, { title: 'Report card' }) + `\nModel cost for this run: $${or.spent().toFixed(5)}\n`;
  writeFileSync(join(out, 'report.md'), md); console.log(md);
} else {
  if (!existsSync(join(out, 'report.json'))) { console.error(`No report in ${out}. Run \`run\` with the same suite and --out first.`); process.exit(2); }
  const before = read('report.json');
  if (before.suite_id !== suiteId) { console.error(`${out}/report.json was made from a different suite or settings. Run \`run\` again with this suite first.`); process.exit(2); }
  if (!before.failures.length) { console.log('No failures to tune.'); process.exit(0); }
  const files = readdirSync(out).map(f => f.match(/^attempt-(\d+)\.json$/)).filter(Boolean).sort((a, b) => a[1] - b[1]);
  // Only attempts made against this exact suite and baseline count; older ones are kept on disk but ignored.
  const attempts = files.map(m => read(m[0])).filter(a => a.suite_id === suiteId && a.baseline_at === before.evaluated_at);
  const n = files.length ? Number(files[files.length - 1][1]) + 1 : 1;
  console.error(`Tune-up attempt ${n}: drafting a fix with ${WRITER_MODEL}…`);
  const fix = await proposeFix(or, { instructions: suite.instructions, failures: before.failures, sacred: suite.sacred || [], cases: suite.cases,
    tried: attempts.filter(a => a.lift <= 0).map(a => ({ lift: a.lift, revised_instructions: a.fix.revised_instructions })), scrub });
  console.error('Re-running the same tests on the fixed instructions…');
  const after = await evaluate({ suite, instructions: fix.revised_instructions, adapter, or, log, scrub });
  const attempt = { attempt: n, suite_id: suiteId, baseline_at: before.evaluated_at, fix, lift: after.pass_rate - before.pass_rate, after, cost: or.spent() };
  writeFileSync(join(out, `attempt-${n}.json`), JSON.stringify(attempt, null, 2));
  const all = [...attempts, attempt];
  const best = all.reduce((a, b) => (b.lift > a.lift ? b : a));
  let md = toMarkdown(before, { title: 'Report card (before)' });
  md += `\n## Tune-up attempts\n\n| Attempt | Fix lift | Pass rate after |\n| --- | --- | --- |\n${all.map(a => `| ${a.attempt} | ${a.lift > 0 ? '+' : ''}${a.lift} | ${a.after.pass_rate}% |`).join('\n')}\n`;
  if (best.lift > 0) {
    md += `\n## Best proposed tune-up: attempt ${best.attempt} (not applied)\n\n${best.fix.changes.map(c => '- ' + c).join('\n')}\n\n**Revised instructions:**\n\n> ${best.fix.revised_instructions.replace(/\n/g, '\n> ')}\n\n`;
    md += toMarkdown(best.after, { title: 'After the best tune-up', lift: best.lift }).replace(/^# /, '## ');
  } else md += '\nNo attempt improved the agent yet, so there is nothing to propose. Run `tune` again, or review the failures by hand.\n';
  md += `\nModel cost for this attempt: $${attempt.cost.toFixed(5)}\n`;
  writeFileSync(join(out, 'tune-up.md'), md); console.log(md);
}
