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
import { httpAdapter, modelAdapter, headerVars } from './src/adapters.js';
import { evaluate, pool, CONCURRENCY } from './src/evaluate.js';
import { validateSuite } from './src/rules.js';
import { proposeFix, WRITER_MODEL } from './src/writer.js';
import { toMarkdown, buildReport, runPassed, regressions } from './src/report.js';
import { scrubber, ScrubError } from './src/redact.js';
import { parseTranscripts, checkConversation } from './src/transcripts.js';
import { judgeConversation, judgeHeld, chatState, JUDGE_MODEL } from './src/judge.js';

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
  // At most CONCURRENCY conversations at once (each asks the judge three times).
  const runs = await pool(convos.map((msgs, i) => [msgs, i]), CONCURRENCY, async ([msgs, i]) => {
    // A chat over the scrubber's size or time cap gets the held finding (unsure), like a run in evaluate: never a crash.
    const findings = [...checkConversation(msgs), ...(or ? await judgeHeld(scrub, chatState(instructions, msgs), (san) => judgeConversation(or, san, { hasInstructions: !!instructions })) : [])];
    // Report text is scrubbed again for display; past the scrubber's cap it is withheld rather than crashing the command
    // (PR #16 review).
    // The report goes through the same fail-closed check as the judge: residual-only secrets are held, not written out (PR #16 review).
    const shown = (t) => { try { const z = scrub.sanitize(t); return z.held ? '[held back: secret-like content]' : z.text; } catch (e) { if (e instanceof ScrubError) return '[held back: too large to scrub safely]'; throw e; } };
    return { case: `chat-${i + 1}`, rep: 1, passed: runPassed(findings), findings: findings.map(f => ({ ...f, quote: f.quote && shown(f.quote) })),
      turns: msgs.map(m => ({ role: m.role, reply: shown(m.content) })), ms: 0, tokens: 0, toolCalls: 0 };
  });
  const rep = buildReport({ suite: { agent: opt('agent', 'Your agent'), repeats: 1 }, instructions, adapter: { name: 'paste', observesTools: false }, runs, judgeModel: or ? JUDGE_MODEL : 'none (rule checks only)', evidenceLevel: 1 });
  rep.scrubbed = scrub.counts();
  writeFileSync(join(out, 'report.json'), JSON.stringify(rep, null, 2));
  const md = toMarkdown(rep, { title: 'Report card' }) + `\nScrubbed before checking: ${Object.entries(rep.scrubbed).map(([k, v]) => `${v} ${k.toLowerCase()}`).join(', ') || 'nothing found'}.` + (or ? ` Model cost: $${or.spent().toFixed(5)}` : '') + '\n';
  writeFileSync(join(out, 'report.md'), md); console.log(md);
  process.exit(0);
}
if (!consent) { console.error(NOTICE + '\nAdd --consent to run with remote models.'); process.exit(2); }

const suite = JSON.parse(readFileSync(file, 'utf8'));
{ const errs = validateSuite(suite); if (errs.length) { console.error('Fix the suite before running (nothing was sent):\n- ' + errs.join('\n- ')); process.exit(2); } }
const repeats = Number(opt('repeats', suite.repeats ?? 1));
if (!Number.isInteger(repeats) || repeats < 1 || repeats > 20) { console.error('--repeats (or the suite\'s "repeats") must be a whole number from 1 to 20.'); process.exit(2); }
suite.repeats = repeats;
// Ties reports and tune-up attempts to the exact suite they came from, so stale files are never mixed in.
// The --private list is part of the identity, so a tune-up can never run with a weaker never-send list than its baseline.
const suiteId = createHash('sha256').update(JSON.stringify(suite) + '\u0000' + JSON.stringify([...terms].map(t => t.toLowerCase()).sort())).digest('hex').slice(0, 16);
const or = client(loadKey(opt('keyfile')));
const scrub = scrubber({ terms });
let adapter;
try { adapter = suite.agent_config.type === 'http' ? httpAdapter(suite.agent_config, { privateTerms: terms }) : modelAdapter(suite.agent_config, or, { scrub, privateTerms: terms }); }
catch (e) { console.error(e.message); process.exit(2); }
if (suite.agent_config.type === 'http') {
  const vars = headerVars(suite.agent_config);
  console.error('Use a test copy of your agent: every case is sent ' + repeats + ' time(s), and again after each tune-up, so real actions (bookings, emails) would repeat.');
  const where = (() => { try { return new URL(suite.agent_config.url).origin; } catch { return '(invalid url)'; } })();   // origin only: a signed URL's secrets never reach logs
  console.error(`Test messages go unchanged to your agent at ${where}` + (vars.length ? ` with ${vars.join(', ')} from your environment.` : '.') + ' Words in --private are never sent.');
}
if (cmd === 'tune' && adapter.acceptsInstructions === false) {
  console.error('This http agent has no way to receive new instructions, so a tune-up cannot be verified by re-running it. Add "{{instructions}}" to agent_config.body, or use the model adapter.'); process.exit(2);
}
const log = (s) => console.error('  ' + s);
// Lift in percentage points from raw pass counts (reports round pass rates for display only).
const rate = (rep) => 100 * rep.runs.filter(r => r.passed).length / rep.runs.length;
const liftOf = (before, after) => rate(after) - rate(before);
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
  if (!before.failures.length) { const u = before.buckets.filter(b => b.status === 'warn').map(b => b.name); console.log(u.length ? `No confident failures to tune, but these were unsure: ${u.join(', ')}. Review them in report.md, or run again with more --repeats.` : 'No failures to tune.'); process.exit(0); }
  const files = readdirSync(out).map(f => f.match(/^attempt-(\d+)\.json$/)).filter(Boolean).sort((a, b) => a[1] - b[1]);
  // Only attempts made against this exact suite and baseline count; older ones are kept on disk but ignored.
  const attempts = files.map(m => read(m[0])).filter(a => a.suite_id === suiteId && a.baseline_at === before.evaluated_at);
  const n = files.length ? Number(files[files.length - 1][1]) + 1 : 1;
  console.error(`Tune-up attempt ${n}: drafting a fix with ${WRITER_MODEL}…`);
  const fix = await proposeFix(or, { instructions: suite.instructions, failures: before.failures, sacred: suite.sacred || [], cases: suite.cases,
    // Every attempt that was not proposed goes back to the writer, including positive-lift ones that broke something.
    tried: attempts.filter(a => a.lift <= 0 || regressions(before, a.after).length).map(a => ({ lift: a.lift, revised_instructions: a.fix.revised_instructions })), scrub });
  console.error('Re-running the same tests on the fixed instructions…');
  const after = await evaluate({ suite, instructions: fix.revised_instructions, adapter, or, log, scrub });
  const attempt = { attempt: n, suite_id: suiteId, baseline_at: before.evaluated_at, fix, lift: liftOf(before, after), after, cost: or.spent() };
  writeFileSync(join(out, `attempt-${n}.json`), JSON.stringify(attempt, null, 2));
  const all = [...attempts, attempt].map(a => ({ ...a, regressions: regressions(before, a.after) }));
  // A tune-up that breaks something that worked, or adds any rules failure, is never proposed, whatever its lift.
  const eligible = all.filter(a => a.lift > 0 && !a.regressions.length);
  const best = eligible.length ? eligible.reduce((a, b) => (b.lift > a.lift ? b : a)) : null;
  let md = toMarkdown(before, { title: 'Report card (before)' });
  md += `\n## Tune-up attempts\n\n| Attempt | Fix lift | Pass rate after | New failures |\n| --- | --- | --- | --- |\n${all.map(a => `| ${a.attempt} | ${a.lift > 0 ? '+' : ''}${Math.round(a.lift * 10) / 10} | ${a.after.pass_rate}% | ${a.regressions.join(', ') || 'none'} |`).join('\n')}\n`;
  if (best) {
    md += `\n## Best proposed tune-up: attempt ${best.attempt} (not applied)\n\n${best.fix.changes.map(c => '- ' + c).join('\n')}\n\n**Revised instructions:**\n\n> ${best.fix.revised_instructions.replace(/\n/g, '\n> ')}\n\n`;
    md += toMarkdown(best.after, { title: 'After the best tune-up', lift: best.lift }).replace(/^# /, '## ');
  } else md += `\nNo attempt improved the agent without breaking something else${all.some(a => a.lift > 0) ? ' (attempts with new failures are never proposed)' : ''}, so there is nothing to propose. Run \`tune\` again, or review the failures by hand.\n`;
  md += `\nModel cost for this attempt: $${attempt.cost.toFixed(5)}\n`;
  writeFileSync(join(out, 'tune-up.md'), md); console.log(md);
}
