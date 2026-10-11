#!/usr/bin/env node
// Agent Tune-Up engine (v0.1).
//   node engine/cli.js run  <suite.json> [--keyfile path] [--out dir] [--repeats N]
//       Evaluate the agent: writes <out>/report.json and report.md.
//   node engine/cli.js tune <suite.json> [--keyfile path] [--out dir] [--repeats N]
//       One verified tune-up attempt: draft the smallest fix for the failures in <out>/report.json,
//       re-run the same tests on it, save <out>/attempt-N.json, and rewrite tune-up.md with the best attempt.
//       Run it again to try once more; earlier attempts that did not help are fed back to the writer.
// A fix is a proposal. This tool never applies it to a real agent.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { loadKey, client } from './src/openrouter.js';
import { httpAdapter, modelAdapter } from './src/adapters.js';
import { evaluate } from './src/evaluate.js';
import { proposeFix, WRITER_MODEL } from './src/writer.js';
import { toMarkdown } from './src/report.js';

const [cmd, file, ...rest] = process.argv.slice(2);
const opt = (name, dflt) => { const i = rest.indexOf('--' + name); return i < 0 ? dflt : (rest[i + 1] && !rest[i + 1].startsWith('--') ? rest[i + 1] : true); };
if (!['run', 'tune'].includes(cmd) || !file) { console.error('usage: node engine/cli.js run|tune <suite.json> [--keyfile path] [--out dir] [--repeats N]'); process.exit(2); }

const suite = JSON.parse(readFileSync(file, 'utf8'));
if (opt('repeats')) suite.repeats = Number(opt('repeats'));
const or = client(loadKey(opt('keyfile')));
const adapter = suite.agent_config.type === 'http' ? httpAdapter(suite.agent_config) : modelAdapter(suite.agent_config, or);
const out = opt('out', 'tune-up-report'); mkdirSync(out, { recursive: true });
const log = (s) => console.error('  ' + s);
const read = (f) => JSON.parse(readFileSync(join(out, f), 'utf8'));

if (cmd === 'run') {
  console.error(`Evaluating ${suite.agent}: ${suite.cases.length} cases × ${suite.repeats || 1} runs`);
  const rep = await evaluate({ suite, instructions: suite.instructions, adapter, or, log });
  writeFileSync(join(out, 'report.json'), JSON.stringify(rep, null, 2));
  const md = toMarkdown(rep, { title: 'Report card' }) + `\nModel cost for this run: $${or.spent().toFixed(5)}\n`;
  writeFileSync(join(out, 'report.md'), md); console.log(md);
} else {
  const before = read('report.json');
  if (!before.failures.length) { console.log('No failures to tune.'); process.exit(0); }
  const attempts = readdirSync(out).filter(f => /^attempt-\d+\.json$/.test(f)).sort().map(read);
  const n = attempts.length + 1;
  console.error(`Tune-up attempt ${n}: drafting a fix with ${WRITER_MODEL}…`);
  const fix = await proposeFix(or, { instructions: suite.instructions, failures: before.failures, sacred: suite.sacred || [], cases: suite.cases,
    tried: attempts.filter(a => a.lift <= 0).map(a => ({ lift: a.lift, revised_instructions: a.fix.revised_instructions })) });
  console.error('Re-running the same tests on the fixed instructions…');
  const after = await evaluate({ suite, instructions: fix.revised_instructions, adapter, or, log });
  const attempt = { attempt: n, fix, lift: after.pass_rate - before.pass_rate, after, cost: or.spent() };
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
