// Runs a test suite against an agent: every case `repeats` times, rule checks first, then the judge.
import { checkCase } from './rules.js';
import { judgeCase, judgeHeld, transcript, heldFinding, JUDGE_MODEL } from './judge.js';
import { HeldBack } from './openrouter.js';
import { buildReport, runPassed } from './report.js';
import { scrubber } from './redact.js';

export const CONCURRENCY = 4;
export async function pool(items, n, fn) {
  const out = new Array(items.length); let next = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (next < items.length) { const i = next++; out[i] = await fn(items[i]); } }));
  return out;
}

// The judge sees a Sanitized only. A ScrubError (the scrubber's size or time cap) means no call for that run: the run is
// marked unsure with the held finding rather than crashing the whole evaluation or sending unscrubbed text.
const judge = (or, scrub, text) => judgeHeld(scrub, text, (sanitized) => judgeCase(or, sanitized));

export async function evaluate({ suite, instructions, adapter, or, log = () => {}, scrub = scrubber() }) {
  // Up to CONCURRENCY cases run at once (bounds cost and rate-limit bursts); repeats of one case run one after another.
  const perCase = await pool(suite.cases, CONCURRENCY, async (c) => {
    const runs = [];
    for (let rep = 1; rep <= (suite.repeats || 1); rep++) {
      const history = []; const turns = []; let held = false;
      for (const message of c.turns) {
        let t;
        // The replay model's input was held back (a secret survived scrubbing): no call was made; the run is unsure.
        try { t = await adapter.turn({ history, message, instructions }); } catch (e) { if (e instanceof HeldBack) { held = true; break; } throw e; }
        turns.push(t);
        // Keep tool calls and results in the history when the adapter exposes them (model adapter), not just the reply.
        history.push({ role: 'user', content: message }, ...(t.messages || [{ role: 'assistant', content: t.reply }]));
      }
      const findings = held ? [heldFinding()] : [...checkCase(c, turns, adapter), ...await judge(or, scrub, transcript(c, instructions, turns, adapter.observesTools))];
      const passed = runPassed(findings);
      runs.push({ case: c.id, rep, passed, findings, turns: turns.map(t => ({ reply: t.reply, tools: t.tools, ...(t.truncated ? { truncated: true } : {}) })),
        ms: turns.reduce((a, t) => a + t.ms, 0), tokens: turns.some(t => t.tokens == null) ? null : turns.reduce((a, t) => a + t.tokens, 0),
        toolCalls: adapter.observesTools ? turns.reduce((a, t) => a + ((t.tools || []).length), 0) : null });
      log(`${c.id} run ${rep}: ${passed ? 'pass' : 'FAIL'}`);
    }
    return runs;
  });
  const runs = perCase.flat();
  return buildReport({ suite, instructions, adapter, runs, judgeModel: JUDGE_MODEL, evidenceLevel: 2 });
}
