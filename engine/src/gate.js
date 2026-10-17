// The CI gate: turns the in-memory findings of a `check` or `run` into one exit code. It never reads report.json, so
// editing that file cannot change the result. Strict: only an explicit pass on every run is a pass.
//   0  every run has findings, every finding passed, and the judge answered for every run
//   1  any finding failed with confidence
//   3  undetermined: any unsure or held finding, a run the judge did not answer, or no runs at all
//   2  usage or config error (decided in cli.js before any check runs, never here)
// Order when results are mixed: 1 beats 3 beats 0.
export const EXIT = Object.freeze({ PASS: 0, FAIL: 1, USAGE: 2, UNDETERMINED: 3 });

// The judge's questions. A run counts as judged only when every one it was asked got an answer that is not held.
const JUDGE = /^judge:(?!held$|error$)/;

/** @param {Array<{findings?: any[]}>} runs */
export function verdict(runs) {
  if (!Array.isArray(runs) || runs.length === 0) return EXIT.UNDETERMINED;
  const all = runs.flatMap(r => (r && Array.isArray(r.findings) ? r.findings : []));
  if (all.some(f => f.ok !== true && f.unsure !== true)) return EXIT.FAIL;
  if (runs.some(r => !r || !Array.isArray(r.findings) || r.findings.length === 0)) return EXIT.UNDETERMINED;
  if (runs.some(r => !r.findings.some(f => JUDGE.test(String(f.code))))) return EXIT.UNDETERMINED;
  if (all.some(f => f.ok !== true)) return EXIT.UNDETERMINED;
  return EXIT.PASS;
}

// One line for the CI log, so a reader can tell "broken" from "couldn't tell" without opening the report.
export function summary(code, runs) {
  const all = (runs || []).flatMap(r => (r && r.findings) || []);
  const failed = [...new Set(all.filter(f => f.ok !== true && f.unsure !== true).map(f => f.code))];
  const unsure = [...new Set(all.filter(f => f.unsure === true).map(f => f.code))];
  if (code === EXIT.PASS) return 'agenttuneup: PASS (exit 0)';
  if (code === EXIT.FAIL) return `agenttuneup: FAIL (exit 1): ${failed.join(', ')}`;
  const why = unsure.length ? `unsure: ${unsure.join(', ')}` : (all.some(f => JUDGE.test(String(f.code))) ? 'a run was not judged' : 'the judge did not run (add --consent and a key)');
  return `agenttuneup: UNDETERMINED (exit 3): ${why}`;
}
