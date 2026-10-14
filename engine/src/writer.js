// Fix writer: drafts the smallest instruction change for the failures found. Its output is a proposal the owner
// reviews; nothing is applied without a yes. Runs on a no-training paid endpoint (OpenRouter account setting).
import { scrubber } from './redact.js';
import { outbound } from './openrouter.js';

export const WRITER_MODEL = 'nvidia/nemotron-3-super-120b-a12b';

// `cases` gives each failing case's intent; `tried` lists earlier attempts that did not help, so the writer
// does not repeat them. The whole prompt is sanitized once, as one text, and leaves only through `outbound`: a hold or a scrubber error means no call
// and no proposal, which is what a tune-up must do when it cannot be sure the secret is gone.
export async function proposeFix(or, { instructions, failures, sacred = [], cases = [], tried = [], scrub = scrubber() }) {
  // Everything sent is scrubbed locally; placeholders in the answer are mapped back here, never remotely.
  // Built from the raw pieces and sanitized ONCE: a second pass over already-scrubbed text would see our own [EMAIL_1]
  // as literal input and mark it ambiguous, so it could not be restored in the proposal (PR #16 review).
  const S = (t) => String(t ?? '');
  const top = [...new Map(failures.map(f => [f.code + f.case, f])).values()].slice(0, 8);
  const intents = [...new Set(top.map(f => f.case))].map(id => `- [${S(id)}] ${S((cases.find(c => c.id === id) || {}).intent || '')}`);
  const prompt = [
    'You improve AI agent instructions with the smallest change that makes the failing tests pass.',
    'Rules: keep the agent\'s purpose; keep every SACRED sentence word for word; do not add new features;',
    'every change must target a listed failure; rewording alone is not a fix. Be concrete about what the agent must do instead.',
    'Reply with JSON only: {"revised_instructions": "...full revised instructions...", "changes": ["<failure it fixes>: <what changed>"]}',
    '', `CURRENT INSTRUCTIONS:\n${S(instructions)}`, '', `SACRED:\n${sacred.map(S).join('\n') || '(none)'}`, '',
    'WHAT EACH FAILING TEST EXPECTS:', ...intents, '',
    'FAILURES FOUND IN TESTING:', ...top.map(f => `- [${S(f.case)}] ${S(f.detail)}${f.quote ? ` (agent said: "${S(f.quote)}")` : ''}`),
    ...(tried.length ? ['', 'ALREADY TRIED, DID NOT HELP (do something different):', ...tried.map(t => `- lift ${t.lift} points with: ${S(t.revised_instructions)}`)] : []),
  ].join('\n');
  const sanitized = scrub.sanitize(prompt);
  const r = await outbound(or, 'chat', sanitized, (content) => ({ model: WRITER_MODEL, messages: [{ role: 'user', content }], max_tokens: Math.max(1200, Math.ceil(instructions.length / 3) + 800), temperature: 0.2, response_format: { type: 'json_object' } }));
  const txt = r.choices[0].message.content || '';
  const j = JSON.parse(txt.slice(txt.indexOf('{'), txt.lastIndexOf('}') + 1));
  if (typeof j.revised_instructions === 'string') {
    j.revised_instructions = scrub.unscrub(j.revised_instructions);
    // The writer sometimes copies the prompt's SACRED list onto the end of the instructions; drop it unless it was there.
    if (!/^\s*SACRED:/m.test(instructions)) j.revised_instructions = j.revised_instructions.replace(/\n+\s*SACRED:[\s\S]*$/, '').trim();
  }
  if (typeof j.revised_instructions !== 'string' || j.revised_instructions.trim().length < 20) throw new Error('Fix writer returned no usable instructions');
  const norm = (s) => s.replace(/\s+/g, ' ').trim();
  if (norm(j.revised_instructions) === norm(instructions)) throw new Error('Fix writer returned the instructions unchanged; nothing to test');
  j.changes = Array.isArray(j.changes) && j.changes.length ? j.changes.map(c => scrub.unscrub(String(c))) : ['(the writer did not list its changes; compare the instructions)'];
  for (const s of sacred) if (!j.revised_instructions.includes(s)) throw new Error('Fix writer changed a sacred sentence; proposal rejected');
  return j;
}
