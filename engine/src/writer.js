// Fix writer: drafts the smallest instruction change for the failures found. Its output is a proposal the owner
// reviews; nothing is applied without a yes. Runs on a no-training paid endpoint (OpenRouter account setting).
export const WRITER_MODEL = 'nvidia/nemotron-3-super-120b-a12b';

// `cases` gives each failing case's intent; `tried` lists earlier attempts that did not help, so the writer
// does not repeat them.
export async function proposeFix(or, { instructions, failures, sacred = [], cases = [], tried = [] }) {
  const top = [...new Map(failures.map(f => [f.code + f.case, f])).values()].slice(0, 8);
  const intents = [...new Set(top.map(f => f.case))].map(id => `- [${id}] ${(cases.find(c => c.id === id) || {}).intent || ''}`);
  const prompt = [
    'You improve AI agent instructions with the smallest change that makes the failing tests pass.',
    'Rules: keep the agent\'s purpose; keep every SACRED sentence word for word; do not add new features;',
    'every change must target a listed failure; rewording alone is not a fix. Be concrete about what the agent must do instead.',
    'Reply with JSON only: {"revised_instructions": "...full revised instructions...", "changes": ["<failure it fixes>: <what changed>"]}',
    '', `CURRENT INSTRUCTIONS:\n${instructions}`, '', `SACRED:\n${sacred.join('\n') || '(none)'}`, '',
    'WHAT EACH FAILING TEST EXPECTS:', ...intents, '',
    'FAILURES FOUND IN TESTING:', ...top.map(f => `- [${f.case}] ${f.detail}${f.quote ? ` (agent said: "${f.quote}")` : ''}`),
    ...(tried.length ? ['', 'ALREADY TRIED, DID NOT HELP (do something different):', ...tried.map(t => `- lift ${t.lift} points with: ${t.revised_instructions}`)] : []),
  ].join('\n');
  const r = await or.chat({ model: WRITER_MODEL, messages: [{ role: 'user', content: prompt }], max_tokens: 1200, temperature: 0.2, response_format: { type: 'json_object' } });
  const txt = r.choices[0].message.content || '';
  const j = JSON.parse(txt.slice(txt.indexOf('{'), txt.lastIndexOf('}') + 1));
  if (typeof j.revised_instructions !== 'string' || j.revised_instructions.trim().length < 20) throw new Error('Fix writer returned no usable instructions');
  j.changes = Array.isArray(j.changes) && j.changes.length ? j.changes.map(String) : ['(the writer did not list its changes; compare the instructions)'];
  for (const s of sacred) if (!j.revised_instructions.includes(s)) throw new Error('Fix writer changed a sacred sentence; proposal rejected');
  return j;
}
