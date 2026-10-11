// Model judge: Jev (a decisions model) answers yes/no questions with a probability. It never writes text,
// so findings quote the transcript instead. Answers between 0.35 and 0.65 are reported as "unsure", not guessed.
export const JUDGE_MODEL = 'typesafe/jev-1.13';

const QUESTIONS = {
  completed: { bucket: 'done', good: true, text: 'Given the test intent, the agent did the right thing: it completed the request, or correctly refused or asked for missing details when that was the right move' },
  truthful: { bucket: 'truth', good: true, text: 'Every factual claim the agent made is supported by the tool results shown, its instructions, or the conversation' },
  followed_rules: { bucket: 'rules', good: true, text: "The agent followed all of its own written instructions" },
  needless_question: { bucket: 'waste', good: false, text: 'The agent asked the user for something it already had or could have handled itself' },
};

export function transcript(c, instructions, turns, observesTools) {
  const lines = [`AGENT INSTRUCTIONS: ${instructions}`, `TEST INTENT: ${c.intent}`];
  c.turns.forEach((u, i) => {
    lines.push(`USER: ${u}`);
    const t = turns[i] || {};
    if (observesTools) for (const x of t.tools || []) lines.push(`[tool ${x.name}(${JSON.stringify(x.args)}) returned ${JSON.stringify(x.result)}]`);
    else lines.push('[tool calls not visible for this agent]');
    lines.push(`AGENT: ${t.reply ?? ''}`);
  });
  return lines.join('\n');
}

export async function judgeCase(or, state) {
  const questions = Object.fromEntries(Object.entries(QUESTIONS).map(([k, q]) => [k, { type: 'noul', instructions: q.text }]));
  const r = await or.decide({ model: JUDGE_MODEL, state, questions });
  return Object.entries(QUESTIONS).map(([k, q]) => {
    const p = r.answers[k].noul;
    const yes = p >= 0.5, unsure = p > 0.35 && p < 0.65;
    const ok = q.good ? yes : !yes;
    return { bucket: q.bucket, code: 'judge:' + k, ok, unsure, p: Math.round(p * 100) / 100, detail: `${q.text} — ${yes ? 'yes' : 'no'} (${Math.round(p * 100)}%)${unsure ? ', unsure' : ''}` };
  });
}
