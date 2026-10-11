import { scrubber } from './redact.js';
// Adapters turn "send this user message to the agent" into whatever the agent's platform needs.
// Every adapter returns { reply, tools, tokens, ms } for one user turn. `tools` lists tool calls the agent made
// (name, args, ok, result) when the platform exposes them; `null` means "not observable here".

// 1) http: any chatbot with an HTTP endpoint. Config:
//    { "type": "http", "url": "...", "headers": {...}, "body": {...with "{{message}}" / "{{history}}"...}, "reply_path": "a.b.0.c" }
// Header values may use ${TUNEUP_AGENT_*} environment variables and nothing else: a suite file can point `url` anywhere,
// so letting it name any variable (e.g. ${TUNEUP_OPENROUTER_KEY}) would let a shared suite send your secrets to its host.
export const AGENT_ENV = /^TUNEUP_AGENT_[A-Z0-9_]+$/;
export function headerVars(cfg) {
  return [...new Set(Object.values(cfg.headers || {}).flatMap(v => [...String(v).matchAll(/\$\{(\w+)\}/g)].map(m => m[1])))];
}

// `privateTerms` (the --private list) never go anywhere, including your own agent: a test message that contains one
// is refused before it is sent. Built-in patterns (emails, keys…) do reach your own agent, because that is what is tested.
export function httpAdapter(cfg, { fetchImpl = fetch, privateTerms = [] } = {}) {
  const bad = headerVars(cfg).filter(n => !AGENT_ENV.test(n));
  if (bad.length) throw new Error(`agent_config.headers may only use \${TUNEUP_AGENT_*} variables; refusing ${bad.map(n => '${' + n + '}').join(', ')}`);
  const fill = (v, vars) => typeof v === 'string'
    ? (v === '{{history}}' ? vars.history : v.replaceAll('{{message}}', vars.message).replaceAll('{{instructions}}', vars.instructions ?? ''))
    : Array.isArray(v) ? v.map(x => fill(x, vars))
    : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x, vars)]))
    : v;
  const pick = (obj, path) => path.split('.').reduce((o, k) => (o == null ? o : o[/^\d+$/.test(k) ? Number(k) : k]), obj);
  const headers = Object.fromEntries(Object.entries(cfg.headers || {}).map(([k, v]) => [k, String(v).replace(/\$\{(\w+)\}/g, (_, n) => process.env[n] || '')]));
  const hasPrivate = (text) => { const s = scrubber({ terms: privateTerms }); s.scrub(text); return (s.counts().PRIVATE || 0) > 0; };
  return {
    name: 'http', observesTools: false,
    // Tuning needs a way to hand the agent new instructions; without {{instructions}} in the body there is none.
    acceptsInstructions: JSON.stringify(cfg.body || {}).includes('{{instructions}}'),
    async turn({ history, message, instructions }) {
      const t = Date.now();
      const body = JSON.stringify(fill(cfg.body || { message: '{{message}}' }, { message, history, instructions }));
      if (privateTerms.length && hasPrivate(body)) throw new Error('A word from your --private list is in a test message or the instructions; it was not sent to the agent. Remove it from the suite.');
      const r = await fetchImpl(cfg.url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body, signal: AbortSignal.timeout(cfg.timeout_ms || 60_000) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(`agent endpoint ${r.status}`);
      return { reply: String(pick(j, cfg.reply_path || 'reply') ?? ''), tools: null, tokens: null, ms: Date.now() - t };
    },
  };
}

// 2) model: an agent defined by instructions + tools, run on an OpenRouter model with simulated tools.
//    Used for Tune-Up's own demo agents and for "replay" of an agent's instructions. Tools are simulated by
//    the suite's `tools` map: { name: { description, parameters, cases: [{ when: {arg: value}, result }], default } }.
// Everything sent to the replay model is scrubbed with `scrub`; its replies and tool arguments are restored locally.
export function modelAdapter(cfg, or, { scrub } = {}) {
  const S = (t) => (scrub ? scrub.scrub(t) : t), U = (t) => (scrub ? scrub.unscrub(t) : t);
  // Tool definitions are sent too, so every string in them is scrubbed (descriptions, enums, examples) except
  // tool and property names and `required` lists, which the model must echo back exactly for dispatch.
  const scrubSchema = (v, key) => typeof v === 'string' ? S(v)
    : Array.isArray(v) ? (key === 'required' ? v : v.map(x => scrubSchema(x)))
    : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, k === 'properties' && x && typeof x === 'object'
      ? Object.fromEntries(Object.entries(x).map(([pk, pv]) => [pk, scrubSchema(pv, pk)])) : scrubSchema(x, k)]))
    : v;
  const toolDefs = () => Object.entries(cfg.tools || {}).map(([name, d]) => ({ type: 'function', function: { name, description: S(d.description ?? ''), parameters: scrubSchema(d.parameters) } }));
  const simulate = (name, args) => {
    const d = (cfg.tools || {})[name];
    if (!d) return { ok: false, result: { error: 'unknown tool' } };
    const hit = (d.cases || []).find(c => Object.entries(c.when || {}).every(([k, v]) => String(args[k] ?? '').toLowerCase() === String(v).toLowerCase()));
    // No matching case and no default means the simulator has nothing to return: that is a failed call, not a success.
    // A defined result of false, 0, '' or null is still a real result.
    if (hit ? !('result' in hit) : !('default' in d)) return { ok: false, result: { error: 'no simulated result for these arguments' } };
    const result = hit ? hit.result : d.default;
    return { ok: !(result && result.error), result };
  };
  return {
    name: 'model:' + cfg.model, observesTools: true,
    async turn({ history, message, instructions }) {
      const t = Date.now(); const tools = []; let tokens = 0; const defs = toolDefs();
      // `messages` is this turn's full exchange (tool calls, tool results, reply) kept locally with real values, so the
      // next turn's history has the same context a live tool-using conversation would. Tool-call arguments stay in the
      // placeholder form the model wrote; the shared scrubber maps them consistently.
      const messages = [];
      const msgs = [{ role: 'system', content: S(instructions) }, ...history.map(h => ({ ...h, content: S(h.content) })), { role: 'user', content: S(message) }];
      for (let hop = 0; hop < 4; hop++) {
        const r = await or.chat({ model: cfg.model, messages: msgs, tools: defs.length ? defs : undefined, max_tokens: cfg.max_tokens || 2000, temperature: cfg.temperature ?? 0.7 });
        tokens += (r.usage && r.usage.total_tokens) || 0;
        const m = r.choices[0].message;
        if (!m.tool_calls || !m.tool_calls.length) {
          const reply = U(m.content || '').trim();
          messages.push({ role: 'assistant', content: reply });
          return { reply, tools, tokens, ms: Date.now() - t, truncated: r.choices[0].finish_reason === 'length', messages };
        }
        msgs.push({ role: 'assistant', content: m.content || '', tool_calls: m.tool_calls });
        messages.push({ role: 'assistant', content: U(m.content || ''), tool_calls: m.tool_calls });
        for (const c of m.tool_calls) {
          let args = {}, s;
          try { args = JSON.parse(U(c.function.arguments || '{}')); s = simulate(c.function.name, args); }
          catch { s = { ok: false, result: { error: 'invalid tool arguments (not JSON)' } }; }
          tools.push({ name: c.function.name, args, ok: s.ok, result: s.result, readOnly: !!(cfg.tools || {})[c.function.name]?.read_only });
          msgs.push({ role: 'tool', tool_call_id: c.id, content: S(JSON.stringify(s.result)) });
          messages.push({ role: 'tool', tool_call_id: c.id, content: JSON.stringify(s.result) });
        }
      }
      messages.push({ role: 'assistant', content: '' });
      return { reply: '', tools, tokens, ms: Date.now() - t, note: 'stopped after 4 tool rounds', messages };
    },
  };
}
