// Adapters turn "send this user message to the agent" into whatever the agent's platform needs.
// Every adapter returns { reply, tools, tokens, ms } for one user turn. `tools` lists tool calls the agent made
// (name, args, ok, result) when the platform exposes them; `null` means "not observable here".

// 1) http: any chatbot with an HTTP endpoint. Config:
//    { "type": "http", "url": "...", "headers": {...}, "body": {...with "{{message}}" / "{{history}}"...}, "reply_path": "a.b.0.c" }
export function httpAdapter(cfg, { fetchImpl = fetch } = {}) {
  const fill = (v, vars) => typeof v === 'string'
    ? (v === '{{history}}' ? vars.history : v.replaceAll('{{message}}', vars.message).replaceAll('{{instructions}}', vars.instructions ?? ''))
    : Array.isArray(v) ? v.map(x => fill(x, vars))
    : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x, vars)]))
    : v;
  const pick = (obj, path) => path.split('.').reduce((o, k) => (o == null ? o : o[/^\d+$/.test(k) ? Number(k) : k]), obj);
  const headers = Object.fromEntries(Object.entries(cfg.headers || {}).map(([k, v]) => [k, String(v).replace(/\$\{(\w+)\}/g, (_, n) => process.env[n] || '')]));
  return {
    name: 'http', observesTools: false,
    // Tuning needs a way to hand the agent new instructions; without {{instructions}} in the body there is none.
    acceptsInstructions: JSON.stringify(cfg.body || {}).includes('{{instructions}}'),
    async turn({ history, message, instructions }) {
      const t = Date.now();
      const r = await fetchImpl(cfg.url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify(fill(cfg.body || { message: '{{message}}' }, { message, history, instructions })), signal: AbortSignal.timeout(cfg.timeout_ms || 60_000) });
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
  const toolDefs = Object.entries(cfg.tools || {}).map(([name, d]) => ({ type: 'function', function: { name, description: d.description, parameters: d.parameters } }));
  const simulate = (name, args) => {
    const d = (cfg.tools || {})[name];
    if (!d) return { ok: false, result: { error: 'unknown tool' } };
    const hit = (d.cases || []).find(c => Object.entries(c.when || {}).every(([k, v]) => String(args[k] ?? '').toLowerCase() === String(v).toLowerCase()));
    const result = hit ? hit.result : d.default;
    return { ok: !(result && result.error), result };
  };
  return {
    name: 'model:' + cfg.model, observesTools: true,
    async turn({ history, message, instructions }) {
      const t = Date.now(); const tools = []; let tokens = 0;
      const msgs = [{ role: 'system', content: S(instructions) }, ...history.map(h => ({ ...h, content: S(h.content) })), { role: 'user', content: S(message) }];
      for (let hop = 0; hop < 4; hop++) {
        const r = await or.chat({ model: cfg.model, messages: msgs, tools: toolDefs.length ? toolDefs : undefined, max_tokens: cfg.max_tokens || 2000, temperature: cfg.temperature ?? 0.7 });
        tokens += (r.usage && r.usage.total_tokens) || 0;
        const m = r.choices[0].message;
        if (!m.tool_calls || !m.tool_calls.length) return { reply: U(m.content || '').trim(), tools, tokens, ms: Date.now() - t, truncated: r.choices[0].finish_reason === 'length' };
        msgs.push({ role: 'assistant', content: m.content || '', tool_calls: m.tool_calls });
        for (const c of m.tool_calls) {
          let args = {}, s;
          try { args = JSON.parse(U(c.function.arguments || '{}')); s = simulate(c.function.name, args); }
          catch { s = { ok: false, result: { error: 'invalid tool arguments (not JSON)' } }; }
          tools.push({ name: c.function.name, args, ok: s.ok, result: s.result });
          msgs.push({ role: 'tool', tool_call_id: c.id, content: S(JSON.stringify(s.result)) });
        }
      }
      return { reply: '', tools, tokens, ms: Date.now() - t, note: 'stopped after 4 tool rounds' };
    },
  };
}
