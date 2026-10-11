// Minimal OpenRouter client. The key comes from the environment (TUNEUP_OPENROUTER_KEY) or a .env-style file
// passed with --keyfile; it is never logged.
import { readFileSync } from 'node:fs';

export function loadKey(keyfile) {
  if (process.env.TUNEUP_OPENROUTER_KEY) return process.env.TUNEUP_OPENROUTER_KEY.trim();
  if (!keyfile) throw new Error('No OpenRouter key: set TUNEUP_OPENROUTER_KEY or pass --keyfile');
  const m = readFileSync(keyfile, 'utf8').match(/^\s*(?:export\s+)?[A-Z_]*OPENROUTER[A-Z_]*\s*=\s*"?([^"\r\n]+)"?/im);
  if (!m) throw new Error('No OPENROUTER line found in ' + keyfile);
  return m[1].trim();
}

export function client(key, { base = 'https://openrouter.ai/api', fetchImpl = fetch, timeoutMs = 90_000 } = {}) {
  let spent = 0;
  // Retries rate limits and provider hiccups (429/5xx) with back-off; other errors fail at once.
  async function post(path, body, attempt = 0) {
    const r = await fetchImpl(base + path, {
      method: 'POST',
      headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json', 'x-title': 'Agent Tune-Up' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const j = await r.json().catch(() => ({}));
    if ((r.status === 429 || r.status >= 500) && attempt < 4) {
      await new Promise(res => setTimeout(res, (2 ** attempt) * 1500 + Math.random() * 500));
      return post(path, body, attempt + 1);
    }
    if (!r.ok) throw new Error(`OpenRouter ${path} ${r.status}: ${(j.error && j.error.message) || 'error'}`.slice(0, 300));
    spent += (j.usage && j.usage.cost) || 0;
    return j;
  }
  return {
    chat: (body) => post('/v1/chat/completions', body),
    decide: (body) => post('/alpha/decisions', body),
    spent: () => spent,
  };
}
