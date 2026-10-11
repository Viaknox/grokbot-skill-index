import { scrubber } from './redact.js';
// Paste-in adapter: turns chats people copy or export into conversations of {role, content} messages.
// Accepts JSON exports ([{role, content}], {messages: [...]}, an array of those, or {conversations: [...]})
// and plain text with speaker labels ("User:", "Bot:", …). Conversations in text are separated by a line of --- or ===.

const USER = /^(user|you|me|human|customer|client|visitor|q)\s*:\s*/i;
const AGENT = /^(assistant|bot|ai|agent|grok|chatgpt|claude|gemini|copilot|support|a)\s*:\s*/i;

// Only user and agent turns count; system, developer and tool messages are not part of the conversation.
const roleOf = (r) => /^(user|human|customer)$/i.test(r) ? 'user' : /^(assistant|bot|ai|agent|model)$/i.test(r) ? 'assistant' : null;
const norm = (m) => ({ role: roleOf(String(m.role || m.author || m.sender || '')),
  content: String(m.content ?? m.text ?? m.message ?? '').trim() });

const twoSided = (c) => c.some(m => m.role === 'user') && c.some(m => m.role === 'assistant');

export function parseTranscripts(raw, { agentName } = {}) {
  const txt = String(raw).trim();
  if (txt.startsWith('[') || txt.startsWith('{')) {
    const j = JSON.parse(txt);
    const list = Array.isArray(j) ? (Array.isArray(j[0]) || (j[0] && j[0].messages) ? j : [j]) : (j.conversations || [j]);
    return list.map(c => (Array.isArray(c) ? c : c.messages || []).map(norm).filter(m => m.role && m.content)).filter(twoSided);
  }
  const named = agentName ? new RegExp(`^${agentName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*:\\s*`, 'i') : null;
  // Linear split on separator lines (a regex with \s* around ^/$ was quadratic on long runs of blank lines).
  const blocks = [[]];
  for (const line of txt.split(/\r?\n/)) { if (/^[ \t]*(?:-{3,}|={3,})[ \t]*$/.test(line)) blocks.push([]); else blocks[blocks.length - 1].push(line); }
  return blocks.map(b => b.join('\n')).map(block => {
    const msgs = [];
    for (const line of block.split(/\r?\n/)) {
      let m;
      if ((m = line.match(USER))) msgs.push({ role: 'user', content: line.slice(m[0].length) });
      else if ((m = (named && line.match(named)) || line.match(AGENT))) msgs.push({ role: 'assistant', content: line.slice(m[0].length) });
      else if (msgs.length && line.trim()) msgs[msgs.length - 1].content += '\n' + line;
    }
    return msgs.map(m => ({ ...m, content: m.content.trim() })).filter(m => m.content);
  }).filter(twoSided);
}

// Rule checks that only make sense on real conversations: friction the user felt.
const CORRECTION = /^(no\b|nope|wait\b|that'?s (wrong|not (it|right|what i))|i said|i already (said|told)|again[,!?.]|still (wrong|not)|you('re| are) (wrong|not listening)|wrong\b|not what i asked)|\b(why did you (say|tell)|you said\b|can you even|i (still )?(haven'?t|didn'?t) (get|got|receive))/i;
const words = (s) => new Set(s.toLowerCase().match(/[a-z0-9']+/g) || []);
const similar = (a, b) => { const A = words(a), B = words(b); if (A.size < 3 || B.size < 3) return false; let n = 0; for (const w of A) if (B.has(w)) n++; return n / Math.min(A.size, B.size) >= 0.7; };

export function checkConversation(msgs) {
  const out = []; const users = msgs.filter(m => m.role === 'user').map(m => m.content);
  users.forEach((u, i) => {
    if (i > 0 && users.slice(0, i).some(p => similar(p, u))) out.push({ bucket: 'happy', code: 'repeated_ask', ok: false, detail: `User had to ask again (message ${i + 1})`, quote: u.slice(0, 160) });
    if (i > 0 && CORRECTION.test(u.trim())) out.push({ bucket: 'happy', code: 'correction', ok: false, detail: `User corrected the agent (message ${i + 1})`, quote: u.slice(0, 160) });
  });
  // The agent repeating sensitive data back: card, key and ID numbers fail; phones and emails are flagged as unsure.
  msgs.forEach((m, i) => {
    if (m.role !== 'assistant') return;
    const c = scrubber(); c.scrub(m.content); const k = c.counts();
    const hard = ['CARD', 'KEY', 'SSN'].filter(x => k[x]), soft = ['PHONE', 'EMAIL'].filter(x => k[x]);
    if (hard.length) out.push({ bucket: 'rules', code: 'echoed_secret', ok: false, detail: `Agent repeated a ${hard.join('/').toLowerCase()} number back (message ${i + 1})` });
    else if (soft.length) out.push({ bucket: 'rules', code: 'echoed_contact', ok: false, unsure: true, detail: `Agent repeated a ${soft.join('/').toLowerCase()} back (message ${i + 1}); fine only if its rules allow it` });
  });
  const lastAgent = [...msgs].reverse().find(m => m.role === 'assistant');
  if (!lastAgent || lastAgent.content.length < 2) out.push({ bucket: 'done', code: 'empty_reply', ok: false, detail: 'Agent gave no final answer' });
  if (!out.some(f => f.bucket === 'happy')) out.push({ bucket: 'happy', code: 'no_friction', ok: true, detail: 'No repeated asks or corrections' });
  return out;
}
