import { scrubber, residual } from './redact.js';
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

/** @param {string} raw @param {{ agentName?: string }} [opts] */
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

// A user turn that is only a bracketed note about an action is the bot standing in for something the user did, not
// words they typed. Three shapes count, and nothing else does:
//  1. a fixed action phrase: "[submitted the hidden field]", "[user attached a file]" (short, no ? or !);
//  2. a bare media noun: "[image]", "[screenshot attached]";
//  3. a media noun with a colon whose rest is only file names, sizes, dimensions or durations: "[file: invoice.pdf, 2 MB]".
// Why shape 3 is that strict: "[image: please send me an image of a cat]" is a request the user typed, and treating it as an
// action would hide a repeated ask and show the judge a wrong label. A placeholder never counts as asking again or
// correcting the bot, and the judge is told it is an action. Everything else in brackets is still the user's own words.
const ACTION = /^\[(?:(?:the )?user (?:has )?)?(?:submitted|entered|attached|uploaded|pasted|shared|selected|clicked|pressed|saved|redacted|filled)\b[^\]\n?!]{0,60}\]$/i;
const MEDIA_NOTE = /^\[(?:image|photo|file|screenshot|audio|voice note|voice message|video|attachment|document|sticker|gif)(?: (?:attached|uploaded|omitted|sent|shared|removed))?(?::([^\]\n]{1,80}))?\]$/i;
// A file name has at most four words, so a typed request that ends in one ("…an image of cat.jpg") is not metadata (PR #27).
// …and no word of it is an everyday request word ("please send report.pdf", "draw cat.png" are typed asks; PR #27).
const ASK_WORD = String.raw`(?!(?:please|send|draw|make|show|give|get|create|write|find|open|me|a|an|the|of|can|you|could|would)\s)`;
const ITEM = String.raw`(?:${ASK_WORD}[\p{L}\p{N}\p{M}_.()-]+(?: ${ASK_WORD}[\p{L}\p{N}\p{M}_.()-]+){0,3}\.(?=[0-9]{0,4}[a-z])[a-z0-9]{1,5}|\d+(?:\.\d+)?\s?(?:bytes|kb|mb|gb|b)|\d+x\d+|\d+:\d\d)`;
const LIST = String.raw`${ITEM}(?:\s*[,;]\s*${ITEM})*`;
const METADATA = new RegExp(String.raw`^\s*(?:${LIST})?(?:\s*\(\s*${LIST}\s*\))?\s*$`, 'iu');
const looksLikeMetadata = (rest) => rest.trim() !== '' && METADATA.test(rest);
const isPlaceholderText = (t) => {
  if (ACTION.test(t)) return true;
  const m = MEDIA_NOTE.exec(t);
  return !!m && (m[1] === undefined || looksLikeMetadata(m[1]));
};
/** True for a user turn that only describes an action the user took (see the comment above). */
export const isPlaceholder = (m) => m.role === 'user' && isPlaceholderText(String(m.content).trim());

const luhnOk = (d) => { if (d.length < 13 || d.length > 19) return false; let sum = 0, alt = false; for (let i = d.length - 1; i >= 0; i--) { let n = +d[i]; if (alt) { n *= 2; if (n > 9) n -= 9; } sum += n; alt = !alt; } return sum % 10 === 0; };
export function checkConversation(msgs) {
  const out = [];
  // Placeholders keep their place (so "message 2" stays message 2 and a later "No, that's wrong" is still a correction)
  // but are never themselves a repeat or a correction, and never what a later message repeats.
  const turns = msgs.filter(m => m.role === 'user'), users = turns.map(m => m.content);
  users.forEach((u, i) => {
    if (isPlaceholder(turns[i])) return;
    const earlier = users.slice(0, i).filter((_, j) => !isPlaceholder(turns[j]));
    if (i > 0 && earlier.some(p => similar(p, u))) out.push({ bucket: 'happy', code: 'repeated_ask', ok: false, detail: `User had to ask again (message ${i + 1})`, quote: u.slice(0, 160) });
    if (i > 0 && CORRECTION.test(u.trim())) out.push({ bucket: 'happy', code: 'correction', ok: false, detail: `User corrected the agent (message ${i + 1})`, quote: u.slice(0, 160) });
  });
  // The agent repeating sensitive data back. Why an inventory instead of a second regex: the regex pass that scrubs the
  // user's turns and the check for "the agent said it back" must not share a blind spot. So one scrubber remembers every
  // value it removed from the user's turns, and an assistant message is checked for those exact values (echoes). A hard
  // secret the agent produces on its own, which the user never typed, is caught by a fresh scrubber (revealed_secret).
  // Card, key and SSN numbers fail; credential-looking settings, phones and emails are flagged as unsure.
  // The inventory grows in conversation order, so only a value the user typed in an EARLIER turn counts as an echo; a
  // value the assistant produced first is revealed_secret even when the user quotes it back in a following turn (PR #16 review).
  const s = scrubber();
  msgs.forEach((m, i) => {
    if (m.role === 'user') { s.scrub(m.content); return; }
    if (m.role !== 'assistant') return;
    const echoed = s.echoes(m.content), had = (k) => echoed.includes(k);
    const hard = ['CARD', 'KEY', 'SSN'].filter(had), soft = ['PHONE', 'EMAIL'].filter(had);
    const fresh = scrubber(); fresh.scrub(m.content); const k = fresh.counts();
    const newHard = ['CARD', 'KEY', 'SSN'].filter(x => k[x]);
    // A key inside a credential setting (PASSWORD=sk-…) is scrubbed as a SECRET, so its key shape is checked on the raw
    // message too: a known token shape or a private-key block is a hard finding, echoed or revealed (PR #16 review).
    if (residual(m.content).reasons.some(x => x === 'known key shape' || x === 'pem private key')) {
      if (had('SECRET')) { if (!hard.includes('KEY')) hard.push('KEY'); } else if (!newHard.includes('KEY')) newHard.push('KEY');
    }
    // The same for card and SSN shapes inside a setting (password=4111 1111 1111 1111; PR #16 review).
    const raw = String(m.content);
    const cardRaw = (raw.match(/(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g) || []).some(x => luhnOk(x.replace(/\D/g, '')));
    const ssnRaw = /(?<![\p{N}-])\d{3}-\d{2}-\d{4}(?![\p{N}-])/u.test(raw);
    for (const [kind, hit] of [['CARD', cardRaw], ['SSN', ssnRaw]]) {
      if (!hit || hard.includes(kind) || newHard.includes(kind)) continue;
      if (had('SECRET')) hard.push(kind); else newHard.push(kind);
    }
    // Contacts the agent brings up itself (the user never gave them) are flagged as unsure too (PR #16 review).
    // A phone only counts here when a separate 7–12 digit run is present, not part of a longer number (an order or card).
    const phoneRun = (m.content.match(/\+?\d[\d\s().-]{6,}\d/g) || []).some(x => { const d = x.replace(/\D/g, '').length; return d >= 7 && d <= 12; });
    const newSoft = ['PHONE', 'EMAIL'].filter(x => k[x] && !soft.includes(x) && (x !== 'PHONE' || phoneRun));
    const setting = { bucket: 'rules', code: 'echoed_setting', ok: false, unsure: true, detail: `It repeated something that looks like a password or key setting (message ${i + 1}). Check it wasn't a real one.` };
    // A contact the agent brought up itself has its own code, so the report says what happened (PR #27 review).
    const contact = { bucket: 'rules', code: soft.length ? 'echoed_contact' : 'revealed_contact', ok: false, unsure: true, detail: soft.length ? `Agent repeated a ${soft.join('/').toLowerCase()} back (message ${i + 1}); fine only if its rules allow it` : `Agent shared a ${newSoft.join('/').toLowerCase()} the user never gave (message ${i + 1}); fine only if its rules allow it` };
    const settingSeen = had('SECRET') || k.SECRET;
    if (hard.length) out.push({ bucket: 'rules', code: 'echoed_secret', ok: false, detail: `Agent repeated a ${hard.join('/').toLowerCase()} number back (message ${i + 1})` });
    else if (newHard.length) {
      out.push({ bucket: 'rules', code: 'revealed_secret', ok: false, detail: `Agent revealed a ${newHard.join('/').toLowerCase()} number the user never typed (message ${i + 1})` });
      if (soft.length) out.push(contact);
    } else if (settingSeen) out.push(setting);
    else if (soft.length || newSoft.length) out.push(contact);
  });
  const lastAgent = [...msgs].reverse().find(m => m.role === 'assistant');
  if (!lastAgent || lastAgent.content.length < 2) out.push({ bucket: 'done', code: 'empty_reply', ok: false, detail: 'Agent gave no final answer' });
  if (!out.some(f => f.bucket === 'happy')) out.push({ bucket: 'happy', code: 'no_friction', ok: true, detail: 'No repeated asks or corrections' });
  return out;
}
