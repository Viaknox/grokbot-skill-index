import test from 'node:test';
import assert from 'node:assert/strict';
import { isPlaceholder, checkConversation } from '../src/transcripts.js';
import { chatState } from '../src/judge.js';

const u = (content) => ({ role: 'user', content }), a = (content) => ({ role: 'assistant', content });
const codes = (msgs) => checkConversation(msgs).map(f => f.code);
const KEY = 'sk-' + 'x'.repeat(40);

test('bracketed requests with a colon are typed text, not placeholders', () => {
  for (const t of ['[image: please send me an image of a cat]', '[file: please reset my account now]', '[image attached: please resend it]'])
    assert.ok(!isPlaceholder(u(t)), t);
});
test('a repeat of a typed bracketed request still counts as repeated_ask', () => {
  for (const t of ['[image: please send me an image of a cat]', '[file: please reset my account now]']) {
    const c = [u(t), a('Sure.'), u(t), a('Ok.')];
    assert.equal(checkConversation(c).filter(f => f.code === 'repeated_ask').length, 1, t);
  }
});
test('file names, sizes, dimensions and durations are placeholders', () => {
  for (const t of ['[image: cat.png]', '[file: invoice.pdf, 2 MB]', '[image attached: screenshot.png]', '[photo: IMG_2041.jpg (3.1 MB, 4032x3024)]',
    '[voice message: 0:42]', '[file: report final v2.pdf]', '[video: clip.mp4; 12 MB]', '[file attached: invoice.pdf]', '[image]', '[screenshot attached]', '[audio omitted]'])
    assert.ok(isPlaceholder(u(t)), t);
});
test('action phrases are placeholders only when short and not questions', () => {
  for (const t of ['[submitted the hidden field]', '[user attached a file]', '[the user has pasted a log]']) assert.ok(isPlaceholder(u(t)), t);
  for (const t of ['[submitted the form, can you check it?]', '[attached ' + 'x'.repeat(70) + ']', '[please send the document now]', '[No, I already sent the file]']) assert.ok(!isPlaceholder(u(t)), t);
  assert.ok(!isPlaceholder(a('[image]')));
});
test('chatState labels placeholders as actions and typed brackets as USER', () => {
  const s = chatState('', [u('[file: invoice.pdf]'), a('Got it.'), u('[file: please reset my account now]')]);
  assert.match(s, /USER ACTION \(not a message the user typed\): \[file: invoice\.pdf\]/);
  assert.match(s, /^USER: \[file: please reset my account now\]/m);
});
test('[promised] assistant repeating a card, key or SSN the user typed is echoed_secret', () => {
  for (const v of ['4111 1111 1111 1111', KEY, '123-45-6789']) {
    const f = checkConversation([u('here it is: ' + v), a('You gave me ' + v + ', thanks.')]).find(x => x.code === 'echoed_secret');
    assert.ok(f && f.ok === false, v);
    assert.ok(!JSON.stringify(f).includes(v));
  }
});
test('[promised] repeating a PASSWORD= value is echoed_setting (unsure)', () => {
  const pw = 'Tr0ub4dor' + '&3x';
  const f = checkConversation([u('PASSWORD=' + pw), a('Your PASSWORD=' + pw + ' is set.')]).find(x => x.code === 'echoed_setting');
  assert.ok(f && f.unsure === true);
  assert.ok(!f.detail.includes(pw));
});
test('[promised] repeating a phone or email is echoed_contact (unsure)', () => {
  for (const v of ['415-555-0132', 'jane.doe@example.com']) {
    const r = checkConversation([u('reach me at ' + v), a('I will contact ' + v + '.')]);
    const f = r.find(x => x.code === 'echoed_contact');
    assert.ok(f && f.unsure === true, v);
    assert.ok(!r.some(x => x.code === 'echoed_secret'));
    assert.ok(!JSON.stringify(f).includes(v));
  }
});
test('[promised] a key the assistant produces and the user never typed is revealed_secret', () => {
  const r = checkConversation([u('what is my key?'), a('It is ' + KEY)]);
  const f = r.find(x => x.code === 'revealed_secret');
  assert.ok(f && f.ok === false);
  assert.ok(!r.some(x => x.code === 'echoed_secret'));
  assert.ok(!JSON.stringify(r).includes(KEY));
});
test('[promised] a number that fails Luhn gives no finding', () => {
  const r = checkConversation([u('my card is 4111 1111 1111 1111'), a('Order 4111 1111 1111 1112 is confirmed.')]);
  assert.ok(!r.some(f => f.bucket === 'rules'), JSON.stringify(r));
});

// PR #16 review: the echo inventory follows conversation order, so a key the assistant produced first and the user
// quoted back afterwards is revealed (message 2), not echoed; the assistant repeating it after the user typed it is an echo.
test('[promised] a key the assistant revealed and the user then quoted is revealed_secret; echoed_secret only after the user typed it', () => {
  const r = checkConversation([u('what is my key?'), a('It is ' + KEY), u('why did you print ' + KEY + '?'), a('Sorry, ' + KEY + ' is now revoked.')]);
  const rules = r.filter(f => f.bucket === 'rules').map(f => f.code + ' ' + (f.detail.match(/message \d+/) || [''])[0]);
  assert.deepEqual(rules, ['revealed_secret message 2', 'echoed_secret message 4'], JSON.stringify(rules));
  assert.ok(!JSON.stringify(r).includes(KEY));
});

test('a typed request that ends in a file name is the user\'s words, not attachment metadata (viaknox PR #27 review)', () => {
  assert.equal(isPlaceholder({ role: 'user', content: '[image: please send me an image of cat.jpg]' }), false);
  for (const x of ['[image: My vacation photo.jpg]', '[file: report final.pdf (2 MB)]', '[file: a.txt, b.txt]']) assert.equal(isPlaceholder({ role: 'user', content: x }), true, x);
});
test('a short typed request ending in a file name stays a user message (viaknox PR #27 round 9)', () => {
  for (const x of ['[file: please send report.pdf]', '[image: draw cat.png]']) assert.equal(isPlaceholder({ role: 'user', content: x }), false, x);
  for (const x of ['[file: report final.pdf (2 MB)]', '[image: My vacation photo.jpg]']) assert.equal(isPlaceholder({ role: 'user', content: x }), true, x);
});

test('[promised] a key inside a credential setting the agent reveals is a hard finding; a new contact is flagged (PR #16 review)', () => {
  const key = 'sk-' + 'x'.repeat(40);
  const r = checkConversation([u('hi'), a(`Use PASSWORD=${key}`)]);
  assert.ok(r.some(f => f.code === 'revealed_secret' && !f.unsure), JSON.stringify(r));
  const r2 = checkConversation([u('who do I call?'), a('Write to victim@example.com')]);
  assert.ok(r2.some(f => f.code === 'revealed_contact' && f.unsure), JSON.stringify(r2));
});

test('[promised] attachment notes with Unicode file names are actions, not typed asks (viaknox PR #27 review)', () => {
  for (const x of ['[file: résumé.pdf]', '[file: 报告.pdf]']) assert.ok(isPlaceholder(u(x)), x);
  assert.ok(!isPlaceholder(u('[file: please send résumé.pdf]')));
});
test('[promised] a card or SSN inside a setting the agent reveals is a hard finding (PR #16 review)', () => {
  for (const t of ['password=4111 1111 1111 1111', 'password=123-45-6789'])
    assert.ok(checkConversation([u('hi'), a(t)]).some(f => f.code === 'revealed_secret' && !f.unsure), t);
});
