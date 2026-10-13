# Scrubber v2: build plan

Written before any production code, as `docs/SCRUBBER-V2-BRIEF.md` requires. The brief is the contract; this file is
how the build session carries it out, what each agent owns, and the decisions made along the way.

## Phase 0 baseline (2026-10-12)

- HEAD `79a3266` contains the brief (`18428bc` and `79a3266`).
- `cd engine && npm test`: 79 tests, 77 pass, 2 fail on this Windows machine. Both failures spawned `cli.js` with
  `new URL('../cli.js', import.meta.url).pathname`, which yields `/F:/work/...` on Windows and cannot be spawned. They
  pass on Linux and macOS. Fixed in `engine/test/codex.test.js` with `fileURLToPath` (a test-only change, no product
  change). After the fix: 79 tests, 79 pass, exit 0. This is the "before" count for the hand-back.
- Read: `engine/src/redact.js`, `transcripts.js`, `openrouter.js`, `judge.js`, `writer.js`, `evaluate.js`,
  `adapters.js`, `cli.js`, every test file, `engine/REVIEW-LESSONS.md`.
- Tools present: Node 24.18, git 2.55, `gh` (logged in), Codex CLI 0.154 (logged in, usable as the non-Claude attacker).

## Agents, files and order

| Phase | Agent | Model | Owns (nothing else) |
|---|---|---|---|
| 1 | **corpus** | main model | `engine/test/corpus/*.txt`, `engine/test/corpus/*.json`, `engine/test/corpus/README.md`, `engine/test/scrubber-v2.test.js` |
| 2 | **scrubber** | main model | `engine/src/redact.js` |
| 2 | **boundary** | main model | `engine/src/openrouter.js`, `judge.js`, `writer.js`, `evaluate.js`, `engine/test/boundary.test.js` |
| 2 | **transcripts** | smaller model | `engine/src/transcripts.js`, `engine/test/transcripts-v2.test.js` |
| 2 | **harness** | smaller model | `engine/test/fuzz.test.js`, `engine/test/perf.test.js`, `engine/scripts/mutate.mjs`, `engine/test/corpus/oracle-shapes.json`, `engine/test/corpus/THIRD_PARTY.md` |
| 3 | **attacker** (fresh, did not write `redact.js`) | a model that did not write the code, plus Codex CLI | writes only `engine/test/corpus/attack-round-N.json`; fixes go to the scrubber owner |
| all | **integrator** (this session) | `engine/package.json` test script, `cli.js` (one call-site change), existing test files when an interface changes, `docs/*`, `engine/REVIEW-LESSONS.md`, merges |

Order: Phase 1 runs alone (tests first, no production code). Phase 2's four agents run in parallel in separate git
worktrees (`F:\work\wt-<agent>` on branch `wt/<agent>`); the integrator merges them one at a time into
`fix-placeholder-turns` in the order scrubber, boundary, transcripts, harness, running the full suite after each merge.
Phase 3 repeats attack rounds until a round finds nothing.

Phase 1 tests are committed with their own script (`npm run test:v2`) and recorded as failing on the old code; they move
into the `test` script in the same commit that lands the new `redact.js`, so every commit still has `npm test` green.

## Interface contract between agents (so they can build in parallel)

`engine/src/redact.js` keeps `scrubber({ terms }) → { scrub, unscrub, counts }` with placeholders `[KIND_n]`, and adds:

```js
export const SCRUBBER_VERSION = '2.0.0';
export class Sanitized   // frozen; fields: text (string), held (boolean), reasons (string[]), version (string)
                         // a brand check (#private field) so a plain object with the same shape is refused
export class ScrubError extends Error   // thrown when the scrubber hits its time or size cap
export function residual(text, { terms = [] } = {}) → { held: boolean, reasons: string[] }
   // the second mechanism: entropy runs, known prefix shapes, leftover never_send terms. Pure, no state.
export function isCredentialName(name) → boolean   // kept from v1
scrubber(...) also returns:
   sanitize(text, { maxMs = 2000, maxChars = 4_000_000 } = {}) → Sanitized   // scrub + residual; idempotent on its own output
   echoes(text) → string[]   // kinds (KEY, SECRET, CARD, SSN, PHONE, EMAIL, PRIVATE) whose inventoried values appear verbatim in `text`
```

Kinds: `KEY` (known token shapes, PEM blocks, URL userinfo, Authorization/Cookie header values), `SECRET` (a value found
by its setting name), `PRIVATE` (never_send terms), `EMAIL`, `CARD`, `SSN`, `PHONE`, `IP`. Placeholder numbering is per
kind, in order of first sight, stable across every text one scrubber sees.

`engine/src/openrouter.js` keeps `loadKey` and `client(key, opts) → { chat, decide, spent }` and adds the one boundary:

```js
export class HeldBack extends Error   // message: 'unsure: we held back part of this chat to protect a secret'
export async function outbound(or, kind, sanitized, build)
   // kind: 'chat' | 'decide'. Refuses (throws TypeError) unless `sanitized instanceof Sanitized`;
   // throws HeldBack if sanitized.held; otherwise calls or[kind](build(sanitized.text)).
   // Never logs, never stores, never returns anything but the model's reply.
```

`judge.js`: `judgeCase(or, sanitized)` and `judgeConversation(or, sanitized, opts)` accept only a `Sanitized`. On
`HeldBack` they return one local finding `{ bucket: 'rules', code: 'judge:held', ok: false, unsure: true, detail: 'unsure: we held back part of this chat to protect a secret' }`
and make no call. `writer.js`: `proposeFix` builds the prompt from scrubbed pieces, sanitizes the whole prompt once, and
sends through `outbound`; `HeldBack` propagates (a tune-up cannot proceed without the writer). `evaluate.js` calls
`judgeCase(or, scrub.sanitize(transcript(...)))`. `cli.js` `check` calls `judgeConversation(or, scrub.sanitize(chatState(...)), ...)`
(integrator change).

`transcripts.js`: `isPlaceholder` per brief item 10; `checkConversation` computes `echoed_secret` from `scrub.echoes()`
over an inventory built by scrubbing every user turn first (brief item 9). A hard secret that the assistant introduces
and the user never typed is reported as `revealed_secret` (same bucket, hard fail), so the v1 coverage is not lost.

## Brief item → test map

| Brief item | Where it is tested |
|---|---|
| 1 line-level redaction, no 200-char cap, continuation lines | `scrubber-v2.test.js` "line level": dotenv, YAML block, trailing `\`, unterminated quote, escaped quote, 200+ char values |
| 2 word-boundary signals and context | `scrubber-v2.test.js` "signals" (password/secret/api_key/token; Authorization Basic/Bearer/Digest; Cookie/Set-Cookie; URL userinfo) and "false-positive traps" (`secretary:`, `tokenLimit=`, `session`/`cookie` in prose) |
| 3 PEM variants | `scrubber-v2.test.js` "pem": plain, RSA/EC/DSA/OPENSSH/ENCRYPTED, Proc-Type/DEK-Info + blank line, no footer, over 16 KB |
| 4 never_send first, in brackets, name prefixes | `scrubber-v2.test.js` "never_send": `[Acme]`, `[Acme Corp]`, `OPENAI-API-KEY=` with `OpenAI`, case-insensitive |
| 5 reserved placeholders, dependency-ordered unscrub, counts | `scrubber-v2.test.js` "placeholders": `[SECRET_1]` wrapping `[PRIVATE_1]`, idempotent scrub, counts after nesting |
| 6 fail-closed residual scan | `scrubber-v2.test.js` "residual" (entropy run, prefix shape, leftover term → held) and `boundary.test.js` (held → no fetch) |
| 7 one outbound boundary | `boundary.test.js`: mocked fetch, no seeded secret or never_send term in any serialized body for judge and writer; plain string refused; HeldBack → no call; scrubber error → no call |
| 8 linear time | `perf.test.js`: 60k < 100 ms, 10k/20k/40k/80k growth, ReDoS payloads |
| 9 echoed_secret by inventory | `transcripts-v2.test.js` |
| 10 placeholder turns | `transcripts-v2.test.js`: `[image: please send me an image of a cat]` and `[file: please reset my account now]` are typed text; `[image: cat.png]`, `[file: invoice.pdf, 2 MB]` are actions |
| Known bypasses (brief list) | `scrubber-v2.test.js` "known bypass" block, one test per bypass, plus `transcripts-v2.test.js` for the two placeholder cases |
| Differential oracle | `fuzz.test.js` "oracle": every sample secret in `corpus/oracle-shapes.json` (gitleaks MIT, detect-secrets Apache-2.0) is absent from the output |
| Property fuzz | `fuzz.test.js`: seeded generator, seed printed on failure, iteration count recorded in the hand-off |
| Mutation check | `engine/scripts/mutate.mjs`, report in the hand-off |
| AI red team / self-attack | Phase 3 fixtures `corpus/attack-round-N.json`, run by `scrubber-v2.test.js` |

## Decisions (security choices: when unsure, remove more text)

- **D1 Credential value extent.** Once a line has a credential signal, the value is removed from the separator to the
  end of the line, or to the end of a quoted field when the value starts with a quote and the quote is terminated on
  that line (escaped quotes do not end it). An unterminated quote, a trailing `\`, or a YAML block indicator (`|`, `>`)
  or empty value followed by deeper-indented lines carries the removal into the following lines. Comments after the
  value (`# mine`) go too.
- **D2 Minimum value length.** None. `password: 1` is scrubbed. A missed secret is worse than a blanked short value.
- **D3 URL userinfo.** The whole `user:pass` is replaced (one KEY), not only the password.
- **D4 Authorization header.** Any `Authorization:` or `Proxy-Authorization:` value is removed whatever the scheme, and
  any bare `Basic <base64>` or `Bearer <token>` is removed. `Cookie:` and `Set-Cookie:` values are removed whole.
- **D5 netrc.** `password <value>` with no separator is treated as a credential only in netrc shape (the line starts
  with `machine`, `default`, `login` or `password`), so chat lines such as "I forgot my password yesterday" are kept.
  Command-line flags `--password <value>`, `--token <value>` and `-p<value>` are credentials.
- **D6 `secretary:` and friends.** Credential words must be whole parts of a name (split on `_`, `-`, `.`, camelCase):
  `secretary`, `tokenizer`, `secretSanta` (parts `secret`, `santa`: `secret` is a whole part, so this IS scrubbed,
  which the brief accepts), `tokenLimit`/`max_tokens` (usage context) are not credentials. The v1 test that expected
  `secretary: Jonathan Smith` to be flagged is changed to `password_hint: Jonathan Smith`, which keeps its intent (a
  credential-looking setting is "unsure", never a hard fail) and follows the brief's false-positive list.
- **D7 Residual scan thresholds.** Hex runs of 20+ characters with at least one letter and Shannon entropy above 3.0
  bits per character; base64-class runs of 24+ characters with entropy above 4.0; a known prefix shape anywhere; any
  never_send term left in the text (case-insensitive, inside brackets too). Thresholds are constants in `redact.js`
  and are checked by the false-positive corpus (prose, URLs, code identifiers must not be held).
- **D8 Held result.** When the residual scan finds anything, nothing is sent: the judge returns a single unsure finding,
  the writer refuses. Users see "unsure: we held back part of this chat to protect a secret".
- **D9 Pre-existing placeholder-looking text.** Text that already looks like `[KIND_n]` in the input is left alone by
  `scrub` (it is not re-matched or nested) and `unscrub` only restores placeholders this scrubber made. Internally the
  scrubber marks its own placeholders with private-use sentinels so no pattern can match inside them.
- **D10 Time cap.** `sanitize` throws `ScrubError` if scrubbing exceeds `maxMs` (default 2 s) or the input exceeds
  `maxChars` (default 4,000,000). A `ScrubError` means no call.
- **D11 Replay model path.** `adapters.js` (the replay model) is outside the brief's file list; it still scrubs every
  field through the shared scrubber but does not pass the residual gate. Listed under "Deferred (needs Paul)".
- **D12 Oracle data at rest.** Sample secrets copied from gitleaks and detect-secrets are stored base64-encoded in
  `corpus/oracle-shapes.json` and decoded at test time, so no literal secret shape sits in the repo (gate 2) and secret
  scanners on GitHub stay quiet.
- **D13 Oracle bare values.** The differential oracle asserts the *line* form of every sample strictly. The *bare* form
  (the secret alone, no name, no shape) is asserted only when it is what the contract's residual scan promises to
  catch: a known prefix shape, or a contiguous run of 20 or more token characters with Shannon entropy of at least 3.0
  bits per character for hex and 4.0 otherwise, and not a UUID (request ids look the same). Low-entropy bare strings
  from the scanners' test data (`abcdefghijklmnopqrstuvwxyz`, `1234567890a`), UUID-shaped client ids and values whose
  only signal is their context (`elastic:P@ssw0rd$1` without the `-u` flag) are counted and reported, not asserted;
  they are listed as known non-coverage in the contract.
- **D14 Credential words, widened by the oracle.** `pw`, `pass`, plural forms (`passwords`, `secrets`, `tokens`),
  `key`/`keys` as the last part of a multi-part name (`iam-key`, `ssh_key`) except after a structural word (public,
  foreign, primary, sort, partition, hash, cache, row, index, composite, idempotency, dedup, translation, i18n,
  shortcut, hot, map, dict, object, array, lookup); `!=` and `==` count as separators; command-line flags of any name
  that is a credential name, and curl `-u user:pass`; XML/HTML elements whose tag name is a credential name.
- **D15 Pre-existing placeholders never collide.** When the input already contains `[KIND_n]`, that number is reserved
  for that kind, so a placeholder this scrubber makes never equals a literal already in the text (otherwise `unscrub`
  could loop forever). `unscrub` is a single pass in reverse creation order, which is dependency order.
- **D16 A YAML credential scope is a record at any depth** (PR #16 review, 2026-10-13). A credential-named YAML block
  map used to become a plain container as soon as one child was structured, so `credentials:` with a nested map kept
  `username: admin` and the nested `account: hunter2`. Now every scalar under it goes at any depth (nested maps are
  walked, block scalars take their block, list items lose their scalar); the line-level test that kept `region: eu`
  under `creds:` was changed to expect it gone, the option that removes more text.
- **D17 Placeholder exemptions are narrow** (PR #16 review). Only the eight kinds the scrubber mints are reserved
  tokens; `[ATTACK_1]` is data. A placeholder is "already scrubbed" only when nothing but closers, punctuation, another
  placeholder or a named sibling field follows it on the line; `[SECRET_1])CorrectHorse9!` is a value and goes whole.
- **D18 Perf budgets are ratios against an in-test baseline** (PR #16 review). The reviewer's machine took 163 ms for
  the 100 ms case, so fixed milliseconds measured the hardware. One unit is a fixed set of linear scans over the same
  text, measured in the same process; the brief's 100 ms and 500 ms become 12 and 60 units (about 8 ms per unit on
  the reference machine). Growth compares 80k to 20k (under 6×, linear is 4×), best of five in two interleaved rounds.
- **D19 No unbounded lookbehind** (PR #16 CI on Linux, 2026-10-13). `(?<=\p{L}[ \t]+)` re-scans every blank of a long
  indent at each position; Node 24 happened to hide it (24 ms), Node 22 did not (1.8 s, over the 2 s cap on a slower
  runner). Lookbehinds are bounded (`{1,4}`), and the Linux CI workflow is the guard.
- **D20 Two coverage tiers** (PR #16 review). Promised shapes are merge-blocking and are what the privacy page may
  state; everything else is best effort, fixed when found. Every fixture is tagged so a reviewer can tell which tier a
  failure belongs to; disguised spellings, other languages and prose forms are best effort even when the underlying
  shape is promised.

## Phase 1 record: new suite against the old `redact.js`

`engine/test/scrubber-v2.test.js`: 53 tests. Against v1 `redact.js`: **46 fail, 7 pass**. The 7 passes are regression
guards or false-positive traps that must keep passing, so they test v1 behaviour that v2 must not lose. Run with
`npm run test:v2` until the new scrubber lands (then the file joins `npm test`).

| Test group | Old result | Note |
|---|---|---|
| corpus dotenv, json-compact, json-pretty, yaml, pypirc, netrc, headers, urls, pem-truncated, pem-big, never-send, chat | fail | 200-char cap, no continuation, headers, userinfo, no-footer PEM, brackets |
| corpus npmrc | fail | strengthened with a 220-char `_authToken` |
| corpus pem (footered variants) | pass | regression guard: v1 already removes footered blocks |
| corpus prose | pass | false-positive trap: must stay unchanged |
| known bypass x7 (PASSWORD+200, truncated RSA, nested restore, [Acme], Basic, escaped quote, OPENAI-API-KEY) | fail | nested restore uses `Acme-<v>` so v1's ordering bug shows |
| line level x7 (backslash, unterminated quote, YAML block, comment, CRLF, CLI flags, long JSON field) | fail | |
| signals x8 (traps, spellings, Digest/Proxy, Cookie, netrc shape, userinfo, look-alike names, zero-width in value) | fail | spellings use 210-char values |
| pem: JSON-escaped no footer; OPENSSH blank line/Comment with and without footer | fail | |
| never_send: case-insensitive, whole-word guards | pass | regression guard (v1 review test) |
| never_send: KEY/PRIVATE/SECRET as terms | fail | |
| placeholders: idempotent on fixtures | fail | |
| placeholders: pre-existing `[KIND_n]` left alone; counts and numbering stable | pass (2) | regression guards for item 5 |
| v2 api, residual x2, sanitize x3, echoes | fail | exports do not exist yet |
| regression guard x2 (PII placeholders; dates, prices, public keys, unscrub) | pass | guards |

Corpus assumptions the scrubber must honour (from the corpus agent): in compact JSON a field after a secret field on the
same line stays; in netrc `machine api.example.com` stays; `Password requirements: 12 characters minimum` and
`token_count: 42` are not credentials; zero-width and confusable characters in a credential name still trigger;
`residual()` must not hold prose, long URL paths, camelCase identifiers, UUIDs or placeholders, and must hold bare
40-char base64 or hex, `AKIA`+16, `sk-`+24, a PEM header fragment, a JWT and a leftover term inside brackets;
`echoes()` returns kinds only; a literal `[EMAIL_1]` in the input survives unchanged.

## Phase 3 record: self-attack

Attacker: the Codex CLI (`codex exec -m gpt-5.5`, a non-Claude model that never saw `redact.js`), given the contract as
threat model, the public API and the corpus template tokens, asked for 40+ concrete bypass inputs as JSON, with the
classes of every earlier round listed as "already fixed, look elsewhere". Candidates were run by an evaluator
(`scrub()` then `sanitize()`; a bypass is confirmed when an 8-character window of a secret or a never-send term survives
`scrub()` and `sanitize()` is not held). Confirmed bypasses became `engine/test/corpus/attack-round-N.json` fixtures
before the fix; the scrubber owner fixed them; the suite picks every round up automatically.

The brief also asks for a fresh Claude subagent as a second attacker. Two attempts (one framed as a red team, one framed
as writing redaction test fixtures) were stopped by the Claude Code safety classifier while generating payloads, so no
Claude-model round ran. This is listed under "Deferred (needs Paul)".

| Round | Candidates | Confirmed (leak) | Held only | Made fixtures | Declined as non-coverage | Fixed |
|---|---|---|---|---|---|---|
| 1 | 63 | 30 | 6 | 33 | placeholder-looking input (D9), a bare base64 blob split over lines | 33 |
| 2 | 70 | 33 | 6 | 29 | bare prose values, Jupyter split sources, .reg generic names, PowerShell variable indirection, "see below" | 29 |
| 3 | 66 | 16 | 2 | 14 | camel-case embedded term (v1 whole-word promise; residual holds it), dotted abbreviation, spreadsheet formula, comment between key and separator | 14 |
| 4 | 63 | 22 | 0 | 18 | YAML merge keys, XML entities, doc comments, term split by punctuation | 18 |
| 5 | 66 | 34 | 2 | 32 | SSH agent socket path, shell `case` branch, hyphenated compound with a cue-less secret, camel-case term | 32 |

Rounds did not converge to zero: each round the attacker found a new structural family (invisible characters and
separators; credential scopes; other languages; whole-scope removal; name/value sibling pairs). After round 5 the
integrator set a stop rule: one more fix batch (round 5) and one verification round (round 6); whatever round 6 finds
is recorded in the hand-off as open classes for Paul, not fixed in this build.

## Deferred (needs Paul)

- D11: route the replay-model requests in `adapters.js` through `outbound` too. Needs a decision on how simulated tool
  results (which can be anything the suite author wrote) should be treated by the residual gate.
- Push: the first four commits of this build (plan, Phase 1 corpus merge, Phase 1 record) carry the author email from
  the machine's global git config, which GitHub's "block pushes that expose my email" setting rejects; rewriting those
  commits was declined by the session's permission classifier, so nothing was pushed. Paul can either rewrite the four
  commits' author/committer email to the noreply address (`git rebase --rebase-merges --exec 'git commit --amend
  --no-edit --reset-author'` from `origin/fix-placeholder-turns` with `user.email` set to the noreply address) or relax
  the setting, then push `fix-placeholder-turns`. Later commits already use the noreply address (repo-local config).
- Second red-team model: a Claude-model attacker round could not be run (safety classifier); only Codex attacked. A
  human-run second round, or a different tool, is needed to meet the brief's "at least 2 models" line.
- Open attack classes after round 6: see `docs/SCRUBBER-V2-HANDOFF.md`.
