# Scrubber v2: hand-off

Build session for PR #14 (`fix-placeholder-turns`), 2026-10-12. The brief is `docs/SCRUBBER-V2-BRIEF.md`, the plan and
decisions are `docs/SCRUBBER-V2-PLAN.md`, the promise is `docs/SCRUBBER-CONTRACT.md` (version 2.0.0). Paul merges;
nothing here was merged, pushed to `main`, or marked ready.

## Test count

| | Tests | Result |
|---|---|---|
| Before (HEAD `79a3266`) | 79 | 77 pass on Windows (2 tests built the CLI path with `URL.pathname`); 79 on Linux/macOS |
| After (`npm test`, commit `7de8ea1`) | 308 | 308 pass, exit 0 |
| After PR #16 review round 3 (commit `87b3b71`) | 311 | 311 pass, exit 0 |
| After PR #16 review round 4 (Codex, 11 threads on `87b3b71`) | 325 | 325 pass, exit 0 |
| After PR #16 review round 5 (Linux CI, tiers; head `441b2b7`) | 325 | 325 pass on Windows (Node 24) and on Linux (WSL Ubuntu, Node 22); `.github/workflows/test.yml` runs the suite on `ubuntu-latest` |

New files: `engine/test/scrubber-v2.test.js` (corpus, known bypasses, placeholders, residual, sanitize, echoes, mutation
survivors, review-2 bypasses, five self-attack rounds), `boundary.test.js`, `transcripts-v2.test.js`, `fuzz.test.js`
(property fuzz + differential oracle), `perf.test.js`, `engine/test/corpus/*` (16 template fixtures, `expand.js`,
`oracle-shapes.json`, `attack-round-1..5.json`, `THIRD_PARTY.md`), `engine/scripts/mutate.mjs`.

## Known bypasses (brief list and review round 2)

| Case | Old result (v1) | New result (v2) |
|---|---|---|
| `PASSWORD=` + 200 chars + `LEAKED_SUFFIX`, unquoted | suffix leaked (200-char cap) | whole value to end of line removed |
| same, `"…"` and `'…'` quoted | suffix leaked | whole quoted field removed, escaped quotes skipped |
| Truncated `RSA PRIVATE KEY` with `Proc-Type: 4,ENCRYPTED` / `DEK-Info` and a blank line after the header | body after the blank line leaked | removed to the end of input (or to the footer when present) |
| Credential value containing a never_send term, restore round trip | `[PRIVATE_1]` left inside the restored value | `[SECRET_1]` wraps `[PRIVATE_1]`; `unscrub` restores in reverse creation order |
| `[Acme]` with never_send `Acme` | leaked (bracket excluded by the lookbehind) | `[[PRIVATE_1]]` |
| `[Acme Corp]` with never_send `Acme Corp` | leaked | scrubbed, case-insensitive, restored |
| `Authorization: Basic dXNlcjpwYXNzd29yZA==` | leaked (only Bearer was known) | header value removed to end of line; bare `Basic`/`Bearer`/`Digest` tokens removed anywhere |
| `API_KEY="abcde\"CorrectHorse9!"` | `CorrectHorse9!` leaked after the escaped quote | whole field removed |
| `OPENAI-API-KEY=CorrectHorse9!` with never_send `OpenAI` | value leaked (the term broke the name) | `[PRIVATE_1]-API-KEY=[SECRET_1]` (name resolved before the check) |
| `[image: please send me an image of a cat]` | counted as a placeholder turn | typed text; a repeat counts as `repeated_ask` |
| `[file: please reset my account now]` | counted as a placeholder turn | typed text |
| `secretary: Jonathan Smith`, `tokenLimit=`, `tokenizer=`, `max_tokens:` | `secretary:` was blanked | left alone (false-positive traps) |
| `password-` × 10000 (linear time) | 12 s in an earlier round, fixed in v1 | 11 ms |
| Review 2: `PASSWORD=abcde`, `API_KEY=12345` | v1 needed 6+ characters | scrubbed, no minimum |
| Review 2: `PASSWORD="alphaX\nbravo\ncharlie"` | value cut at the first line | consumed through the closing quote |
| Review 2: `ACME-PASSWORD=` with never_send `Acme` | value leaked | `[PRIVATE_1]-PASSWORD=[SECRET_1]` |
| Review 2: `--password=x`, `--api-key=x`, `--token x` | partly leaked | all three removed, and the result is not falsely held |
| Review 2: bare `key=CorrectHorseBatteryStaple` | leaked | scrubbed in dotenv form (`key=`, `export key=`); `key:` labels stay (contract) |
| Review 2: never_send term in a tool name, schema property name or `required` entry (`adapters.js`) | sent unscrubbed | the run is refused before any request is built |
| Review 3: `Use the password 'cat123'`, `use password x9k2`, `The secret phrase is secret12345.`, `my api key here is abc123xyz` | leaked (prose forms) | scrubbed; `my password yesterday.` and `API key rotation policy is documented` stay |
| Review 3: `usér@exämple.com`, `δοκιμή@παράδειγμα.δοκιμή` | leaked (ASCII email rule) | `[EMAIL_n]`, round trip |
| Review 4 (PR #16, Codex): URL password over 256 characters | leaked (regex ceiling) | whole userinfo goes, no ceiling |
| Review 4: `<textarea name="password">hunter2</TEXTAREA>` | leaked (case-sensitive closing tag) | element text goes |
| Review 4: `password=[ATTACK_1]` | treated as already sanitized | only the eight real kinds are reserved; the value is scrubbed |
| Review 4: `credentials:` with a nested YAML map | both scalars leaked (scope abandoned) | every scalar under the scope goes at any depth (plan D16) |
| Review 4: Markdown row `\| a\\\|b \| hunter2 \|` under a `password` header | row skipped (cell count) | escaped pipe is cell text; `hunter2` goes |
| Review 4: `PASSWORD=[SECRET_1])CorrectHorse9!` | trailing data leaked (any delimiter exempted) | whole value goes; closers, another placeholder or a named sibling still count as complete (plan D17) |
| Review 4: `user@Acme` with never_send `Acme` | leaked (`@` excluded for the one-letter-term case) | `user@[PRIVATE_1]` by a second sweep after the email rule; `jo@x.example` with term `x` is still `[EMAIL_1]` |
| Review 4: never_send term in `$defs`, `definitions`, `patternProperties`, `dependentSchemas`, `dependentRequired`, `dependencies` names | sent unscrubbed | the run is refused like a property name |
| Review 4: `check --consent` on a chat over the 4,000,000-character cap | `ScrubError` crashed the command | one `judge:held` finding (unsure), exit 0, no call (`judgeHeld` shared with `evaluate`) |
| Review 4: key revealed by the agent in message 2 and quoted by the user in message 3 | `echoed_secret` (inventory built from all user turns first) | `revealed_secret` (message 2); an echo only after the user typed it |
| Review 4: perf budgets in fixed milliseconds | failed on the reviewer's slower machine | ratios against an in-test baseline unit (plan D18) |
| Review 5 (PR #16, Linux CI): `2000 YAML lines, growing indent` perf payload took 1.8 s on Node 22 (24 ms on Node 24) | `ScrubError` from the 2 s cap, `npm test` red on Linux | the review-3 prose rule's unbounded `[ \t]+` lookbehind is bounded to 4 blanks; 32 ms on Node 22, root cause fixed, payload kept at 2M characters |
| Found while adding the review-4 perf payloads: 4000 `<textarea name="password">x</textarea>` lines | 1.6 s (the sibling-pair pass rescanned to the end of the text for every name with no `value=`) | 150 ms, linear (last search remembered; the indexed-variable search bounded to its 20 lines) |

## Fuzz, oracle, perf

- **Fuzz:** `FUZZ_SEED=20261012`, `FUZZ_ITER=1500` (override with those variables; `FUZZ_ONLY=<i>` replays one iteration).
  Final run: 1500 of 1500 caught by `scrub()` alone, 0 only by the residual hold, 0 failures; round trip and idempotence
  hold on every iteration.
- **Differential oracle:** 458 samples (292 gitleaks, MIT, commit `b58d3f1`; 166 detect-secrets, Apache-2.0, commit
  `5e14193`; see `engine/test/corpus/THIRD_PARTY.md`), stored as shapes and rebuilt with the seeded generator. Line
  form: 411 scrubbed, 45 held by the residual scan, 0 failures. Bare "knowable" values (plan D13): 117 scrubbed, 262
  held, 0 failures; 81 bare values are not knowable (low-entropy shapes, UUID-shaped ids, context-only values) and are
  reported, not asserted. Two sample lines are
  accepted misses (`secrete.assign(…)`, `other_value_here: 1234567890a`; contract "Known non-coverage").
- **Perf** (`engine/test/perf.test.js`, best of 3, this Windows machine, after the PR #16 review round): budgets are
  ratios against a baseline unit measured in the same process (plan D18); here 1 unit = 6.1 ms. `sanitize` of a
  realistic 60k mixed chat 31.4 ms = 5.2 units (budget 12 = 100 ms on the reference machine); residual alone 0.6 ms;
  growth 10k 3.7 ms, 20k 8.8 ms, 40k 18.6 ms, 80k 38.9 ms (4.4× for 20k→80k, limit 6×, linear is 4×); 21 ReDoS
  payloads all under 18 units (worst `token: |` × 20000, 103.9 ms = 17.1 units; the new `<textarea name=password>` × 5000
  payload 95.3 ms = 15.7 units; limit 60 units = 500 ms on the reference machine). On Linux (WSL Ubuntu, Node 22.23):
  1 unit = 5.9 ms, sanitize 60k 35.2 ms = 6.0 units, growth 80k/20k 5.5×, the growing-indent payload 31.7 ms after the
  lookbehind fix (1753.8 ms before it). `.github/workflows/test.yml` (ubuntu-latest, Node 22, `cd engine && npm test`)
  runs the suite on every push and pull request. v1 scrubbed the same 60k in about 1.5 ms; v2 pays for whole-scope, sibling-pair and
  folded-view passes.

## Mutation check (`engine/scripts/mutate.mjs`)

Full report: `docs/SCRUBBER-V2-MUTATION.md` (final code, commit `7de8ea1`, 63 minutes on this machine).

| Run | Mutants | Killed | Killed by timeout | Survivors |
|---|---|---|---|---|
| Baseline, pre-round-1 scrubber (366 lines) | 175 | 165 | 5 | 5 |
| Final scrubber (1048 lines) | 645 | 350 | 15 | 280 |

The five baseline survivors (letter/digit name splits, the empty-name guard, the structural-key index) are killed by the
"mutation:" tests. The 280 final survivors sit almost entirely in the passes added during the self-attack rounds
(`scrubLineForms` 44, `scrubTables` 36, `entryEnd` 18, `scrubNameValuePairs` 16, `scrubHtmlAttrs` 15, `scrubMultipart`
15, `fold` 12, `scrubScopes` 11, `scrubXml` 10), each of which is exercised by one fixture per shape, so a comparison
flipped at a bound (`<` to `<=`), a bound constant raised by one (64 KB scope limits, the 8192-entry fold cache, the
20-line sibling look-ahead), a surrogate-pair or C1-control branch, or one alternative of a multi-branch regex survives.
By operator: cmp 116 of 138, and-or 68 of 166, regex 37 of 144, int 32 of 70, eq 24 of 97, bool 3 of 18, ret 0 of 12.
None of the survivors is a "never matches" mutant of a credential rule that a fixture covers; they are boundary and
bound-constant cases. Killing them needs per-pass boundary tests (values exactly at and past each bound, a surrogate
pair inside a name, a C1 control as a separator, each alternative of each combined regex), which is listed under
"Deferred" rather than done here, because every such test is a new fixture family and the build had to stop somewhere.
A survivor is not a leak: the leak evidence is the corpus, the oracle, the fuzz and the six attack rounds.

## Secret scan

gitleaks 8.30.1 (default rules), run from the repo root after the rewrite:

| Scan | Command | Findings |
|---|---|---|
| Working tree | `gitleaks dir .` | 0 |
| Local commits | `gitleaks git . --log-opts="origin/fix-placeholder-turns..HEAD"` | 0 |

The repo's own gate (`sk-…`, `ghp_…`, `AKIA…`, `xox…`, PEM header) matches nothing in the branch diff either.

## Self-attack

Attacker: Codex CLI (`gpt-5.5`), a non-Claude model that never saw `redact.js`, with the contract as threat model, the
public API and the corpus tokens. Every confirmed bypass became a fixture (`engine/test/corpus/attack-round-N.json`)
before it was fixed. The brief's second attacker (a fresh Claude subagent) could not run: two attempts were stopped by
the Claude Code safety classifier while generating payloads (see "Deferred").

| Round | Candidates | Confirmed | Held only | Fixtures | Fixed | Declined (documented non-coverage) |
|---|---|---|---|---|---|---|
| 1 | 63 | 30 | 6 | 33 | 33 | placeholder-looking input, a bare base64 blob split over lines |
| 2 | 70 | 33 | 6 | 29 | 29 | bare prose values, Jupyter split sources, `.reg` generic names, PowerShell variable indirection, "see below" |
| 3 | 66 | 16 | 2 | 14 | 14 | camel-case embedded term (whole-word promise; residual holds it), dotted abbreviation, spreadsheet formula, comment between key and separator |
| 4 | 63 | 22 | 0 | 18 | 18 | YAML merge keys, XML entities, doc comments, term split by punctuation |
| 5 | 66 | 34 | 2 | 32 | 32 | SSH agent socket path, shell `case` branch, hyphenated compound with a cue-less secret |
| 6 | 70 | 5 | 13 | 1 | 1 (a regression of a documented promise: a value prefixed by placeholder-looking text) | 3 open classes below; 1 evaluator false alarm (`pre[SECRET_1]post` is scrubbed, the checker matched the literal `[SECRET_` window) |

Classes fixed, in order: invisible and look-alike characters (a folded view with an index map), Unicode and arrow
separators, JSON and percent-encoded names, two-token lines, CSV/TSV/SQL/Markdown/HTML table columns, YAML explicit
keys and tagged blocks, HTML attribute forms, credential scopes (INI/TOML/HOCON/HCL/XML), Kubernetes `kind: Secret`,
command forms, prose and copula forms in ten languages, whole-scope removal, adjacent pairs, aliases, multipart,
Makefile operators, name/value sibling pairs, qualifiers, URL path segments.

### Round 6 findings (open, for Paul)

Round 6 confirmed only 5 of 70 candidates (13 more were caught by the fail-closed residual hold rather than the main
pass, which is the intended backstop: TOML quoted dotted keys, a credential cue in a YAML anchor name or custom tag,
JSON5 comments between key and colon, HTML inside an `srcdoc` attribute, a shell `read -s -p 'Password:'` here-doc, a
`cmd` `for %password` loop, a protobuf `json_name` option, a CSV header after a BOM, a spreadsheet `&` concatenation,
a never-send term in mathematical bold letters). Still open after this build:

- JSON Patch / JSON Pointer paths: `{"op":"add","path":"/users/0/password","value":"…"}` (a path whose last segment is a
  credential should mark the `value` sibling; an extension of the name/value sibling rule to `path`).
- Erlang/Elixir proplists with atom keys: `{password, "…"}` (the tuple rule accepts only quoted names).
- A never-send term spelled with spaces between its letters (`A c m e`, including no-break spaces).


## Tiers and CI

The contract now has two tiers (`docs/SCRUBBER-CONTRACT.md`, "Tiers"): **Promised** (merge-blocking: emails, phones,
Luhn cards, US SSNs, IPv4, private-key blocks, the listed token formats, URL userinfo, Basic/Bearer/Digest,
credential-named settings in dotenv/JSON/YAML/INI/headers including Authorization and Cookie, CLI credential flags,
never_send terms, and the scrubber's own mechanisms) and **Best effort** (everything else: disguises, other
languages, prose, tables, XML/HTML, scopes, sibling pairs, code forms, netrc, URL query parameters). Every scrubber
test name starts with `[promised]` or `[best-effort]` and every `attack-round-*.json` fixture carries `tier` (the
loader refuses one without it): 61 of the 70 named scrubber-v2 tests, the fuzz test, every boundary and perf test and
the six echo tests are promised; 6 of the 127 attack fixtures are promised, the rest best effort; the oracle test is
best effort. `npm run test:promised` runs the merge-blocking subset; `npm test` and CI run everything.

## Deferred (needs Paul)

- **Push and secret scanning.** The branch was pushed after the local commits were re-made (a first attempt was
  rejected: GitHub push protection decodes base64 and had found the scanners' example values inside the earlier
  base64-stored oracle file). Root-cause fix, no bypass: the oracle now holds only line templates and value *shapes*
  (`engine/test/corpus/oracle-shapes.json`), every value is rebuilt by the seeded generator at test time, the two v1
  tests that held literal key shapes build them from pieces, and the local commits were re-made from
  `origin/fix-placeholder-turns` so no commit ever contained a secret-shaped literal. gitleaks 8.30.1: working tree
  `gitleaks dir .` = 0 findings; history `gitleaks git --log-opts="origin/fix-placeholder-turns..HEAD"` = 0 findings
  (both recorded below under "Secret scan").
- **Second red-team model.** Only Codex attacked. A Claude-model round (or a human-run one) is still owed to meet the
  brief's "at least 2 models" line.
- **Self-attack did not converge.** Rounds found 30, 33, 16, 22, 34 bypasses; each round opened a new structural family.
  The integrator stopped after five fix batches and one verification round (round 6). Its findings are listed above as
  open classes; the contract's "Known non-coverage" lists what is deliberately out of scope.
- **Mutation survivors.** 280 of 645 mutants survive, concentrated in the self-attack passes (see the mutation
  section). Per-pass boundary tests would raise the kill rate; a reviewer should treat the mutation score as "the
  self-attack passes are covered by one example each", not as proof of their edges.
- **D11** (`adapters.js` replay path through `outbound` and the residual gate). The replay path scrubs every field with
  the shared scrubber and now refuses runs with never-send words in tool or property names, but its requests do not pass
  the residual hold. Needs a decision on simulated tool results.
- **Over-scrubbing inside credential scopes.** By design (plan: when in doubt, remove more), every value inside a
  credential-named object or section goes, including a `username`, and since the PR #16 review round a YAML scope is
  walked at any depth (plan D16). Reports therefore show `[SECRET_n]` for some harmless
  fields; the judge treats those as "unsure", never a hard fail.
- `engine/src/judge.js:34` contains the word "later" in a pre-existing question string (not changed code; gate 5 is
  about changed code).
