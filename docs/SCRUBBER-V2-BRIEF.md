# Scrubber v2: build brief

**Owner:** Paul (merges). **Builder:** a Claude Code session with parallel agents. **Hosted side, docs and review threads:** the separate Claude session; don't touch the viaknox repo.
**Why:** four review rounds on PR #14 kept finding new leak edge cases. The frontier panel (4/4, consensus 0.96) chose a redesign plus a full review over more patching.

## Scope (this repo only)
- `engine/src/redact.js`: the redesign.
- `engine/src/transcripts.js`: placeholder fix (2 open threads).
- `engine/src/openrouter.js`, `judge.js`, `writer.js`, `evaluate.js`: one outbound boundary.
- `engine/test/**`: new tests, corpus and fuzz.
- Work on branch `fix-placeholder-turns` (PR #14). Use agent worktrees, with one integrator committing to the branch.

## Hard rules
- Never merge, never push to `main`, and never mark the PR ready. Paul does those.
- Never print, copy or commit real keys or tokens. Test secrets are built at runtime (`'sk-' + 'x'.repeat(40)`) so the source holds no literal secrets.
- No new runtime npm dependency. Rule sets from other scanners may be copied **as data** only from MIT or Apache-2.0 sources (gitleaks = MIT, detect-secrets = Apache-2.0); credit them in `engine/test/corpus/THIRD_PARTY.md`. **Do not copy from trufflehog (AGPL).** Check each source's LICENSE before copying.
- Keep the public API the same: `scrubber({terms})` → `{scrub, unscrub, counts}`, placeholders `[KIND_n]`.
- `cd engine && npm test` must pass before every commit (check the exit code; don't pipe it through grep).
- End commit messages with:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01A2mqnwASb4jTHXiQoNPzPE`

## Design (required)
1. **Line-level redaction.** If a line (or a JSON/YAML field) contains a credential signal, replace the whole value through the end of the line or field, plus continuation lines (indented YAML blocks, trailing `\`, unterminated quotes, escaped quotes). There is no 200-character cap on what gets removed.
2. **Credential signals use word boundaries and context.** `password`, `secret`, `api_key`, `token` (not `tokenLimit`, `secretary`), `Authorization: Basic|Bearer|Digest`, `Cookie`/`Set-Cookie`, and URL userinfo `user:pass@`. Ordinary chat that merely mentions "session" or "cookie" must not be blanked.
3. **PEM.** Any `-----BEGIN … PRIVATE KEY-----` (including `ENCRYPTED`, `OPENSSH`, `RSA`/`EC`/`DSA`, Proc-Type/DEK-Info headers and blank lines) is removed through the footer. With no footer, it is removed to the end of the input. Blocks over 16 KB are handled the same way.
4. **never_send terms run first**, match case-insensitively, match inside brackets (`[Acme]`), and must not break later credential detection (`OPENAI-API-KEY=…` with never_send `OpenAI` must still redact the value).
5. **Placeholders are reserved tokens.** They are never re-matched or nested, and `unscrub` restores them in dependency order. `counts()` stays accurate.
6. **Fail-closed residual scan** using a *different mechanism* from the main pass: high-entropy runs (length ≥ 20, Shannon entropy over a tuned threshold), known prefix shapes, and any leftover never_send term. If anything remains, **do not call OpenRouter**. Return a local result marked "unsure: we held back part of this chat to protect a secret".
7. **One outbound boundary.** All judge and writer calls go through one function that accepts only a `Sanitized` value from the scrubber plus the residual scan. Restore maps never leave the request scope and are never logged. A scrubber error or timeout means no call.
8. **Linear time.** No catastrophic regexes, and no re-scanning the whole string inside a loop. Hosted budget: 60k characters in under 100 ms. The CLI may take bigger inputs, but within a time cap.
9. **echoed_secret** = an exact match of user-side secret values (inventoried during scrubbing) found inside assistant text, not a second regex.
10. **Placeholder turns** (`transcripts.js`): only fixed action phrases count. A media noun with a colon (`[image: …]`, `[file: …]`) counts only when the rest looks like a file name or metadata (`x.png`, `2 MB`), never like a sentence.

## Assurance (we have no human reviewer, so evidence replaces opinion)
- **Corpus** `engine/test/corpus/`: dotenv, compact and pretty JSON, YAML blocks, `.npmrc`/`.pypirc`/`.netrc`, Basic/Bearer/Cookie headers, URL userinfo, every PEM variant above, escaped quotes, values over 200 characters, never_send inside brackets and as name prefixes, Unicode look-alikes and zero-width characters, nested placeholders, false-positive traps (`secretary:`, `tokenLimit=`, `session` in prose).
- **Differential oracle:** for every sample secret in gitleaks and detect-secrets test data, the secret's characters must not appear in our output.
- **Property fuzz** (plain `node:test` plus a seeded generator, no dependency): random wrapping, splitting, quoting and casing around seeded secrets. Assert the seed never survives. Record the seed so failures can be repeated.
- **Mutation check:** a script that flips each regex and branch in `redact.js` and confirms at least one test fails. Report survivors.
- **Outbound interception test:** mock `fetch` and assert that no seeded secret or never_send term appears anywhere in the serialized request body, for judge and writer.
- **Growth test:** at 10k, 20k, 40k and 80k characters, time must grow roughly linearly, with ReDoS payloads included.
- **AI red team:** at least 2 models that didn't write the code get the threat model and corpus and must return **concrete bypass inputs**. Every confirmed bypass becomes a fixture *before* it is fixed.
- All 14 open review threads on #14 and viaknox #25 become fixtures (listed below).

## Known bypasses that must become fixtures
- `PASSWORD=` + 200 characters + `LEAKED_SUFFIX`, quoted and unquoted.
- Truncated `RSA PRIVATE KEY` with `Proc-Type: 4,ENCRYPTED` / `DEK-Info`, and a blank line after the header.
- A credential value that contains a never_send term, plus restoring it (`[SECRET_1]` wrapping `[PRIVATE_1]`).
- `[Acme]` and `[Acme Corp]` with never_send terms.
- `Authorization: Basic dXNlcjpwYXNzd29yZA==`.
- `API_KEY="abcde\"CorrectHorse9!"`.
- `OPENAI-API-KEY=CorrectHorse9!` with never_send `OpenAI`.
- `[image: please send me an image of a cat]` and `[file: please reset my account now]` must count as typed text.

## Definition of done (merge bar)
Merging is blocked only by:
- a confirmed leak path;
- ReDoS or a hang;
- logging before scrubbing;
- an unscrub round-trip failure;
- a mismatch with the privacy page.

Minor review comments don't block. When done:
- all tests pass;
- the 14 known bypasses are fixed;
- the oracle and fuzz suites are green;
- the mutation report is attached to the PR;
- the red-team results are summarised in the PR body;
- `docs/SCRUBBER-CONTRACT.md` is written: version `2.0.0`, input shapes, placeholder format, covered shapes, known non-coverage (names and addresses unless listed);
- `engine/src/redact.js` exports `SCRUBBER_VERSION`.

Hand back to the hosted-side session when done. It re-syncs viaknox #25, runs the frontier-gate verify, and replies on the threads.
