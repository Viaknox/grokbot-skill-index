# Engine review lessons

Findings from the PR #12 reviews (Copilot, Codex, Aikido) that came back more than once. Check new engine code against
each row before opening a PR; the test named in the last column guards it.

| Lesson | Why it bit us | Guard |
| --- | --- | --- |
| Everything sent to a remote model goes through the scrubber, including tool schemas and anything a suite file supplies | tool descriptions and enums leaked unscrubbed | `test/codex.test.js` codex 1 |
| A suite file is lower-trust input: it must not choose where your credentials go, run unbounded work, or run arbitrary regexes | `${ENV}` in headers, redirects, `(a+)+` patterns | codex 10, round 2 redirects, round 4 validation |
| Privacy settings are part of a run's identity | `tune` could run with a weaker `--private` list than its baseline | round 4 private identity |
| A completion claim needs a matching, latest, successful action; unclear cases are "unsure", never a pass | lookups, unrelated actions and old successes were accepted as proof | codex 2, round 2-4 claims |
| Unsure verdicts never dilute, hide or inflate a result | unsure diluted failure rates | codex 8 |
| Compare failures by stable identity (case, rule, what was violated, without vote percentages), counted | regressions were masked or invented | round 2/4 regressions |
| Unknown is not zero | http usage printed as 0 tokens | round 4 unknown usage |
| Secrets are found by their setting name too, not only by known value shapes (any name holding key/secret/token/password/credential) | `AWS_SECRET_ACCESS_KEY=…` reached the judge | `test/codex.test.js` "credentials named like…" (viaknox PR #14, Aikido) |
| A privacy promise is enforced in the request, not left to account settings: every OpenRouter call sends `provider.data_collection: 'deny'` and fails rather than falls back | no-training was only an account setting | `test/codex.test.js` "every OpenRouter call…" (viaknox PR #14, Aikido) |
