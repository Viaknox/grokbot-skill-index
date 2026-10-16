# Agent Tune-Up CLI: plan

**Status:** plan for Paul's sign-off. Nothing built yet. **Owner:** Paul (decides, merges, approves releases).
**Builder:** a Claude Code session after sign-off. Same pattern as `docs/SCRUBBER-V2-PLAN.md`: tests first, then build,
then attack and mutation, then frontier-gate `verify` against the checklists below.

## 1. Decisions (final, 2026-10-16)

| # | Decision | Choice | How decided |
|---|---|---|---|
| D1 | npm name | `agenttuneup` (unscoped). Also reserve the `@viaknox` npm org | Paul |
| D2 | Releases | GitHub Release UI with `cli-vX.Y.Z` tags, trusted publishing (OIDC) with provenance, Paul approves each | Frontier panel, unanimous (0.98) |
| D3–D5 | Gate policy | **Strict everywhere, sequenced:** strict CI gate ships first (R1); then pass / fail / undetermined in the report and `tune` (R2), with the hosted connector re-copied the same day | Panel split (0.31); Paul chose B |
| Q3 | Judge in CI | Opt-in only (`--consent`). Without it the result reads **PASS: local rules only** | Panel checklist |

Panel records: `F:\ENV\Claude outputs\frontier-gate\2026-10-16-cli-gate-policy\` and `...-cli-release-tags\`.

## 2. Facts this plan rests on (verified 2026-10-16)

| Fact | Where |
|---|---|
| A local CLI exists (`check`, `run`, `tune`), not installable (`private: true`, no `bin`), zero dependencies | `engine/cli.js`, `engine/package.json` |
| `check` and `run` always exit 0 | `engine/cli.js` |
| A run whose findings are all ok **or unsure** counts as passed; held chats are unsure, so they pass too | `engine/src/report.js` `runPassed`, `engine/src/judge.js` `heldFinding` |
| `pass_rate` is rounded (79.6 shows as 80) | `engine/src/report.js` |
| `tune` lift and regressions use the same lenient pass, so a fix that makes answers vaguer can show lift | `engine/cli.js` `liftOf`, `report.js` `regressions` |
| The hosted card is already strict: unsure 🟨 and held ⬜ are never shown as passed | viaknox `src/lib/tuneup-card.js` |
| The hosted connector vendors `engine/src` at b2ffa57; changes reach it only by a re-copy PR | viaknox `src/lib/tuneup-engine/SOURCE.txt` |
| 475 engine tests, all passing; CI runs them on Node 22 / Linux | `engine/test`, `.github/workflows/test.yml` |
| **`main` has no branch protection**; auto-merge off | GitHub API |
| Plugin releases use `v0.3.x` tags | git tags |
| README example paths (`examples/sample-chats.txt`, `sample-instructions.txt`) do not exist | `engine/README.md` |
| Quality tooling: `SathiaAI/quality-gate` already comment-reviews every Viaknox PR; `SathiaAI/sast-check` is not on this repo yet | both repos |

## 3. Releases

| Release | Contents | Channel |
|---|---|---|
| **R1** `cli-v0.1.0-rc.N` → `cli-v0.1.0` | Installable CLI, strict gate, exit codes, guards, release workflow, docs | `next` only |
| **R2** `cli-v0.2.0-rc.N` → `cli-v0.2.0` | pass / fail / undetermined in report.json, report.md and `tune`; one shared evidence classifier; same-day re-copy to the hosted connector | `next` only |
| **First `latest`** | Only after Paul approves written criteria: judge calibration (≥80% agreement with human labels), privacy notes, compatibility, failure handling | `latest` |

0.x semver: any change to the report schema, config or gate behaviour is a **minor** bump, never a patch.

## 4. Gate design (R1)

### Evidence states

Every evaluated item is one of: **ok**, **failed**, **undetermined** (judge unsure or text held), **missing** (expected but
not produced), **not requested** (judge not asked: rules-only). Only *ok* counts toward a pass. In R1 this lives in a new
pure module `engine/src/gate.js`; in R2 the report and `tune` use the same module (one implementation, checklist PG8).

### Defaults (strict; loosening is explicit and printed)

| Flag | Default | Meaning |
|---|---|---|
| `--min <0-100>` | **100** when gating | Strict pass rate from raw counts, never rounded |
| `--max-undetermined <0-100>` | **0** | % of judged items that may be undetermined |
| `--allow-rules-fail` | off | A "Follows your rules" failure always fails otherwise |
| `--consent` / `TUNEUP_CONSENT=1` | off | Sends scrubbed text to the judge. Without it: rules-only |
| `--gate` | off | Turns gating on; without it exit code is 0 whatever the result (today's behaviour) |
| `--json` | off | Writes `gate.json` |

Every loosened setting is printed in the verdict line and written to `gate.json`, so a weakened gate is visible in the
CI log.

### Verdicts and exit codes

| Exit | Verdict line | When |
|---|---|---|
| 0 | `PASS (judged)` | Gate on, all thresholds met with the judge |
| 0 | `PASS: local rules only` | Gate on, no `--consent`, rules met. Never badge-eligible |
| 1 | `FAIL` | Below threshold, a rules failure, or too many undetermined |
| 2 | `ERROR: usage/config` | Bad flag, bad suite, `--consent` with no key |
| 3 | `UNDETERMINED` | Nothing evaluated, expected cases missing, every requested judge call held, or the judge was requested but failed |

**A judge that was asked for and failed never falls back to rules-only** (exit 3, not `PASS: local rules only`).

`gate.json` records: engine version, policy (every threshold), evidence scope, suite id, judge model, raw counts per state.

## 5. Stories (each run through story-gate; quality-gate reviews every PR automatically)

| # | Story | Done when | Panel checklist (§10) |
|---|---|---|---|
| S0 | **Repo protection (Paul's clicks, guided)** | Branch protection on `main`: PRs required, `test` and `sast-check / scan` required, no force or direct pushes, Code Owner review required. CODEOWNERS covers `.github/**`, `engine/test/**`, `engine/src/gate.js`, `engine/package.json`, `.sast-check.toml`, `.github/CODEOWNERS`, release config | PG1, PG2, PT1, PT2, PT13 |
| S1 | Add sast-check | `.github/workflows/sast.yml` pinned by full SHA; zizmor clean on all workflows | PG2, PT5, PT11 |
| S2 | Tests first (R1) | §6 tests committed; a CI run linked in the PR shows them failing on today's code | PG10 |
| S3 | `gate.js` + CLI wiring | §6 green; no existing test changed except where this plan says | PG3–PG7, PG9, PT12 |
| S4 | Packaging | `bin`, `files` allowlist, `private` removed; `npm pack` shows only allowlisted files; tarball runs via `npx` | PT6, PT23 |
| S5 | Guards | No-skip check, test-count ratchet, golden known-bad fixture, mutation run on `gate.js` with zero survivors | PG10 |
| S6 | Release workflow | Triggers on `release: published` for `cli-v*` only; asserts tag = package version, commit on `main`, tests pass, pack allowlist; `id-token: write` only on publish job; actions pinned by SHA; explicit `--tag next` for pre-releases; approval summary shows version, channel, commit, file list with digests. Each release starts as a prepared release PR (version bump, CLI changelog, channel) that Paul merges; then Paul publishes the GitHub Release from the UI | PT3, PT4, PT7–PT11, PT15, PT16, PT20, PT22, PT23 |
| S7 | Docs | README uses `npx agenttuneup@<exact version>`; broken example paths fixed; outside-team CI guide (protect suites, never expose the key to fork PRs, `pull_request` not `pull_request_target`, Level 1 vs Level 2); 0.x compatibility policy; incident runbook; CHANGELOG | PG14, PT17, PT18, PT21 |
| S8 | npm bootstrap (Paul, guided) | `@viaknox` org reserved; first `0.1.0-rc.1` published to `next` from the release workflow's checks; trusted publisher configured; token publishing disallowed; 2FA and recovery confirmed | PT19 |
| S9 | R2: shared classifier | report.json, report.md and `tune` use pass / fail / undetermined; `tune` re-tests matched cases and repeats, reports evidence changes separately from behaviour gains, never says "verified" with incomplete evidence; old and new counts shown side by side for one release | PG8, PG11, PG13, PG15 |
| S10 | R2: hosted re-copy | Same-day viaknox PR re-copies `engine/src`, updates SOURCE.txt; a viaknox CI check fails if SOURCE.txt and vendored files disagree; hosted card output snapshot unchanged or explained | PG9, PG11 |
| — | Badges | Stay disabled until calibration and badge evidence rules are agreed | PG12 |

## 6. Tests (written first)

### Gate (`engine/test/gate.test.js`, pure)

| ID | Case | Expected |
|---|---|---|
| G1 | All ok, judged | exit 0, `PASS (judged)` |
| G2 | Strict rate equals `--min` exactly | exit 0 |
| G3 | One item below `--min` | exit 1 |
| G3b | 79.6% with `--min 80` | exit 1 (no rounding) |
| G4 | Every judge answer undetermined | exit 1 or 3, never 0 |
| G5 | `--consent`, every judge call held | exit 3 |
| G5b | `--consent`, judge request errors | exit 3, never `PASS: local rules only` |
| G6 | One rules failure, everything else ok | exit 1 |
| G7 | G6 with `--allow-rules-fail` | exit 0, and the loosening is printed and in `gate.json` |
| G8 | 1 undetermined with default `--max-undetermined 0` | exit 1 |
| G9 | No `--consent`, rules all ok | exit 0, `PASS: local rules only`, `gate.json.evidence = "rules-only"` |
| G10 | No `--gate` | exit 0 whatever the result |
| G11 | `--min` `-1`, `101`, `abc`, missing value | exit 2, nothing evaluated |
| G12 | Zero conversations or empty suite | exit 3 |
| G13 | Suite case expected but produced no run | exit 3 (missing never improves the denominator) |
| G14 | `gate.json` against a frozen schema | matches; includes version, policy, scope, raw counts |

### Package and CLI (`engine/test/cli-package.test.js`)

| ID | Case | Expected |
|---|---|---|
| P1 | `npm pack --dry-run` file list | only the allowlist; no `test/`, `.sqlite`, brand files |
| P2 | Install tarball in a temp dir, `npx agenttuneup --version` | version printed, exit 0 |
| P3 | `npx agenttuneup check <fixture> --gate`, no consent, fetch stubbed to throw | runs, no network call |
| P4 | Exit codes 0/1/2/3 propagate through `npx` | each matches the gate test |
| P5 | Fake key in env, network stubbed | key never in stdout, stderr, report.md, gate.json |
| P6 | Paths via `fileURLToPath` | works on Windows, Linux, macOS |

### Golden fixtures (offline, in CI)

| ID | Fixture | Expected |
|---|---|---|
| F1 | known-bad chats: fake "done", card number echoed | `FAIL`, names both |
| F2 | known-good chats | `PASS: local rules only` |
| F3 | all-undetermined (judge stubbed to 50%) | never exit 0 |

### R2 additions

| ID | Case | Expected |
|---|---|---|
| X1 | A tune attempt that turns failures into undetermined | lift is 0 or negative; not "verified" |
| X2 | report.md for a held chat | shows "couldn't tell", not PASSED |
| X3 | CLI and hosted card on the same chats | same counts per state |

## 7. Guards against "green just to merge"

| Guard | Catches |
|---|---|
| Branch protection + CODEOWNERS (S0) | A PR that loosens tests and code together, or edits its own CI |
| Red-first CI run linked in the PR (S2) | Tests that could never fail |
| Golden fixtures F1, F3 must fail (S5) | A gate weakened to always pass |
| No `skip` / `only` / `todo` in `engine/test` (S5) | Quietly disabled tests |
| Test-count ratchet `engine/test/BASELINE` = 475 now (S5) | Deleted tests |
| Mutation run on `gate.js`, zero survivors (S5) | Tests that pass whatever the code does |
| quality-gate review on every PR (automatic) | Weakened asserts, swallowed errors; findings get a written disposition |
| sast-check required (S1) | Security issues and risky workflow changes |
| Second-model diff review (Qwen or DeepSeek) for weakened tests | What a skim misses |
| frontier-gate `verify` against both checklists before each release | Skipped checklist items |

AI reviews are advisory. They do not replace a human security review where one is needed (panel item PT14).

## 8. Risks

| Risk | Mitigation |
|---|---|
| Strict defaults fail too many PRs while the judge is uncalibrated | Defaults are strict on purpose; teams loosen visibly; R1/R2 stay on `next`; calibration gates `latest` |
| CLI and hosted scores drift | One classifier (R2), same-day re-copy, SOURCE.txt check in viaknox, X3 |
| A bad publish breaks pinned CI users | Exact pins in docs, `next` first, incident runbook (deprecate, restore `latest`, never reuse versions or move tags) |
| Typosquats | Reserve `@viaknox`; publish the real name early via `next` |
| Teams leak their judge key to fork PRs | CI guide: `pull_request` only, secrets only in protected environments |

## 9. Not in this plan

Hosted sign-in from the CLI (free capped judge for CLI users), `fixes --apply`, badges. Separate plans after R2.

## 10. Panel checklists (the contract `verify` checks against)

### Gate policy (PG)

1. Enable branch protection on `main` to enforce CODEOWNERS, required checks, stale approval invalidation, and mandatory approval from Paul for gate, test, workflow, or policy changes.
2. Integrate `SathiaAI/sast-check` using a pinned SHA as a required CI check for the `tune-up` repository and protect all workflow files from unauthorized modification.
3. Implement a tri-state redesign (pass, fail, undetermined) that fails closed by default for missing credentials, missing results, or mandatory-rule failures unless explicit, visible overrides are configured.
4. Enforce a strict default gate requiring --min 100, --max-unsure 0, no mandatory-rule failures, and no missing evaluations, where unsure or held evidence never counts as passed.
5. Require explicit evidence scope selection where rules-only modes must display a prominent 'PASS: local rules only' verdict and cannot be triggered by judge failures.
6. Maintain judge use as opt-in with explicit consent, ensuring API keys or CI environments do not authorize data transmission without documented provider and scrubber disclosures.
7. Validate expected cases, repeats, and findings before scoring, ensuring empty suites or missing cases never improve the denominator or coverage metrics.
8. Share a single evidence-classification implementation across reports, gate, and tune that distinguishes between ok, failed, inconclusive, missing, and not-requested status.
9. Record engine version, policy, scope, suite/judge identity, and raw counts in reports, and pin the engine version in viaknox with a CI check for SOURCE.txt consistency.
10. Test the packaged npm CLI end-to-end for exit-code propagation and run golden-fixture, no-skip, count-ratchet, and mutation safeguards to prevent hidden coverage gaps.
11. Sequence the versioned breaking change after the strict gate ships, including a changelog, fixture snapshots, and a same-day MCP recopy PR to verify hosted card output.
12. Disable public badges and scores until judge-vs-human calibration is complete and badge-specific evidence requirements are satisfied.
13. Re-test tune using matched cases and repeats. Report confidence/coverage changes separately from behavioral gains, and do not label fixes verified when required evidence is incomplete.
14. Publish outside-team CI guidance that protects suites and policies, does not expose judge credentials to untrusted PR code, and distinguishes Level 1 transcript checks from Level 2 evaluation of the changed agent. Keep badges disabled until calibration and badge-specific evidence requirements are satisfied.
15. Publish old vs new pass counts in tune output during a transition window

### Release tags (PT)

1. Enable branch protection on `main` requiring pull requests, passing `test.yml` and `sast-check` (pinned by SHA), and blocking force-pushes and direct pushes.
2. Assign Paul as the mandatory CODEOWNER for `.github/**`, `engine/package.json`, security configurations, and release configurations.
3. Restrict `cli-v*` tag creation to the owner and ensure tags are immutable, targeting approved commits reachable from the protected `main` branch.
4. Configure a 'release' GitHub environment requiring Paul's manual approval, restricted to protected refs, with `id-token: write` and `contents: read` permissions only.
5. Integrate `SathiaAI/sast-check` to block merges on critical vulnerabilities and use `zizmor` to lint release workflows.
6. Use a strictly whitelisted `files` array in `engine/package.json` to include only compiled code, LICENSE, and README, while explicitly excluding brand assets, secrets, and fixtures.
7. Verify that the `engine/package.json` version exactly matches the git tag and that the package is not marked as private before proceeding with the release.
8. Build and test the packed artifact in an isolated job using Node 22.14+ and npm 11.5.1+, validating the full supported platform matrix and exit codes.
9. Provide a plain-language approval summary showing the version, `dist-tag`, commit, compatibility changes, and a full `npm pack` file list with digests.
10. Route releases to `--tag next` for prerelease suffixes (-rc, -beta) and `latest` otherwise, ensuring an explicit `dist-tag` is always passed to npm.
11. Pin all third-party GitHub Actions to full SHAs, set `persist-credentials: false`, and prevent the execution of untrusted PR code in the publishing job.
12. Require opt-in for external judge data transmission, document data retention/redaction, and ensure judge unavailability or lack of calibration results in a gate failure.
13. Protect main before releasing: require PRs, passing tests and the pinned-SHA sast-check; prevent force pushes and ordinary direct pushes, and tightly restrict bypass rights. Add CODEOWNERS for workflows, packaging, security configuration and release configuration, with a review policy workable for Paul as the sole merger.
14. Keep quality-gate advisory and require disposition of actionable findings. Require written reasons for security suppressions. Do not treat an AI review or approval by a non-coder as a substitute for technical security review when needed.
15. Provide a prepared release PR containing the version, CLI-specific changelog, compatibility changes and release channel. After Paul merges it, automation should create the protected tag; the existing plugin release process should remain separate.
16. Use a pinned publishing toolchain meeting Node 22.14+ and npm 11.5.1+ requirements. Match the trusted-publisher repository, workflow filename and environment configuration exactly. Give id-token: write only to the publishing job, pin third-party actions by SHA and avoid executing untrusted PR code in that job.
17. Start the uncalibrated CLI on next, preferably with prerelease versions. Define calibration, privacy, compatibility and failure-handling criteria before Paul authorizes the first latest release. Always pass an explicit dist-tag; do not automatically equate every 0.x non-prerelease with suitability for external CI.
18. Document exact CI pins such as agenttuneup@0.1.0, not @0.1, latest or next. Keep CLI, plugin, report-schema and rubric versions distinct. Document the 0.x compatibility policy, treating incompatible schema, configuration and gate-behavior changes as minor rather than patch changes.
19. Complete the controlled account-based bootstrap, then enable OIDC and disable token publishing. Verify account 2FA, recovery and organizational package ownership; reserving @viaknox alone does not transfer ownership of the unscoped agenttuneup package.
20. Serialize releases, reject duplicate versions and provide safe recovery after a partially completed publish. Verify registry integrity, provenance and channel after publishing, then create the CLI-specific GitHub release.
21. Document incident response: freeze releases, deprecate affected versions, restore latest to a known-good version and publish a new corrective version without reusing old versions or moving git tags. Configure separate OIDC dist-tag permission if channel management needs it. Explain that changing latest does not repair consumers pinned to a bad version.
22. Make the non-coder path explicit: Paul creates a GitHub Release from the UI choosing a new tag cli-vX.Y.Z (or cli-vX.Y.Z-rc.N with 'pre-release' ticked); workflow triggers on release: published, not on arbitrary tag push
23. Workflow must assert: tag matches engine/package.json version; tagged commit is reachable from main; package.json has private removed; run full test suite; npm pack --dry-run and fail if any file outside the allowlist (engine source, LICENSE, README, package.json) appears; fail if any brand asset path appears

Where PT15 (automation creates the tag after a release PR merges) and PT22 (Paul creates the release in the GitHub UI) overlap, this plan uses PT22 for the tag and keeps PT15's prepared release PR. Records: `F:\ENV\Claude outputs\frontier-gate\2026-10-16-cli-*`.
