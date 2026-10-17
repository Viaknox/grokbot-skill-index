# Agent Tune-Up engine (v0.1, Phase 0)

Evaluates an AI agent against a test suite and writes a six-part report card. It can also draft a verified tune-up: the smallest instruction change, re-tested on the same cases, with the fix lift reported. Nothing is ever applied to your agent; every fix is a proposal for you to review.

## Run it

Needs Node 20+ and an OpenRouter key in `TUNEUP_OPENROUTER_KEY` or in a file passed with `--keyfile` (a line like `OPENROUTER=sk-or-...`). The key is never printed or logged.

```bash
cd engine
npm test                                                     # offline unit tests
# Check real chats you pasted or exported (Level 1). Without --consent nothing leaves your machine.
node cli.js check examples/sample-chats.txt --instructions examples/sample-instructions.txt --agent SupportBot
node cli.js check examples/sample-chats.txt --instructions examples/sample-instructions.txt --agent SupportBot --consent

# Test an agent by re-running cases against it (Level 2), then try a verified tune-up
node cli.js run  examples/bookbot.suite.json --out my-run --consent    # my-run/report.md + report.json
node cli.js tune examples/bookbot.suite.json --out my-run --consent    # one verified attempt; run again to retry
```

## Use it in CI (strict gate)

```bash
npx agenttuneup check chats.txt --instructions instructions.txt --consent --out tune-up-report
```

| Exit code | Meaning | CI result |
| --- | --- | --- |
| `0` | Every check passed, and the judge answered for every chat or case | Pass |
| `1` | At least one check failed | Fail |
| `3` | Undetermined: an unsure answer, a held-back chat, the judge was unreachable, or the judge did not run | **Fail** |
| `2` | Usage or config error (unknown option, `--consent` with no key) | Fail |

When results are mixed, `1` beats `3` beats `0`. The exit code comes from the run itself, never from an old or edited `report.json`.

**Strict CI needs `--consent` and a key.** Without them only the local rule checks run, so the result is always `3`. Store the key as a CI secret, never in the repo. There is no option or setting that skips a check or turns a failure into a pass; unknown options and unknown `TUNEUP_*` settings stop the run with `2`.

```yaml
# .github/workflows/agent-check.yml
on: [pull_request]
jobs:
  agent-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npx agenttuneup@0.1 check chats.txt --instructions instructions.txt --consent --out tune-up-report
        env:
          TUNEUP_OPENROUTER_KEY: ${{ secrets.TUNEUP_OPENROUTER_KEY }}
```

## Your data

- **Scrubbing happens on your machine first.** Emails, phone numbers, API keys and tokens, card numbers (checksum-verified), US Social Security numbers and IPv4 addresses become placeholders such as `[EMAIL_1]` before any text goes to a remote model. This catches common patterns, not everything: names, street addresses, other IDs (passport or licence numbers) and IPv6 addresses are not detected, so list names in `--private` or remove them before checking. The same value always gets the same placeholder. Placeholders in a proposed fix are put back locally.
- **Your own never-send list.** Put names the patterns can't know (your employer, clients, people) in a file, one per line, and pass `--private words.txt`. They become `[PRIVATE_1]`… before anything goes to a remote model, and they are never sent to your own agent either: if a test message for an `http` agent contains one, the run stops before sending it.
- **What goes where.** Scrubbing covers everything Tune-Up sends to its remote models (the judge, the fix writer, and the `model` adapter, including tool descriptions). An `http` agent is your own bot, so its test messages reach it unchanged (apart from the `--private` rule above): that is what is being tested. `run` and `tune` print the agent URL before the first request.
- **Nothing is sent without `--consent`.** Without it, `check` runs only the local rule checks, and `run`/`tune` stop and explain what would be sent where.
- **Turn on "no training" in your OpenRouter privacy settings.** That keeps your requests away from providers that train on them.

Pasted chats can be plain text with speaker labels (`User:` / `Bot:`, or your bot's name with `--agent`), with `---` between chats, or JSON exports (`[{role, content}]`, `{messages}`, `{conversations}`).

## What it checks

| Report card part | How it is checked |
| --- | --- |
| Gets it done | Rule checks on the final reply (expected content, asked for missing details, not empty) plus the judge |
| Uses tools and skills right | Expected tool called successfully; forbidden tools not called (only when tool calls are visible) |
| Tells the truth | "Done" claimed with no successful tool call behind it; the judge checks claims against tool results |
| Follows your rules | Words that must never appear, required refusals, and the judge. **One failure fails this part; it is never averaged** |
| Wastes nothing | Time, tokens and tool calls per case; the judge flags needless questions |
| Keeps you happy | Not available from scripted tests; needs real conversations |

- **Rule checks run first.** They are exact and cost nothing.
- **The judge is Jev** (`typesafe/jev-1.13`), a decisions model that answers yes/no with a probability. Answers between 35% and 65% are reported as unsure, never as a pass or a fail.
- **Fix drafts come from Nemotron 3 Super** on a paid, no-training endpoint.
- **Each case runs several times** (`repeats`), and cases that pass in one run but fail in another are listed as inconsistent.

## Evidence levels

Every report states how much it could see. **Level 1** is chats only. **Level 2** means the agent was re-run on the test cases (this engine). **Level 3** adds live telemetry.

## Suites and adapters

A suite (see `examples/bookbot.suite.json`) holds the agent's instructions, the sentences that must never change (`sacred`), how to reach the agent (`agent_config`), and the test cases. Each case has an intent, the user turns, and what to expect.

| Adapter | Use | Tool calls visible? |
| --- | --- | --- |
| `http` | Any chatbot with an HTTP endpoint. You set the URL, headers, a body template with `{{message}}` / `{{history}}` (and `{{instructions}}` if the agent accepts them; `tune` needs it), and where the reply is in the response. Header values can use environment variables named `TUNEUP_AGENT_*` only (for example `"authorization": "Bearer ${TUNEUP_AGENT_TOKEN}"`); any other `${...}` is refused, and they are only filled in when the suite's `url` is on the address you set in `TUNEUP_AGENT_URL`, so a suite file someone sends you can't read your other secrets or send your agent token elsewhere | No |
| `model` | An agent defined by instructions plus simulated tools, run on an OpenRouter model. Used for demos and for replaying an agent's instructions. Everything it sends is scrubbed first. Mark lookup tools with `"read_only": true` (names starting with get/list/search/find/read/check/lookup/fetch/view/query/show count as lookups anyway): a lookup succeeding is not proof that a booking or send happened. A call with no matching simulated case and no `default` counts as a failed call | Yes |

Point `run` and `tune` at a **test copy** of an `http` agent: every case is sent `--repeats` times and again after each tune-up, so real actions (bookings, emails) would repeat. Requests never follow redirects, and up to 4 cases run at a time.

`tune` never proposes an attempt that breaks a case that used to pass or adds a new rules failure, even if its overall lift is positive; the attempts table lists what each one broke.

Pasted or exported chats go through `check` (see above). A Grok Bot adapter (an owner-created webhook routine) comes next.

## Status

This is Phase 0. The rubric (`six-part@0.1`) and the report schema (`tune-up/report@0.1`) will change until the judge is calibrated against human-labelled cases (target: at least 80% agreement). Do not publish badges from these reports yet.
