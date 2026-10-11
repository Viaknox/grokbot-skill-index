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

## Your data

- **Scrubbing happens on your machine first.** Emails, phone numbers, API keys and tokens, card numbers (checksum-verified), US Social Security numbers and IPv4 addresses become placeholders such as `[EMAIL_1]` before any text goes to a remote model. Other IDs (passport or licence numbers, IPv6 addresses, names) are not detected yet, so remove them before checking. The same value always gets the same placeholder. Placeholders in a proposed fix are put back locally.
- **Your own never-send list.** Put names the patterns can't know (your employer, clients, people) in a file, one per line, and pass `--private words.txt`. They become `[PRIVATE_1]`… before anything is sent.
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
| `http` | Any chatbot with an HTTP endpoint. You set the URL, headers, a body template with `{{message}}` / `{{history}}` (and `{{instructions}}` if the agent accepts them; `tune` needs it), and where the reply is in the response | No |
| `model` | An agent defined by instructions plus simulated tools, run on an OpenRouter model. Used for demos and for replaying an agent's instructions. Everything it sends is scrubbed first | Yes |

Pasted or exported chats go through `check` (see above). A Grok Bot adapter (an owner-created webhook routine) comes next.

## Status

This is Phase 0. The rubric (`six-part@0.1`) and the report schema (`tune-up/report@0.1`) will change until the judge is calibrated against human-labelled cases (target: at least 80% agreement). Do not publish badges from these reports yet.
