# Security policy

Agent Tune-Up checks other people's chats, so a privacy bug is the most serious bug we can have. Thank you for looking.

## What's in scope

| Area | Where |
|---|---|
| The scrubber that removes secrets and some personal data before anything is sent to a model (see coverage below) | `engine/src/redact.js` |
| Everything that sends text to a model (judge, fix writer and replay adapter) | `engine/src/openrouter.js`, `judge.js`, `writer.js`, `evaluate.js`, `adapters.js` |
| How chats are parsed | `engine/src/transcripts.js` |
| The hosted connector at `viaknox.com/api/tuneup/mcp`: sign-in, tokens, free-check limits, deleting your data, how reports display | Hosted by Viaknox (code not in this repo; report issues here anyway) |
| The skill library and the Tune-Up plugin | `skills/`, `tune-up/`, `starters/`, `rules/`, `library.sqlite`, `schema.sql`, `marketplaces.json` |

The things we most want to hear about:
- **Leaks:** any input where a secret, a personal detail the scrubber claims to cover, or a "never send" word reaches a model.
- **Slowdowns:** any input that makes the scrubber hang or take much longer than usual.
- **Access:** any way to use someone else's checks, token or data.

## What the scrubber covers

**Removed before anything is sent:** email addresses, phone numbers, card numbers, US Social Security numbers, IPv4 addresses, private keys, API keys and tokens, values of password, secret, key and token settings, and any words you list as "never send".

**Not removed:** names, street addresses, other ID numbers, and secrets that look like ordinary words, unless you list them as "never send".

- **A miss of something on the "removed" list is a vulnerability.** Please report it privately.
- **A miss of something on the "not removed" list is a known limit.** Report it anyway; it helps us decide what to cover next.

## How to report

**Privately, through GitHub:** go to the repository's **Security** tab and choose **Report a vulnerability**. Only the maintainers can see the report.

Please don't open a public issue, pull request or discussion for a security problem until it's fixed.

A good report has:
- the exact input, with **fake** secrets only (never send us a real key or real personal data);
- what you expected to happen and what actually happened;
- the commit, release or date you tested.

## What happens next

- We aim to reply within **3 business days**. Viaknox is a small team, so please allow for that.
- Confirmed leaks are our top priority. For a leak in the hosted connector, we can pause all hosted checks with a configuration switch while we fix it.
- We aim to add a test for every confirmed bypass alongside its fix, so we notice if it comes back.
- When it's fixed, we'll credit you in `CHANGELOG.md` and the security advisory, unless you'd rather stay anonymous.
- We don't run a paid bug bounty.

## Good-faith research

Test only with your own account, your own token and fake data. Don't access other people's data, don't run attacks that harm the service for others (load or flood testing included), and give us reasonable time to fix a problem before you publish it. If you follow these rules, we won't take action against you for your research.

## Supported versions

Only the latest release and the `main` branch get security fixes. Fixes reach the hosted connector after they are reviewed and merged; the security advisory says when a fix is live.
