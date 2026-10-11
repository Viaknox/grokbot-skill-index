# Tune-Up: the bot that improves your bots

Tune-Up is a Grok bot with one job: make your other Grok bots more useful. Its title is Bot Evaluator.

It reads how your bots actually perform. It finds misses and waste. It suggests small, clear fixes. It also moves long, repeated procedures out of a bot's instructions and into the Skill Index, so the bot stays short and cheap to run.

## Two ways to set it up

**A. Let a bot do it (Skill Index installed).**
Tell any Grok bot: "Set up Tune-Up." It will explain what it is about to do and ask you to confirm. Then it asks four short questions:

- Which bots may Tune-Up review? (Default: all.)
- What must never change? (Default: each bot's purpose.)
- Suggest only, or apply after your yes? (Default: suggest only.)
- How often should it review? (Default: weekly.)

It creates the bot, checks the instructions landed exactly, and runs one supervised review with you. The steps are in [the set-up skill](../skills/set-up-tune-up/SKILL.md).

**B. Do it by hand.**
Create a new bot in Grok Bot. Name it Tune-Up. Paste the text from [INSTRUCTIONS.md](INSTRUCTIONS.md) as its instructions. Edit the SETUP CHOICES lines first if you want different answers.

## What it will do

- Help you design new bots: a short interview, then a draft for you to approve.
- Check each bot against clear standards: clarity, plain English, relevance, complete but not overwhelming, true to purpose, and cost.
- Keep a roster: what each bot is for, last check, weak spots, next fix.
- Turn every miss into a check, and call it fixed only after the bot passes.
- Find wasted routines and repeated friction in chats, including its own.
- Suggest skills from your library or the marketplaces when a bot is missing one.

## What it won't do

- Change a bot's purpose.
- Delete or rename a bot without your yes.
- Apply a change you haven't seen.
- Send, post, spend, or delete for you. Those stop at a draft.
- Add a marketplace skill without your yes.

## Your first week

- **Day 1:** setup and one supervised review of one bot. Expect a short list of proposed changes. You pick which to apply.
- **During the week:** a few small suggestions as it sees real misses. Silence when nothing needs fixing.
- **End of week:** the first weekly review. A count per bot of false "done" reports, weak facts, needless questions, and loops that didn't stop, plus the next fix to try.

Small changes, often, each one shown to you first. That is the whole idea.

---

Skill Index, by Viaknox™. MIT licensed. Viaknox is a trademark of Viaknox Holding LLC; see [TRADEMARK.md](../TRADEMARK.md). Not affiliated with or endorsed by SpaceXAI (xAI).
