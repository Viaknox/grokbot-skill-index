<p align="center">
  <img src="brand/github/readme-banner-1600x480.png" alt="Skill Index by Viaknox. One skill at a time. Or none." width="100%" />
</p>

<h1 align="center">Skill Index for Grok Bot</h1>

<p align="center"><b>One skill at a time. Or none.</b> · by Viaknox™</p>

<p align="center">
  <img src="https://img.shields.io/badge/For-Grok%20Bot-08333A?style=flat-square" alt="For Grok Bot" />
  <img src="https://img.shields.io/badge/Skill%20library-ask%20in%20plain%20English-08333A?style=flat-square" alt="Skill library" />
  <img src="https://img.shields.io/badge/License-MIT-C9A227?style=flat-square" alt="License: MIT" />
</p>

<p align="center">
  A skill library for <b>Grok Bot</b>. Ask for the job in plain English. The bot picks up one skill. Your bot instructions stay short.
</p>

## Contents

- [What is Skill Index?](#what-is-skill-index)
- [What's the outcome of using it?](#whats-the-outcome-of-using-it)
- [How can you use it with Grok Bot?](#how-can-you-use-it-with-grok-bot)
- [How can you install it?](#how-can-you-install-it)
- [FAQs](#faqs)
- [License](#license)
- [Trademarks](#trademarks)

## What is Skill Index?

Skill Index is a skill library for Grok Bot. A skill is a saved way to do one job, such as writing a release note or checking a pull request. Each skill lives in its own file instead of being pasted into a bot's standing instructions.

The bot only sees a short label for each skill: its name and when to use it. The full instructions load only when you ask for that job. The plugin also helps the bot find new skills in public skill marketplaces and add them to your local library, but only when you say so.

| Piece | What it is for |
| --- | --- |
| [Skill index](skills/skill-index/SKILL.md) | How a bot picks one skill, or none. |
| [Find a skill](skills/find-skill/SKILL.md) | Searches marketplaces when your library has no match, and asks before adding. |
| [Import a skill](skills/import-agent-skill/SKILL.md) | Adds a skill you approved into your local library. |
| [Always-on line](rules/skill-index.mdc) | The one short rule the bot keeps in mind. |
| [Starter skills](starters/file-index/index.md) | Three examples: release note, class deck check, pull request check. |
| [Marketplaces](marketplaces.json) | Six default places the plugin can search. You can add your own. |

## What's the outcome of using it?

- **Shorter bot instructions.** Your bots keep one line about the skill index instead of a long file covering every job.
- **Fewer tokens.** Skills you aren't using stay out of the conversation, so each chat is lighter and cheaper.
- **More consistent work.** The same job is done the same way every time, because the bot follows the saved skill.
- **One library for all your bots.** Every Grok bot that has the plugin can use the same skills.
- **You stay in control.** Nothing from a marketplace is added until you say add, and the bot never picks between two matching skills for you.

## How can you use it with Grok Bot?

Just ask for the work in plain English. You don't need to name the skill.

| You say | What happens |
| --- | --- |
| "Write a short release note." | One skill matches, so the bot uses it. |
| "Check this class deck and this pull request." | Two skills fit. The bot names both and asks which you want. |
| "Is there a skill for organizing invoices?" | The bot searches your marketplaces and shows matches. Nothing is added until you say add. |
| "Search awesomeskill.ai for a meeting-notes skill." | The bot searches that site, then asks whether it should join your default search list. |

To set up a bot:

1. Install the plugin (below).
2. In that bot's instructions, keep one short line: "Before a multi-step job, check the skill index and load at most one skill."
3. Ask the bot for a job. If a saved skill matches, it uses it.
4. If nothing matches, the bot searches the default marketplaces and asks if it should add one. Say add, and the skill is ready from then on.

A skill never overrides who the bot is. The bot's own rules still win.

## How can you install it?

**Option 1: ask your Grok bot.** Tell it: "Install the skill index plugin from https://github.com/viaknox/grokbot-skill-index into `~/.cursor/plugins/local/grokbot-skill-index`." Then reload.

**Option 2: install it yourself.**

```bash
git clone https://github.com/viaknox/grokbot-skill-index.git ~/.cursor/plugins/local/grokbot-skill-index
```

Then reload the window and test it by asking a Grok bot: "Write a short release note."

The plugin ships with an empty SQLite library (`library.sqlite`) and the default marketplace list. Only skills you add are written to the library.

To update later, run `git pull` inside that folder.

## FAQs

**Do I need to name the skill when I ask?**
No. Ask for the job in plain English and the bot finds the matching skill.

**What if two skills match?**
The bot names both and asks you to pick. It won't guess.

**Does connecting a marketplace download all its skills?**
No. Marketplaces are only searched. Results are shown to you and not saved. Only a skill you choose to add is written to your library.

**Can I add my own marketplaces?**
Yes. Name a site in chat and the bot will search it and ask whether to add it to the default list, or edit `marketplaces.json` yourself.

**What if the same skill is listed in several marketplaces?**
It shows up as one entry with a link for each place. A different skill with a similar name stays its own entry.

**Will a skill change my bot's personality or rules?**
No. A skill only covers how to do one job. The bot's own instructions always win.

**Can I write my own skills?**
Yes. A skill is a folder with a `SKILL.md` file. Look at the [starter skills](starters/file-index/index.md) for examples, then ask your bot to import yours.

**Does it cost anything?**
No. It's free and open source under the MIT license.

**Is this an official Grok Bot product?**
No. It's built by Viaknox for Grok Bot users and isn't affiliated with or endorsed by SpaceXAI, xAI, or X.

## License

MIT. See [LICENSE](LICENSE).

## Trademarks

Viaknox is a trademark of Viaknox Holding LLC. The MIT license covers the code and text, not the Viaknox name or marks. See [TRADEMARK.md](TRADEMARK.md). Brand files and usage rules are in [brand/BRAND.md](brand/BRAND.md).

Grok and Grok Bot are SpaceXAI (xAI) products, named here only to say what this plugin is built for. Not affiliated with or endorsed by SpaceXAI, xAI, or X.
