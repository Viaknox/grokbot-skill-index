<h1 align="center">Grokbot-skill-index</h1>

<p align="center"><b>Skill Index for Grok Bot</b> · A Viaknox™ skill — by SathiaAI, a Viaknox Holding LLC project</p>

<p align="center">
  <img src="logo.png" alt="Grokbot-skill-index" width="280" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/For-Grok%20Bot-111111?style=flat-square" alt="For Grok Bot" />
  <img src="https://img.shields.io/badge/Skill%20library-ask%20in%20plain%20English-111111?style=flat-square" alt="Skill library" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="License: MIT" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/One%20skill%20at%20a%20time-111111?style=for-the-badge" alt="One skill at a time" />
  <img src="https://img.shields.io/badge/Shorter%20bot%20instructions-111111?style=for-the-badge" alt="Shorter bot instructions" />
  <img src="https://img.shields.io/badge/Fewer%20tokens-111111?style=for-the-badge" alt="Fewer tokens" />
</p>

<p align="center">
  A skill library for <b>Grok Bot</b>. Ask for the job in plain English. The bot picks up one skill. Your bot instructions stay short.
</p>

## Contents

- [Use it in the real world](#use-it-in-the-real-world)
- [Install](#install)
- [Add it to your Grok bots](#add-it-to-your-grok-bots)
- [What's in this plugin](#whats-in-this-plugin)
- [What are skills](#what-are-skills)
- [License](#license)
- [Trademarks](#trademarks)

## Use it in the real world

You do not paste every job into the bot. You ask for the work.

| You say | What happens |
| --- | --- |
| "Write a short release note." | One skill matches. The bot uses that one. |
| "Check this class deck and this pull request." | Two skills fit. The bot names both and uses neither, so you can pick. |
| "Is there a skill for organizing invoices?" | The bot looks through the skill marketplaces you connected and shows matches. Nothing is added until you say add. |

The same skill found in more than one marketplace is one entry, with a link for each place. A copy from the same repo, or a fork of that repo, is another link. A different skill stays its own entry.

## Install

1. Copy this folder to `~/.cursor/plugins/local/grokbot-skill-index`.
2. Reload the window.
3. Ask a Grok bot: "Write a short release note."

The plugin ships with an empty SQLite library and a default list of marketplaces to search. Search results are shown to you. They are not saved.

Only a skill you add is written to that library. Connecting a marketplace does not fill the database.

You can add other marketplace links for search. Those extra links work the same way. Search only. Nothing is saved until you add a skill.

## Add it to your Grok bots

Your bots do not need a long instruction file for every job.

1. Install the plugin (above).
2. In the bot you want to use it, keep a short line: before a multi-step job, check the skill index and load at most one skill.
3. Ask that bot for the job. If a saved skill matches, it uses that skill. You do not need to ask.
4. If the library has no match, the bot searches the six default marketplaces and asks if one can be added. Say add. That skill is then available.
5. You can also name a site to search. The bot searches it, then asks if that site should join the default search list.

A skill does not overwrite who the bot is. The bot's own rules still win.

## What's in this plugin

| Piece | What it is for |
| --- | --- |
| [Find a skill](skills/find-skill/SKILL.md) | Library miss, or a site you name. Shows matches and asks before adding. |
| [Skill index](skills/skill-index/SKILL.md) | How a bot picks one skill, or none. |
| [Import a skill](skills/import-agent-skill/SKILL.md) | Adds a skill you approved into your local library. |
| [Always-on line](rules/skill-index.mdc) | The short rule the bot keeps. Unused skills stay out of the chat. |
| [Starter skills](starters/file-index/index.md) | Three examples: release note, class deck check, pull request check. |
| [Marketplaces](marketplaces.json) | Six places the plugin can look. You can add your own. |

## What are skills

A skill is a saved way to do one job. It lives in its own file, not in the bot's standing instructions.

The bot sees a short label: the name, and when to use it. The full instructions load only when that job is the one you asked for. That is why the bot stays light, and why unused jobs stop burning tokens.

This plugin is the library and the lookup. It is not a dump of other people's skills. You choose what gets added.

## License

MIT. Author: SathiaAI. MIT licensed, also on GitHub: https://github.com/viaknox/grokbot-skill-index


## Trademarks

Viaknox is a trademark of Viaknox Holding LLC. The MIT license covers the code and text, not the Viaknox name or marks. See [TRADEMARK.md](TRADEMARK.md).

Grok and Grok Bot are SpaceXAI (xAI) products, named here only to say what this plugin is built for. Not affiliated with or endorsed by SpaceXAI, xAI, or X.
