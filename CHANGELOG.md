# Changelog

## Unreleased

- Brand assets are now explicitly outside the MIT License: `LICENSE-BRAND.md` (all rights reserved, with allowed uses), `LICENSE.md` in `brand/` and `tune-up/brand/`, and notes in README, TRADEMARK.md, BRAND.md and the skill footers. `LICENSE` itself is unchanged MIT and still covers the code and text.

## 0.3.2 — 2026-10-10

- New line everywhere: "Tunes up your Grok bots. Loads the right skill only when it's needed." README banner, GitHub social preview and social posts updated.
- Added the Tune-Up icon: `icon.png` (repo root, 512 px) and `brand/icon/` (SVG, 16–1024 px PNGs, favicon.ico).
- Explainer v2 (45 s): Tune-Up reviews a drifting bot, turns a miss into a test, applies a small fix you approve; the skill index loads one skill and adds from marketplaces on yes; Tune-Up moves repeated jobs into the index.
- New Tune-Up brand art from the Viaknox brand kit (v1.7.0): Tune-Up wordmark, lockups, marks, PNGs and tokens renamed `tune-up-*`; README banner, GitHub social preview, explainer (MP4, GIF, still), before/after and social posts all read Tune-Up and github.com/viaknox/tune-up.
- `brand/BRAND.md` rewritten for Tune-Up; the old grokbot-skill-index repo address is gone. Added `brand/avatar/` (sticker version with a Paper outline for Grok's dark UI).
- `tune-up/brand/tune-up-explainer-960.gif` replaced with the Tune-Up version.

## 0.3.1 — 2026-10-10

- Tune-Up's title is now "Bot that tunes up other bots".
- Tune-Up's bot picture is the new sticker raven, and the new Tune-Up artwork is in `brand/`.
- README: TL;DR, plain description, and the problems Tune-Up solves.
- Agensi-ready zip attached to this release.

## 0.3.0 — 2026-10-10

- Renamed the product from Skill Index (`grokbot-skill-index`) to Tune-Up (`tune-up`). First mention is "Tune-Up for Grok Bot". The skill library is now "the skill index", a feature of Tune-Up.
- Repo moved to https://github.com/viaknox/tune-up. Old links redirect. Install folder is now `~/.cursor/plugins/local/tune-up`.
- Plugin name is `tune-up` (display name Tune-Up). Skill ids `skill-index`, `find-skill`, `import-agent-skill`, and `set-up-tune-up` are unchanged.
- Tune-Up bot instructions now point at the new install folder.
- README rewritten to lead with Tune-Up. Footers, repository links, and `TRADEMARK.md` updated.
- The logo wordmark, lockup files, and README banner art still read Skill Index, pending new art. The raven mark is unchanged and is Tune-Up's mascot.
- Retired the old 0.1.0 Agensi packaging script. It rebuilt from a stale snapshot and would overwrite current files. The Agensi package is now built from the current tree.

## 0.2.0 — 2026-10-10

- New Skill Index brand (tinkerer raven, Deep Petrol and Brass). Brand files and rules in `brand/`.
- Removed the old brain logo.
- Tune-Up now ships with its raven mascot in `tune-up/brand/`, and setup sets it as the bot's picture.
- Added the new headline, a before-and-after explainer, the Tune-Up animated explainer (GIF and MP4), and social images (link card, square post, story) in `brand/`.
- Credit lines and skill author now read Viaknox.
- LICENSE copyright holder is now Viaknox Holding LLC.
- Added Tune-Up, a bot that evaluates and improves your other Grok bots: `skills/set-up-tune-up/SKILL.md` (set it up by asking any bot) and `tune-up/` (paste-ready instructions and a guide).

## 0.1.0 — 2026-10-10

First release as Grokbot-skill-index, published by Viaknox Holding LLC.

- Renamed the plugin to `grokbot-skill-index`.
- Added Viaknox™ branding lines, `TRADEMARK.md`, and a not-affiliated-with-SpaceXAI/xAI notice.
- Added `metadata` (author, publisher, version, repository) and `license` to the skill frontmatter.
- README: added "MIT licensed, also on GitHub" line and trademark section.
- Added an Agensi-ready single-skill package build (not part of the plugin layout).
