---
name: import-agent-skill
description: Use when the user gives a Claude skill, Codex skill, SKILL.md, or a marketplace listing and wants it in the skill index. Map it onto one listing. Do not paste it into a bot profile.
license: MIT
metadata:
  author: Viaknox Holding LLC
  publisher: Viaknox Holding LLC
  brand: Viaknox™
  version: "0.3.2"
  repository: https://github.com/viaknox/tune-up
---

# Import an agent skill

Claude skills, Codex skills, and this index use the same file shape: `SKILL.md` with a name, a when-to-use line, a body, and optional references. A marketplace listing is the same idea with a URL instead of a local file.

## Map

1. Read the `SKILL.md` frontmatter and body, or the marketplace listing. Do not read scripts into the chat. Record the source repo.
2. Attach to an existing listing only if this is the same skill: the same repo, or a fork of that repo. Same name is not enough. A different repo that is not a fork is a new listing.
3. Add a location on that listing: store, path or URL, repo or fork parent, license if known, last checked. Index the place. Do not copy the body into the listing.
4. On a new listing, write:
   - name = frontmatter name, or the marketplace name
   - purpose = when to use (must say when)
   - keywords = exact names already in the file, plus any the user adds. Do not invent a pile.
   - repo = the source repo
   - success check = one line taken from the skill if it states a done bar. If it does not, ask once, or write "worked if the steps completed without a listed veto."
5. Edge cases start empty unless the skill already has a clear "do not" section. Lift those as veto rows.
6. Lessons start empty.
7. Show the listing and the new location before they land.

If two different listings would both match, leave them as two listings. The load rule will refuse both.

## Skip

- Secrets, tokens, or private paths
- A license you cannot use
- Identity or standing locks. Those stay in the profile.

An imported skill is a retrieved skill. It does not become a standing instruction.

---

Tune-Up, by Viaknox™. Code and text MIT licensed; brand art is not. Viaknox and Agent Tune-Up are trademarks of Viaknox Holding LLC; see TRADEMARK.md. Not affiliated with or endorsed by SpaceXAI (xAI).
