---
name: find-skill
description: >-
  Use when a needed skill is not in the local library, or when the user names a
  site to search. Show matches. Ask before adding a skill or a search location.
license: MIT
metadata:
  author: Viaknox Holding LLC
  publisher: Viaknox Holding LLC
  brand: Viaknox™
  version: "0.3.2"
  repository: https://github.com/viaknox/tune-up
---

# Find a skill

The user does not need to ask for a search. If the job needs a skill and the local library has no match, search. If the library has a match, do not use this path. Use the skill.

## Default search

The default list is `marketplaces.json`. It already has six places. Also search any location the user has added. The user does not name a marketplace for this. Use each source's API. Do not scrape. If a source has no public search API, skip it and say so.

Read listings only: name, purpose, source repo, marketplace URL. Do not load every body.

Show a short list. If the same skill appears on more than one marketplace, or on a fork of the same repo, show it once with every link. Same name from a different repo that is not a fork is its own line.

Then ask if one can be added to the library. Stop. Do not write the search results until the user says add.

## Named site

If the user asks to search a certain site, search that site the same way. Then ask if that location should be added to the default search list. Add it only if they say yes. A new search location does not fill the library.

## Do not

- Save a match because it was found.
- Search the marketplaces when the library already has the one skill the job needs.
- Paste a body into a bot profile.
- Guess a body if a marketplace is down. Say which store you could not read.

## After they say add

Write that one skill to the local SQLite library. Only saved skills live there. Same repo, or a fork of that repo, is another link on that entry, not a second row.

---

Tune-Up, by Viaknox™. MIT licensed. Viaknox and Agent Tune-Up are trademarks of Viaknox Holding LLC; see TRADEMARK.md. Not affiliated with or endorsed by SpaceXAI (xAI).
