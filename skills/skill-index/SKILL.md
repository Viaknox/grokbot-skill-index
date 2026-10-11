---
name: skill-index
description: >-
  Use when starting a multi-step job, when the user names a procedure, or when a
  keyword might match a stored skill. Retrieve one skill body. Do not load the
  index into the standing prompt.
license: MIT
metadata:
  author: Viaknox Holding LLC
  publisher: Viaknox Holding LLC
  brand: Viaknox™
  version: "0.3.0"
  repository: https://github.com/viaknox/tune-up
---
# Skill index

Part of Tune-Up. Tune-Up keeps a skill index so each bot loads one skill only when the job needs it.

The standing prompt keeps identity, lanes, and locks. Procedures live in an index and load only after a real match.

## Index fields (thin listing)

The plugin database has one listing per skill. Match listings, not every copy.

- name
- purpose (when to use, one line)
- keywords (exact hits)
- do-not-use-when (hard veto)
- success check (worked if… / fail if…)
- where it may load (this chat, named rooms, never a group)
- repo (the skill's source repo)

A listing does not store the body.

## Locations

Each listing has one or more locations. A location is where that same skill was found.

- store (files, Notion, a marketplace, a repo)
- path or URL
- repo, or the repo it was forked from
- license, if known
- last checked

Add a location to an existing listing only if it is the same skill: tied to the same repo, or a fork of that repo. Same name is not enough. Do not create a second listing for another copy of that same skill.

Overlapping purpose is not a merge. A different repo that is not a fork of this one is a different listing, even if the name matches.

Linked, not on the standing row:

- Edge cases: trigger, do or don't, hard stop or warning
- Lessons: date, what happened, skill that fired or should have, what changed, still open

## Load order

1. Match purpose and keywords on listings, against the current turn.
2. Drop any hit whose do-not-use-when or edge case matches this turn.
3. If two listings still match, load neither. Name both and why. A closer keyword does not cancel a second match. Extra locations on one listing are not a second match.
4. Load one body from one location, the matching edge cases, and only lessons tied to this skill or this kind of miss. Prefer a confirmed license, then a local copy. Do not load every location.
5. Before saying done, score the success line. If it cannot be scored from this turn, the score is not a hit. If it fails, write a lesson in the same turn.
6. If the store is down, use a local thin cache of listings only. No body. No guess. Locks still hold.

## Stores

Same fields, any store: files, Notion, Airtable, Coda, a sheet, or a marketplace. The store is what a human edits, or a source you import from. Keep a small local copy of the listing fields. Do not query every store on every message.

## What never goes in the index

Standing locks, secrets, and another bot's private instructions.

## Three flows

1. In the library. If one listing matches the job, use it. The user does not need to ask. Do not search marketplaces.
2. Not in the library. Search the default list in marketplaces.json, plus any location the user added. Use each source's API. Do not scrape. Show the relevant skills and ask if one can be added. Do not write until they say add.
3. Named site. If the user names a site to search, search that site. Then ask if that location should be added to the default search list. Add it only if they say yes. A new search location does not fill the library.

Same repo, or a fork of that repo, is another link on the one listing. Do not guess a body.

---

Tune-Up, by Viaknox™. MIT licensed. Viaknox is a trademark of Viaknox Holding LLC; see TRADEMARK.md. Not affiliated with or endorsed by SpaceXAI (xAI).
