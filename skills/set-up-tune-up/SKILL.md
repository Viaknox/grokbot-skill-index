---
name: set-up-tune-up
description: >-
  Use when the user says "set up Tune-Up", or wants a bot that evaluates and
  improves their other Grok bots. Confirm first, ask four short questions,
  create the bot, verify its instructions, then run one supervised review.
license: MIT
metadata:
  author: Viaknox Holding LLC
  publisher: Viaknox Holding LLC
  brand: Viaknox™
  version: "0.3.2"
  repository: https://github.com/viaknox/tune-up
---

# Set up Tune-Up

Tune-Up is a bot that checks the user's other Grok bots and suggests small fixes. It uses the skill index to keep their instructions short. Its full instructions are in `tune-up/INSTRUCTIONS.md` in this plugin (the text inside the box).

## Do not

- Create anything before the user says yes.
- Delete, rename, or change any existing bot during setup.
- Invent click paths in the Grok Bot app. Use the bot-creation ability Grok Bot gives you.
- Shorten, summarize, or send part of the instructions. Send the full text.
- Create a routine without a separate yes.

## Steps

1. **Confirm.** Say in one or two lines what Tune-Up is: a new bot, named Tune-Up, that reviews the user's bots and shows proposed changes before anything is applied. Ask if you should create it. Stop until they say yes.

2. **Ask four short questions.** Offer the defaults so the user can just say "defaults".
   - Which bots may it review? Default: all of them.
   - What behavior is sacred and must never change? Default: each bot's purpose.
   - How much freedom? Suggest only, or apply after a yes. Default: suggest only.
   - How often should it review? Default: weekly.

3. **Fill in the answers.** Read `tune-up/INSTRUCTIONS.md`. Take the full text inside the box. Replace only the four lines under SETUP CHOICES with the user's answers. Change nothing else. Write the result to a file. Check it is under 20,000 characters.

4. **Create the bot.** Use Grok Bot's create-bot tool if you have one. If not, ask Grok Bot to create a new bot. Name: Tune-Up. Title: Bot that tunes up other bots. Instructions: the full text from your file.

5. **Give it its mascot.** Set the new bot's profile picture to `tune-up/brand/tune-up-avatar-512.png` (the Tune-Up raven sticker, which reads on dark and light screens). Use Grok Bot's avatar or profile tool if you have one. If you can't set it, tell the user where the file is so they can set it. Never redraw, recolor, or crop the raven.

6. **Verify.** Re-read the new bot's live instructions. Pass means an exact match with your file. If it does not match, say so and fix it before going on. Do not call setup done until this passes.

7. **Offer a routine.** Ask if Tune-Up should run a review on the schedule the user chose. Create the routine only after a yes. Before scheduling, run one review by hand and show the output.

8. **Supervised first review.** Ask Tune-Up to review one bot the user picks. Show every proposed change in full. Apply nothing until the user says yes to that change.

## Success check

Worked if: a bot named Tune-Up exists with the raven mascot as its picture (or the user was told where the file is), its live instructions exactly match the filled-in text, no other bot changed, and the user saw the first review's proposed changes before anything was applied.

Fail if: a bot was created without a yes, the instructions were cut or summarized, or any existing bot was changed, renamed, or deleted.

---

Tune-Up, by Viaknox™. Code and text MIT licensed; brand art is not. Viaknox and Agent Tune-Up are trademarks of Viaknox Holding LLC; see TRADEMARK.md. Not affiliated with or endorsed by SpaceXAI (xAI).
