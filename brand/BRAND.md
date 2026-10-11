# Tune-Up — brand

**Tune-Up by Viaknox** — for Grok Bot. Repo: github.com/viaknox/tune-up (MIT). Renamed from Skill Index (`grokbot-skill-index`) on 10 Oct 2026; the plugin name is now `tune-up`.
Status: approved, 10 Oct 2026. Source of truth: the private Viaknox brand repo, `12-Product-marks/tune-up/` (v1.7.0). This folder is a copy for the plugin.

## Idea

The raven is **Tune-Up** — the product, and the Grok bot you talk to. A tinkerer raven standing on a toolbox. Spanner in one claw, an index card in the other, goggles up.

- **Toolbox** = the skill library.
- **Index card** (with a tab) = the one skill it picked for this job, from your library or a marketplace.
- **Spanner** = it does the work, then checks it.
- **Goggles** = ready to work, careful.

Line: **Tunes up your Grok bots. Loads the right skill only when it's needed.** (Library first; if no match, it searches the connected marketplaces and sets the skill up once you say add. It does not rewrite the skill's body, so don't claim it "customises" skills.)

## Raven exception (rule change)

The guidelines allowed one raven outside the C mark: story-gate's librarian. Tune-Up is a second, approved by Paul on 10 Oct 2026. Keep them apart:

| | story-gate | Tune-Up |
|---|---|---|
| Raven | Librarian, glasses, checklist | Tinkerer, goggles, spanner + card, on a toolbox |
| Tile | Signal Yellow | Paper (on dark) / none (on light) |
| Ink | Black + Graphite | Deep Petrol |

Never on a Tangelo disc, never inside City art, never next to the C mark at the same size, never redrawn or recoloured.

## Files

| Use | File |
|---|---|
| App icon, avatar, dark surfaces | `mark/tune-up-mark.svg` (Paper tile) |
| On light pages | `mark/tune-up-mark-no-tile.svg` |
| Under 48 px (favicon) | `mark/tune-up-mark-small.svg` (head crop) |
| One colour | `mark/tune-up-mark-mono-petrol.svg` |
| Wordmark alone | `wordmark/tune-up-wordmark-petrol.svg` / `-paper.svg` |
| Primary lockup | `lockup/tune-up-lockup-by-viaknox-on-light.svg` / `-on-dark.svg` |
| Lockup without endorsement | `lockup/tune-up-lockup-on-light.svg` / `-on-dark.svg` |
| PNG sizes | `png/tune-up-mark-{16…1024}.png`, lockup PNGs |
| GitHub | `github/social-preview-1280x640.png`, `github/readme-banner-1600x480.png` |
| Tokens | `tokens/tune-up-tokens.css` |
| App / repo icon | `icon/` — `icon.png` (512), SVG, 16–1024 PNGs, `favicon.ico` |
| Bot avatar | `avatar/` — use `tune-up-sticker-*.png` on Grok (transparent with a Paper outline, works on dark). See `avatar/README.md`. |

## Colour

| Token | Hex | Role | Contrast |
|---|---|---|---|
| Deep Petrol | `#08333A` | Raven ink, text, dark surfaces | 12.9:1 on Paper |
| Brass | `#C9A227` | Spanner, primary buttons, focus | Petrol on Brass 5.6:1; Brass on Petrol 5.6:1 |
| Brass ink | `#73590C` | Accent text on Paper | 6.3:1 |
| Tomato | `#EE3430` | Goggles, alerts. Small details only | 3.4:1 on Petrol (graphics only) |
| Tomato ink | `#B8221D` | Error text on Paper | 6.1:1 |
| Paper | `#FFF8F2` | Surface, tile | — |
| Muted | `#4F6B6E` / `#9CB9BA` | Secondary text on Paper / on Petrol | 5.5:1 / 6.5:1 |

Rules: Brass and Tomato are never text on Paper (use the ink versions). Tomato is never a fill or background. No Tangelo anywhere.
Why Brass, not goldenrod: goldenrod `#FCB432` is a near-match for Toolhand Marigold `#FFB627` (CIEDE2000 ΔE 1.2). Brass sits ~11 away.
Known overlap: Tomato is close to Viaknox Tangelo (ΔE 8.3). Keeping it to small details keeps products from reading as Viaknox orange.

## Type

- **Wordmark:** Rubik Bold 700, −2% tracking, converted to outlines. Artwork only — never typed.
- **Headings:** Clash Display 600. **Body/UI:** Switzer 400–600 (Viaknox family pattern).
- Rubik may be used for short UI labels in the product; not for headings.

## Name

- Product name: **Tune-Up** (hyphen, capital U). Full form: **Tune-Up by Viaknox**. Descriptor: **for Grok Bot** (descriptive use only, never in the logo). "Skill index" may describe the feature in lowercase ("Tune-Up's skill library"); it is not a product name.
- Repo: `github.com/viaknox/tune-up`. Plugin name `tune-up`, install folder `~/.cursor/plugins/local/tune-up`.
- Not affiliated with xAI/SpaceXAI — keep the notice in README and TRADEMARK.md.

## Endorsement

"by" + Viaknox wordmark artwork (Aubergine on light, Paper on dark). Never typed.

## Don't

- Redraw, recolour, rotate, or crop the raven (except the supplied small crop).
- Put the tile-less mark on a dark surface (the Petrol raven disappears).
- Use the old brain logo — brains are banned imagery.
- Add sparkles, robots, or glow.

## Explainer and social

In `explainer/`: the animated explainer with Tune-Up working in a chat (`tune-up-explainer-1600x900.mp4`, 25 s loop; `-960.gif` for READMEs; `-still` for a poster frame) and a static before/after (`explainer-before-after-1600x900.png`). In `social/`: social posts (`social-square-1080.png`, `social-link-card-1200x630.png`, `social-story-1080x1920.png`). The marketplace result in the explainer (`invoice-sorter`) is labelled as an example.
