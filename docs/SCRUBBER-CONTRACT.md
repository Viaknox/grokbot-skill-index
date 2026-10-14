# Scrubber contract, version 2.0.0

`engine/src/redact.js` exports `SCRUBBER_VERSION = '2.0.0'`. This file says what the scrubber promises, what it covers,
and what it does not. The privacy page must not promise more than the **Promised** tier below.

## Where it runs

On the user's machine, before any text goes to a remote model. Every judge and fix-writer request goes through one
function, `outbound()` in `engine/src/openrouter.js`, which accepts only a `Sanitized` value made by the scrubber. If the
scrubber's residual scan finds anything secret-looking, nothing is sent and the result is "unsure: we held back part of
this chat to protect a secret". A scrubber error or a scrub that runs past its time cap also means no call.

## Input shapes

`scrubber({ terms }).scrub(text)` takes any string: chat transcripts, pasted files, JSON, YAML, dotenv, netrc, npmrc,
pypirc, HTTP headers, shell commands, XML. Line endings may be LF or CRLF. The scrubber builds a folded view of the text (zero-width characters, soft hyphens,
combining marks and PowerShell backticks removed; fullwidth, decomposed and Turkish dotted/dotless forms folded; JSON
`\uXXXX` and percent-encoded names decoded; bidirectional isolates dropped and other control characters read as spaces) and matches never-send terms, key shapes and credential names on that
view, then replaces the original span, disguise included. The output text is changed only by replacement. Inputs over 4,000,000 characters, or a scrub that takes over 2 seconds, raise `ScrubError` from
`sanitize()`.

## Placeholders

A found value becomes `[KIND_n]`: `KIND` is one of `KEY`, `SECRET`, `PRIVATE`, `EMAIL`, `CARD`, `SSN`, `PHONE`, `IP`
and `n` counts distinct values of that kind, in order of first sight, across every text one scrubber instance sees. The
same value always gets the same placeholder. Placeholders are reserved tokens: no rule matches inside one, and a value
that already contains a placeholder (a password that contains a never-send term) nests it, so `unscrub` restores
`[SECRET_1]` and then the `[PRIVATE_1]` inside it. Text that already looks like `[KIND_n]` in the input is left alone,
not counted, and its number is reserved so a real placeholder never collides with it; this holds for those eight kinds
only (`[ATTACK_1]` or any other bracketed word is ordinary text, and as a credential value it is scrubbed like any
value). A placeholder followed by more data on the same line (`PASSWORD=[SECRET_1])CorrectHorse9!`) is not complete: the
whole value, placeholder included, is scrubbed; only closers, punctuation, another placeholder or a named sibling field
(`[SECRET_1],"after":"x"`, `[SECRET_1]; next=1`) may follow it. `counts()` reports the number of
distinct values per kind. `unscrub(text)` puts the real values back, locally; the restore map never leaves the scrubber.

## Tiers

Coverage comes in two tiers, and every scrubber fixture is tagged with one:

- **Promised** (merge-blocking). The shapes in the next section. A change that makes a promised fixture fail does not
  merge. This tier is what the privacy page may state.
- **Best effort** (fixed when found, not merge-blocking). Everything in the section after it. These shapes are covered
  today and guarded by tests, and a regression or a new bypass in them is fixed when a review or a self-attack round
  finds it, but they are not a promise and a reviewer may accept a known best-effort gap on a merge.

Tags: every test name in `engine/test/scrubber-v2.test.js`, `fuzz.test.js`, `boundary.test.js`, `perf.test.js` and the
echo tests of `transcripts-v2.test.js` starts with `[promised]` or `[best-effort]`; every fixture in
`engine/test/corpus/attack-round-*.json` carries `"tier"`, and the loader refuses a fixture without one. The
scrubber's own mechanisms (placeholders, idempotence, the residual hold, `ScrubError` becoming a held finding, the
outbound boundary, the perf budgets) are promised. `npm run test:promised` runs only the merge-blocking set; `npm test`
runs everything, and `.github/workflows/test.yml` runs `npm test` on `ubuntu-latest` with Node 22 so a Linux result is
on record for every push.

## Promised (merge-blocking)

| Kind | What is removed |
|---|---|
| `KEY` | **Private-key blocks:** any `-----BEGIN … PRIVATE KEY-----` (plain, RSA, EC, DSA, OPENSSH, ENCRYPTED, with Proc-Type/DEK-Info/Comment headers and blank lines) through the footer that carries the same type words (an RSA block ends at `-----END RSA PRIVATE KEY-----`; a footer of another type is treated like no footer); with no footer, to the end of the input (a JSON-escaped block ends at its closing quote). **Listed token formats:** OpenAI/OpenRouter/Anthropic `sk-…`, GitHub `gh?_…`, Slack `xox?-…`, AWS access key ids, Google `AIza…`/`ya29.…`, JWTs, Stripe `sk_live_…`/`pk_live_…`/`rk_live_…`, `whsec_…`, GitLab `gl…-…`, npm `npm_…`, PyPI `pypi-…`, age `AGE-SECRET-KEY-1…`, Amazon Bedrock `ABSK…`, Mailchimp, Cloudflare origin CA. **URL userinfo** (`scheme://user:pass@host`, the whole `user:pass`, with no length ceiling; the scheme may be a single letter). **`Basic`, `Bearer` and `Digest`** scheme tokens anywhere, with no minimum length (`Basic YTpi`); a short plain lowercase word after the scheme name (`Bearer token`, `Basic auth`) is prose and stays. |
| `SECRET` | **Credential-named settings** in dotenv, JSON, YAML, INI/TOML (npmrc and pypirc included) and HTTP headers, and **credential flags** on a command line. A credential name is `password`, `passwd`, `pwd`, `pw`, `pass`, `passphrase`, `secret`, `credential(s)`, `api_key`/`apiKey`/`api-key`, `access_key`, `private_key`, `token` (except usage settings such as `tokenLimit`, `max_tokens`, `token_count`), `auth_token`, `access_token`, `bearer`, `auth`, `_authToken`, `_password`, `_auth`, `key` as the last part of a multi-part name or alone in the dotenv form (`key=…`, `export key=…`; a YAML/JSON `key:` label is the name of something and stays), `creds`, `session`/`sid`/`sessionid`/`jsessionid`/`phpsessid`, the headers `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie` and any credential-named header (`X-Api-Key`), and plural forms; name parts are split at `_`, `-`, `.`, camelCase and letter/digit boundaries, so `DB_PASSWORD`, `clientSecret` and `token2` all count. Forms: `NAME=value` and `export NAME=value` (dotenv), `"name": value` (JSON, compact or pretty), `name: value` (YAML, including block scalars `|`/`>` and a deeper-indented block under an empty value), `name = value` (INI/TOML, with `[section]` headers kept), `Header: value` (HTTP). The value is removed from the separator to the end of the line, or to the end of a quoted field (escaped quotes do not end it); an unterminated quote, a trailing `\`, a YAML block scalar or an empty value followed by a deeper-indented block carry the removal onto the following lines; a trailing comment goes too; there is no minimum and no maximum length. Flags: `--password x`, `--password=x`, `--password = x`, `--token=x`, `-pX`, `-ClientSecret 'x'`, `--api-key x`, and curl `-u user:pass`. Any quoted string that contains an escaped quote is also removed whole. |
| `PRIVATE` | **Never-send terms** from `--private`: whole word (plural and possessive forms included), any case, inside brackets too, inside values too, as a prefix of a credential name (`ACME-PASSWORD=` still loses its value) and beside `@` when the text is not an email address (`user@Acme`); inside a real address the whole address becomes `[EMAIL_n]`, term included. Terms run before credential detection and cannot hide it (`OPENAI-API-KEY=…` with term `OpenAI` still loses its value). |
| `EMAIL` | Email addresses, including internationalised ones (`usér@exämple.com`, `δοκιμή@παράδειγμα.δοκιμή`). |
| `CARD` | 13 to 19 digit numbers with spaces or dashes that pass the Luhn check. |
| `SSN` | US Social Security numbers `ddd-dd-dddd`. |
| `PHONE` | Phone numbers with separators, optional country code. |
| `IP` | IPv4 addresses. |

Promised too: the false-positive traps below stay as written; placeholders behave as the Placeholders section says;
`sanitize()` holds or throws as the Residual scan section says; the outbound boundary accepts nothing but a `Sanitized`.

## Best effort (fixed when found, not merge-blocking)

Everything the scrubber covers beyond the promised shapes. All of it is guarded by tagged tests today.

- **Separators and disguises.** The separators `:=`, `=>`, `->`, `~=`, `!=`, `==`, `<<<`, Makefile `?=`, `+=`, `::=`,
  the Unicode look-alikes `∶ ꞉ ﹕ ＝ ： →`, a bidirectional isolate around a separator; credential names written with
  zero-width characters, soft hyphens, combining marks, fullwidth or look-alike letters, PowerShell backticks, JSON
  `\uXXXX` or percent-encoding (`pass%77ord=`), a `.properties` name split by a backslash-newline, names built from
  concatenated string literals in code (`"pass" + "word"`); a known key prefix hidden with a soft hyphen.
- **Credential words in other languages.** French (`mot de passe`, `mdp`, `clé`, `jeton`), German (`Passwort`,
  `Kennwort`, `Geheimnis`, `Schlüssel`, `Zugangsdaten`), Spanish (`contraseña`, `clave`, `secreto`, `credenciales`),
  Portuguese (`senha`, `chave`), Italian (`chiave`, `segreto`), Dutch (`wachtwoord`, `sleutel`), Russian (`пароль`,
  `секрет`, `ключ`, `токен`), Japanese (`パスワード`, `秘密鍵`, `トークン`), Chinese (`密码`, `密钥`, `口令`, `令牌`) and
  Korean (`비밀번호`, `암호`), and the copulas `est`, `ist`, `lautet`, `es`, `é`, `è`, `это`.
- **Prose.** `password is <value>`, `creds are user:pass`, `pw's x`, `password's x`, up to two plain words between the
  noun and the copula (`the secret phrase is x`, `my api key here is x`), a credential noun followed directly by a quoted
  value or by a bare token that carries a digit or symbol (`use the password 'cat123'`, `use password x9k2`; `my password
  yesterday.` stays), `pin`/`passcode`/`otp`/`recovery code`/`backup code`/`verification code` phrases, phrases such as
  `api key: <value>`, qualified labels (`password (prod):`, `token [staging]:`, `api key/prod:`), a bare credential name
  on its own line followed by a deeper-indented value, name, separator and value on three consecutive lines, a bare name
  line with an inline `;`/`#` comment before the separator line, `[password]=x` bracketed INI keys.
- **Other file and command forms.** netrc `password <value>` lines (netrc shape only); a line that is only `name value`
  (`export PASSWORD v`, `//registry/:_authToken v`); `ENV`/`ARG`/`export`/`set` lines with a credential name followed by a
  value among other pairs; `read -s password <<< x`; `-Dpassword:x`; `net use … /user:name <pass>`;
  `ConvertTo-SecureString '<x>'`; `New-Object pscredential 'u', 'x'` and `[pscredential]::new('u', 'x')`;
  `--pwfile=`/`--keyfile=` style paths; `--set-json` arrays; URL query parameters named code, auth, sig, signature, key,
  token, secret, password, pwd, pass, access_token, refresh_token, id_token, apikey, api_key, session, sid, jwt, otp;
  a credential name as a URL path segment followed by its value (`/token/<x>/`); a header name followed by a space
  inside a bracket list (`[Set-Cookie sid=x; Path=/, …]`); multipart form-data parts whose `Content-Disposition` names
  a credential (the body up to the next boundary); YAML explicit keys (`? password` / `: value`); YAML tagged blocks
  (`!vault |`, `!!binary |`); a YAML alias under a credential key takes its anchored value (`password: *s` and
  `shared: &s x`); adjacent pairs `[password, x]`, Clojure/EDN `{:password "x"}`.
- **Tables.** CSV columns under a header cell that is a credential name (the quoted field may span lines) and a line that
  starts with a credential name and a comma; SQL `INSERT … (cols) VALUES (…)` and `COPY … FROM stdin` rows; Markdown
  tables (an escaped `\|` is cell text, not a boundary) and HTML tables.
- **XML and HTML.** XML/HTML elements whose tag name is a credential name; HTML tags whose `name`, `id`, `http-equiv`,
  `aria-label`, `placeholder`, `data-field`, `data-name`, `data-key`, `title` or `for` attribute is a credential name or
  an auth header (their other attribute values go, and their element text, the closing tag matched without case:
  `<textarea name="password">x</TEXTAREA>`); `Name="password"` attributes (the next `*Value` child); `KeyName`,
  `KeyValue`, `X509Data`, `DEREncodedKeyValue` elements; plist `<key>Password</key>` followed by `<string>`/`<data>`.
- **Credential scopes.** INI/TOML sections `[password]`/`[[credentials]]`, git-config `[credential "…"]`, HOCON/HCL
  blocks `credentials { … }`, Terraform `variable "db_password" { default = … }`, JSON objects and YAML flow or block
  maps under a credential key (a YAML block map is walked at any depth: nested maps, block scalars and list items all
  lose their scalars, map heads stay, and a blank line inside the record does not end it), in which **every** value goes until the scope ends (a username inside a
  `credentials` object goes too); a Kubernetes document with `kind: Secret` loses every scalar under `data:` and
  `stringData:`.
- **Sibling pairs.** A name field (`name`, `key`, `label`, `field`, `var`, `env`, `option`, `setting`, `property`,
  `param`) whose value is a credential name, next to a value field (`value`, `val`, `default`, `data`, `content`,
  `secret`, …) in the same entry, in JSON, YAML, TOML, INI, `.properties` (`env[0].name` / `env[0].value`), dotenv
  (`ENV_0_NAME` / `ENV_0_VALUE`), Python, JavaScript, PHP, Ruby, Go struct tags, Java and C# annotations, Rust
  attributes, GraphQL, protobuf text and Ansible vars.
- **Code forms.** Tuples `('password', 'x')`, C++ designated initialisers `.password = "x"`, a credential passed as a
  quoted call argument (`setPassword('x')`, `std::string secret("x")`), option declarations whose first argument is the
  option name (`@click.option('--password', default='x')`), JSON-schema `example` under a credential property, OpenAPI
  `securitySchemes` examples.
- **Residual-only catches.** A bare value with a known prefix or high entropy and no name is held, not scrubbed
  (`sanitize` returns `held: true`); six or more spaced groups of four hex characters (recovery codes) likewise.

False-positive traps that are deliberately left alone (promised): `secretary:`, `tokenizer=`, `tokenLimit=`,
`max_tokens:`, `token_count:`, `Password requirements: …`, prose that mentions a password, session or cookie without a
separator ("I forgot my password yesterday"), long URLs, code identifiers, dates, prices, order numbers that fail Luhn,
public keys and certificates.

## Residual scan (fail closed)

After scrubbing, `residual(text, { terms })` looks with a different mechanism: known prefix shapes regardless of
entropy; hex runs of 20 or more characters with at least one letter and Shannon entropy above 3.0 bits per character;
base64-class runs of 20 or more characters that mix at least two of upper case, lower case and digits with entropy
above 4.0; six or more groups of four hex characters separated by spaces or dashes; a leftover `name=value` credential assignment or `Authorization:` header; any never-send term still present.
UUIDs and the scrubber's own placeholders are skipped. If it finds anything, `sanitize()` returns `held: true` and the
reasons (which name the mechanism, never the value), and the caller must not send the text. Past the size or time cap
`sanitize()` throws `ScrubError`; `run` and `check` both turn that into the single `judge:held` finding for that
conversation (unsure), never a crash and never a call.

## Never-send words in tool definitions

Tool names, JSON-schema property names, the names in every other schema-keyed map (`$defs`, `definitions`,
`patternProperties`, `dependentSchemas`, `dependentRequired`, `dependencies`) and `required` entries are sent to the
replay model unscrubbed, because the model must echo them exactly for dispatch. A never-send word inside one of them (as
a whole word or a camelCase part, `acme_lookup`, `acmeId`, `AcmeUser` in `$defs`) cannot be hidden without breaking the tool, so the model adapter refuses the run before any
request is built: "A word from your --private list is in a tool name, a parameter name or a required list". Tool
descriptions, enums and examples are scrubbed as before.

## Echoed secrets

`echoes(text)` returns the kinds of values this scrubber inventoried (from the user's side of a conversation) that
appear verbatim in `text`. `transcripts.js` uses it so "the agent repeated the user's card number" is an exact match of
the user's value, not a second regex. The inventory grows in conversation order: only a value the user typed in an
earlier turn is an echo; a hard secret the agent introduces first is reported as `revealed_secret` even when the user
quotes it back in a following turn (the agent repeating it after that is then an echo).

## Performance

Linear time: every pattern is bounded, nothing re-scans the whole text per match, and no lookbehind is unbounded (an
unbounded `[ \t]+` lookbehind re-scanned a long indent at every position and cost 1.8 s on Node 22). Budgets are
machine-independent ratios measured in `engine/test/perf.test.js`: one *unit* is the time of a fixed set of plain
linear scans over the same 60,000-character chat on the machine running the tests (about 8 ms on the reference
machine), `sanitize` of that chat must take under 12 units (100 ms there), growth from 20,000 to 80,000 characters
under 6× (linear is 4×), and each of the 21 ReDoS payloads under 60 units (500 ms there). The printed unit keeps an
absolute number visible in CI logs; the CI workflow runs the same suite on Linux with Node 22.

## Known non-coverage

- Names, postal addresses, dates of birth, passport and national id numbers other than US SSNs, IBANs and bank account
  numbers, IPv6 addresses, phone numbers written without separators.
- A bare secret with no name, no known prefix and low entropy (for example a dictionary-word password pasted on its own)
  cannot be told from ordinary text; the residual scan holds the text only when the value has a known shape or high
  entropy.
- A secret split across words or lines without a continuation marker (`\`, an open quote, a YAML block) is scrubbed
  only as far as the main rules reach.
- A value a user typed that already looks like a placeholder (`[EMAIL_1]`, a password that is literally `[SECRET_1]`)
  is left as written and its number is reserved; `unscrub` of a model's reply restores only placeholders the scrubber
  made. A credential value that *starts* with such text and continues with other characters (`password=[SECRET_1]abc`)
  is scrubbed whole; a value that is only a placeholder (plus closing punctuation) is left as already scrubbed.
- A bare base64 blob split across several lines with no name is caught only by the residual scan (held, not scrubbed).
- Credential names built at run time by code other than string-literal concatenation (format strings, variables), and
  values passed through a variable (`$p = 'x'; … ConvertTo-SecureString $p`).
- A value whose only cue is on another line or in another JSON array item ("password: see below" then the value;
  Jupyter sources split across list items; a `.reg` value under a generic name; a file path that happens to contain a
  secret).
- A bare password in prose with no cue at all ("use hunter2 to log in") when it is short or low-entropy.
- A never-send term embedded inside another word (`ProjectAcmePilot`, `ACMEcorp`): whole-word matching is a v1 promise
  (so `Ivory` does not match `Ivo`); the residual scan still holds such text. Dotted abbreviations (`A.C.M.E.`),
  spreadsheet formulas that build a credential (`=CONCAT("password","=",…)`), and a comment between a key and its
  separator on one line are not covered.
- Parse-time indirection: YAML merge keys (`<<: *base` under a credential key), XML `<!ENTITY>` references, and values
  mentioned only in a doc comment (`/** password default x */`).
- The replay-model path in `engine/src/adapters.js` scrubs every field with the same scrubber but does not pass the
  residual gate (plan decision D11, deferred).
- Scrubbing happens before the model sees the text; the model's own output is not scanned for new secrets except by the
  echo and reveal checks on pasted conversations.
