# Scrubber corpus

Fixtures for `engine/test/scrubber-v2.test.js`. They are **templates**: no file here holds a secret shape, because the
repo's gate 2 refuses any commit whose diff contains a key prefix or a PEM header. `expand.js` fills the `{{TOKEN}}`
markers at test time from a seeded generator (the seed is the file name, so values are stable across runs and machines)
and returns every value it made, so a test can assert that no 8-character window of any value survives scrubbing.

## Tokens

| Token | Produces |
|---|---|
| `{{SECRET n}}` | n letters and digits, at least one upper, one lower, one digit (a password-like value) |
| `{{B64 n}}` / `{{HEX n}}` | n base64 / lowercase-hex characters |
| `{{PREFIX kind}}` | a known token shape: `sk`, `skor`, `skant`, `ghp`, `akia`, `asia`, `xoxb`, `xoxp`, `aiza`, `jwt`, `sklive`, `whsec`, `glpat`, `npm`, `ya29`, `pypi` |
| `{{BASIC}}` | base64 of `user:<secret>`; both the base64 and the plain secret are recorded |
| `{{PEM_HEAD label}}` / `{{PEM_FOOT label}}` | `-----BEGIN <label> PRIVATE KEY-----` and its footer; label may be empty, `RSA`, `EC`, `DSA`, `OPENSSH`, `ENCRYPTED` |
| `{{PEM_BODY n}}` | n lines of 64 base64 characters, each recorded as a secret |

Files are read with CRLF normalised to LF (Windows checkouts); CRLF behaviour is tested from strings built in code.

## Families

| File | Covers |
|---|---|
| `dotenv.txt` | `KEY=value`, `export`, quoted and unquoted, a 200+ character value with a suffix, trailing `\` continuation, an escaped quote, a trailing comment, known prefixes (sk, ghp, xoxb, AKIA, sk_live, JWT); keepers `tokenLimit`, `max_tokens`, `tokenizer` |
| `json-compact.json` | one-line JSON: password, api_key, nested client_secret with escaped quotes, Bearer header, cookie, a PEM inside a string with `\n` escapes; fields after a secret field stay |
| `json-pretty.json` | multi-line JSON: camelCase names, 200+ value, escaped quote, `Authorization: Basic`, `Cookie`, usage limits that stay |
| `yaml.txt` | `key: value`, quoted, `\|` and `>` block scalars, an empty key with a deeper-indented block, single-quoted 200+ value; keepers `max_tokens`, `secretary: Jonathan Smith`, prose with "session" |
| `npmrc.txt` | `//host/:_authToken=`, `:_password=`, `:_auth=`, one 220-character token; `registry=`, `username=`, `save-exact` stay |
| `pypirc.txt` | `password = value` with spaces round `=`, a pypi- token and a 210-character password; repositories stay |
| `netrc.txt` | `password <value>` with no separator, one-line and multi-line netrc; machine names stay |
| `headers.txt` | `Authorization: Basic/Bearer/Digest`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`, a header inside a quoted curl argument; request line, Host and Content-Type stay |
| `urls.txt` | `user:pass@` userinfo in postgres, https, redis (empty user), mongodb+srv and a 210-character password; hosts and a plain long documentation URL stay |
| `pem.txt` | plain, RSA with `Proc-Type`/`DEK-Info` and a blank line, EC, DSA, OPENSSH with blank lines inside, ENCRYPTED; the line after the keys stays |
| `pem-truncated.txt` | RSA header, `Proc-Type`, `DEK-Info`, blank line, body, no footer: removed to the end of input |
| `pem-big.txt` | a 300-line key with a footer (over 16 KB) followed by a line that stays, then a 1100-line key with no footer |
| `prose.txt` | false-positive traps: chat about passwords, sessions, cookies, tokens, `secretary`, `tokenizer`, `tokenLimit`, a long URL, a camelCase identifier, an order number, a price, "Password requirements:"; must come back unchanged |
| `never-send.txt` | terms `Acme`, `Acme Corp`, `OpenAI` in brackets, as a name prefix (`OPENAI-API-KEY=`), lower case, possessive, inside a value |
| `chat.txt` | a labelled chat with a `.env` block pasted mid-message (220-character password) and a literal `[EMAIL_1]` that must be left alone |

## Self-attack rounds (Phase 3)

`attack-round-N.json` files are picked up automatically. Each is a list of cases:

```json
[{ "name": "what the attacker tried", "terms": ["Acme"], "input": "PASSWORD={{SECRET 24}} ...", "gone": ["literal text that must also vanish"], "keep": ["literal text that must stay"] }]
```

`input` uses the tokens above; every generated value plus every `gone` string must be absent from the output, every
`keep` string present, and no `terms` entry may survive in any case.

## Licences

The oracle data (`oracle-shapes.json`) is copied from other scanners' test data; see `THIRD_PARTY.md`. Everything else
here was written for this repo.
