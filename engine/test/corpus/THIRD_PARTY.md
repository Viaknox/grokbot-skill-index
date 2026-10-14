# Third-party data in the test corpus

`oracle-shapes.json` holds sample strings taken, as data only, from two open-source secret scanners. They feed the
differential oracle in `engine/test/fuzz.test.js`: the scrubber must remove each sample's secret or hold the text back.
No code was copied, and no sample string is stored as such: `oracle-shapes.json` keeps each sample as a line template with a `{{V}}` marker and the secret's *shape* (short literal prefixes and separators, plus random runs as charset and length). The fuzz test rebuilds a value of the same shape with its seeded generator, so no secret-shaped literal sits in the repo and secret scanners (the repo's own gate, gitleaks, GitHub push protection) find nothing
(the commit gate and GitHub's own scanners would otherwise flag it).

Nothing was taken from trufflehog (AGPL) or from any other scanner.

## gitleaks

- URL: https://github.com/gitleaks/gitleaks
- License: MIT (`LICENSE` at the repository root, read at the commit below)
- Commit read: `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`
- What was copied: the literal sample secrets in `cmd/generate/config/rules/*.go` (the second argument of
  `utils.GenerateSampleSecrets("<id>", "<literal>")` and the literal strings in `tps := []string{...}`), 292 samples
  from 37 rules. Samples built with `secrets.NewSecret(...)` are random at build time and were left out. For
  `GenerateSampleSecrets` the lines are the wrappers that function produces (INI, JSON, XML, YAML, Go, Python), filled with
  the literal. A sample is kept only when the rule's own regex (from `config/gitleaks.toml`) matches its line; the secret
  is the rule's secret group.
- Each sample's `source` is `gitleaks:<rule id>`.

## detect-secrets

- URL: https://github.com/Yelp/detect-secrets
- License: Apache-2.0 (`LICENSE` at the repository root, read at the commit below)
- Commit read: `5e141933554a0b74e7341841f318be21e895339c`
- What was copied: true-positive strings from `tests/plugins/*_test.py` (parametrized cases the test marks as flagged;
  cases marked should-not-detect were left out, as was the public-IP plugin because an IP address is not a credential),
  and the secrets the repository's own `test_data/baseline.file` flags in `test_data/each_secret.py`,
  `config.env`, `config.ini`, `config.yaml`, `config2.yaml` and `files/*` (found by matching the baseline's SHA-1 hash
  to a token on the flagged line), 166 samples from 28 files. Placeholder values (fewer than 5 distinct characters,
  such as a run of one letter) were dropped.
- Each sample's `source` is `detect-secrets:<path of the file it came from>`.
- Where a plugin test gives only a line, the secret is the longest value-like token on it (or the password part of
  URL userinfo, or the last path segment of a webhook URL); the secret recorded for each sample is always a substring
  of its line.

Samples with a secret shorter than 6 characters were dropped, and exact duplicates were removed.

## License notices

### gitleaks (MIT)

```
MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### detect-secrets (Apache License 2.0)

```
Copyright 2017-2018 Yelp Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

The full Apache-2.0 text is at https://www.apache.org/licenses/LICENSE-2.0. The upstream repository has no NOTICE file.
The sample strings are reduced to their shapes (prefix, separators, charset, length) and, for gitleaks, the generated wrapper lines
described above.
