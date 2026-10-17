// Guards the npm release workflow (.github/workflows/release.yml, docs/CLI-PLAN.md S6 and the PT checklist) and the
// release PR it starts from. Each test names what it stops: a release that publishes without Paul's approval, with a
// token, to the wrong channel, from an untested tarball, or that tags before npm is verified.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { section, compatibility } from '../scripts/release-notes.mjs';

const read = (p) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), 'utf8');
const yml = read('../../.github/workflows/release.yml');
const pkg = JSON.parse(read('../package.json'));
// The text of one job, from its key to the next job key.
const job = (name) => { const m = new RegExp(`\\n  ${name}:\\n([\\s\\S]*?)(?=\\n  [a-z-]+:\\n|$)`).exec(yml); assert.ok(m, `job ${name} missing`); return m[1]; };

test('S6: a merged release PR on main starts a release; tags and other branches never do', () => {
  assert.match(yml, /\non:\n  push:\n    branches: \[main\]\n    paths: \['engine\/package\.json', 'engine\/RELEASE_CHANNEL'\]\n\n/);
  assert.doesNotMatch(yml, /tags:|workflow_dispatch|pull_request|release:\n\s+types/, 'no tag, manual, PR or release-event trigger');
});

test('PT20: releases are serialised and a pending one is queued, never dropped', () => {
  assert.match(yml, /\nconcurrency:\n  group: agenttuneup-release\n  cancel-in-progress: false\n  queue: max\n/);
});

test('PT4/PT16: only the publish job waits for the release environment and holds id-token', () => {
  assert.match(yml, /\npermissions: \{\}\n/, 'the workflow default grants nothing');
  assert.equal((yml.match(/id-token: write/g) || []).length, 1);
  assert.match(job('publish'), /\n    environment: release\n/);
  assert.match(job('publish'), /\n    permissions:\n      contents: read\n      id-token: write /);
  assert.match(job('publish'), /\n    if: needs\.prepare\.outputs\.release == 'true'\n/);
  assert.match(job('publish'), /needs: \[prepare, smoke\]/, 'publish waits for the full smoke matrix');
  for (const j of ['prepare', 'smoke', 'tag']) assert.doesNotMatch(job(j), /environment: release\n|id-token/, j);
});

test('PT10/PT17: npm always gets an explicit --tag from engine/RELEASE_CHANNEL; no stored token', () => {
  assert.match(job('publish'), /npm publish "\$file" --tag "\$CHANNEL" --access public --provenance\n/);
  assert.match(job('publish'), /file="\.\/dist\/\$TARBALL"/, 'a local tarball path must start with ./ or npm treats it as a GitHub spec');
  assert.match(job('prepare'), /channel="\$\(tr -d '\[:space:\]' < engine\/RELEASE_CHANNEL\)"/);
  assert.match(job('prepare'), /case "\$channel" in next\|latest\) ;; \*\) echo "::error::/);
  assert.match(job('prepare'), /if \[ "\$prerelease" = true \] && \[ "\$channel" = latest \]; then echo "::error::/);
  assert.doesNotMatch(yml, /NPM_TOKEN|NODE_AUTH_TOKEN|registry-url|_authToken/, 'trusted publishing only');
  assert.match(job('publish'), /npm install -g npm@11\.5\.1\n/, 'npm 11.5.1 or later for trusted publishing, pinned');
});

test('PT7/PT23: version shape, not private, on main, full tests and gate mutation before the tarball is built', () => {
  const p = job('prepare');
  const at = (s) => { const i = p.indexOf(s); assert.ok(i >= 0, `missing: ${s}`); return i; };
  const pack = at('npm pack --silent');
  for (const s of ["grep -Eq '^[0-9]+\\.[0-9]+\\.[0-9]+(-(rc|beta)\\.[0-9]+)?$'", 'private === undefined', 'git merge-base --is-ancestor "$GITHUB_SHA" origin/main', 'npm test && npm run mutate:gate']) assert.ok(at(s) < pack, `${s} must run before the pack`);
  assert.match(p, /grep -Ev '\^\(cli\\\.js\|package\\\.json\|README\\\.md\|LICENSE\|src\/\[A-Za-z0-9_-\]\+\\\.js\)\$'/, 'file allowlist');
  assert.match(p, /\[ "\$version" = "0\.1\.0-rc\.0" \]; then release=false/, 'exactly the bootstrap version is never published here (S8)');
  assert.match(p, /\[ "\$version" = "\$before" \]; then release=false/, 'a push that does not change the version releases nothing');
});

test('PT8/PT9: the exact tarball is smoke-tested on every OS and Node, and the approval summary lists it', () => {
  const s = job('smoke');
  assert.match(s, /os: \[ubuntu-latest, windows-latest, macos-latest\]/); assert.match(s, /node: \['20\.12', '22'\]/);
  assert.match(s, /TU_TEST_TARBALL="\$GITHUB_WORKSPACE\/dist\/\$TARBALL" node --test test\/cli-package\.test\.js/);
  const p = job('prepare');
  for (const s2 of ['Version', 'npm channel (dist-tag)', 'Commit', 'Tarball integrity', '**Compatibility:**', 'sha256sum']) assert.ok(p.includes(s2), `summary lacks ${s2}`);
  assert.match(job('publish'), /\[ "\$got" = "\$INTEGRITY" \] \|\| \{ echo "::error::downloaded tarball differs/, 'publish the tested bytes only');
});

test('PT20: a re-run resumes only for the identical tarball, and npm is verified before anything is tagged', () => {
  const p = job('publish');
  assert.match(p, /\[ "\$onnpm" = "\$INTEGRITY" \] \|\| \{ echo "::error::agenttuneup@\$VERSION is already on npm with a different tarball/);
  assert.match(p, /"\$prov" = "https:\/\/slsa\.dev\/provenance\/v1"/); assert.match(p, /"\$tag" = "\$VERSION"/);
  assert.match(job('tag'), /needs: \[prepare, publish\]/);
});

test('PT3/S6: the tag job uses the release App, targets the approved commit, never moves a tag, keeps Latest', () => {
  const t = job('tag');
  assert.match(t, /environment: release-tag\n/); assert.match(t, /\n    permissions: \{\}\n/);
  assert.match(t, /app-id: \$\{\{ vars\.RELEASE_APP_ID \}\}/); assert.match(t, /permission-contents: write/);
  assert.match(t, /\[ "\$existing" = "commit \$GITHUB_SHA" \] \|\| \{ echo "::error::/, 'an existing tag must point at the approved commit');
  assert.match(t, /-f ref="refs\/tags\/\$tag" -f sha="\$GITHUB_SHA"/);
  assert.match(t, /onmain \|\| \{ echo "::error::approved commit left main"; exit 1; \}\n\s+gh api -X POST "repos\/\$REPO\/git\/refs"/, 'main is re-checked just before the tag is created');
  assert.match(t, /-F prerelease="\$pre" -f make_latest=false/);
  assert.doesNotMatch(t, /-X (?:PATCH|DELETE)|git push/, 'nothing updates or deletes a tag');
});

test('PT11: every action is pinned to a full SHA, checkouts keep no credentials, run scripts take inputs via env only', () => {
  for (const m of yml.matchAll(/uses: (\S+)/g)) assert.match(m[1], /@[0-9a-f]{40}$/, `action not pinned to a commit: ${m[1]}`);
  const checkouts = yml.split('uses: actions/checkout@').slice(1);
  assert.ok(checkouts.length >= 2); for (const c of checkouts) assert.match(c.slice(0, 200), /persist-credentials: false/);
  // A ${{ }} inside a run: script is a template-injection risk (zizmor); values go through env: instead.
  for (const m of yml.matchAll(/\n(\s+)run: \|\n((?:\1  .*\n|\s*\n)+)/g)) assert.doesNotMatch(m[2], /\$\{\{/, 'expression inside a run script');
  for (const m of yml.matchAll(/\n\s+run: (?!\|)(.*)/g)) assert.doesNotMatch(m[1], /\$\{\{/, 'expression inside a run line');
});

test('S6 release PR: CHANGELOG section with Compatibility, a valid channel, and README pinned to this version', () => {
  const v = pkg.version;
  assert.match(v, /^\d+\.\d+\.\d+(?:-(?:rc|beta)\.\d+)?$/);
  const body = section(read('../CHANGELOG.md'), v);
  assert.ok(body, `engine/CHANGELOG.md has no "## ${v}" section`); assert.ok(compatibility(body), 'the section needs a "Compatibility:" line');
  const channel = read('../RELEASE_CHANNEL').trim();
  assert.ok(['next', 'latest'].includes(channel), `RELEASE_CHANNEL is "${channel}"`);
  if (v.includes('-')) assert.equal(channel, 'next', 'a pre-release version only goes to next');
  // Until Paul approves the first latest (docs/CLI-PLAN.md §3), every release goes to next.
  assert.equal(channel, 'next');
  const pins = [...read('../README.md').matchAll(/agenttuneup@([\w.-]+)/g)].map(m => m[1]);
  assert.ok(pins.length > 0); for (const p of pins) assert.equal(p, v, 'README pins an exact version, and it is this one');
  assert.equal(section('## 1.0.0\n\nx\n\nCompatibility: none\n## 0.9.0\ny', '1.0.0'), 'x\n\nCompatibility: none');
  assert.equal(section('## 1.0.0-rc.1\nx', '1.0.0'), null, 'a version prefix is not a match');
  assert.equal(compatibility('no line here'), null);
});

test('PR #33 review: a re-run never moves a channel back, and the token-holding tag job runs no repository code', () => {
  const p = job('publish');
  const guard = p.indexOf('refusing to move it back'), pub = p.indexOf('npm publish "$file"');
  assert.ok(guard > 0 && guard < pub, 'the channel check runs before publish');
  // The inline comparison, run here on real version pairs.
  const src = /node -e '\n([\s\S]*?)'\)"/.exec(p)[1].replace(/\\\\/g, '\\');
  const cmp = (cur, nw) => spawnSync(process.execPath, ['-e', src], { env: { ...process.env, CUR: cur, NEW: nw }, encoding: 'utf8' }).stdout.trim();
  for (const [cur, nw, want] of [['0.1.0-rc.2', '0.1.0-rc.1', 'yes'], ['0.1.0', '0.1.0-rc.9', 'yes'], ['0.2.0-rc.0', '0.1.9', 'yes'], ['0.1.0-rc.1', '0.1.0-rc.2', 'no'], ['0.1.0-rc.9', '0.1.0', 'no'], ['0.1.0-rc.10', '0.1.0-rc.9', 'yes'], ['0.1.0-beta.3', '0.1.0-rc.1', 'no']]) assert.equal(cmp(cur, nw), want, `${cur} vs ${nw}`);
  const t = job('tag');
  assert.doesNotMatch(t, /actions\/checkout|node /, 'no checkout and no node in the job with the App token');
  assert.match(t, /name: agenttuneup-release-notes/);
  assert.match(job('prepare'), /node scripts\/release-notes\.mjs "\$VERSION" > \.\.\/notes\/notes\.md/);
});

test('PR #33 review: the release-notes script runs from engine/ with a relative path, as the workflow calls it', () => {
  const engine = fileURLToPath(new URL('..', import.meta.url));
  const v = pkg.version;
  const notes = spawnSync(process.execPath, ['scripts/release-notes.mjs', v], { cwd: engine, encoding: 'utf8' });
  assert.equal(notes.status, 0, notes.stderr); assert.match(notes.stdout, /Compatibility:/);
  const compat = spawnSync(process.execPath, ['scripts/release-notes.mjs', v, '--compatibility'], { cwd: engine, encoding: 'utf8' });
  assert.equal(compat.status, 0); assert.equal(compat.stdout.trim(), compatibility(section(read('../CHANGELOG.md'), v)));
  const missing = spawnSync(process.execPath, ['scripts/release-notes.mjs', '9.9.9'], { cwd: engine, encoding: 'utf8' });
  assert.equal(missing.status, 1, 'a version without a CHANGELOG section stops the release');
});
