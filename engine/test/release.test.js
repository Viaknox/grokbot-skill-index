// Guards the npm release workflow (.github/workflows/release.yml): a tag alone must never publish, and publishing must
// run the full checks first with no stored npm token (PR #33 security review).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const yml = readFileSync(fileURLToPath(new URL('../../.github/workflows/release.yml', import.meta.url)), 'utf8');

test('release: publishing waits for the protected "release" environment and is the only job with id-token', () => {
  assert.match(yml, /\n  publish:\n(?:    .*\n)*?    environment: release\n/, 'the publish job must use environment: release');
  assert.equal((yml.match(/id-token: write/g) || []).length, 1, 'id-token: write appears once, on the publish job');
  assert.match(yml, /^permissions:\n  contents: read\n/m, 'workflow default is read-only');
});

test('release: tag must equal the version and be on main; tests and gate mutation run before publish; no npm token', () => {
  const at = (s) => { const i = yml.indexOf(s); assert.ok(i >= 0, `missing: ${s}`); return i; };
  const publish = at('npm publish --provenance --access public');
  for (const step of ['"$GITHUB_REF_NAME" = "$want"', 'merge-base --is-ancestor "$GITHUB_SHA" origin/main', 'npm test', 'npm run mutate:gate']) assert.ok(at(step) < publish, `${step} must run before publish`);
  assert.doesNotMatch(yml, /NPM_TOKEN|NODE_AUTH_TOKEN|secrets\./, 'no stored npm token');
  for (const m of yml.matchAll(/uses: (\S+)/g)) assert.match(m[1], /@[0-9a-f]{40}$/, `action not pinned to a commit: ${m[1]}`);
});
