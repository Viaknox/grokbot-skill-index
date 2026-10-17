// Checks on CI and tooling files outside src/ (workflows, the mutation script). Kept out of gate.test.js, which the
// mutation check runs inside an engine-only copy where ../.github does not exist.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ENGINE = fileURLToPath(new URL('..', import.meta.url));

test('PR #32 review: the CI keeps one stable "engine" check that fails unless every matrix cell passed', () => {
  const yml = readFileSync(fileURLToPath(new URL('../../.github/workflows/test.yml', import.meta.url)), 'utf8');
  assert.match(yml, /\n  engine:\n    if: always\(\)\n    needs: engine-matrix\n/);
  assert.match(yml, /RESULT: \$\{\{ needs\.engine-matrix\.result \}\}\n\s+run: '\[ "\$RESULT" = "success" \]/);
});

test('PR #32 review: the mutation check runs the unmutated baseline first and fails if it does not pass', () => {
  const src = readFileSync(join(ENGINE, 'scripts', 'mutate.mjs'), 'utf8');
  assert.match(src, /const base = run\(src, files, opt\.timeout\);\n\s+if \(base !== 'survived'\)/);
  assert.doesNotMatch(src, /node_modules\|scripts\|/, 'scripts/ must be copied into the mutation copy');
});
