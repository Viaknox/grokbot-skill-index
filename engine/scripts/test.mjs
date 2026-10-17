#!/usr/bin/env node
// Runs every test/*.test.js with Node's test runner. Lists the files itself because Node 20 (still supported) does not
// expand globs for --test, so `node --test "test/*.test.js"` would find nothing there (PR #32 review). Extra arguments
// (for example --test-name-pattern=promised) go to the runner. Exits with the runner's code; an empty list is a failure.
import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = fileURLToPath(new URL('../test', import.meta.url));
const files = readdirSync(dir).filter(f => f.endsWith('.test.js')).sort().map(f => join(dir, f));
if (!files.length) { console.error('No test files found in test/.'); process.exit(1); }
const r = spawnSync(process.execPath, ['--test', ...process.argv.slice(2), ...files], { stdio: 'inherit' });
process.exit(r.status ?? 1);
