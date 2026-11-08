import assert from 'node:assert/strict';
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { summarize } from './security-summary.mjs';
const snapshot = {
  branch: 'alpha',
  sha: 'a'.repeat(40),
  base: 'b'.repeat(40),
  candidate: 'c'.repeat(40),
  pr: '1',
  requestId: '123-1',
};
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'summary-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, '.data/test-gates/security');
  mkdirSync(join(path, 'source'), { recursive: true });
  const files = {
    'source/sast.json': {
      errors: [],
      paths: { scanned: ['src/main.ts'] },
      results: [],
    },
    'secrets.json': { scanned: ['src/main.ts'], findings: [] },
    'audit-application.json': {},
    'audit-sandbox.json': {},
    'gitleaks.json': [],
    'trivy.json': {
      SchemaVersion: 2,
      Results: [
        'bun.lock',
        'sandbox/bun.lock',
        'deploy/woodpecker/gitee/go.mod',
        'sandbox/envd/go.mod',
      ].map((Target) => ({ Target, Packages: [{}] })),
    },
    'result.json': { status: 'passed' },
  };
  for (const [name, value] of Object.entries(files))
    writeFileSync(join(path, name), JSON.stringify(value));
  return { root, path };
}
test('only a complete successful phase with passing gate can publish clean summary', (t) => {
  const { root, path } = fixture(t);
  assert.equal(summarize(root, snapshot, true).success, true);
  assert.equal(summarize(root, snapshot, false).success, false);
  rmSync(join(path, 'gitleaks.json'));
  const value = summarize(root, snapshot, true);
  assert.equal(value.success, false);
  assert.equal(value.scanners.gitleaks.complete, false);
});
test('matched strings, symlinks, malformed levels and findings never become clean or public text', (t) => {
  const { root, path } = fixture(t);
  writeFileSync(
    join(path, 'gitleaks.json'),
    JSON.stringify([
      {
        RuleID: 'fixture',
        File: 'PRIVATE_SENTINEL',
        Secret: 'PRIVATE_SENTINEL',
      },
    ]),
  );
  let report = summarize(root, snapshot, true);
  assert.equal(report.success, false);
  assert.equal(report.scanners.gitleaks.counts.high, 1);
  assert.ok(!JSON.stringify(report).includes('PRIVATE_SENTINEL'));
  rmSync(join(path, 'gitleaks.json'));
  symlinkSync('/etc/passwd', join(path, 'gitleaks.json'));
  report = summarize(root, snapshot, true);
  assert.equal(report.scanners.gitleaks.complete, false);
  writeFileSync(
    join(path, 'audit-sandbox.json'),
    JSON.stringify({ pkg: [{ id: 1, severity: 'clean' }] }),
  );
  assert.equal(
    summarize(root, snapshot, true).scanners['bun-sandbox'].complete,
    false,
  );
});
