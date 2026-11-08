import assert from 'node:assert/strict';
import { lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { github, revalidate } from './request.mjs';

export const scannerNames = [
  'semgrep',
  'secrets',
  'bun-application',
  'bun-sandbox',
  'gitleaks',
  'trivy',
];
export const levels = ['unknown', 'low', 'medium', 'high', 'critical'];
function read(root, file) {
  // The trusted publisher never imports source code or emits raw scanner strings.
  for (const segment of file.split('/')) {
    root = join(root, segment);
    assert.ok(!lstatSync(root).isSymbolicLink());
  }
  const info = lstatSync(root);
  assert.ok(info.isFile() && info.size <= 32 * 1024 * 1024);
  return JSON.parse(readFileSync(root, 'utf8'));
}
export function summarize(root, snapshot, success, now = new Date()) {
  const report = {
    version: 1,
    branch: snapshot.branch,
    sha: snapshot.sha,
    base: snapshot.base,
    candidate: snapshot.candidate,
    pr: snapshot.pr,
    requestId: snapshot.requestId,
    at: now.toISOString(),
    success: false,
    scanners: {},
  };
  const directory = join(root, '.data/test-gates/security');
  for (const name of scannerNames) {
    const counts = Object.fromEntries(levels.map((level) => [level, 0]));
    let complete = false;
    try {
      let severities;
      if (name === 'semgrep') {
        const value = read(directory, 'source/sast.json');
        assert.ok(
          Array.isArray(value.errors) &&
            !value.errors.length &&
            value.paths.scanned.length &&
            Array.isArray(value.results),
        );
        severities = value.results.map(() => 'high');
      } else if (name === 'secrets') {
        const value = read(directory, 'secrets.json');
        assert.ok(value.scanned.length && Array.isArray(value.findings));
        severities = value.findings.map(() => 'high');
      } else if (name.startsWith('bun-')) {
        const value = read(directory, `audit-${name.slice(4)}.json`);
        assert.ok(value && !Array.isArray(value) && typeof value === 'object');
        severities = Object.values(value).flatMap((items) => {
          assert.ok(Array.isArray(items) && items.length);
          return items.map((item) => {
            assert.ok(item.id);
            return item.severity === 'moderate' ? 'medium' : item.severity;
          });
        });
      } else if (name === 'gitleaks') {
        const value = read(directory, 'gitleaks.json');
        assert.ok(Array.isArray(value));
        severities = value.map((item) => {
          assert.ok(
            typeof item.RuleID === 'string' && typeof item.File === 'string',
          );
          return 'high';
        });
      } else {
        const value = read(directory, 'trivy.json');
        assert.equal(value.SchemaVersion, 2);
        assert.ok(Array.isArray(value.Results));
        for (const target of [
          'bun.lock',
          'sandbox/bun.lock',
          'deploy/woodpecker/gitee/go.mod',
          'sandbox/envd/go.mod',
        ])
          assert.ok(
            value.Results.some(
              (item) => item.Target === target && item.Packages?.length,
            ),
          );
        severities = value.Results.flatMap((item) =>
          (item.Vulnerabilities || []).map((vuln) => {
            assert.ok(vuln.VulnerabilityID);
            return vuln.Severity.toLowerCase();
          }),
        );
      }
      assert.ok(severities.length <= 1000000);
      for (const level of severities) {
        assert.ok(levels.includes(level));
        counts[level]++;
      }
      complete = true;
    } catch {
      /* Missing/malformed reports are incomplete, never clean scans. */
    }
    report.scanners[name] = { complete, counts };
  }
  let gatePassed = false;
  try {
    gatePassed = read(directory, 'result.json').status === 'passed';
  } catch {
    /* Incomplete. */
  }
  report.success =
    success &&
    gatePassed &&
    Object.values(report.scanners).every(
      (item) => item.complete && !item.counts.high && !item.counts.critical,
    );
  return report;
}
export async function publishSecurity(root, snapshot, success, api, now) {
  await revalidate(snapshot, api);
  const report = summarize(root, snapshot, success, now);
  const check = await api('/check-runs', 'POST', {
    name: 'Security scan summary',
    head_sha: snapshot.sha,
    status: 'completed',
    conclusion: report.success ? 'success' : 'failure',
    external_id: `sandboxpi:${snapshot.requestId}:security`,
    details_url:
      'https://sandboxpi.feeling.ltd/monitoring/d/sandboxpi-security',
    output: {
      title: 'Security scan summary',
      summary:
        'Aggregated scan results only. Required App quality and test gates remain authoritative.',
      text: JSON.stringify(report),
    },
  });
  assert.equal(check.app?.id, 5497722);
  return report;
}
export const securityApi = github;
