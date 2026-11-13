import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { github, repository, validateRequest } from './request.mjs';

// Trusted host requests and scheduled backup do not depend on private default-main event registration.
export async function discover(
  environment,
  source = github(environment.SOURCE_TOKEN),
  request = fetch,
  now = Date.now,
) {
  assert.equal(environment.GITHUB_REPOSITORY, 'BANG404/sandboxpi-actions');
  assert.equal(environment.GITHUB_REF, 'refs/heads/main');
  assert.ok(
    ['schedule', 'workflow_dispatch'].includes(environment.GITHUB_EVENT_NAME),
  );
  let submitted = 0;
  for (let page = 1; page <= 10; page++) {
    const prs = await source(`/pulls?state=open&per_page=100&page=${page}`);
    assert.ok(Array.isArray(prs));
    for (const pr of prs) {
      if (
        !['alpha', 'beta', 'rc', 'main'].includes(pr.base?.ref) ||
        pr.head?.repo?.full_name !== repository
      )
        continue;
      if (
        environment.GITHUB_EVENT_NAME === 'schedule' &&
        now() - Date.parse(pr.updated_at) < 120000
      )
        continue;
      const input = {
        action: 'pr',
        branch: pr.base.ref,
        sha: pr.head.sha,
        pr: String(pr.number),
        runGates: true,
        requestId: randomUUID(),
      };
      let snapshot;
      try {
        snapshot = await validateRequest(input, source);
      } catch {
        continue;
      }
      const found = await source(
        `/commits/${input.sha}/check-runs?filter=all&per_page=100`,
      );
      assert.ok(Array.isArray(found.check_runs));
      const baseMarker = `Sandboxpi source base: ${snapshot.base}`;
      const branchMarker = `Sandboxpi source branch: ${input.branch}`;
      const sameSource = found.check_runs.filter(
        (check) =>
          check.app?.id === 5497722 &&
          (input.branch === 'alpha'
            ? (check.output?.summary || '')
                .split('\n')
                .filter((line) =>
                  /^Sandboxpi source base: [a-f0-9]{40}$/u.test(line),
                ).length === 1
            : (check.output?.summary || '').split('\n').includes(baseMarker)) &&
          (check.output?.summary || '').split('\n').includes(branchMarker),
      );
      if (
        sameSource.some((check) =>
          [
            'Public quality checks',
            'Public PR test gates',
            'Public validation request',
          ].includes(check.name),
        )
      )
        continue;
      const marker = await source('/check-runs', 'POST', {
        name: 'Public validation request',
        head_sha: input.sha,
        status: 'queued',
        external_id: `sandboxpi:watch:${input.requestId}`,
        output: {
          title: 'Public validation request',
          summary: `${branchMarker}\n${baseMarker}\nA public executor request is queued; this is not a passing gate.`,
        },
      });
      assert.equal(marker.app?.id, 5497722);
      assert.ok(Number.isSafeInteger(marker.id) && marker.id > 0);
      const response = await request(
        'https://api.github.com/repos/BANG404/sandboxpi-actions/actions/workflows/runner.yml/dispatches',
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${environment.GITHUB_TOKEN}`,
            Accept: 'application/vnd.github+json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            ref: 'main',
            inputs: {
              source_sha: input.sha,
              source_branch: input.branch,
              source_pr: input.pr,
              action: 'pr',
              run_gates: 'true',
              full_scope: 'false',
              request_id: input.requestId,
              watch_check_id: String(marker.id),
            },
          }),
          signal: AbortSignal.timeout(30000),
        },
      );
      if (response.status !== 204) {
        await source(`/check-runs/${marker.id}`, 'PATCH', {
          status: 'completed',
          conclusion: 'failure',
          output: {
            title: 'Public dispatch failed',
            summary: `${branchMarker}\n${baseMarker}\nDispatch failed; no quality result was produced.`,
          },
        });
        throw new Error('Public validation dispatch failed');
      }
      submitted++;
    }
    if (prs.length < 100) break;
    assert.ok(page < 10, 'PR discovery exceeded the bounded page limit');
  }
  console.log(
    `Public validation requests submitted: ${submitted}. Actual source checks determine quality.`,
  );
  return submitted;
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  try {
    await discover(process.env);
  } catch {
    console.error('Private PR discovery failed.');
    process.exitCode = 1;
  }
}
