import assert from 'node:assert/strict';
import { appendFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  conclusions,
  github,
  normalize,
  revalidate,
  validateRequest,
} from './request.mjs';

export function checkDefinitions(input) {
  return {
    quality: 'Public quality checks',
    ...(input.runGates ? { gates: 'Public PR test gates' } : {}),
    ...(['validate', 'publish'].includes(input.action)
      ? { image: `Public CD ${input.action}` }
      : {}),
  };
}
export async function report(
  mode,
  environment,
  api = github(environment.SOURCE_TOKEN),
  output = (key, value) =>
    appendFileSync(environment.GITHUB_OUTPUT, `${key}=${value}\n`),
) {
  const input = normalize(environment);
  const definitions = checkDefinitions(input);
  const external = (phase) => `sandboxpi:${input.requestId}:${phase}`;
  if (mode === 'start') {
    const snapshot = await validateRequest(input, api);
    output('snapshot', JSON.stringify(snapshot));
    output('run_gates', String(input.runGates));
    for (const [phase, name] of Object.entries(definitions)) {
      const check = await api('/check-runs', 'POST', {
        name,
        head_sha: input.sha,
        status: 'in_progress',
        external_id: external(phase),
        output: {
          title: name,
          summary: `Sandboxpi source branch: ${input.branch}\nSandboxpi source base: ${snapshot.base}\nValidation is running; dispatch is not quality.`,
        },
        details_url: `https://github.com/BANG404/sandboxpi-actions/actions/runs/${environment.GITHUB_RUN_ID}`,
      });
      assert.equal(check.app?.id, 5497722, 'Unexpected callback App');
      assert.ok(Number.isSafeInteger(check.id) && check.id > 0);
      output(`${phase}_id`, check.id);
    }
    return;
  }
  assert.equal(mode, 'finish');
  const snapshot = JSON.parse(environment.SOURCE_SNAPSHOT);
  const results = conclusions(input, JSON.parse(environment.JOB_NEEDS || '{}'));
  try {
    assert.deepEqual(
      input,
      Object.fromEntries(Object.keys(input).map((key) => [key, snapshot[key]])),
    );
    await revalidate(snapshot, api);
  } catch {
    for (const phase of Object.keys(results)) results[phase] = 'failure';
  }
  let failed = false;
  for (const [phase, name] of Object.entries(definitions)) {
    const id = environment[`${phase.toUpperCase()}_ID`];
    if (!id) {
      failed = true;
      continue;
    }
    try {
      assert.match(id, /^[1-9]\d*$/u);
      const check = await api(`/check-runs/${id}`);
      assert.equal(check.app?.id, 5497722);
      assert.equal(check.name, name);
      assert.equal(check.head_sha, input.sha);
      assert.equal(check.external_id, external(phase));
      await api(`/check-runs/${id}`, 'PATCH', {
        name,
        status: 'completed',
        conclusion: results[phase],
        output: {
          title: name,
          summary: `Sandboxpi source branch: ${input.branch}\nSandboxpi source base: ${snapshot.base}\nResult: ${results[phase]}. Private reports: ${environment.GITHUB_RUN_ID}-${environment.GITHUB_RUN_ATTEMPT}-quality, -gate-NAME or -image in ghcr.io/bang404/sandboxpi-ci-data. Dispatch acknowledgment is not quality evidence.`,
        },
      });
      if (results[phase] !== 'success') failed = true;
    } catch {
      failed = true;
    }
  }
  if (environment.WATCH_CHECK_ID) {
    assert.match(environment.WATCH_CHECK_ID, /^[1-9]\d*$/u);
    const marker = await api(`/check-runs/${environment.WATCH_CHECK_ID}`);
    assert.equal(marker.app?.id, 5497722);
    assert.equal(marker.name, 'Public validation request');
    assert.equal(marker.head_sha, input.sha);
    assert.equal(marker.external_id, `sandboxpi:watch:${input.requestId}`);
    await api(`/check-runs/${environment.WATCH_CHECK_ID}`, 'PATCH', {
      status: 'completed',
      conclusion: failed ? 'failure' : 'success',
      output: {
        title: 'Public validation request',
        summary: `Sandboxpi source branch: ${input.branch}\nSandboxpi source base: ${snapshot.base}\nActual validation finished; required quality and gate checks remain authoritative.`,
      },
    });
  }
  assert.ok(!failed, 'Private source results failed or could not be finalized');
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    await report(process.argv[2], process.env);
  } catch {
    console.error('Private source validation or callback failed.');
    process.exitCode = 1;
  }
}
