import assert from 'node:assert/strict';
import { appendFileSync } from 'node:fs';
const environment = process.env;
assert.match(environment.SOURCE_SHA || '', /^[a-f0-9]{40}$/u);
const mode = environment.PUBLIC_ACTION;
assert.ok(['ci', 'validate', 'publish'].includes(mode));
const name = mode === 'ci' ? 'Public quality checks' : `Public CD ${mode}`;
const headers = {
  Authorization: `Bearer ${environment.SOURCE_TOKEN}`,
  Accept: 'application/vnd.github+json',
  'Content-Type': 'application/json',
};
const start = process.argv[2] === 'start';
if (!start) assert.match(environment.CHECK_ID || '', /^[1-9]\d*$/u);
const response = await fetch(
  `https://api.github.com/repos/BANG404/sandboxpi/check-runs${start ? '' : `/${environment.CHECK_ID}`}`,
  {
    method: start ? 'POST' : 'PATCH',
    headers,
    body: JSON.stringify(
      start
        ? {
            name,
            head_sha: environment.SOURCE_SHA,
            status: 'in_progress',
            details_url: `https://github.com/BANG404/sandboxpi-actions/actions/runs/${environment.GITHUB_RUN_ID}`,
          }
        : {
            name,
            status: 'completed',
            conclusion:
              environment.RUN_RESULT === 'success' ? 'success' : 'failure',
            output: {
              title: name,
              summary: `Result: ${environment.RUN_RESULT}. Full logs and reports: private ghcr.io/bang404/sandboxpi-ci-data:report-${environment.GITHUB_RUN_ID}-${environment.GITHUB_RUN_ATTEMPT}.`,
            },
          },
    ),
    signal: AbortSignal.timeout(30_000),
  },
);
assert.ok(
  response.ok,
  `Cannot update the private source check (HTTP ${response.status})`,
);
if (start)
  appendFileSync(
    environment.GITHUB_OUTPUT,
    `check_id=${(await response.json()).id}\n`,
  );
