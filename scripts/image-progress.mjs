import assert from 'node:assert/strict';

const stages = new Set([
  'checkout',
  'cache-restore',
  'dependencies',
  'scanner-setup',
  'image',
  'build',
  'runtime-test',
  'vulnerability-scan',
  'acr-login',
  'acr-image-push',
  'acr-plugin-build',
  'acr-plugin-push',
  'tencent-transfer',
  'acr-latest-push',
  'release-record',
  'ags-activation',
  'cache-export',
  'report-export',
]);

// The project output is untrusted: only this fixed vocabulary can leave private storage.
export function imageProgressLines(onPhase) {
  let pending = '';
  return (chunk) => {
    pending += chunk.toString('utf8');
    const lines = pending.split('\n');
    pending = lines.pop().slice(-256);
    for (const line of lines) {
      const match = /^CD_IMAGE_PHASE ([a-z-]+) (started|passed|failed)$/u.exec(
        line,
      );
      if (match && stages.has(match[1])) onPhase(match[1], match[2]);
    }
  };
}

// This diagnostic check never satisfies a private source or deployment gate.
export async function imageProgress(
  environment,
  request = fetch,
  now = Date.now,
) {
  assert.match(environment.GITHUB_SHA, /^[a-f0-9]{40}$/u);
  assert.match(environment.GITHUB_RUN_ID, /^\d+$/u);
  const url =
    'https://api.github.com/repos/BANG404/sandboxpi-actions/check-runs';
  const send = async (method, path, body) => {
    const response = await request(path, {
      method,
      headers: {
        Authorization: `Bearer ${environment.GHCR_TOKEN}`,
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
    assert.ok(response.ok, 'Cannot publish image phase diagnostics');
    return response.json();
  };
  const check = await send('POST', url, {
    name: 'Image publication phases',
    head_sha: environment.GITHUB_SHA,
    external_id: `image-phase:${environment.GITHUB_RUN_ID}:${environment.GITHUB_RUN_ATTEMPT}`,
    details_url: `https://github.com/BANG404/sandboxpi-actions/actions/runs/${environment.GITHUB_RUN_ID}`,
    status: 'in_progress',
  });
  let queue = Promise.resolve();
  const records = [];
  let active;
  const update = (stage, status) => {
    assert.ok(stages.has(stage));
    assert.ok(['started', 'passed', 'failed'].includes(status));
    if (status === 'started') {
      if (records.some((record) => record.stage === stage)) return queue;
      active = { stage, status, started: now() };
      records.push(active);
    } else {
      const record = records.findLast(
        (record) => record.stage === stage && record.status === 'started',
      );
      if (!record) return queue;
      Object.assign(record, { status, durationMs: now() - record.started });
    }
    console.log(`Image phase: ${stage} ${status}`);
    const summary = JSON.stringify(
      records.map(({ stage, status, started, durationMs }) => ({
        stage,
        status,
        durationMs: durationMs ?? now() - started,
      })),
    );
    queue = queue
      .then(() =>
        send('PATCH', `${url}/${check.id}`, {
          output: { title: `Image publication: ${stage} ${status}`, summary },
        }),
      )
      .catch(() => {
        console.log('Image phase diagnostics update unavailable');
      });
    return queue;
  };
  return {
    update,
    async failActive() {
      if (active?.status === 'started') await update(active.stage, 'failed');
    },
    async finish(success) {
      if (!success && active?.status === 'started')
        await update(active.stage, 'failed');
      await queue;
      await send('PATCH', `${url}/${check.id}`, {
        status: 'completed',
        conclusion: success ? 'success' : 'failure',
      });
    },
  };
}
