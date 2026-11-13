import assert from 'node:assert/strict';
import { test } from 'node:test';
import { discover } from './watch.mjs';
import {
  promotionFixture,
  promotionRejections,
  rejectedPromotionPairs,
} from './promotion-fixtures.mjs';

const base = 'a'.repeat(40),
  sha = 'b'.repeat(40),
  merge = 'c'.repeat(40);
const env = {
  GITHUB_REPOSITORY: 'BANG404/sandboxpi-actions',
  GITHUB_EVENT_NAME: 'workflow_dispatch',
  GITHUB_REF: 'refs/heads/main',
  GITHUB_TOKEN: 'private-dispatch-token',
};

function promotionWatch(f) {
  const writes = [];
  const dispatches = [];
  return {
    writes,
    dispatches,
    source: async (path, method = 'GET', body) => {
      if (method !== 'GET') {
        writes.push({ path, method, body });
        return { id: 100, app: { id: 5497722 } };
      }
      if (path.startsWith('/pulls?')) return [f.values.pull];
      if (path.startsWith('/commits/')) return { check_runs: [] };
      return f.api(path);
    },
    request: async (_url, init) => {
      dispatches.push(JSON.parse(init.body));
      return { status: 204 };
    },
  };
}

test('watch inherits all three protected bot promotions from validateRequest', async () => {
  for (const [source, target] of [
    ['alpha', 'beta'],
    ['beta', 'rc'],
    ['rc', 'main'],
  ]) {
    const f = promotionFixture(source, target);
    const watch = promotionWatch(f);
    assert.equal(await discover(env, watch.source, watch.request), 1);
    assert.equal(watch.dispatches[0].inputs.source_branch, target);
    assert.equal(watch.dispatches[0].inputs.source_sha, f.input.sha);
    assert.equal(watch.writes[0].body.status, 'queued');
    assert.ok(!f.calls.some((path) => path.startsWith('collaborators/')));
  }
});

test('watch refuses every invalid bot promotion before writes or dispatch', async (t) => {
  for (const [source, target] of rejectedPromotionPairs) {
    const f = promotionFixture(source, target);
    const watch = promotionWatch(f);
    assert.equal(await discover(env, watch.source, watch.request), 0);
    assert.deepEqual(watch.writes, []);
    assert.deepEqual(watch.dispatches, []);
  }
  for (const [name, change] of promotionRejections)
    await t.test(name, async () => {
      const f = promotionFixture();
      change(f.values);
      const watch = promotionWatch(f);
      assert.equal(await discover(env, watch.source, watch.request), 0);
      assert.deepEqual(watch.writes, []);
      assert.deepEqual(watch.dispatches, []);
    });
  const f = promotionFixture();
  const watch = promotionWatch(f);
  assert.equal(
    await discover(
      env,
      async (path, ...args) => {
        if (path === '/branches/alpha') throw new Error('API unavailable');
        return watch.source(path, ...args);
      },
      watch.request,
    ),
    0,
  );
  assert.deepEqual(watch.writes, []);
  assert.deepEqual(watch.dispatches, []);
});
function fixture({ checks = [], permission = 'write', recent = false } = {}) {
  const pr = {
    number: 45,
    state: 'open',
    mergeable: true,
    merge_commit_sha: merge,
    user: { login: 'operator' },
    updated_at: recent ? '2026-11-06T00:00:00Z' : '2026-11-01T00:00:00Z',
    head: { sha, repo: { full_name: 'BANG404/sandboxpi', fork: false } },
    base: { ref: 'alpha', sha: base, repo: { full_name: 'BANG404/sandboxpi' } },
  };
  const writes = [],
    dispatches = [];
  const source = async (path, method = 'GET', body) => {
    if (method !== 'GET') {
      writes.push({ path, method, body });
      return { id: 100, app: { id: 5497722 } };
    }
    if (path.startsWith('/pulls?')) return [pr];
    if (path === '/pulls/45') return pr;
    if (path === '/branches/alpha') return { commit: { sha: base } };
    if (path === '/collaborators/operator/permission') return { permission };
    if (path === '/git/ref/pull/45/merge') return { object: { sha: merge } };
    if (path === `/git/commits/${merge}`)
      return { parents: [{ sha: base }, { sha }] };
    if (path.startsWith(`/commits/${sha}/check-runs`))
      return { check_runs: checks };
    throw new Error('Unexpected source API');
  };
  const request = async (_url, init) => {
    dispatches.push(JSON.parse(init.body));
    return { status: 204 };
  };
  return { pr, source, request, writes, dispatches };
}
test('authenticated fallback submits a complete correlated public validation, never a passing dispatch marker', async () => {
  const f = fixture();
  assert.equal(await discover(env, f.source, f.request), 1);
  assert.equal(f.writes[0].body.status, 'queued');
  assert.equal(f.writes[0].body.conclusion, undefined);
  const input = f.dispatches[0].inputs;
  assert.equal(input.action, 'pr');
  assert.equal(input.source_sha, sha);
  assert.equal(input.run_gates, 'true');
  assert.equal(input.source_pr, '45');
  assert.equal(input.watch_check_id, '100');
  assert.equal(
    f.writes[0].body.external_id,
    `sandboxpi:watch:${input.request_id}`,
  );
  assert.ok(!JSON.stringify(input).includes(env.GITHUB_TOKEN));
});
test('pending or failed current-source evidence prevents automatic duplicate validation', async () => {
  for (const name of [
    'Public quality checks',
    'Public PR test gates',
    'Public validation request',
  ]) {
    const checks = [
      {
        name,
        app: { id: 5497722 },
        output: {
          summary: `Sandboxpi source branch: alpha\nSandboxpi source base: ${base}`,
        },
      },
    ];
    const f = fixture({ checks });
    assert.equal(await discover(env, f.source, f.request), 0);
    assert.equal(f.dispatches.length, 0);
  }
});
test('alpha advancement does not redispatch valid checks for the same PR HEAD', async () => {
  const f = fixture({
    checks: [
      {
        name: 'Public quality checks',
        app: { id: 5497722 },
        output: {
          summary: `Sandboxpi source branch: alpha\nSandboxpi source base: ${'d'.repeat(40)}`,
        },
      },
    ],
  });
  assert.equal(await discover(env, f.source, f.request), 0);
  assert.equal(f.dispatches.length, 0);
});
test('forks, read-only authors and changed merge candidates receive no public execution', async () => {
  for (const change of ['fork', 'permission', 'base']) {
    const f = fixture({
      permission: change === 'permission' ? 'read' : 'write',
    });
    if (change === 'fork') f.pr.head.repo.full_name = 'fork/sandboxpi';
    if (change === 'base') f.pr.base.sha = 'd'.repeat(40);
    assert.equal(await discover(env, f.source, f.request), 0);
    assert.equal(f.writes.length, 0);
  }
});
test('scheduled fallback lets the immediate dispatcher start first and dispatch failures are terminal for that request', async () => {
  const f = fixture({ recent: true });
  assert.equal(
    await discover(
      { ...env, GITHUB_EVENT_NAME: 'schedule' },
      f.source,
      f.request,
      () => Date.parse('2026-11-06T00:01:00Z'),
    ),
    0,
  );
  const g = fixture();
  await assert.rejects(discover(env, g.source, async () => ({ status: 503 })));
  assert.equal(g.writes.at(-1).body.conclusion, 'failure');
  await assert.rejects(
    discover(
      { ...env, GITHUB_REF: 'refs/heads/unreviewed' },
      g.source,
      g.request,
    ),
  );
});
