import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  conclusions,
  gates,
  normalize,
  revalidate,
  validateRequest,
} from './request.mjs';
import { checkDefinitions, report } from './status.mjs';

const head = 'a'.repeat(40),
  base = 'b'.repeat(40),
  merge = 'c'.repeat(40);
export const environment = {
  GITHUB_REPOSITORY: 'BANG404/sandboxpi-actions',
  GITHUB_EVENT_NAME: 'workflow_dispatch',
  GITHUB_REF: 'refs/heads/main',
  GITHUB_RUN_ID: '123',
  GITHUB_RUN_ATTEMPT: '2',
  PUBLIC_ACTION: 'pr',
  SOURCE_BRANCH: 'alpha',
  SOURCE_PR: '27',
  SOURCE_SHA: head,
  REQUEST_ID: '4a245183-1234-4567-8abc-123456789012',
};
function fixture(overrides = {}) {
  const values = {
    branch: { commit: { sha: base } },
    pull: {
      state: 'open',
      head: {
        sha: head,
        repo: { full_name: 'BANG404/sandboxpi', fork: false },
      },
      base: {
        ref: 'alpha',
        sha: base,
        repo: { full_name: 'BANG404/sandboxpi' },
      },
      mergeable: true,
      merge_commit_sha: merge,
      user: { login: 'trusted-writer' },
    },
    permission: { permission: 'write' },
    ref: { object: { sha: merge } },
    commit: { parents: [{ sha: base }, { sha: head }] },
    comparison: { status: 'ahead', merge_base_commit: { sha: head } },
    ...overrides,
  };
  const paths = {
    '/branches/alpha': 'branch',
    '/pulls/27': 'pull',
    '/collaborators/trusted-writer/permission': 'permission',
    '/git/ref/pull/27/merge': 'ref',
    [`/git/commits/${merge}`]: 'commit',
    [`/compare/${head}...${base}`]: 'comparison',
  };
  return async (path) => {
    assert.ok(paths[path], `Unexpected fixture API path ${path}`);
    return structuredClone(values[paths[path]]);
  };
}
test('legacy ci and image contracts remain valid while PR always enables all gates', () => {
  const legacy = {
    ...environment,
    PUBLIC_ACTION: 'ci',
    SOURCE_PR: '',
    SOURCE_BRANCH: '',
    REQUEST_ID: '',
  };
  assert.deepEqual(normalize(legacy), {
    action: 'ci',
    branch: 'main',
    sha: head,
    pr: '',
    runGates: false,
    requestId: '123-2',
  });
  for (const action of ['validate', 'publish'])
    for (const [branch, channel] of [
      ['main', 'production'],
      ['alpha', 'alpha'],
      ['beta', 'beta'],
      ['rc', 'rc'],
    ]) {
      assert.equal(
        normalize({
          ...legacy,
          PUBLIC_ACTION: action,
          SOURCE_BRANCH: branch,
          AGS_CHANNEL: channel,
        }).action,
        action,
      );
      assert.throws(() =>
        normalize({
          ...legacy,
          PUBLIC_ACTION: action,
          SOURCE_BRANCH: branch,
          AGS_CHANNEL: channel === 'production' ? 'alpha' : 'production',
        }),
      );
    }
  assert.equal(
    normalize({ ...environment, RUN_GATES: 'false' }).runGates,
    true,
  );
  assert.equal(normalize({ ...legacy, RUN_GATES: 'true' }).runGates, true);
});
test('reject unsupported refs, malformed correlation and adversarial inputs before API or checkout', () => {
  for (const patch of [
    { PUBLIC_ACTION: 'deploy' },
    { SOURCE_SHA: 'head' },
    { SOURCE_SHA: '../main' },
    { SOURCE_BRANCH: 'feature' },
    { SOURCE_BRANCH: 'main\nalpha' },
    { SOURCE_PR: '' },
    { SOURCE_PR: '27; echo leaked' },
    { SOURCE_PR: '0' },
    { REQUEST_ID: 'hello' },
    { RUN_GATES: 'TRUE' },
    { GITHUB_REF: 'refs/heads/alpha' },
    { GITHUB_EVENT_NAME: 'pull_request' },
    { GITHUB_REPOSITORY: 'attacker/repo' },
    { PUBLIC_ACTION: 'publish', AGS_CHANNEL: 'alpha' },
  ])
    assert.throws(() => normalize({ ...environment, ...patch }));
});
test('PR candidate is only the GitHub merge ref with exact head/base and trusted author', async () => {
  const snapshot = await validateRequest(normalize(environment), fixture());
  assert.equal(snapshot.candidate, merge);
  assert.equal(snapshot.ref, 'refs/pull/27/merge');
  assert.equal(snapshot.sha, head);
  await revalidate(snapshot, fixture());
  const valid = await fixture()('/pulls/27');
  for (const pull of [
    { ...valid, state: 'closed' },
    { ...valid, mergeable: null },
    { ...valid, mergeable: false },
    { ...valid, head: { ...valid.head, sha: base } },
    {
      ...valid,
      head: {
        ...valid.head,
        repo: { full_name: 'fork/sandboxpi', fork: true },
      },
    },
    {
      ...valid,
      head: {
        ...valid.head,
        repo: { full_name: 'BANG404/sandboxpi', fork: true },
      },
    },
    { ...valid, base: { ...valid.base, ref: 'main' } },
    { ...valid, base: { ...valid.base, sha: head } },
    {
      ...valid,
      base: { ...valid.base, repo: { full_name: 'fork/sandboxpi' } },
    },
    { ...valid, user: { login: '../attacker' } },
  ])
    await assert.rejects(
      validateRequest(normalize(environment), fixture({ pull })),
    );
  for (const permission of ['read', 'triage', 'none'])
    await assert.rejects(
      validateRequest(
        normalize(environment),
        fixture({ permission: { permission } }),
      ),
    );
  await assert.rejects(
    validateRequest(
      normalize(environment),
      fixture({ ref: { object: { sha: head } } }),
    ),
  );
  await assert.rejects(
    validateRequest(
      normalize(environment),
      fixture({ commit: { parents: [{ sha: head }, { sha: base }] } }),
    ),
  );
  await assert.rejects(
    revalidate(snapshot, fixture({ branch: { commit: { sha: merge } } })),
  );
});
test('non-PR requests require exact trusted-branch ancestry, never arbitrary commits', async () => {
  const input = normalize({
    ...environment,
    SOURCE_PR: '',
    PUBLIC_ACTION: 'ci',
  });
  assert.equal((await validateRequest(input, fixture())).candidate, head);
  for (const comparison of [
    { status: 'diverged', merge_base_commit: { sha: head } },
    { status: 'behind', merge_base_commit: { sha: head } },
    { status: 'ahead', merge_base_commit: { sha: base } },
  ])
    await assert.rejects(validateRequest(input, fixture({ comparison })));
});
test('legacy channel CI revalidates ancestry even when the channel advances', async () => {
  const input = normalize({
    ...environment,
    PUBLIC_ACTION: 'ci',
    SOURCE_PR: '',
  });
  const snapshot = await validateRequest(input, fixture());
  const advanced = async (path) => {
    if (path === '/branches/alpha') return { commit: { sha: merge } };
    if (path === `/compare/${head}...${merge}`)
      return { status: 'ahead', merge_base_commit: { sha: head } };
    throw new Error('Unexpected API call');
  };
  assert.equal((await revalidate(snapshot, advanced)).candidate, head);
  await assert.rejects(
    revalidate(snapshot, async (path) =>
      path.startsWith('/compare/') ? { status: 'diverged' } : advanced(path),
    ),
  );
});
test('every failed, cancelled, skipped or absent matrix result fails closed', () => {
  const input = normalize(environment);
  const needs = {
    prepare: { result: 'success' },
    runner: { result: 'success' },
    gate: { result: 'success' },
    image: { result: 'skipped' },
  };
  assert.deepEqual(conclusions(input, needs), {
    quality: 'success',
    gates: 'success',
  });
  // Actions reduces the complete fail-fast:false matrix; any individual non-success makes gate non-success.
  for (const gate of gates)
    for (const result of ['failure', 'cancelled', 'skipped', undefined]) {
      const matrix = Object.fromEntries(
        gates.map((name) => [name, name === gate ? result : 'success']),
      );
      const overall = Object.values(matrix).every(
        (value) => value === 'success',
      )
        ? 'success'
        : result;
      assert.equal(
        conclusions(input, { ...needs, gate: { result: overall } }).gates,
        'failure',
      );
    }
  for (const result of ['failure', 'cancelled', 'skipped', undefined]) {
    assert.equal(
      conclusions(input, { ...needs, runner: { result } }).quality,
      'failure',
    );
    assert.deepEqual(conclusions(input, { ...needs, prepare: { result } }), {
      quality: 'failure',
      gates: 'failure',
    });
  }
});
test('callbacks use exact head, both names and protocol external IDs, and fail changed requests', async () => {
  const input = normalize(environment),
    outputs = {},
    checks = {},
    patches = [];
  const api = async (path, method, body) => {
    if (path === '/check-runs' && method === 'POST') {
      const check = {
        ...body,
        id: Object.keys(checks).length + 1,
        app: { id: 5497722 },
      };
      checks[check.id] = check;
      return check;
    }
    if (path.startsWith('/check-runs/')) {
      const id = path.split('/').at(-1);
      if (method === 'PATCH') {
        patches.push(body);
        return {};
      }
      return checks[id];
    }
    return fixture()(path);
  };
  await report('start', environment, api, (key, value) => {
    outputs[key] = String(value);
  });
  assert.deepEqual(
    Object.values(checks).map((check) => [
      check.name,
      check.head_sha,
      check.external_id,
    ]),
    [
      ['Public quality checks', head, `sandboxpi:${input.requestId}:quality`],
      ['Public PR test gates', head, `sandboxpi:${input.requestId}:gates`],
    ],
  );
  const finalEnv = {
    ...environment,
    SOURCE_SNAPSHOT: outputs.snapshot,
    QUALITY_ID: outputs.quality_id,
    GATES_ID: outputs.gates_id,
    JOB_NEEDS: JSON.stringify({
      prepare: { result: 'success' },
      runner: { result: 'success' },
      gate: { result: 'success' },
    }),
  };
  await report('finish', finalEnv, api);
  assert.ok(patches.every((patch) => patch.conclusion === 'success'));
  patches.length = 0;
  await assert.rejects(
    report('finish', finalEnv, async (path, ...args) =>
      path === '/branches/alpha'
        ? { commit: { sha: merge } }
        : api(path, ...args),
    ),
  );
  assert.equal(patches.length, 2);
  assert.ok(patches.every((patch) => patch.conclusion === 'failure'));
  checks[1].app.id = 1;
  patches.length = 0;
  await assert.rejects(report('finish', finalEnv, api));
  assert.equal(patches.length, 1);
  assert.equal(patches[0].name, 'Public PR test gates');
  assert.equal(
    checkDefinitions({ action: 'publish', runGates: false }).image,
    'Public CD publish',
  );
});
