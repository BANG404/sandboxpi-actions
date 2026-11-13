import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';

export const repository = 'BANG404/sandboxpi';
export const gates = [
  'boundary',
  'coverage',
  'api',
  'integration',
  'security',
  'mutation',
  'risk',
];
const shaPattern = /^[a-f0-9]{40}$/u;
export function normalize(environment) {
  assert.equal(environment.GITHUB_REPOSITORY, 'BANG404/sandboxpi-actions');
  assert.equal(environment.GITHUB_EVENT_NAME, 'workflow_dispatch');
  assert.equal(environment.GITHUB_REF, 'refs/heads/main');
  const action = environment.PUBLIC_ACTION || 'ci';
  const branch = environment.SOURCE_BRANCH || 'main';
  assert.ok(['ci', 'pr', 'validate', 'publish'].includes(action));
  assert.ok(['alpha', 'beta', 'rc', 'main'].includes(branch));
  assert.match(environment.SOURCE_SHA || '', shaPattern);
  const pr = environment.SOURCE_PR || '';
  assert.ok(!pr || /^[1-9]\d{0,8}$/u.test(pr));
  assert.ok(action !== 'pr' || pr);
  assert.ok(!pr || ['ci', 'pr'].includes(action));
  assert.ok(['', 'true', 'false'].includes(environment.RUN_GATES || ''));
  assert.ok(['', 'true', 'false'].includes(environment.FULL_SCOPE || ''));
  const runGates =
    action === 'pr' || action === 'publish' || environment.RUN_GATES === 'true';
  const requestId =
    environment.REQUEST_ID ||
    `${environment.GITHUB_RUN_ID}-${environment.GITHUB_RUN_ATTEMPT}`;
  if (environment.REQUEST_ID)
    assert.match(
      requestId,
      /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/iu,
    );
  else assert.match(requestId, /^[1-9]\d*-[1-9]\d*$/u);
  if (['validate', 'publish'].includes(action))
    assert.equal(
      environment.AGS_CHANNEL || 'production',
      branch === 'main' ? 'production' : branch,
    );
  return {
    action,
    branch,
    sha: environment.SOURCE_SHA,
    pr,
    runGates,
    requestId,
    ...(environment.FULL_SCOPE || action === 'publish'
      ? { fullScope: action === 'publish' || environment.FULL_SCOPE === 'true' }
      : {}),
  };
}
// Synchronous source commands can outlive pooled sockets. Close GET connections
// and retry only bounded, idempotent reads; ambiguous writes are never repeated.
export async function readResponse(
  request,
  url,
  { headers = {}, timeoutMs = 30_000, sleep = delay } = {},
) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const response = await request(url, {
        method: 'GET',
        headers: { ...headers, Connection: 'close' },
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (![429, 500, 502, 503, 504].includes(response.status) || attempt === 2)
        return response;
      await response.body?.cancel();
    } catch (error) {
      if (attempt === 2) throw error;
    }
    await sleep(500 * (attempt + 1));
  }
}
export function github(token, request = fetch, sleep = delay) {
  assert.ok(token);
  return async (path, method = 'GET', body) => {
    const url = `https://api.github.com/repos/${repository}${path}`;
    const headers = {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'X-GitHub-Api-Version': '2022-11-28',
    };
    const response =
      method === 'GET'
        ? await readResponse(request, url, { headers, sleep })
        : await request(url, {
            method,
            headers,
            ...(body ? { body: JSON.stringify(body) } : {}),
            signal: AbortSignal.timeout(30_000),
          });
    assert.ok(
      response.ok,
      `Private source API operation failed: ${method} ${path} HTTP ${response.status}`,
    );
    return response.json();
  };
}
export async function validateRequest(input, api) {
  const branch = await api(`/branches/${input.branch}`);
  assert.match(branch.commit?.sha || '', shaPattern);
  const base = branch.commit.sha;
  if (!input.pr) {
    const comparison = await api(`/compare/${input.sha}...${base}`);
    assert.ok(['ahead', 'identical'].includes(comparison.status));
    assert.equal(comparison.merge_base_commit?.sha, input.sha);
    return { ...input, base, candidate: input.sha, ref: input.sha };
  }
  const pr = await api(`/pulls/${input.pr}`);
  assert.equal(pr.state, 'open');
  assert.equal(pr.head?.repo?.full_name, repository);
  assert.equal(pr.head?.repo?.fork, false);
  assert.equal(pr.base?.repo?.full_name, repository);
  assert.equal(pr.base?.ref, input.branch);
  assert.equal(pr.base?.sha, base);
  assert.equal(pr.head?.sha, input.sha);
  assert.equal(pr.mergeable, true);
  assert.match(pr.merge_commit_sha || '', shaPattern);
  // Bot trust is bound to GitHub's immutable account and current protected refs.
  if (
    pr.user?.login === 'github-actions[bot]' &&
    pr.user.id === 41898282 &&
    pr.user.type === 'Bot'
  ) {
    assert.equal(branch.protected, true);
    assert.equal(
      pr.head.ref,
      { beta: 'alpha', rc: 'beta', main: 'rc' }[input.branch],
    );
    assert.ok(['alpha', 'beta', 'rc'].includes(pr.head.ref));
    const source = await api(`/branches/${pr.head.ref}`);
    assert.equal(source.protected, true);
    assert.equal(source.commit?.sha, input.sha);
  } else {
    assert.notEqual(pr.user?.type, 'Bot');
    assert.match(pr.user?.login || '', /^[a-z0-9][a-z0-9-]{0,38}$/iu);
    const permission = await api(`/collaborators/${pr.user.login}/permission`);
    assert.ok(['admin', 'maintain', 'write'].includes(permission.permission));
  }
  const ref = `refs/pull/${input.pr}/merge`;
  const merge = await api(`/git/ref/pull/${input.pr}/merge`);
  assert.equal(merge.object?.sha, pr.merge_commit_sha);
  const commit = await api(`/git/commits/${pr.merge_commit_sha}`);
  assert.deepEqual(
    commit.parents?.map((parent) => parent.sha),
    [base, input.sha],
  );
  return { ...input, base, candidate: pr.merge_commit_sha, ref };
}
export async function revalidate(snapshot, api) {
  const current = await validateRequest(snapshot, api);
  if (snapshot.pr && snapshot.branch === 'alpha') {
    // Freeze the tested merge candidate while allowing normal alpha advancement.
    // Head changes, conflicts, permission loss and history rewrites still fail.
    assert.deepEqual(current, {
      ...snapshot,
      base: current.base,
      candidate: current.candidate,
    });
    if (current.base !== snapshot.base) {
      const comparison = await api(
        `/compare/${snapshot.base}...${current.base}`,
      );
      assert.ok(['ahead', 'identical'].includes(comparison.status));
      assert.equal(comparison.merge_base_commit?.sha, snapshot.base);
    }
    const tested = await api(`/git/commits/${snapshot.candidate}`);
    assert.deepEqual(
      tested.parents?.map((parent) => parent.sha),
      [snapshot.base, snapshot.sha],
    );
    return snapshot;
  }
  // Channel CI still accepts an immutable ancestor after the channel advances.
  // PR checks bind to a particular base as well as the exact merge candidate.
  const expected = snapshot.pr ? snapshot : { ...snapshot, base: current.base };
  assert.deepEqual(
    current,
    expected,
    'Source request changed during execution',
  );
  return current;
}
export function conclusions(input, needs) {
  const success = (name) => needs[name]?.result === 'success';
  const prepared = success('prepare');
  const quality = prepared && success('runner');
  const gateResult = prepared && success('gate');
  const image =
    prepared && quality && (!input.runGates || gateResult) && success('image');
  return {
    quality: quality ? 'success' : 'failure',
    ...(input.runGates ? { gates: gateResult ? 'success' : 'failure' } : {}),
    ...(['validate', 'publish'].includes(input.action)
      ? { image: image ? 'success' : 'failure' }
      : {}),
  };
}
