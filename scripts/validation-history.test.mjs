import assert from 'node:assert/strict';
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  beginEvidenceAttempt,
  restoreEvidenceHistory,
  sealEvidenceAttempt,
  validationChecks,
  invalidatedReuses,
  terminalAttemptTime,
} from './validation-history.mjs';

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'unit-history-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const checks = new Map(),
    archives = new Map();
  let id = 0,
    eventId = 0;
  const api = async (path, method, body) => {
    if (method === 'POST') {
      const check = { id: ++id, app: { id: 5497722 }, ...body };
      checks.set(id, check);
      return check;
    }
    if (path.startsWith('/commits/'))
      return { total_count: checks.size, check_runs: [...checks.values()] };
    const check = checks.get(Number(path.split('/').at(-1)));
    assert.ok(check);
    if (method === 'PATCH')
      Object.assign(
        check,
        body,
        body.status === 'completed'
          ? { completed_at: new Date().toISOString() }
          : {},
      );
    return check;
  };
  const directory = (name) => {
    const path = join(root, name);
    mkdirSync(path, { recursive: true, mode: 0o700 });
    return path;
  };
  const options = {
    api,
    snapshot: {
      branch: 'alpha',
      sha: 'a'.repeat(40),
      candidate: 'b'.repeat(40),
      requestId: 'original',
    },
    environment: {
      GITHUB_SHA: 'c'.repeat(40),
      GITHUB_RUN_ID: '1',
      GITHUB_RUN_ATTEMPT: '1',
    },
    phase: 'quality',
    executorRepository: 'BANG404/sandboxpi-actions',
    ancestors: async () => [],
    loadArchive: async (payload) => {
      assert.ok(archives.has(payload.attemptCheckId || payload.runId));
      return {
        directory: archives.get(payload.attemptCheckId || payload.runId),
      };
    },
  };
  const event = (
    path,
    unit,
    status = 'passed',
    fingerprint = 'd'.repeat(64),
  ) => {
    mkdirSync(join(path, 'events'), { recursive: true, mode: 0o700 });
    const row = {
      schemaVersion: 1,
      unit,
      status,
      fingerprint,
      context: 'e'.repeat(64),
      sourceRevision: options.snapshot.sha,
      checkedAt: new Date().toISOString(),
      executionId: `execution-${eventId}`,
      ordinal: eventId,
      outputs: [],
      result: { code: status === 'passed' ? 0 : 1 },
    };
    writeFileSync(
      join(path, `events/${(++eventId).toString(16)}.json`),
      JSON.stringify(row),
      { mode: 0o600 },
    );
    return row;
  };
  const seal = async (
    path,
    attempt,
    history = { coveredAttempts: [], pendingHeads: [] },
    success = true,
  ) =>
    sealEvidenceAttempt(path, {
      api,
      attempt,
      history,
      success,
      exportArchive: async (payload) => {
        const archive = directory(
          `archive-${payload.runId}-${payload.runAttempt}`,
        );
        cpSync(path, archive, { recursive: true });
        archives.set(payload.runId, archive);
      },
    });
  return {
    ...options,
    root,
    options,
    directory,
    event,
    seal,
    checks,
    archives,
  };
}
const rows = (path) =>
  readdirSync(join(path, 'events')).map((name) =>
    JSON.parse(readFileSync(join(path, 'events', name))),
  );

test('immutable history imports successful units from failed aggregate runs and preserves negative and reverted-input records', async (t) => {
  const f = fixture(t),
    first = f.directory('first');
  const a = await beginEvidenceAttempt(f.options);
  const original = f.event(first, 'unchanged');
  f.event(first, 'changed');
  await f.seal(first, a);
  const second = f.directory('second');
  cpSync(first, second, { recursive: true });
  const next = {
    ...f.options,
    snapshot: { ...f.snapshot, requestId: 'second' },
    environment: { ...f.environment, GITHUB_RUN_ID: '2' },
  };
  const b = await beginEvidenceAttempt(next);
  f.event(second, 'changed', 'failed');
  f.event(second, 'other-input', 'passed', 'f'.repeat(64));
  await f.seal(
    second,
    b,
    { coveredAttempts: [a.checkId], pendingHeads: [] },
    false,
  );
  const current = {
    ...next,
    snapshot: { ...f.snapshot, requestId: 'current' },
    environment: { ...f.environment, GITHUB_RUN_ID: '3' },
  };
  const attempt = await beginEvidenceAttempt(current);
  const history = await restoreEvidenceHistory(first, { ...current, attempt });
  assert.equal(history.trusted, true);
  assert.equal(history.diagnostics.importedAttempts, 1);
  assert.deepEqual(history.diagnostics.fencedAttempts, []);
  assert.ok(
    rows(first).some(
      (row) => row.unit === 'changed' && row.status === 'failed',
    ),
  );
  assert.ok(rows(first).some((row) => row.fingerprint === 'f'.repeat(64)));
  assert.equal(
    rows(first).find((row) => row.unit === 'unchanged').checkedAt,
    original.checkedAt,
  );
  assert.equal(f.checks.get(b.checkId).conclusion, 'failure');
});

test('missing archives and unfinished attempts fence older passes, including reruns with the same request UUID', async (t) => {
  for (const missing of [false, true]) {
    const f = fixture(t),
      path = f.directory('seed');
    const a = await beginEvidenceAttempt(f.options);
    f.event(path, 'old-pass');
    await f.seal(path, a);
    const retry = {
      ...f.options,
      environment: { ...f.environment, GITHUB_RUN_ATTEMPT: '2' },
    };
    const b = await beginEvidenceAttempt(retry);
    if (missing)
      await f.api(`/check-runs/${b.checkId}`, 'PATCH', {
        status: 'completed',
        conclusion: 'failure',
      });
    const current = {
      ...f.options,
      environment: { ...f.environment, GITHUB_RUN_ID: '3' },
    };
    const attempt = await beginEvidenceAttempt(current);
    const history = await restoreEvidenceHistory(path, { ...current, attempt });
    assert.equal(history.trusted, false);
    assert.equal(rows(path).length, 0);
    assert.equal(
      history.diagnostics.fencedAttempts[0].reason,
      missing ? 'attempt-proof-unavailable' : 'attempt-still-unsealed',
    );
    assert.equal(history.coveredAttempts.includes(b.checkId), missing);
    assert.deepEqual(history.pendingHeads, missing ? [] : [f.snapshot.sha]);
  }
});

test('tampered manifests and changed policies cannot authenticate a seed', async (t) => {
  for (const mode of ['tamper', 'executor', 'ancestry']) {
    const f = fixture(t),
      path = f.directory('seed');
    const a = await beginEvidenceAttempt(f.options);
    f.event(path, 'one');
    await f.seal(path, a);
    const options = {
      ...f.options,
      attempt: await beginEvidenceAttempt({
        ...f.options,
        environment: { ...f.environment, GITHUB_RUN_ID: '2' },
      }),
    };
    if (mode === 'tamper') f.event(path, 'forged');
    if (mode === 'executor')
      options.environment = { ...f.environment, GITHUB_SHA: 'f'.repeat(40) };
    if (mode === 'ancestry')
      options.ancestors = async () => {
        throw new Error('unrelated history');
      };
    assert.equal((await restoreEvidenceHistory(path, options)).trusted, false);
  }
});

test('a storage failure cannot publish a successful evidence proof', async (t) => {
  const f = fixture(t),
    path = f.directory('seed');
  const attempt = await beginEvidenceAttempt(f.options);
  f.event(path, 'one');
  await assert.rejects(
    sealEvidenceAttempt(path, {
      api: f.api,
      attempt,
      history: { coveredAttempts: [], pendingHeads: [] },
      exportArchive: async () => {
        throw new Error('unavailable');
      },
    }),
  );
  assert.ok(
    [...f.checks.values()].every((check) => check.status !== 'completed'),
  );
});

test('cancelled attempts fence older receipts but cease poisoning later freshly verified results', async (t) => {
  const f = fixture(t),
    path = f.directory('seed');
  const original = await beginEvidenceAttempt(f.options);
  f.event(path, 'old-pass');
  await f.seal(path, original);
  const cancelled = await beginEvidenceAttempt({
    ...f.options,
    environment: { ...f.environment, GITHUB_RUN_ID: '2' },
  });
  const run = {
    id: 2,
    run_attempt: 1,
    head_sha: f.environment.GITHUB_SHA,
    repository: { full_name: f.options.executorRepository },
    status: 'completed',
    conclusion: 'cancelled',
    updated_at: new Date().toISOString(),
  };
  const options = {
    ...f.options,
    readAttempt: async () => run,
    environment: { ...f.environment, GITHUB_RUN_ID: '3' },
  };
  const attempt = await beginEvidenceAttempt(options);
  const history = await restoreEvidenceHistory(path, { ...options, attempt });
  assert.equal(history.trusted, false);
  assert.equal(
    history.diagnostics.fencedAttempts[0].reason,
    'terminal-attempt-without-proof',
  );
  assert.ok(history.coveredAttempts.includes(cancelled.checkId));
  assert.deepEqual(history.pendingHeads, []);
  await new Promise((resolve) => setTimeout(resolve, 1100));
  f.event(path, 'fresh-pass');
  await f.seal(path, attempt, history);
  const next = {
    ...options,
    environment: { ...f.environment, GITHUB_RUN_ID: '4' },
  };
  const restored = await restoreEvidenceHistory(path, {
    ...next,
    attempt: await beginEvidenceAttempt(next),
  });
  assert.equal(restored.trusted, true);
  assert.deepEqual(restored.diagnostics.fencedAttempts, []);
  for (const patch of [
    { id: 9 },
    { run_attempt: 2 },
    { head_sha: 'f'.repeat(40) },
    { status: 'in_progress' },
    { repository: { full_name: 'foreign/repository' } },
    { updated_at: new Date(Date.now() + 120_000).toISOString() },
  ]) {
    assert.equal(
      await terminalAttemptTime(cancelled.payload, async () => ({
        ...run,
        ...patch,
      })),
      Infinity,
    );
  }
});

test('a displaced mutable seed is recovered from an authentic ancestral immutable archive', async (t) => {
  const f = fixture(t),
    first = f.directory('first');
  const original = await beginEvidenceAttempt(f.options);
  f.event(first, 'preserved');
  await f.seal(first, original);
  const displaced = f.directory('displaced');
  writeFileSync(join(displaced, 'attestation.json'), '{}', { mode: 0o600 });
  const current = {
    ...f.options,
    environment: { ...f.environment, GITHUB_RUN_ID: '2' },
  };
  const attempt = await beginEvidenceAttempt(current);
  const history = await restoreEvidenceHistory(displaced, {
    ...current,
    attempt,
    recentCommits: async () => [f.snapshot.sha],
  });
  assert.equal(history.trusted, true);
  assert.equal(history.diagnostics.seed, 'ancestral-immutable-archive');
  assert.equal(rows(displaced)[0].unit, 'preserved');
});

test('completion reconciliation detects a matching failure recorded after a cached unit was reused', async (t) => {
  const f = fixture(t),
    first = f.directory('first');
  const original = await beginEvidenceAttempt(f.options);
  const used = f.event(first, 'reused');
  await f.seal(first, original);
  const current = {
    ...f.options,
    environment: { ...f.environment, GITHUB_RUN_ID: '2' },
  };
  const attempt = await beginEvidenceAttempt(current);
  const history = await restoreEvidenceHistory(first, { ...current, attempt });
  const journal = f.directory('journal');
  writeFileSync(join(journal, '123.json'), JSON.stringify(used), {
    mode: 0o600,
  });
  assert.deepEqual(invalidatedReuses(first, journal), []);
  const sibling = {
    ...f.options,
    environment: { ...f.environment, GITHUB_RUN_ID: '3' },
  };
  const siblingAttempt = await beginEvidenceAttempt(sibling);
  const siblingDirectory = f.directory('sibling');
  f.event(siblingDirectory, 'reused', 'failed');
  await f.seal(
    siblingDirectory,
    siblingAttempt,
    { coveredAttempts: [], pendingHeads: [] },
    false,
  );
  await restoreEvidenceHistory(first, {
    ...current,
    attempt,
    verifiedSeed: history.verifiedSeed,
  });
  assert.deepEqual(invalidatedReuses(first, journal), ['reused']);
});

test('complete pagination is required and duplicate pages cannot conceal missing observations', async () => {
  assert.equal(
    (
      await validationChecks(
        async (path) =>
          path.endsWith('page=1')
            ? { total_count: 2, check_runs: [{ id: 1 }] }
            : { total_count: 2, check_runs: [{ id: 2 }] },
        'a'.repeat(40),
      )
    ).length,
    2,
  );
  await assert.rejects(
    validationChecks(
      async () => ({ total_count: 2, check_runs: [{ id: 1 }] }),
      'a'.repeat(40),
    ),
    /Incomplete/,
  );
});
