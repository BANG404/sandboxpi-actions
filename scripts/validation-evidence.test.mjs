import assert from 'node:assert/strict';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
  existsSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  evidenceName,
  authenticateEvidence,
  attestEvidence,
  evidenceManifest,
} from './validation-evidence.mjs';

async function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'authenticated-unit-proof-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  mkdirSync(join(directory, 'events'), { mode: 0o700 });
  const event = {
    schemaVersion: 1,
    unit: 'test:unit',
    fingerprint: 'f'.repeat(64),
    status: 'passed',
    checkedAt: '2026-11-10T08:00:00.000Z',
    sourceRevision: 'a'.repeat(40),
    context: 'b'.repeat(64),
    executionId: 'one',
    outputs: [],
    result: { code: 0 },
  };
  writeFileSync(join(directory, 'events/1234.json'), JSON.stringify(event), {
    mode: 0o600,
  });
  const environment = {
    GITHUB_SHA: 'c'.repeat(40),
    GITHUB_RUN_ID: '123',
    GITHUB_RUN_ATTEMPT: '1',
  };
  const snapshot = {
    branch: 'alpha',
    sha: 'a'.repeat(40),
    candidate: 'd'.repeat(40),
    requestId: 'original',
  };
  let check;
  const api = async (path, method, body) => {
    if (method === 'POST') {
      check = {
        id: 456,
        ...body,
        app: { id: 5497722 },
        completed_at: '2026-11-10T08:00:01Z',
      };
      return check;
    }
    assert.equal(path, '/check-runs/456');
    return check;
  };
  await attestEvidence(directory, {
    api,
    environment,
    snapshot,
    phase: 'quality',
  });
  return {
    directory,
    environment,
    snapshot,
    api,
    event,
    ancestors: () => [],
    checks: async () => [],
    get check() {
      return check;
    },
  };
}
test('only the protected App attestation authenticates unchanged partial unit results', async (t) => {
  const f = await fixture(t);
  assert.equal(f.check.name, evidenceName);
  assert.ok(
    await authenticateEvidence(f.directory, {
      ...f,
      phase: 'quality',
      snapshot: { ...f.snapshot, requestId: 'current' },
      ancestors: () => ['e'.repeat(40)],
    }),
  );
  assert.equal(
    JSON.parse(readFileSync(join(f.directory, 'events/1234.json'))).checkedAt,
    f.event.checkedAt,
  );
});
test('an overall failure from the same correlated run does not erase successful unit evidence', async (t) => {
  const f = await fixture(t);
  assert.ok(
    await authenticateEvidence(f.directory, {
      ...f,
      phase: 'quality',
      snapshot: { ...f.snapshot, requestId: 'current' },
      checks: async () => [
        {
          app: { id: 5497722 },
          external_id: 'sandboxpi:original:quality',
          conclusion: 'failure',
          completed_at: '2026-11-10T08:00:03Z',
        },
      ],
    }),
  );
});
test('newer unrepresented attempts, changed executor, wrong App and tampered payloads discard only evidence', async (t) => {
  for (const mode of ['newer', 'executor', 'app', 'tamper', 'ancestry']) {
    const f = await fixture(t);
    const options = {
      ...f,
      phase: 'quality',
      snapshot: { ...f.snapshot, requestId: 'current' },
    };
    if (mode === 'newer')
      options.checks = async () => [
        {
          app: { id: 5497722 },
          external_id: 'sandboxpi:missing:quality',
          conclusion: 'failure',
          completed_at: '2026-11-10T08:01:00Z',
        },
      ];
    if (mode === 'executor')
      options.environment = { ...f.environment, GITHUB_SHA: '0'.repeat(40) };
    if (mode === 'app') f.check.app.id = 1;
    if (mode === 'tamper')
      writeFileSync(
        join(f.directory, 'events/1234.json'),
        JSON.stringify({ ...f.event, status: 'failed' }),
        { mode: 0o600 },
      );
    if (mode === 'ancestry')
      options.ancestors = () => {
        throw new Error('Not an ancestor');
      };
    assert.equal(await authenticateEvidence(f.directory, options), false, mode);
    assert.ok(!existsSync(join(f.directory, 'events/1234.json')));
  }
});
test('source filenames stay out of App summaries and outputs are included by digest', async (t) => {
  const f = await fixture(t);
  assert.ok(!f.check.output.summary.includes('events/1234.json'));
  assert.equal(evidenceManifest(f.directory).length, 1);
});
