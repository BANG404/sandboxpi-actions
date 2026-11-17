import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parse } from 'yaml';
import { verifyVideoUpstream, verifySnapshotVideo } from './video-upstream.mjs';
import { sourceEnvironment } from './runtime.mjs';

const base = 'a'.repeat(40),
  source = 'b'.repeat(40),
  cumulative = 'c'.repeat(40);
const lock = {
  schema: 1,
  repository: 'https://gitee.com/alx1501/video_claw',
  baseRepository: 'https://gitee.com/sdtrc/video_claw',
  baseBranch: 'dev',
  branch: 'codex/test',
  commit: source,
};
function fixture() {
  const values = new Map([
    ['sdtrc/video_claw/branches/dev', { commit: { sha: base } }],
    ['alx1501/video_claw/branches/codex%2Ftest', { commit: { sha: source } }],
    ['alx1501/video_claw', {}],
    [
      'alx1501/video_claw/branches/codex%2Fbeta-upstream',
      { commit: { sha: cumulative } },
    ],
    [
      `alx1501/video_claw/compare/${base}...${source}`,
      { base_commit: { sha: base }, merge_base_commit: { sha: base } },
    ],
    [
      `alx1501/video_claw/compare/${cumulative}...${source}`,
      {
        base_commit: { sha: cumulative },
        merge_base_commit: { sha: cumulative },
      },
    ],
  ]);
  const calls = [];
  const api = async (path) => {
    calls.push(path);
    assert.ok(values.has(path), path);
    return structuredClone(values.get(path));
  };
  return { values, calls, api };
}
test('locked source passes independently of current upstream and cumulative heads', async () => {
  const f = fixture();
  assert.deepEqual(await verifyVideoUpstream(lock, { api: f.api }), { source });
  assert.deepEqual(f.calls, ['alx1501/video_claw/branches/codex%2Ftest']);
  f.values.set('sdtrc/video_claw/branches/dev', {
    commit: { sha: 'd'.repeat(40) },
  });
  f.values.set('alx1501/video_claw/branches/codex%2Fbeta-upstream', null);
  assert.deepEqual(await verifyVideoUpstream(lock, { api: f.api }), { source });
});
test('moved locked sources and failed source reads block admission', async () => {
  const f = fixture();
  f.values.set('alx1501/video_claw/branches/codex%2Ftest', {
    commit: { sha: base },
  });
  await assert.rejects(
    verifyVideoUpstream(lock, { api: f.api }),
    /branch moved/,
  );
  await assert.rejects(
    verifyVideoUpstream(lock, {
      api: async () => {
        throw Error('denied');
      },
    }),
    /denied/,
  );
});
test('trusted reads use only allowlisted Gitee GET endpoints and never forward redirects or private response text', async () => {
  const f = fixture(),
    calls = [];
  await verifyVideoUpstream(lock, {
    token: 'fixture-secret',
    request: async (url, options) => {
      calls.push({ url, options });
      const path = url.replace('https://gitee.com/api/v5/repos/', '');
      return Response.json(await f.api(path));
    },
  });
  assert.ok(
    calls.every(
      ({ url, options }) =>
        url.startsWith('https://gitee.com/api/v5/repos/') &&
        options.method === 'GET' &&
        options.redirect === 'error' &&
        options.headers.Authorization === 'Bearer fixture-secret',
    ),
  );
  for (const invalid of [
    { ...lock, repository: 'https://attacker.invalid/video_claw' },
    { ...lock, commit: 'invalid' },
    { ...lock, baseBranch: 'master' },
  ])
    await assert.rejects(
      verifyVideoUpstream(invalid, {
        request: () => assert.fail('Invalid lock reached the network'),
      }),
    );
  await assert.rejects(
    verifyVideoUpstream(lock),
    /Configure VIDEO_CLAW_UPSTREAM_TOKEN/,
  );
  await assert.rejects(
    verifyVideoUpstream(lock, {
      token: 'fixture-secret',
      request: async () => new Response('PRIVATE_RESPONSE', { status: 403 }),
    }),
    (error) =>
      !error.message.includes('PRIVATE_RESPONSE') &&
      !error.message.includes('fixture-secret'),
  );
});
test('missing or unbound source snapshots cannot supply locked source proof', async () => {
  await assert.rejects(
    verifySnapshotVideo(
      { candidate: 'invalid' },
      () => assert.fail('Invalid snapshot reached API'),
      {},
    ),
  );
  await assert.rejects(
    verifySnapshotVideo(
      { candidate: source },
      async (path) => {
        assert.equal(
          path,
          `/contents/integrations/video-claw.lock.json?ref=${source}`,
        );
        return { encoding: 'utf8', content: 'PRIVATE' };
      },
      {},
    ),
  );
});
test('CI callbacks bind the gate while source children receive no upstream token', () => {
  const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
  const publicWorkflow = parse(read('../.github/workflows/runner.yml'));
  for (const name of ['prepare', 'quality_result', 'gates_result', 'finalize'])
    assert.equal(
      publicWorkflow.jobs[name].steps.at(-1).env.VIDEO_CLAW_UPSTREAM_TOKEN,
      '${{ secrets.VIDEO_CLAW_UPSTREAM_TOKEN }}',
    );
  const child = sourceEnvironment(
    { VIDEO_CLAW_UPSTREAM_TOKEN: 'PRIVATE', PATH: process.env.PATH },
    { sha: source, candidate: source, branch: 'alpha' },
    '/source',
    '/temporary',
  );
  assert.equal(child.VIDEO_CLAW_UPSTREAM_TOKEN, undefined);
});
