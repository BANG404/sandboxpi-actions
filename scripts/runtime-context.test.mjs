import assert from 'node:assert/strict';
import { test } from 'node:test';
import { describeMapping, publishRuntimeContext } from './runtime-context.mjs';
const now = Date.parse('2026-11-09T08:00:00Z');
const sha = 'a'.repeat(40);
const target = { toolId: 'sdt-fixture', region: 'ap-guangzhou' };
const env = {
  TENCENTCLOUD_SECRET_ID: 'AKID-fixture',
  TENCENTCLOUD_SECRET_KEY: 'fixture-key',
};
const tool = () => ({
  ToolId: target.toolId,
  Status: 'ACTIVE',
  NetworkConfiguration: { VpcId: 'private-vpc' },
  CustomConfiguration: {
    Image: 'private.example/runtime@sha256:' + 'f'.repeat(64),
    Env: { PRIVATE_KEY: 'private-value' },
  },
});
test('the trusted context helper signs exactly one read-only Describe operation and publishes only hashes', async () => {
  let calls = 0;
  const value = await describeMapping(
    target,
    env,
    async (url, options) => {
      calls++;
      assert.equal(url, 'https://ags.tencentcloudapi.com/');
      assert.equal(options.method, 'POST');
      assert.equal(options.redirect, 'error');
      assert.equal(options.headers['X-TC-Action'], 'DescribeSandboxToolList');
      assert.deepEqual(JSON.parse(options.body), {
        ToolIds: [target.toolId],
        Limit: 1,
      });
      assert.equal(
        options.headers.Authorization,
        'TC3-HMAC-SHA256 Credential=AKID-fixture/2026-11-09/ags/tc3_request, SignedHeaders=content-type;host;x-tc-action, Signature=cb6f154ea22ffbe383c1fdb02ef7162bbd0f7a3bd1eff8fd26a6fdac4a615e2d',
      );
      return Response.json({ Response: { SandboxToolSet: [tool()] } });
    },
    now,
  );
  assert.equal(calls, 1);
  assert.equal(value.schemaVersion, 1);
  for (const field of ['toolHash', 'imageHash', 'configurationHash'])
    assert.match(value[field], /^[a-f0-9]{64}$/u);
  for (const secret of [
    'private-value',
    'private-vpc',
    'private.example',
    env.TENCENTCLOUD_SECRET_KEY,
  ])
    assert.ok(!JSON.stringify(value).includes(secret));
});
test('network/configuration changes invalidate the fingerprint; object key order and audit timestamps do not', async () => {
  const read = (value) =>
    describeMapping(
      target,
      env,
      async () => Response.json({ Response: { SandboxToolSet: [value] } }),
      now,
    );
  const first = await read(tool());
  const renamed = { ...tool(), CreateTime: 'new-audit-time' };
  assert.equal(
    (await read(renamed)).configurationHash,
    first.configurationHash,
  );
  const changed = tool();
  changed.NetworkConfiguration.VpcId = 'changed';
  assert.notEqual(
    (await read(changed)).configurationHash,
    first.configurationHash,
  );
  changed.CustomConfiguration.Env.PRIVATE_KEY = 'rotated';
  assert.notEqual(
    (await read(changed)).configurationHash,
    first.configurationHash,
  );
});
test('missing/inactive/mutable mappings and failed or redirected API reads cannot issue runtime evidence', async () => {
  for (const modify of [
    (t) => (t.Status = 'FAILED'),
    (t) => (t.ToolId = 'sdt-other'),
    (t) => (t.CustomConfiguration.Image = 'private.example/runtime:latest'),
  ]) {
    const value = tool();
    modify(value);
    await assert.rejects(
      describeMapping(
        target,
        env,
        async () => Response.json({ Response: { SandboxToolSet: [value] } }),
        now,
      ),
    );
  }
  for (const status of [302, 401, 403, 500]) {
    let calls = 0;
    await assert.rejects(
      describeMapping(
        target,
        env,
        async () => {
          calls++;
          return new Response(null, { status });
        },
        now,
      ),
    );
    assert.equal(calls, 1);
  }
});
test('only protected official execution and ancestral private sources can create App-bound context checks', async () => {
  const frame = {
    ...env,
    GITHUB_REPOSITORY: 'BANG404/sandboxpi-actions',
    GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_REF: 'refs/heads/main',
    GITHUB_RUN_ID: '123',
    SOURCE_TOKEN: 'private-read-check-write',
    SOURCE_SHA: sha,
    REQUEST_ID: '12345678-1234-1234-1234-123456789abc',
  };
  const patches = [];
  const request = async (url, options) => {
    if (url === 'https://ags.tencentcloudapi.com/')
      return Response.json({ Response: { SandboxToolSet: [tool()] } });
    assert.equal(
      options.headers.Authorization,
      'Bearer private-read-check-write',
    );
    assert.ok(
      url.startsWith('https://api.github.com/repos/BANG404/sandboxpi/'),
    );
    if (url.endsWith('/branches/alpha'))
      return Response.json({ commit: { sha } });
    if (url.includes('/compare/'))
      return Response.json({ status: 'identical', merge_base_commit: { sha } });
    if (url.includes('/contents/'))
      return Response.json({
        encoding: 'base64',
        content: Buffer.from(JSON.stringify({ alpha: target })).toString(
          'base64',
        ),
      });
    if (options.method === 'POST')
      return Response.json({ id: 1, app: { id: 5497722 } });
    if (options.method === 'PATCH') {
      patches.push(JSON.parse(options.body));
      return Response.json({ id: 1 });
    }
    throw Error('Unexpected request');
  };
  await publishRuntimeContext(frame, request);
  assert.equal(patches.length, 1);
  assert.equal(patches[0].conclusion, 'success');
  assert.match(
    JSON.parse(patches[0].output.summary).imageHash,
    /^[a-f0-9]{64}$/u,
  );
  for (const patch of [
    { GITHUB_REPOSITORY: 'other/repo' },
    { GITHUB_REF: 'refs/heads/feature' },
    { GITHUB_EVENT_NAME: 'pull_request' },
    { SOURCE_SHA: 'invalid' },
  ])
    await assert.rejects(
      publishRuntimeContext({ ...frame, ...patch }, async () => {
        throw Error('Must reject before requesting');
      }),
    );
});
