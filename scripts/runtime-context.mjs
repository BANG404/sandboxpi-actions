import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { github } from './request.mjs';

const hash = (value) => createHash('sha256').update(value).digest('hex');
const mac = (key, value) => createHmac('sha256', key).update(value).digest();
const canonicalJson = (value) =>
  Array.isArray(value)
    ? value.map(canonicalJson)
    : value && typeof value === 'object'
      ? Object.fromEntries(
          Object.keys(value)
            .sort()
            .map((key) => [key, canonicalJson(value[key])]),
        )
      : value;
export async function describeMapping(
  target,
  env,
  request = fetch,
  now = Date.now(),
) {
  assert.match(target.toolId || '', /^sdt-[a-z0-9]+$/u);
  assert.match(target.region || '', /^ap-[a-z]+(?:-[a-z]+)?$/u);
  assert.ok(env.TENCENTCLOUD_SECRET_ID && env.TENCENTCLOUD_SECRET_KEY);
  const host = 'ags.tencentcloudapi.com',
    action = 'DescribeSandboxToolList';
  const body = JSON.stringify({ ToolIds: [target.toolId], Limit: 1 });
  const timestamp = Math.floor(now / 1000),
    date = new Date(now).toISOString().slice(0, 10);
  const canonical = `POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:${host}\nx-tc-action:${action.toLowerCase()}\n\ncontent-type;host;x-tc-action\n${hash(body)}`;
  const scope = `${date}/ags/tc3_request`;
  const signing = mac(
    mac(mac(`TC3${env.TENCENTCLOUD_SECRET_KEY}`, date), 'ags'),
    'tc3_request',
  );
  const signature = mac(
    signing,
    `TC3-HMAC-SHA256\n${timestamp}\n${scope}\n${hash(canonical)}`,
  ).toString('hex');
  const response = await request('https://' + host + '/', {
    method: 'POST',
    redirect: 'error',
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'X-TC-Action': action,
      'X-TC-Version': '2025-09-20',
      'X-TC-Region': target.region,
      'X-TC-Timestamp': String(timestamp),
      Authorization: `TC3-HMAC-SHA256 Credential=${env.TENCENTCLOUD_SECRET_ID}/${scope}, SignedHeaders=content-type;host;x-tc-action, Signature=${signature}`,
      ...(env.TENCENTCLOUD_SESSION_TOKEN
        ? { 'X-TC-Token': env.TENCENTCLOUD_SESSION_TOKEN }
        : {}),
    },
    body,
    signal: AbortSignal.timeout(20000),
  });
  assert.equal(response.status, 200);
  const value = (await response.json()).Response;
  assert.ok(value && !value.Error && value.SandboxToolSet?.length === 1);
  const tool = value.SandboxToolSet[0],
    config = tool.CustomConfiguration;
  assert.equal(tool.ToolId, target.toolId);
  assert.equal(tool.Status, 'ACTIVE');
  const digest = config?.ImageDigest || config?.Image?.split('@')[1];
  assert.match(digest || '', /^sha256:[a-f0-9]{64}$/u);
  const effective = { ...tool };
  for (const field of ['CreateTime', 'UpdateTime', 'CreatedAt', 'UpdatedAt'])
    delete effective[field];
  return {
    schemaVersion: 1,
    toolHash: hash(tool.ToolId),
    imageHash: hash(digest),
    configurationHash: hash(JSON.stringify(canonicalJson(effective))),
    checkedAt: new Date(now).toISOString(),
    schemaFields: Object.keys(tool).sort(),
  };
}

export async function publishRuntimeContext(env, request = fetch) {
  assert.equal(env.GITHUB_REPOSITORY, 'BANG404/sandboxpi-actions');
  assert.equal(env.GITHUB_EVENT_NAME, 'workflow_dispatch');
  assert.equal(env.GITHUB_REF, 'refs/heads/main');
  assert.match(env.SOURCE_SHA || '', /^[a-f0-9]{40}$/u);
  assert.match(
    env.REQUEST_ID || '',
    /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u,
  );
  const api = github(env.SOURCE_TOKEN, request);
  const branch = await api('/branches/alpha');
  const comparison = await api(
    `/compare/${env.SOURCE_SHA}...${branch.commit.sha}`,
  );
  assert.ok(['ahead', 'identical'].includes(comparison.status));
  assert.equal(comparison.merge_base_commit?.sha, env.SOURCE_SHA);
  const source = await api(
    `/contents/deploy/ags/tools.json?ref=${env.SOURCE_SHA}`,
  );
  assert.equal(source.encoding, 'base64');
  const target = JSON.parse(
    Buffer.from(source.content, 'base64').toString(),
  ).alpha;
  const created = await api('/check-runs', 'POST', {
    name: 'AGS runtime fingerprint',
    head_sha: env.SOURCE_SHA,
    external_id: 'sandboxpi-runtime:' + env.REQUEST_ID,
    details_url: `https://github.com/BANG404/sandboxpi-actions/actions/runs/${env.GITHUB_RUN_ID}`,
    status: 'in_progress',
  });
  assert.ok(Number.isSafeInteger(created.id) && created.id > 0);
  assert.equal(created.app?.id, 5497722);
  try {
    const context = await describeMapping(target, env, request);
    await api('/check-runs/' + created.id, 'PATCH', {
      status: 'completed',
      conclusion: 'success',
      output: {
        title: 'Verified live immutable AGS mapping',
        summary: JSON.stringify(context),
      },
    });
  } catch {
    await api('/check-runs/' + created.id, 'PATCH', {
      status: 'completed',
      conclusion: 'failure',
      output: {
        title: 'AGS mapping unavailable',
        summary: 'No reusable runtime evidence was issued.',
      },
    });
    throw new Error('Read-only runtime fingerprint unavailable');
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    await publishRuntimeContext(process.env);
  } catch {
    console.error(
      'Read-only runtime context failed; no raw diagnostics or credentials are published.',
    );
    process.exitCode = 1;
  }
}
