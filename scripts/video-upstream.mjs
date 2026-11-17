import assert from 'node:assert/strict';
import { readResponse } from './request.mjs';

const sha = /^[a-f0-9]{40}$/u;
const fork = 'alx1501/video_claw';
const upstream = 'sdtrc/video_claw';
const repository = (value) => {
  assert.ok(typeof value === 'string');
  const name = value
    .replace(/^https:\/\/gitee\.com\//u, '')
    .replace(/\.git$/u, '');
  assert.ok(
    [fork, upstream].includes(name),
    'Unexpected Video Claw repository',
  );
  return name;
};

// Runs only in trusted control processes. Never expose this token to source children.
export async function verifyVideoUpstream(
  lock,
  { token, request = fetch, api } = {},
) {
  assert.equal(lock.schema, 1);
  assert.equal(lock.baseBranch, 'dev');
  assert.match(lock.commit || '', sha);
  assert.equal(repository(lock.baseRepository ?? lock.repository), upstream);
  const source = repository(lock.repository);
  assert.ok(
    typeof lock.branch === 'string' &&
      lock.branch &&
      !/[\x00-\x20?#]/u.test(lock.branch),
  );
  const read =
    api ||
    (async (path, optional = false) => {
      assert.ok(
        token,
        'Configure VIDEO_CLAW_UPSTREAM_TOKEN for upstream ancestry checks',
      );
      const response = await readResponse(
        (url, options) => request(url, { ...options, redirect: 'error' }),
        `https://gitee.com/api/v5/repos/${path}`,
        { headers: { Authorization: `Bearer ${token}` } },
      );
      if (optional && response.status === 404) return null;
      assert.equal(
        response.status,
        200,
        `Video Claw upstream read failed (HTTP ${response.status})`,
      );
      return response.json();
    });
  const branch = async (repo, name, optional = false) => {
    const value = await read(
      `${repo}/branches/${encodeURIComponent(name)}`,
      optional,
    );
    if (optional && value === null) return null;
    assert.match(
      value?.commit?.sha || '',
      sha,
      'Missing Video Claw branch identity',
    );
    return value.commit.sha;
  };
  const base = await branch(upstream, 'dev');
  assert.equal(
    await branch(source, lock.branch),
    lock.commit,
    'Locked Video Claw branch moved; refresh and reverify the source',
  );
  const contains = async (ancestor) => {
    if (ancestor === lock.commit) return;
    const comparison = await read(
      `${source}/compare/${ancestor}...${lock.commit}`,
    );
    assert.equal(
      comparison.base_commit?.sha,
      ancestor,
      'Upstream comparison base changed',
    );
    assert.equal(
      comparison.merge_base_commit?.sha,
      ancestor,
      'Video Claw source omits current upstream/cumulative history; merge it, update the lock and restart alpha CI/CD',
    );
  };
  await contains(base);
  // Verify repository access before interpreting an absent cumulative branch as empty.
  await read(fork);
  const cumulative = await branch(fork, 'codex/beta-upstream', true);
  if (cumulative) await contains(cumulative);
  assert.equal(
    await branch(upstream, 'dev'),
    base,
    'Upstream dev moved during validation; restart with the latest source',
  );
  assert.equal(
    await branch(fork, 'codex/beta-upstream', true),
    cumulative,
    'Cumulative Video Claw history moved during validation',
  );
  return { source: lock.commit, upstream: base, cumulative };
}

export async function verifySnapshotVideo(snapshot, github, environment) {
  assert.match(snapshot.candidate || '', sha);
  const file = await github(
    `/contents/integrations/video-claw.lock.json?ref=${snapshot.candidate}`,
  );
  assert.equal(file.encoding, 'base64');
  const lock = JSON.parse(Buffer.from(file.content, 'base64').toString('utf8'));
  return verifyVideoUpstream(lock, {
    token: environment.VIDEO_CLAW_UPSTREAM_TOKEN,
  });
}
