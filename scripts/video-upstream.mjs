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
        'Configure VIDEO_CLAW_UPSTREAM_TOKEN for locked source checks',
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
        `Video Claw source read failed (HTTP ${response.status})`,
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
  assert.equal(
    await branch(source, lock.branch),
    lock.commit,
    'Locked Video Claw branch moved; refresh and reverify the source',
  );
  return { source: lock.commit };
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
