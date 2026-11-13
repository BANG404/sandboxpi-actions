import assert from 'node:assert/strict';
import { test } from 'node:test';
import { imageProgress, imageProgressLines } from './image-progress.mjs';

test('only complete allowlisted phase markers escape private source capture', () => {
  const observed = [];
  const read = imageProgressLines((...entry) => observed.push(entry));
  read(Buffer.from('PRIVATE source /password\nCD_IMAGE_PHASE bu'));
  read(Buffer.from('ild started\nCD_IMAGE_PHASE secret failed\n'));
  read(Buffer.from('::error::PRIVATE\nCD_IMAGE_PHASE build passed extra\n'));
  read(Buffer.from('CD_IMAGE_PHASE build passed\n'));
  assert.deepEqual(observed, [
    ['build', 'started'],
    ['build', 'passed'],
  ]);
});

test('diagnostic check binds the public execution and preserves the failed subphase', async () => {
  const requests = [];
  let elapsed = 0;
  const progress = await imageProgress(
    {
      GITHUB_SHA: 'a'.repeat(40),
      GITHUB_RUN_ID: '123',
      GITHUB_RUN_ATTEMPT: '1',
      GHCR_TOKEN: 'public-only-token',
    },
    async (url, options) => {
      requests.push({ url, body: JSON.parse(options.body) });
      return { ok: true, json: async () => ({ id: 456 }) };
    },
    () => elapsed,
  );
  await progress.update('build', 'started');
  elapsed = 700;
  await progress.finish(false);
  assert.equal(requests[0].body.head_sha, 'a'.repeat(40));
  assert.equal(requests[0].body.external_id, 'image-phase:123:1');
  assert.deepEqual(JSON.parse(requests[2].body.output.summary), [
    { stage: 'build', status: 'failed', durationMs: 700 },
  ]);
  assert.equal(requests.at(-1).body.conclusion, 'failure');
  assert.doesNotMatch(JSON.stringify(requests), /public-only-token/);
});
