import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parse } from 'yaml';
import { gates } from './request.mjs';

const read = (file) =>
  readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
const workflow = parse(read('.github/workflows/runner.yml'));
test('standard hosted jobs parallelize complete quality and seven real gates without source workflows or public data stores', () => {
  assert.deepEqual(Object.keys(workflow.on), ['workflow_dispatch']);
  assert.deepEqual(workflow.jobs.gate.strategy.matrix.gate, gates);
  assert.equal(workflow.jobs.gate.strategy['fail-fast'], false);
  assert.equal(workflow.jobs.runner.needs, 'prepare');
  assert.equal(workflow.jobs.gate.needs, 'prepare');
  assert.equal(
    workflow.jobs.gate.if,
    "needs.prepare.outputs.run_gates == 'true'",
  );
  for (const [name, job] of Object.entries(workflow.jobs)) {
    assert.equal(job['runs-on'], 'ubuntu-24.04');
    assert.equal(job.environment, 'release');
    for (const step of job.steps) {
      if (step.uses?.startsWith('actions/checkout@')) {
        assert.equal(step.with['persist-credentials'], false);
        assert.equal(step.with.repository, undefined);
      }
      assert.doesNotMatch(
        step.uses || '',
        /upload-artifact|actions\/cache|\.\/source/u,
      );
      assert.doesNotMatch(step.run || '', /source\/|public-runner\.mjs/u);
      if (step.with && Object.hasOwn(step.with, 'cache'))
        assert.equal(step.with.cache, false);
    }
  }
  assert.match(workflow.jobs.finalize.if, /always\(\)/u);
  assert.deepEqual(workflow.jobs.finalize.needs, [
    'prepare',
    'runner',
    'gate',
    'quality_result',
    'gates_result',
    'image',
  ]);
  assert.match(workflow.jobs.image.if, /needs\.runner\.result == 'success'/u);
  assert.match(workflow.jobs.image.if, /needs\.gate\.result == 'success'/u);
});
test('each callback waits only for its workload and images require both applicable callbacks', () => {
  for (const [phase, workload] of [
    ['quality', 'runner'],
    ['gates', 'gate'],
  ]) {
    const job = workflow.jobs[`${phase}_result`];
    assert.deepEqual(job.needs, ['prepare', workload]);
    assert.match(job.if, /always\(\)/u);
    assert.match(job.if, /needs\.prepare\.outputs\.snapshot != ''/u);
    assert.equal(job.steps.at(-1).run, `node scripts/status.mjs ${phase}`);
    assert.equal(job.steps.at(-1).env.JOB_NEEDS, '${{ toJSON(needs) }}');
    assert.ok(
      job.steps.some((step) => step.with?.['permission-checks'] === 'write'),
    );
  }
  assert.match(workflow.jobs.gates_result.if, /run_gates == 'true'/u);
  for (const name of ['quality_result', 'gates_result']) {
    assert.ok(workflow.jobs.image.needs.includes(name));
    assert.ok(workflow.jobs.finalize.needs.includes(name));
    assert.ok(
      workflow.jobs.image.if.includes(`needs.${name}.result == 'success'`),
    );
  }
  assert.equal(
    workflow.jobs.finalize.steps.at(-1).run,
    'node scripts/status.mjs finish',
  );
});
test('only post-quality image receives release credentials, source checkout jobs have contents-read only', () => {
  for (const [name, job] of Object.entries(workflow.jobs))
    for (const step of job.steps) {
      if (step.uses?.startsWith('actions/create-github-app-token@')) {
        assert.equal(step.with.repositories, 'sandboxpi');
        assert.equal(
          step.with['permission-contents'],
          step.id === 'release' ? 'write' : 'read',
        );
        if (step.with['permission-checks'])
          assert.ok(
            [
              'prepare',
              'finalize',
              'runner',
              'gate',
              'quality_result',
              'gates_result',
            ].includes(name),
          );
        if (step.id === 'release') assert.equal(name, 'image');
      }
      for (const key of [
        'GITHUB_TOKEN',
        'SKILL_SOURCES_TOKEN',
        'ACR_PASSWORD',
        'WOODPECKER_TOKEN',
        'TENCENTCLOUD_SECRET_ID',
        'TENCENTCLOUD_SECRET_KEY',
        'TENCENTCLOUD_SESSION_TOKEN',
      ]) {
        if (step.env?.[key]) {
          assert.equal(name, 'image');
          assert.equal(step.id, 'image');
        }
      }
    }
  for (const key of [
    'TENCENTCLOUD_SECRET_ID',
    'TENCENTCLOUD_SECRET_KEY',
    'TENCENTCLOUD_SESSION_TOKEN',
  ])
    assert.match(
      workflow.jobs.image.steps.at(-1).env[key],
      /inputs\.action == 'publish'/u,
    );
});
test('report reader accepts only legacy or known independent phase keys', () => {
  const report = read('.github/workflows/report.yml');
  const literal = report.match(
    /assert\.match\(process\.env\.REPORT_RUN,\/(.*)\/u\);/u,
  )?.[1];
  assert.ok(literal);
  const pattern = new RegExp(literal, 'u');
  for (const key of [
    '123-2',
    '123-2-quality',
    '123-2-image',
    ...gates.map((gate) => `123-2-gate-${gate}`),
  ])
    assert.match(key, pattern);
  for (const key of [
    '../123-2',
    '123-2-unknown',
    '123-2-gate-other',
    '123-2-quality;cat secrets',
    '123-0',
    '123-2\n',
  ])
    assert.doesNotMatch(key, pattern);
  assert.match(report, /PRIVATE_REPORT_ENVELOPE/u);
  assert.match(report, /aes-256-gcm/u);
  assert.doesNotMatch(report, /upload-artifact|actions\/cache/u);
});
