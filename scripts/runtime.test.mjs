import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  closeSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { test } from 'node:test';
import { gates } from './request.mjs';
import {
  captured,
  capturedAsync,
  executePhaseCommands,
  phaseCommands,
  phaseCachePaths,
  phaseReportPaths,
  sourceEnvironment,
  storageKeys,
  verifyPrivateStorage,
  supportsEvidenceJournal,
} from './runtime.mjs';

test('older source ledgers without the scoped completion journal execute fresh', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'journal-capability-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, 'scripts/validation'), { recursive: true });
  assert.equal(supportsEvidenceJournal(root), false);
  const path = join(root, 'scripts/validation/validation-ledger.mjs');
  writeFileSync(path, 'VALIDATION_REUSE_JOURNAL');
  assert.equal(supportsEvidenceJournal(root), false);
  writeFileSync(path, 'VALIDATION_REUSE_JOURNAL VALIDATION_EVIDENCE_DIRECTORY');
  assert.equal(supportsEvidenceJournal(root), true);
});

test('frozen installation precedes concurrent quality/security and a failure drains its sibling', async () => {
  const commands = phaseCommands('quality'),
    timings = [],
    started = [];
  let release,
    dependencyDone = false,
    securityDone = false;
  const sibling = new Promise((resolve) => {
    release = resolve;
  });
  const result = executePhaseCommands(commands, {
    phase: 'quality',
    runGates: false,
    timings,
    async run([stage]) {
      started.push(stage);
      if (stage === 'dependencies') {
        dependencyDone = true;
        return;
      }
      assert.ok(dependencyDone);
      if (stage === 'quality') throw new Error('fixture failure');
      await sibling;
      securityDone = true;
    },
  });
  let settled = false;
  const observed = result.then(
    () => {
      settled = true;
    },
    (error) => {
      settled = true;
      return error;
    },
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, ['dependencies', 'quality', 'security']);
  assert.equal(settled, false);
  release();
  assert.ok((await observed) instanceof AggregateError);
  assert.equal(securityDone, true);
  assert.deepEqual(
    timings.map(({ stage, status }) => [stage, status]),
    [
      ['dependencies', 'passed'],
      ['quality', 'failed'],
      ['security', 'passed'],
    ],
  );
});
test('failed installation launches no source checks; matrices scan security once and other phases stay ordered', async () => {
  const started = [];
  await assert.rejects(
    executePhaseCommands(phaseCommands('quality'), {
      phase: 'quality',
      runGates: false,
      run: async ([stage]) => {
        started.push(stage);
        throw Error('install');
      },
    }),
  );
  assert.deepEqual(started, ['dependencies']);
  const timings = [];
  await executePhaseCommands(phaseCommands('quality'), {
    phase: 'quality',
    runGates: true,
    timings,
    run: async ([stage]) => started.push(stage),
  });
  assert.equal(started.includes('security'), false);
  assert.equal(
    timings.find((item) => item.stage === 'security').status,
    'separate-matrix',
  );
  let active = 0,
    maximum = 0;
  await executePhaseCommands(phaseCommands('gate-boundary'), {
    phase: 'gate-boundary',
    runGates: true,
    run: async () => {
      maximum = Math.max(maximum, ++active);
      await new Promise((resolve) => setImmediate(resolve));
      active--;
    },
  });
  assert.equal(maximum, 1);
});
test('asynchronous source capture retains private output, removes credentials and enforces process deadlines', async (t) => {
  const root = directory(t),
    output = join(root, 'async.log'),
    descriptor = openSync(output, 'w', 0o600);
  try {
    const childEnv = sourceEnvironment(
      {
        ...process.env,
        GITHUB_TOKEN: 'credential',
        GITHUB_OUTPUT: join(root, 'command'),
      },
      snapshot,
      root,
      root,
    );
    await capturedAsync(
      process.execPath,
      [
        '-e',
        "console.log('PRIVATE_ASYNC');if(process.env.GITHUB_TOKEN||process.env.GITHUB_OUTPUT)process.exit(8)",
      ],
      { cwd: root, env: childEnv, descriptor },
    );
    assert.match(readFileSync(output, 'utf8'), /PRIVATE_ASYNC/u);
    assert.equal(
      await capturedAsync(
        process.execPath,
        ['-e', 'setInterval(()=>{},1000)'],
        { cwd: root, env: childEnv, descriptor, timeout: 50, optional: true },
      ),
      false,
    );
    await assert.rejects(
      capturedAsync('missing-fixture-executable', [], {
        cwd: root,
        env: childEnv,
        descriptor,
      }),
      /Private phase command failed/u,
    );
  } finally {
    closeSync(descriptor);
  }
});

const env = {
  GITHUB_REPOSITORY: 'BANG404/sandboxpi-actions',
  GITHUB_EVENT_NAME: 'workflow_dispatch',
  GITHUB_REF: 'refs/heads/main',
  GITHUB_RUN_ID: '123',
  GITHUB_RUN_ATTEMPT: '2',
  PUBLIC_ACTION: 'ci',
  SOURCE_BRANCH: 'alpha',
  SOURCE_SHA: 'a'.repeat(40),
  SOURCE_TOKEN: 'checkout-secret',
  GHCR_TOKEN: 'package-secret',
};
const snapshot = {
  action: 'ci',
  branch: 'alpha',
  sha: env.SOURCE_SHA,
  pr: '',
  runGates: false,
  requestId: '123-2',
  base: 'b'.repeat(40),
  candidate: env.SOURCE_SHA,
  ref: env.SOURCE_SHA,
};
function directory(t) {
  const root = mkdtempSync(join(tmpdir(), 'bootstrap-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}
test('source stdout/stderr, thrown errors and command-file attacks stay in private capture', (t) => {
  const root = directory(t),
    log = join(root, 'private.log'),
    commandFile = join(root, 'commands');
  const secrets = {
    ...process.env,
    GITHUB_OUTPUT: commandFile,
    GITHUB_ENV: commandFile,
    GITHUB_PATH: commandFile,
    GITHUB_STEP_SUMMARY: commandFile,
    GITHUB_STATE: commandFile,
    ACTIONS_RUNTIME_TOKEN: 'runtime-secret',
    ACTIONS_CACHE_URL: 'private-url',
    GHCR_TOKEN: 'package-secret',
    GITHUB_TOKEN: 'source-secret',
    SOURCE_TOKEN: 'checkout-secret',
    ACR_PASSWORD: 'release-secret',
    NODE_OPTIONS: '--expose-secret',
    BASH_ENV: 'secret-script',
  };
  const childEnv = sourceEnvironment(secrets, snapshot, root, root);
  for (const key of Object.keys(secrets).filter((key) =>
    /TOKEN|PASSWORD|ACTIONS_|GITHUB_(OUTPUT|ENV|PATH|STEP_SUMMARY|STATE)|NODE_OPTIONS|BASH_ENV/u.test(
      key,
    ),
  ))
    assert.equal(childEnv[key], undefined, key);
  const descriptor = openSync(log, 'w', 0o600);
  try {
    const attack = `const fs=require('node:fs');console.log('PRIVATE_SENTINEL_STDOUT');console.error('PRIVATE_SENTINEL_STDERR');for(const key of ['GITHUB_OUTPUT','GITHUB_ENV','GITHUB_PATH','GITHUB_STEP_SUMMARY','GITHUB_STATE'])if(process.env[key])fs.appendFileSync(process.env[key],'PRIVATE_SENTINEL_COMMAND');console.log('::notice::PRIVATE_SENTINEL_NOTICE');throw new Error('PRIVATE_SENTINEL_EXCEPTION');`;
    assert.throws(
      () =>
        captured(process.execPath, ['-e', attack], {
          cwd: root,
          env: childEnv,
          descriptor,
        }),
      /^Error: Private phase command failed: .*status 1, error none$/u,
    );
    assert.equal(existsSync(commandFile), false);
    const output = readFileSync(log, 'utf8');
    for (const sentinel of ['STDOUT', 'STDERR', 'NOTICE', 'EXCEPTION'])
      assert.ok(output.includes(`PRIVATE_SENTINEL_${sentinel}`));
    assert.equal(
      captured(
        process.execPath,
        ['-e', 'process.kill(process.pid,"SIGTERM")'],
        { cwd: root, env: childEnv, descriptor, optional: true },
      ),
      false,
    );
  } finally {
    closeSync(descriptor);
  }
});
test('full verify and all seven substantive gate commands are fixed, including runner regressions', () => {
  assert.deepEqual(phaseCommands('quality'), [
    ['dependencies', 'bun', ['install', '--frozen-lockfile']],
    ['quality', 'bun', ['run', 'verify']],
    ['security', 'node', ['scripts/validation/test-gate.mjs', 'security']],
  ]);
  const refs = new Set();
  for (const phase of [
    'quality',
    'image',
    ...gates.map((gate) => `gate-${gate}`),
  ]) {
    const keys = storageKeys(env, phase);
    refs.add(keys.report);
    refs.add(keys.cache);
    if (phase.startsWith('gate-'))
      assert.deepEqual(phaseCommands(phase)[1], [
        'gate',
        'node',
        ['scripts/validation/test-gate.mjs', phase.slice(5)],
      ]);
  }
  assert.equal(refs.size, 18);
  assert.equal(phaseCommands('gate-boundary').length, 4);
  assert.deepEqual(phaseCommands('image').at(-1), [
    'image',
    'bash',
    ['deploy/github/publish-ags.sh'],
  ]);
  for (const phase of ['ci', 'deploy', 'gate-unknown', '../quality'])
    assert.throws(() => phaseCommands(phase));
});
test('private storage requires authenticated seed plus anonymous denial, never a name or successful push', async () => {
  const events = [];
  await verifyPrivateStorage(
    ['sandboxpi-ci-data', 'sandboxpi-build-cache'],
    (ref) => events.push(ref),
    async () => new Response('', { status: 403 }),
  );
  assert.equal(events.length, 2);
  for (const status of [200, 302, 404, 429, 500])
    await assert.rejects(
      verifyPrivateStorage(
        ['sandboxpi-ci-data'],
        () => {},
        async () => new Response('', { status }),
      ),
    );
  await assert.rejects(
    verifyPrivateStorage(
      ['sandboxpi-ci-data'],
      () => {
        throw new Error('Missing seed');
      },
      () => {
        throw new Error('Must not fetch');
      },
    ),
  );
  await assert.rejects(
    verifyPrivateStorage(
      ['sandboxpi-ci-data'],
      () => {},
      async () => {
        throw new Error('Network unavailable');
      },
    ),
  );
});
test('actual outer runtime captures malicious source output and blocks every export when privacy is absent', (t) => {
  const runtime = new URL('./runtime.mjs', import.meta.url).href;
  for (const scenario of [
    { statuses: [401], exit: 0, uploads: 4, sources: 2 },
    { statuses: [200], exit: 1, uploads: 0, sources: 0 },
    { statuses: [404], exit: 1, uploads: 0, sources: 0 },
    { statuses: [401, 200], exit: 1, uploads: 0, sources: 2 },
    { statuses: [401], failSource: true, exit: 1, uploads: 4, sources: 2 },
    { statuses: [401], restoreFailure: true, exit: 1, uploads: 2, sources: 0 },
    {
      statuses: [401],
      validationFailure: true,
      exit: 1,
      uploads: 4,
      sources: 2,
    },
  ]) {
    const root = directory(t),
      bin = join(root, 'bin');
    mkdirSync(bin);
    const operations = join(root, 'operations'),
      commandFile = join(root, 'summary');
    const tool = `#!${process.execPath}\nconst fs=require('node:fs');const name=require('node:path').basename(process.argv[1]);const args=process.argv.slice(2);fs.appendFileSync(${JSON.stringify(operations)},JSON.stringify([name,...args])+'\\n');if(name==='docker'&&args[0]==='pull')process.exit(${scenario.restoreFailure ? 0 : 1});if(name==='tar'&&args.includes('-xf')&&${!!scenario.restoreFailure})process.exit(3);if(name==='tar'&&args.includes('-cf')){const base=args[args.indexOf('-C')+1];if(base.endsWith('/report'))fs.copyFileSync(base+'/build.log',${JSON.stringify(join(root, 'captured-report.log'))});fs.writeFileSync(args[args.indexOf('-cf')+1],'fixture');}if(name==='bun'){console.log('PRIVATE_SOURCE_STDOUT');console.error('PRIVATE_SOURCE_STDERR');console.log('::notice::PRIVATE_SOURCE_COMMAND');for(const k of ['GITHUB_OUTPUT','GITHUB_STEP_SUMMARY','GITHUB_ENV','GITHUB_PATH'])if(process.env[k])fs.appendFileSync(process.env[k],'LEAK');if(Object.keys(process.env).some(k=>/TOKEN|PASSWORD|ACTIONS_/u.test(k)))process.exit(7);if(${!!scenario.failSource}&&args[0]==='run')process.exit(3);}`;
    for (const name of ['git', 'docker', 'tar', 'bun']) {
      writeFileSync(join(bin, name), tool);
      chmodSync(join(bin, name), 0o755);
    }
    const script = `import {runPhase} from ${JSON.stringify(runtime)};const statuses=${JSON.stringify(scenario.statuses)};let privacyIndex=0,branchReads=0;globalThis.fetch=async url=>{if(url.includes('ghcr.io/token'))return new Response('',{status:statuses[Math.min(privacyIndex++,statuses.length-1)]});if(url.includes('/branches/')){if(++branchReads>1&&${!!scenario.validationFailure})throw new Error('PRIVATE_VALIDATION_FAILURE');return Response.json({commit:{sha:${JSON.stringify(snapshot.base)}}});}if(url.includes('/compare/'))return Response.json({status:'ahead',merge_base_commit:{sha:${JSON.stringify(snapshot.sha)}}});throw new Error('Unexpected API');};const env=JSON.parse(process.env.FIXTURE_ENV);try{await runPhase(env)}catch{console.log('Generic failure');process.exitCode=1}`;
    const childEnvironment = {
      ...env,
      SOURCE_SNAPSHOT: JSON.stringify({ ...snapshot, runGates: true }),
      RUN_GATES: 'true',
      PUBLIC_PHASE: 'quality',
      PATH: `${bin}${delimiter}${process.env.PATH}`,
      GITHUB_OUTPUT: commandFile,
      GITHUB_STEP_SUMMARY: commandFile,
    };
    const result = spawnSync(
      process.execPath,
      ['--input-type=module', '-e', script],
      {
        cwd: root,
        encoding: 'utf8',
        env: {
          PATH: process.env.PATH,
          FIXTURE_ENV: JSON.stringify(childEnvironment),
        },
      },
    );
    assert.equal(result.status, scenario.exit, result.stderr + result.stdout);
    assert.doesNotMatch(
      result.stdout + result.stderr,
      /PRIVATE_SOURCE|checkout-secret|package-secret|LEAK/u,
    );
    assert.equal(existsSync(commandFile), false);
    const commands = readFileSync(operations, 'utf8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line));
    const uploads = commands.filter(
      ([name, op]) => name === 'docker' && ['build', 'push'].includes(op),
    );
    const sources = commands.filter(([name]) => name === 'bun');
    assert.equal(uploads.length, scenario.uploads);
    assert.equal(sources.length, scenario.sources);
    if (scenario.validationFailure)
      assert.match(
        readFileSync(join(root, 'captured-report.log'), 'utf8'),
        /Private bootstrap failure:.*PRIVATE_VALIDATION_FAILURE/u,
      );
  }
});

test('PR cache exports cannot overwrite protected-channel cache keys', () => {
  const frame = { GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '1' };
  assert.notEqual(
    storageKeys({ ...frame, PUBLIC_ACTION: 'pr' }, 'quality').cache,
    storageKeys({ ...frame, PUBLIC_ACTION: 'ci' }, 'quality').cache,
  );
});

test('expanded security caches use a new generation without restoring incompatible archives', () => {
  assert.match(storageKeys(env, 'quality').cache, /quality-v6$/u);
  assert.match(storageKeys(env, 'gate-security').cache, /gate-security-v5$/u);
  assert.match(storageKeys(env, 'image').cache, /image-v2$/u);
  assert.ok(phaseCachePaths('gate-security').includes('.data/security-tools'));
  assert.ok(phaseCachePaths('quality').includes('.data/validation/evidence'));
  assert.ok(phaseReportPaths('quality').includes('.data/validation'));
});
test('integration module caches stay private caches and never inflate diagnostic reports', () => {
  assert.ok(
    phaseCachePaths('gate-integration').includes('.data/test-gates/go'),
  );
  assert.deepEqual(phaseReportPaths('gate-integration'), [
    'dist/build-info.json',
    '.data/test-gates/integration',
  ]);
  assert.deepEqual(phaseReportPaths('image'), [
    'dist/build-info.json',
    '.data/cd/trivy.json',
  ]);
  assert.throws(() => phaseCachePaths('untrusted'));
});

test('image capture kills descendants that retain output pipes at the deadline', async (t) => {
  const root = directory(t),
    descriptor = openSync(join(root, 'deadline.log'), 'w', 0o600);
  t.after(() => closeSync(descriptor));
  const sentinel = join(root, 'orphan-write');
  const grandchild = `setTimeout(()=>require('node:fs').writeFileSync(${JSON.stringify(sentinel)},'orphan'),450);setInterval(()=>{},1000)`;
  const script = `require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(grandchild)}],{stdio:'inherit'});setInterval(()=>{},1000)`;
  const started = performance.now();
  await assert.rejects(
    capturedAsync(process.execPath, ['-e', script], {
      cwd: root,
      env: process.env,
      descriptor,
      timeout: 150,
      onOutput: () => {},
    }),
    /SIGKILL/u,
  );
  assert.ok(performance.now() - started < 2000);
  await new Promise((resolve) => setTimeout(resolve, 500));
  assert.equal(existsSync(sentinel), false);
});
