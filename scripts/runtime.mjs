import assert from 'node:assert/strict';
import { publishSecurity, securityApi } from './security-summary.mjs';
import { spawnSync } from 'node:child_process';
import {
  closeSync,
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  rmSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  gates,
  github,
  normalize,
  readResponse,
  revalidate,
} from './request.mjs';

export const dataPackage = 'ghcr.io/bang404/sandboxpi-ci-data';
export function sourceEnvironment(environment, snapshot, root, temporary) {
  // An allowlist also removes future GitHub command files, credentials and injected Node/Bun options.
  const env = {};
  for (const key of ['PATH', 'LANG', 'LC_ALL', 'TZ', 'JAVA_HOME', 'GOROOT'])
    if (environment[key]) env[key] = environment[key];
  return {
    ...env,
    HOME: join(temporary, 'home'),
    TMPDIR: join(temporary, 'tmp'),
    RUNNER_TEMP: join(temporary, 'tmp'),
    CI: 'true',
    NO_COLOR: '1',
    FORCE_COLOR: '0',
    GITHUB_RUN_ID: environment.GITHUB_RUN_ID,
    GITHUB_RUN_ATTEMPT: environment.GITHUB_RUN_ATTEMPT,
    GITHUB_REPOSITORY: 'BANG404/sandboxpi',
    GITHUB_EVENT_NAME: snapshot.pr ? 'pull_request' : 'workflow_dispatch',
    GITHUB_SHA: snapshot.candidate,
    GITHUB_REF: snapshot.pr ? snapshot.ref : `refs/heads/${snapshot.branch}`,
    GITHUB_REF_NAME: snapshot.pr ? `${snapshot.pr}/merge` : snapshot.branch,
    GITHUB_BASE_REF: snapshot.pr ? snapshot.branch : '',
    GITHUB_HEAD_REF: snapshot.pr ? 'trusted-pr' : '',
    BUN_INSTALL_CACHE_DIR: join(root, '.data/bun-cache'),
    GOMODCACHE: join(root, '.data/go-mod'),
    GOCACHE: join(root, '.data/go-build'),
    TRIVY_CACHE_DIR: join(root, '.data/trivy'),
    DOCKER_CONFIG: join(temporary, 'source-docker'),
  };
}
export function captured(
  program,
  args,
  { cwd, env, descriptor, input, optional = false, timeout = 85 * 60_000 },
) {
  const result = spawnSync(program, args, {
    cwd,
    env,
    input,
    stdio: [input === undefined ? 'ignore' : 'pipe', descriptor, descriptor],
    timeout,
    killSignal: 'SIGKILL',
  });
  const ok = !result.error && result.status === 0;
  if (!ok && !optional)
    throw new Error(
      `Private phase command failed: ${program}, status ${result.status}, error ${result.error?.message || 'none'}`,
    );
  return ok;
}
export async function verifyPrivateStorage(packages, inspect, request = fetch) {
  for (const name of packages) {
    await inspect(`ghcr.io/bang404/${name}:privacy-seed`);
    const response = await readResponse(
      request,
      `https://ghcr.io/token?service=ghcr.io&scope=repository:bang404/${name}:pull`,
      { timeoutMs: 20_000 },
    );
    assert.ok(
      [401, 403].includes(response.status),
      'Private storage privacy gate failed',
    );
  }
}
export function phaseCommands(phase) {
  assert.ok(
    ['quality', 'image', ...gates.map((gate) => `gate-${gate}`)].includes(
      phase,
    ),
  );
  const commands = [['dependencies', 'bun', ['install', '--frozen-lockfile']]];
  if (phase === 'quality')
    commands.push(
      ['quality', 'bun', ['run', 'verify']],
      ['security', 'node', ['scripts/test-gate.mjs', 'security']],
    );
  else if (phase === 'image')
    commands.push(
      [
        'scanner-setup',
        'bash',
        [fileURLToPath(new URL('./install-trivy.sh', import.meta.url))],
      ],
      ['image', 'bash', ['deploy/github/publish-ags.sh']],
    );
  else {
    commands.push(['gate', 'node', ['scripts/test-gate.mjs', phase.slice(5)]]);
    if (phase === 'gate-boundary')
      commands.push(
        ['runner-regressions', 'bun', ['run', 'test:gates']],
        [
          'workflow-regressions',
          'node',
          ['--test', 'scripts/cd-workflow.test.mjs'],
        ],
      );
  }
  return commands;
}
export function storageKeys(environment, phase) {
  phaseCommands(phase);
  assert.match(environment.GITHUB_RUN_ID || '', /^[1-9]\d*$/u);
  assert.match(environment.GITHUB_RUN_ATTEMPT || '', /^[1-9]\d*$/u);
  return {
    cache: `${dataPackage}:deps-${environment.PUBLIC_ACTION === 'pr' || environment.SOURCE_PR ? 'pr-' : ''}${phase}-v2`,
    report: `${dataPackage}:report-${environment.GITHUB_RUN_ID}-${environment.GITHUB_RUN_ATTEMPT}-${phase}`,
  };
}
export function phaseCachePaths(phase) {
  phaseCommands(phase);
  if (phase === 'image') return ['.data/trivy', '.data/buildx-cache'];
  return [
    '.data/bun-cache',
    '.data/go-mod',
    '.data/go-build',
    '.data/security-tools',
    '.data/trivy',
    ...(phase === 'gate-integration'
      ? ['.data/test-gates/go', '.data/test-gates/go-build']
      : []),
  ];
}
export function phaseReportPaths(phase) {
  phaseCommands(phase);
  return [
    'dist/build-info.json',
    ...(phase.startsWith('gate-')
      ? [`.data/test-gates/${phase.slice(5)}`]
      : []),
    ...(phase === 'quality' ? ['coverage', '.data/test-gates/security'] : []),
    ...(phase === 'image' ? ['.data/cd/trivy.json'] : []),
  ];
}
export async function runPhase(environment) {
  const input = normalize(environment);
  const snapshot = JSON.parse(environment.SOURCE_SNAPSHOT);
  assert.deepEqual(
    normalize(environment),
    Object.fromEntries(Object.keys(input).map((key) => [key, snapshot[key]])),
  );
  const phase = environment.PUBLIC_PHASE;
  const commands = phaseCommands(phase);
  assert.ok(
    phase !== 'image' || ['validate', 'publish'].includes(input.action),
  );
  assert.ok(!phase.startsWith('gate-') || input.runGates);
  const keys = storageKeys(environment, phase);
  const temporary = mkdtempSync(join(tmpdir(), 'trusted-public-'));
  const root = resolve('source');
  const descriptor = openSync(join(temporary, 'build.log'), 'a', 0o600);
  const childEnv = sourceEnvironment(environment, snapshot, root, temporary);
  for (const path of [childEnv.HOME, childEnv.TMPDIR, childEnv.DOCKER_CONFIG])
    mkdirSync(path, { recursive: true });
  const trustedEnv = {
    PATH: environment.PATH,
    HOME: childEnv.HOME,
    DOCKER_CONFIG: join(temporary, 'registry-auth'),
  };
  const command = (program, args, options = {}) =>
    captured(program, args, {
      cwd: temporary,
      env: trustedEnv,
      descriptor,
      ...options,
    });
  let privacy = false,
    cacheReady = false,
    failure = false;
  const cachePaths = phaseCachePaths(phase);
  const bundle = (reference, paths, base) => {
    const context = mkdtempSync(join(temporary, 'bundle-'));
    try {
      command('tar', [
        '--zstd',
        '-cf',
        join(context, 'payload.tar.zst'),
        '-C',
        base,
        ...paths,
      ]);
      writeFileSync(
        join(context, 'Dockerfile'),
        'FROM scratch\nCOPY payload.tar.zst /payload.tar.zst\n',
      );
      command('docker', ['build', '-t', reference, context]);
      command('docker', ['push', reference]);
    } finally {
      rmSync(context, { recursive: true, force: true });
    }
  };
  try {
    await revalidate(snapshot, github(environment.SOURCE_TOKEN));
    assert.ok(!existsSync(root), 'Private checkout already exists');
    mkdirSync(root);
    command('git', ['init', '--quiet', root]);
    command(
      'git',
      ['remote', 'add', 'origin', 'https://github.com/BANG404/sandboxpi.git'],
      { cwd: root },
    );
    const gitEnv = {
      ...trustedEnv,
      GIT_TERMINAL_PROMPT: '0',
      GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader',
      GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${environment.SOURCE_TOKEN}`).toString('base64')}`,
    };
    command(
      'git',
      [
        'fetch',
        '--quiet',
        '--tags',
        'origin',
        '+refs/heads/*:refs/remotes/origin/*',
        snapshot.ref,
      ],
      { cwd: root, env: gitEnv },
    );
    command(
      'git',
      [
        '-c',
        'core.hooksPath=/dev/null',
        'checkout',
        '--quiet',
        '--detach',
        snapshot.candidate,
      ],
      { cwd: root },
    );
    // Never pass the checkout token, package token or command-file environment to project code.
    command(
      'docker',
      ['login', 'ghcr.io', '--username', 'BANG404', '--password-stdin'],
      { input: environment.GHCR_TOKEN },
    );
    await verifyPrivateStorage(
      [
        'sandboxpi-ci-data',
        ...(phase === 'image' ? ['sandboxpi-build-cache'] : []),
      ],
      (ref) => command('docker', ['manifest', 'inspect', ref]),
    );
    privacy = true;
    for (const path of cachePaths)
      mkdirSync(join(root, path), { recursive: true });
    if (command('docker', ['pull', keys.cache], { optional: true })) {
      const container = `private-cache-${environment.GITHUB_RUN_ID}-${environment.GITHUB_RUN_ATTEMPT}-${phase}`;
      try {
        command('docker', [
          'create',
          '--name',
          container,
          keys.cache,
          '/unused',
        ]);
        command('docker', [
          'cp',
          `${container}:/payload.tar.zst`,
          join(temporary, 'cache.tar.zst'),
        ]);
        command('tar', [
          '--zstd',
          '-xf',
          join(temporary, 'cache.tar.zst'),
          '-C',
          root,
          '--no-same-owner',
          ...cachePaths,
        ]);
      } finally {
        command('docker', ['rm', '--force', container], { optional: true });
      }
    }
    cacheReady = true;
    if (phase === 'image') {
      // The source image driver can use a credential-free Buildx builder; registry auth remains outside source env.
      command(
        'docker',
        [
          'buildx',
          'create',
          '--name',
          'private-image',
          '--driver',
          'docker-container',
          '--use',
        ],
        { env: childEnv },
      );
      childEnv.AGS_BUILD_CACHE = '.data/buildx-cache';
      childEnv.PUBLISH_AGS = input.action === 'publish' ? 'true' : 'false';
      childEnv.VALIDATE_AGS = input.action === 'validate' ? 'true' : 'false';
      childEnv.AGS_CHANNEL = environment.AGS_CHANNEL || 'production';
    }
    for (const [stage, program, args] of commands) {
      if (stage === 'security' && snapshot.runGates) continue;
      console.log(`Phase ${phase}: ${stage}`);
      const env = { ...childEnv };
      if (stage === 'image')
        for (const key of [
          'GITHUB_TOKEN',
          'SKILL_SOURCES_TOKEN',
          'ACR_USERNAME',
          'ACR_PASSWORD',
          'WOODPECKER_TOKEN',
          'WOODPECKER_REPO_ID',
          'AGS_TAG',
          'TENCENTCLOUD_SECRET_ID',
          'TENCENTCLOUD_SECRET_KEY',
          'TENCENTCLOUD_SESSION_TOKEN',
        ])
          if (environment[key]) env[key] = environment[key];
      captured(program, args, { cwd: root, env, descriptor });
      if (stage === 'scanner-setup')
        childEnv.PATH = `${childEnv.RUNNER_TEMP}/trivy-bin:${childEnv.PATH}`;
    }
    await revalidate(snapshot, github(environment.SOURCE_TOKEN));
  } catch (error) {
    writeSync(
      descriptor,
      `\nPrivate bootstrap failure: ${error?.stack || String(error)}\n`,
    );
    failure = true;
  } finally {
    try {
      if (privacy && cacheReady) {
        await verifyPrivateStorage(['sandboxpi-ci-data'], (ref) =>
          command('docker', ['manifest', 'inspect', ref]),
        );
        bundle(keys.cache, cachePaths, root);
      }
    } catch (error) {
      writeSync(
        descriptor,
        `\nPrivate cache export failure: ${error?.stack || String(error)}\n`,
      );
      failure = true;
    }
    try {
      assert.ok(privacy, 'Storage privacy gate blocked export');
      const report = join(temporary, 'report');
      mkdirSync(report);
      copyFileSync(join(temporary, 'build.log'), join(report, 'build.log'));
      for (const path of phaseReportPaths(phase)) {
        if (existsSync(join(root, path)))
          cpSync(join(root, path), join(report, path), { recursive: true });
      }
      writeFileSync(
        join(report, 'phase.json'),
        JSON.stringify({
          phase,
          success: !failure,
          candidate: snapshot.candidate,
        }),
      );
      // Recheck immediately before every report export; an anonymous/public package never receives project data.
      await verifyPrivateStorage(['sandboxpi-ci-data'], (ref) =>
        command('docker', ['manifest', 'inspect', ref]),
      );
      bundle(keys.report, ['.'], report);
      console.log(`Private report: ${keys.report}`);
    } catch {
      failure = true;
    }
    if (
      existsSync(join(root, 'scripts/security-open-source.mjs')) &&
      (phase === 'gate-security' || (phase === 'quality' && !snapshot.runGates))
    ) {
      try {
        const summary = await publishSecurity(
          root,
          snapshot,
          !failure,
          securityApi(environment.SOURCE_TOKEN),
        );
        assert.ok(summary.success, 'Incomplete or failed security evidence');
      } catch {
        failure = true;
      }
    }
    closeSync(descriptor);
    rmSync(temporary, { recursive: true, force: true });
  }
  console.log(`Phase ${phase}: ${failure ? 'failure' : 'success'}`);
  if (failure) throw new Error('Private phase failed');
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  const environment = { ...process.env };
  // Environment secrets are kept only in this trusted process's closure.
  for (const key of Object.keys(process.env))
    if (/TOKEN|PASSWORD|SECRET|PRIVATE_KEY|GITHUB_|ACTIONS_/u.test(key))
      delete process.env[key];
  try {
    await runPhase(environment);
  } catch {
    console.error('Private phase failed; inspect the private report.');
    process.exitCode = 1;
  }
}
