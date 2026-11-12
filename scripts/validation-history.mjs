import assert from 'node:assert/strict';
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import {
  evidenceManifest,
  evidenceName,
  proofSummary,
} from './validation-evidence.mjs';

export const attemptName = 'Public validation unit attempt';
const appId = 5497722;
const read = (directory) =>
  JSON.parse(readFileSync(join(directory, 'attestation.json'), 'utf8'));
const reset = (directory) => {
  rmSync(directory, { recursive: true, force: true });
  mkdirSync(directory, { recursive: true, mode: 0o700 });
};
const write = (directory, envelope) =>
  writeFileSync(join(directory, 'attestation.json'), JSON.stringify(envelope), {
    mode: 0o600,
  });
const url = (repository, runId) =>
  `https://github.com/${repository}/actions/runs/${runId}`;
const markerId = (payload) =>
  `sandboxpi:${payload.requestId}:attempt:${payload.phase}:${payload.runAttempt}`;
export function evidenceArchive(runId, runAttempt, phase) {
  assert.match(String(runId), /^[1-9]\d*$/u);
  assert.match(String(runAttempt), /^[1-9]\d*$/u);
  assert.match(
    phase,
    /^(?:quality|gate-(?:boundary|api|coverage|integration|security|mutation|risk))$/u,
  );
  return `evidence-${runId}-${runAttempt}-${phase}-v2`;
}
export async function validationChecks(api, sha) {
  const checks = new Map();
  for (let page = 1; page <= 10; page++) {
    const response = await api(
      `/commits/${sha}/check-runs?filter=all&per_page=100&page=${page}`,
    );
    for (const check of response.check_runs) checks.set(check.id, check);
    if (checks.size >= response.total_count) return [...checks.values()];
  }
  throw new Error('Incomplete validation attempt history');
}
export async function beginEvidenceAttempt({
  api,
  snapshot,
  phase,
  environment,
  executorRepository,
  policy,
}) {
  const payload = {
    schemaVersion: 2,
    phase,
    branch: snapshot.branch,
    sourceSha: snapshot.sha,
    sourceCandidate: snapshot.candidate,
    requestId: snapshot.requestId,
    executorRevision: environment.GITHUB_SHA,
    executorRepository,
    ...(policy ? { policy } : {}),
    runId: environment.GITHUB_RUN_ID,
    runAttempt: environment.GITHUB_RUN_ATTEMPT,
    startedAt: new Date().toISOString(),
  };
  evidenceArchive(payload.runId, payload.runAttempt, phase);
  const check = await api('/check-runs', 'POST', {
    name: attemptName,
    head_sha: snapshot.sha,
    status: 'in_progress',
    external_id: markerId(payload),
    details_url: url(executorRepository, payload.runId),
    output: {
      title: 'Validation attempt admitted',
      summary: JSON.stringify(payload),
    },
  });
  assert.equal(check.app?.id, appId);
  assert.ok(Number.isSafeInteger(check.id) && check.id > 0);
  return { payload, checkId: check.id };
}
async function verify(directory, options) {
  const {
    api,
    snapshot,
    phase,
    environment,
    executorRepository,
    policy,
    ancestors,
  } = options;
  const envelope = read(directory),
    { payload, checkId } = envelope;
  assert.equal(payload.schemaVersion, 2, 'legacy-evidence');
  assert.equal(payload.phase, phase, 'phase-changed');
  assert.equal(payload.branch, snapshot.branch, 'channel-changed');
  assert.equal(
    payload.executorRepository,
    executorRepository,
    'executor-changed',
  );
  assert.equal(
    policy ? payload.policy : payload.executorRevision,
    policy || environment.GITHUB_SHA,
    'executor-changed',
  );
  assert.match(payload.sourceSha, /^[a-f0-9]{40}$/u);
  assert.match(String(payload.attemptCheckId), /^[1-9]\d*$/u);
  assert.ok(Number.isFinite(Date.parse(payload.startedAt)));
  assert.ok(
    Array.isArray(payload.coveredAttempts) &&
      payload.coveredAttempts.length <= 1000,
  );
  assert.ok(
    Array.isArray(payload.pendingHeads) && payload.pendingHeads.length <= 100,
  );
  assert.deepEqual(
    payload.manifest,
    evidenceManifest(directory),
    'manifest-mismatch',
  );
  const check = await api(`/check-runs/${checkId}`);
  assert.ok(
    check.app?.id === appId &&
      check.name === evidenceName &&
      check.head_sha === payload.sourceSha &&
      check.status === 'completed' &&
      check.conclusion === 'success' &&
      check.external_id ===
        `sandboxpi:${payload.requestId}:evidence:${phase}:${payload.runAttempt}` &&
      check.details_url === url(executorRepository, payload.runId) &&
      check.output?.summary === proofSummary(payload),
    'untrusted-app-check',
  );
  const delta = await ancestors(payload.sourceSha, snapshot.candidate);
  assert.ok(Array.isArray(delta) && delta.length <= 100, 'unbounded-history');
  assert.ok(
    Number.isFinite(Date.parse(check.completed_at)),
    'invalid-check-time',
  );
  return { ...envelope, check, delta };
}
function mergeFresh(directory, incoming, proof) {
  const start = Date.parse(proof.payload.startedAt),
    end = Date.parse(proof.check.completed_at) + 999;
  for (const [path] of proof.payload.manifest) {
    if (!path.startsWith('events/')) continue;
    const source = join(incoming, path),
      event = JSON.parse(readFileSync(source));
    if (
      event.sourceRevision !== proof.payload.sourceSha ||
      Date.parse(event.checkedAt) < start ||
      Date.parse(event.checkedAt) > end
    )
      continue;
    for (const output of event.outputs) {
      const relative = `outputs/${output.stored}`;
      copy(relative);
    }
    copy(path);
  }
  function copy(path) {
    const target = join(directory, path);
    if (existsSync(target))
      assert.deepEqual(
        readFileSync(target),
        readFileSync(join(incoming, path)),
        'conflicting-evidence',
      );
    else {
      mkdirSync(join(target, '..'), { recursive: true, mode: 0o700 });
      cpSync(join(incoming, path), target);
    }
  }
}
// Dependency caches are only seeds. Every intervening attempt is reconciled from
// an immutable private archive authenticated by the App; aggregate failure is not
// a reason to erase its individually successful units.
export async function restoreEvidenceHistory(directory, options) {
  const {
    api,
    snapshot,
    phase,
    attempt,
    diagnostics = {},
    loadArchive,
    checks = (sha) => validationChecks(api, sha),
  } = options;
  const covered = new Set(),
    pendingHeads = new Set();
  let seed;
  Object.assign(diagnostics, {
    hit: false,
    reason: 'missing-attestation',
    importedAttempts: 0,
    fencedAttempts: [],
  });
  try {
    try {
      seed = options.verifiedSeed || (await verify(directory, options));
    } catch (error) {
      if (!options.recentCommits) throw error;
      const commits = await options.recentCommits();
      assert.ok(
        Array.isArray(commits) && commits.length <= 50,
        'unbounded-history',
      );
      let tried = 0;
      search: for (const sha of commits) {
        const candidates = (await checks(sha)).filter(
          (check) =>
            check.app?.id === appId &&
            check.name === attemptName &&
            check.status === 'completed',
        );
        candidates.sort(
          (a, b) => Date.parse(b.completed_at) - Date.parse(a.completed_at),
        );
        for (const check of candidates) {
          let archive;
          try {
            const payload = JSON.parse(check.output?.summary);
            if (
              payload.phase !== phase ||
              payload.branch !== snapshot.branch ||
              check.external_id !== markerId(payload)
            )
              continue;
            if (++tried > 20) break search;
            archive = await loadArchive(payload);
            seed = await verify(archive.directory, options);
            reset(directory);
            cpSync(archive.directory, directory, { recursive: true });
            diagnostics.seed = 'ancestral-immutable-archive';
            break search;
          } catch {
            seed =
              undefined; /* Eviction and foreign snapshots require another authentic ancestor. */
          } finally {
            archive?.cleanup?.();
          }
        }
      }
      if (!seed) throw error;
    }
    for (const id of seed.payload.coveredAttempts) covered.add(id);
    covered.add(seed.payload.attemptCheckId);
    // A retained unit can be older than the latest cache producer. Include its
    // original source delta too, so retries on earlier commits stay observable.
    const origins = new Set([seed.payload.sourceSha]);
    for (const [path] of evidenceManifest(directory))
      if (path.startsWith('events/'))
        origins.add(
          JSON.parse(readFileSync(join(directory, path))).sourceRevision,
        );
    assert.ok(origins.size <= 100, 'unbounded-history');
    const commitsSet = new Set([...seed.delta, ...seed.payload.pendingHeads]);
    for (const origin of origins) {
      commitsSet.add(origin);
      const delta = await options.ancestors(origin, snapshot.candidate);
      assert.ok(
        Array.isArray(delta) && delta.length <= 100,
        'unbounded-history',
      );
      for (const commit of delta) commitsSet.add(commit);
      assert.ok(commitsSet.size <= 100, 'unbounded-history');
    }
    const commits = [...commitsSet];
    assert.ok(commits.length <= 100, 'unbounded-history');
    const observations = new Map();
    for (const sha of commits)
      for (const check of await checks(sha)) observations.set(check.id, check);
    assert.ok(observations.size <= 10000, 'unbounded-history');
    let cutoff = 0;
    const markers = [...observations.values()].filter(
      (check) => check.app?.id === appId && check.name === attemptName,
    );
    const represented = new Set([seed.payload.requestId, snapshot.requestId]);
    for (const check of markers) {
      let payload;
      try {
        payload = JSON.parse(check.output?.summary);
      } catch {
        throw new Error('invalid-attempt-marker');
      }
      if (payload.phase !== phase || payload.branch !== snapshot.branch)
        continue;
      assert.ok(
        check.head_sha === payload.sourceSha &&
          check.external_id === markerId(payload) &&
          check.details_url === url(payload.executorRepository, payload.runId),
        'invalid-attempt-marker',
      );
      represented.add(payload.requestId);
      if (check.id === attempt.checkId || covered.has(check.id)) continue;
      if (
        check.status === 'completed' &&
        Date.parse(check.completed_at) < Date.parse(seed.payload.startedAt)
      )
        continue;
      try {
        const archive = await loadArchive(payload);
        try {
          const proof = await verify(archive.directory, options);
          assert.equal(
            proof.payload.attemptCheckId,
            check.id,
            'attempt-proof-mismatch',
          );
          assert.equal(
            proof.payload.startedAt,
            payload.startedAt,
            'attempt-proof-mismatch',
          );
          mergeFresh(directory, archive.directory, proof);
          covered.add(check.id);
          diagnostics.importedAttempts++;
        } finally {
          archive.cleanup?.();
        }
      } catch {
        const terminal =
          check.status === 'completed' &&
          Number.isFinite(Date.parse(check.completed_at));
        cutoff = Math.max(
          cutoff,
          terminal ? Date.parse(check.completed_at) + 999 : Infinity,
        );
        diagnostics.fencedAttempts.push({
          checkId: check.id,
          reason: terminal
            ? 'attempt-proof-unavailable'
            : 'attempt-still-unsealed',
        });
        if (terminal) covered.add(check.id);
        else pendingHeads.add(check.head_sha);
      }
    }
    const kind = phase === 'quality' ? 'quality' : 'gates';
    for (const check of observations.values()) {
      const match = /^sandboxpi:([^:]+):(quality|gates)$/u.exec(
        check.external_id ?? '',
      );
      if (
        check.app?.id !== appId ||
        !match ||
        match[2] !== kind ||
        represented.has(match[1]) ||
        covered.has(check.id)
      )
        continue;
      if (
        Math.max(
          Date.parse(check.started_at) || 0,
          Date.parse(check.completed_at) || 0,
        ) < Date.parse(seed.payload.startedAt)
      )
        continue;
      const terminal =
        check.status === 'completed' &&
        Number.isFinite(Date.parse(check.completed_at));
      cutoff = Math.max(
        cutoff,
        terminal ? Date.parse(check.completed_at) + 999 : Infinity,
      );
      diagnostics.fencedAttempts.push({
        checkId: check.id,
        reason: 'legacy-attempt-without-unit-proof',
      });
      if (terminal) covered.add(check.id);
      else pendingHeads.add(check.head_sha);
    }
    if (cutoff)
      for (const [path] of evidenceManifest(directory)) {
        if (
          path.startsWith('events/') &&
          Date.parse(
            JSON.parse(readFileSync(join(directory, path))).checkedAt,
          ) <= cutoff
        )
          rmSync(join(directory, path));
      }
    diagnostics.hit = evidenceManifest(directory).some(([path]) =>
      path.startsWith('events/'),
    );
    diagnostics.reason = diagnostics.fencedAttempts.length
      ? 'history-reconciled-with-fences'
      : 'authenticated-history';
  } catch (error) {
    // Raw exceptions can contain private paths. Publish fixed diagnostic codes only.
    const known = [
      'legacy-evidence',
      'phase-changed',
      'channel-changed',
      'executor-changed',
      'manifest-mismatch',
      'untrusted-app-check',
      'unbounded-history',
      'invalid-check-time',
      'invalid-attempt-marker',
    ];
    diagnostics.reason =
      known.find((code) => error?.message?.includes(code)) ||
      (existsSync(join(directory, 'attestation.json'))
        ? 'history-authentication-failed'
        : 'missing-attestation');
    reset(directory);
    covered.clear();
  }
  return {
    trusted: diagnostics.hit,
    coveredAttempts: [...covered],
    pendingHeads: [...pendingHeads],
    diagnostics,
    verifiedSeed: seed && {
      ...seed,
      payload: {
        ...seed.payload,
        coveredAttempts: [...covered],
        pendingHeads: [...pendingHeads],
      },
    },
  };
}
export function invalidatedReuses(directory, journal) {
  if (!existsSync(journal)) return [];
  const events = evidenceManifest(directory)
    .filter(([path]) => path.startsWith('events/'))
    .map(([path]) => JSON.parse(readFileSync(join(directory, path))));
  const invalid = new Set();
  const names = readdirSync(journal);
  assert.ok(names.length <= 10000, 'Unbounded reuse journal');
  for (const name of names) {
    assert.match(name, /^[a-f0-9-]+\.json$/u);
    const path = join(journal, name),
      stat = lstatSync(path);
    assert.ok(
      stat.isFile() &&
        !stat.isSymbolicLink() &&
        stat.uid === process.getuid() &&
        !(stat.mode & 0o077) &&
        stat.size <= 65536,
      'Unsafe reuse journal',
    );
    const used = JSON.parse(readFileSync(path));
    const matching = events.filter(
      (event) =>
        event.unit === used.unit &&
        event.fingerprint === used.fingerprint &&
        event.context === used.context,
    );
    matching.sort(
      (a, b) =>
        Date.parse(b.checkedAt) - Date.parse(a.checkedAt) ||
        (a.executionId === b.executionId
          ? (b.ordinal || 0) - (a.ordinal || 0)
          : { failed: 0, incomplete: 1, passed: 2 }[a.status] -
            { failed: 0, incomplete: 1, passed: 2 }[b.status]),
    );
    if (
      !matching.length ||
      matching[0].status !== 'passed' ||
      Date.parse(matching[0].checkedAt) < Date.parse(used.checkedAt)
    )
      invalid.add(used.unit);
  }
  return [...invalid];
}
export async function sealEvidenceAttempt(
  directory,
  { api, attempt, history, exportArchive, success },
) {
  const payload = {
    ...attempt.payload,
    attemptCheckId: attempt.checkId,
    coveredAttempts: history.coveredAttempts,
    pendingHeads: history.pendingHeads,
    manifest: evidenceManifest(directory),
  };
  const check = await api('/check-runs', 'POST', {
    name: evidenceName,
    head_sha: payload.sourceSha,
    status: 'in_progress',
    external_id: `sandboxpi:${payload.requestId}:evidence:${payload.phase}:${payload.runAttempt}`,
    details_url: url(payload.executorRepository, payload.runId),
    output: {
      title: 'Authenticated per-unit results and original provenance',
      summary: proofSummary(payload),
    },
  });
  assert.equal(check.app?.id, appId);
  assert.ok(Number.isSafeInteger(check.id) && check.id > 0);
  write(directory, { payload, checkId: check.id });
  // A successful App proof is published only after private durable storage exists.
  await exportArchive(payload);
  await api(`/check-runs/${check.id}`, 'PATCH', {
    status: 'completed',
    conclusion: 'success',
  });
  await api(`/check-runs/${attempt.checkId}`, 'PATCH', {
    status: 'completed',
    conclusion: success ? 'success' : 'failure',
  });
  return { payload, checkId: check.id };
}
