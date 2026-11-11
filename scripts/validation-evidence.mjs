import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

export const evidenceName = 'Public validation unit evidence';
const sha256 = (content) => createHash('sha256').update(content).digest('hex');
export function evidenceManifest(directory) {
  const manifest = [];
  const read = (path) => {
    const full = join(directory, path),
      stat = lstatSync(full);
    assert.ok(
      stat.isFile() &&
        !stat.isSymbolicLink() &&
        stat.uid === process.getuid() &&
        !(stat.mode & 0o077) &&
        stat.size <= 8 * 1024 * 1024,
      'Unsafe validation evidence',
    );
    const content = readFileSync(full);
    manifest.push([path, sha256(content)]);
    return content;
  };
  if (!existsSync(join(directory, 'events'))) return manifest;
  const names = readdirSync(join(directory, 'events'))
    .filter((name) => /^[a-f0-9-]+\.json$/u.test(name))
    .sort();
  assert.ok(names.length <= 10000, 'Validation history exceeds its bound');
  for (const name of names) {
    const event = JSON.parse(read(`events/${name}`));
    assert.ok(
      event.schemaVersion === 1 &&
        ['passed', 'failed', 'incomplete'].includes(event.status) &&
        (event.status !== 'passed' ||
          (event.result?.code === 0 &&
            !event.result.signal &&
            !event.result.error)) &&
        /^[a-f0-9]{64}$/u.test(event.fingerprint) &&
        /^[a-f0-9]{64}$/u.test(event.context) &&
        /^[a-f0-9]{40}$/u.test(event.sourceRevision) &&
        Number.isFinite(Date.parse(event.checkedAt)) &&
        Array.isArray(event.outputs),
      'Incomplete validation event',
    );
    for (const output of event.outputs) {
      assert.match(output.stored, /^[a-f0-9-]+\/\d+$/u);
      const content = read(`outputs/${output.stored}`);
      assert.equal(sha256(content), output.digest, 'Validation output drift');
    }
  }
  return [...new Map(manifest)].sort(([a], [b]) => a.localeCompare(b));
}
export function proofSummary(payload) {
  return `Validation unit manifest SHA256: ${sha256(JSON.stringify(payload))}`;
}
export async function authenticateEvidence(
  directory,
  {
    api,
    environment,
    snapshot,
    phase,
    diagnostics = {},
    ancestors = () => {
      throw new Error('Validation ancestry is unavailable');
    },
    checks = async () => {
      throw new Error('Validation observations are unavailable');
    },
  } = {},
) {
  diagnostics.hit = false;
  diagnostics.reason = 'missing-attestation';
  try {
    const envelope = JSON.parse(
      readFileSync(join(directory, 'attestation.json'), 'utf8'),
    );
    const payload = envelope.payload;
    diagnostics.reason = 'invalid-envelope';
    assert.ok(
      payload.schemaVersion === 1 &&
        payload.phase === phase &&
        /^[a-f0-9]{40}$/u.test(payload.sourceSha) &&
        /^\d+$/u.test(String(envelope.checkId)),
    );
    diagnostics.reason = 'executor-changed';
    assert.equal(payload.executorRevision, environment.GITHUB_SHA);
    diagnostics.reason = 'channel-changed';
    assert.equal(payload.branch, snapshot.branch);
    diagnostics.reason = 'manifest-mismatch';
    assert.deepEqual(payload.manifest, evidenceManifest(directory));
    diagnostics.reason = 'check-read-failed';
    const check = await api(`/check-runs/${envelope.checkId}`);
    diagnostics.reason = 'untrusted-app-check';
    assert.ok(
      check.app?.id === 5497722 &&
        check.name === evidenceName &&
        check.status === 'completed' &&
        check.conclusion === 'success' &&
        check.head_sha === payload.sourceSha &&
        check.external_id ===
          `sandboxpi:${payload.requestId}:evidence:${phase}` &&
        check.details_url ===
          `https://github.com/BANG404/sandboxpi-actions/actions/runs/${payload.runId}` &&
        check.output?.summary === proofSummary(payload),
      'Unauthenticated validation cache',
    );
    diagnostics.reason = 'non-ancestor-or-missing-history';
    const commits = await ancestors(payload.sourceSha, snapshot.candidate);
    diagnostics.reason = 'unbounded-history';
    assert.ok(
      Array.isArray(commits) && commits.length <= 100,
      'Unbounded validation delta',
    );
    const identity = phase === 'quality' ? 'quality' : 'gates';
    const observed = Date.parse(check.completed_at);
    diagnostics.reason = 'invalid-check-time';
    assert.ok(Number.isFinite(observed));
    // Include the previous head itself to observe later retries of that SHA.
    for (const commit of [...new Set([payload.sourceSha, ...commits])]) {
      diagnostics.reason = 'history-read-failed';
      const runs = await checks(commit);
      for (const current of runs) {
        if (current.app?.id !== 5497722) continue;
        const match = /^sandboxpi:([^:]+):(quality|gates)$/u.exec(
          current.external_id ?? '',
        );
        if (
          !match ||
          match[2] !== identity ||
          [payload.requestId, snapshot.requestId].includes(match[1])
        )
          continue;
        const time = Math.max(
          Date.parse(current.started_at) || 0,
          Date.parse(current.completed_at) || 0,
        );
        diagnostics.reason = 'newer-unrepresented-attempt';
        assert.ok(
          time <= observed,
          'A newer validation attempt is absent from this cache',
        );
      }
    }
    diagnostics.hit = true;
    diagnostics.reason = 'authenticated';
    return true;
  } catch {
    // A dependency cache is not authoritative proof. Discard only evidence and
    // execute the real tests whenever authentication/history is unavailable.
    rmSync(directory, { recursive: true, force: true });
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    return false;
  }
}
export async function attestEvidence(
  directory,
  { api, environment, snapshot, phase } = {},
) {
  const manifest = evidenceManifest(directory);
  if (!manifest.length) return;
  assert.match(environment.GITHUB_SHA || '', /^[a-f0-9]{40}$/u);
  const payload = {
    schemaVersion: 1,
    phase,
    branch: snapshot.branch,
    sourceSha: snapshot.sha,
    sourceCandidate: snapshot.candidate,
    requestId: snapshot.requestId,
    executorRevision: environment.GITHUB_SHA,
    runId: environment.GITHUB_RUN_ID,
    runAttempt: environment.GITHUB_RUN_ATTEMPT,
    manifest,
  };
  const check = await api('/check-runs', 'POST', {
    name: evidenceName,
    head_sha: snapshot.sha,
    external_id: `sandboxpi:${snapshot.requestId}:evidence:${phase}`,
    details_url: `https://github.com/BANG404/sandboxpi-actions/actions/runs/${environment.GITHUB_RUN_ID}`,
    status: 'completed',
    conclusion: 'success',
    output: {
      title: 'Authenticated per-unit results and original provenance',
      summary: proofSummary(payload),
    },
  });
  assert.ok(/^\d+$/u.test(String(check.id)));
  writeFileSync(
    join(directory, 'attestation.json'),
    JSON.stringify({ payload, checkId: check.id }),
    { mode: 0o600 },
  );
  return { payload, checkId: check.id };
}
