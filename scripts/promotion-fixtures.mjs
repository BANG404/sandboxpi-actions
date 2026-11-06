// Shared security cases for private routing and the separately deployed bootstrap.
import assert from 'node:assert/strict';

export const rejectedPromotionPairs = [
  ['alpha', 'rc'],
  ['alpha', 'main'],
  ['beta', 'main'],
  ['beta', 'alpha'],
  ['rc', 'beta'],
  ['main', 'rc'],
  ['feature', 'beta'],
];

export function promotionFixture(source = 'alpha', target = 'beta') {
  const sha = 'a'.repeat(40),
    base = 'b'.repeat(40),
    merge = 'c'.repeat(40);
  const values = {
    pull: {
      number: 37,
      state: 'open',
      user: { login: 'github-actions[bot]', id: 41898282, type: 'Bot' },
      head: {
        sha,
        ref: source,
        repo: { full_name: 'BANG404/sandboxpi', fork: false },
      },
      base: {
        sha: base,
        ref: target,
        repo: { full_name: 'BANG404/sandboxpi' },
      },
      mergeable: true,
      merge_commit_sha: merge,
    },
    target: { protected: true, commit: { sha: base } },
    source: { protected: true, commit: { sha } },
    ref: { object: { type: 'commit', sha: merge } },
    commit: { sha: merge, parents: [{ sha: base }, { sha }] },
    permission: { permission: 'none' },
  };
  const calls = [];
  const api = async (path) => {
    path = path.replace(/^\//u, '');
    calls.push(path);
    const key = {
      'pulls/37': 'pull',
      [`branches/${target}`]: 'target',
      [`branches/${source}`]: 'source',
      'git/ref/pull/37/merge': 'ref',
      [`git/commits/${merge}`]: 'commit',
    }[path];
    if (path === `git/ref/heads/${target}`)
      return { object: { sha: values.target.commit?.sha } };
    if (path.startsWith('collaborators/')) return values.permission;
    assert.ok(key, `Unexpected promotion fixture API: ${path}`);
    return structuredClone(values[key]);
  };
  return {
    values,
    calls,
    api,
    input: {
      action: 'pr',
      branch: target,
      sha,
      pr: '37',
      runGates: true,
      requestId: '4a245183-1234-4567-8abc-123456789012',
    },
  };
}

export const promotionRejections = [
  ['other bot', (v) => (v.pull.user.login = 'dependabot[bot]')],
  ['similar login', (v) => (v.pull.user.login = 'github-actions-bot')],
  ['login case', (v) => (v.pull.user.login = 'GitHub-Actions[bot]')],
  ['wrong ID', (v) => (v.pull.user.id = 1)],
  ['string ID', (v) => (v.pull.user.id = '41898282')],
  ['missing ID', (v) => delete v.pull.user.id],
  ['wrong type', (v) => (v.pull.user.type = 'User')],
  ['missing type', (v) => delete v.pull.user.type],
  ['unknown author', (v) => (v.pull.user = {})],
  ['read-only user', (v) => (v.pull.user = { login: 'reader', type: 'User' })],
  [
    'other bot with writer permission',
    (v) => {
      v.pull.user = { login: 'automation', id: 123, type: 'Bot' };
      v.permission.permission = 'write';
    },
  ],
  ['feature source', (v) => (v.pull.head.ref = 'feature')],
  ['missing source', (v) => delete v.pull.head.ref],
  ['skipped channel', (v) => (v.pull.base.ref = 'rc')],
  [
    'reverse channel',
    (v) => {
      v.pull.head.ref = 'rc';
      v.pull.base.ref = 'beta';
    },
  ],
  ['alpha target', (v) => (v.pull.base.ref = 'alpha')],
  ['same channel', (v) => (v.pull.head.ref = 'beta')],
  ['stale source', (v) => (v.source.commit.sha = 'd'.repeat(40))],
  ['unprotected source', (v) => (v.source.protected = false)],
  ['missing source protection', (v) => delete v.source.protected],
  ['unprotected target', (v) => (v.target.protected = false)],
  ['missing target protection', (v) => delete v.target.protected],
  ['fork', (v) => (v.pull.head.repo.fork = true)],
  ['missing fork flag', (v) => delete v.pull.head.repo.fork],
  ['different source repo', (v) => (v.pull.head.repo.full_name = 'fork/repo')],
  ['different target repo', (v) => (v.pull.base.repo.full_name = 'fork/repo')],
  ['closed PR', (v) => (v.pull.state = 'closed')],
  ['stale target', (v) => (v.target.commit.sha = 'd'.repeat(40))],
];
