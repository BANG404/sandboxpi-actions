# sandboxpi public executor

Only this reviewed bootstrap may be copied to `BANG404/sandboxpi-actions`.
Never copy private source, skills, environment files, generated reports or caches.
The private source repository remains `BANG404/sandboxpi`. Requests use ordinary
public Ubuntu 24.04 hosted jobs; no service deployment occurs here.

`runner.yml` is main-only and accepts `ci`, `pr`, `validate`, and `publish`.
`source_sha` is an exact lowercase 40-character commit SHA; `source_branch` is
alpha/beta/rc/main (default main). `source_pr` is optional for `ci` and required
for `pr`. `run_gates` defaults false; `pr` always enables every gate. Optional
`request_id` is a UUID; legacy calls correlate by public run ID and attempt.
Existing two-input main CI and matching source_branch/channel image calls work.
Image channels remain alpha -> alpha, beta -> beta, rc -> rc, main -> production.

Server validation occurs before checkout, before each phase, after execution,
and before callback success. Channel requests require source ancestry. PRs must
be open in the same repository, target the selected channel, have the exact head
and current base, and have a write/maintain/admin author. The sole bot exception is GitHub Actions
(login `github-actions[bot]`, ID `41898282`, type `Bot`) promoting adjacent
protected channels with exact current source and base SHAs. Other bots, forks,
feature heads, stale source heads and skipped/reverse stages are rejected. Forks are rejected.
Only GitHub's merge ref is fetched and its exact merge SHA executed after its
parents are verified as current base and requested head. Changed head, base,
merge candidate, permissions or PR state invalidates PR success. Channel CI
continues to accept an exact immutable ancestor after its channel advances. Private source
workflow files are never executed as Actions workflows.

The `runner` job runs frozen install and the complete `bun run verify`. In
parallel, a fail-fast-disabled matrix runs all seven substantive existing gates:
boundary, coverage, api, integration, security, mutation and risk. Boundary also
runs gate-runner and release-workflow regressions. Integration uses disposable
local Docker fixtures; security retains locked SCA, offline SAST and its positive
controls; mutation and isolated performance/DAST run on every requested matrix.
No source job runs on a persistent trusted host or receives service credentials.

The trusted `scripts/runtime.mjs` owns checkout, stdout/stderr capture, storage
and report export. It never imports or runs the source `public-runner.mjs`.
Every private child, including dependency installation, scanners and image
commands, writes only to the private log. Public messages contain fixed phase,
result and report identifiers. Trusted bootstrap failures and API status details
are recorded only in the private report, preserving failed validation status.
Read-only API/privacy requests close connections and retry transient network or
429/5xx failures at most three times; ambiguous callback/dispatch writes never
retry. This avoids stale pooled connections after synchronous source commands. Source environments use an allowlist without
checkout/package tokens, GitHub/Actions command-file variables, injected runtime
options or release secrets. Image release credentials enter only the final
post-quality image command. This is an ephemeral hosted execution boundary for
trusted source authors, not an absolute defense against deliberate exfiltration
by an authorized writer with arbitrary code execution.

Keep `CI_APP_ID=5497722` and `CI_APP_PRIVATE_KEY` in the existing protected
`release` environment. Source-only jobs reference only this App key to mint
sandboxpi-only contents-read/PR-read tokens (checks-write only for callbacks).
Unused environment secrets do not enter source processes. Only the post-quality
image job references a contents-write release token, SKILL_SOURCES_TOKEN,
ACR/Woodpecker settings and publish-only CAM secrets.
Keep these credentials outside Git. Image publication/activation retains the
private source's runtime, zero-finding Trivy, ACR and Tencent transfer contracts.

The App creates **Public quality checks**, plus **Public PR test gates** when
requested, on the exact source/PR head. External IDs are
`sandboxpi:<request_id>:quality` and `sandboxpi:<request_id>:gates`.
Image actions additionally retain **Public CD validate/publish**. Finalization
runs with `always()`, uses actual job results, and rejects failed, cancelled,
skipped or missing required jobs. Dispatch acknowledgment never proves quality.
An unavailable callback API leaves required evidence incomplete, never green.
Root must verify actual callbacks and privacy before migrating private rules.

Project data never enters public Actions artifacts, caches or summaries. Private
GHCR `sandboxpi-ci-data` stores independent `deps-PHASE-v3` quality/gate caches
(image retains v2) and
`report-RUN-ATTEMPT-PHASE` reports. PHASE is quality, image or gate-NAME.
Image Buildx uses local mode=max runtime/AGS caches inside its private phase
bundle, so package-write credentials stay outside the source environment.
Every project export requires authenticated `privacy-seed` inspection and
anonymous GHCR token denial (401/403); source execution is blocked if the initial
privacy check fails. Cache-restore failure preserves the existing remote cache.
The storage initializer and existing `sandboxpi-build-cache` seed remain intact.
Reports retain full command logs, build identity, coverage/LCOV, mutation,
SAST/SCA and DAST/performance output, including after failed commands.

`Read private report` accepts legacy RUN-ATTEMPT and the new phase-suffixed keys,
then encrypts the payload to the operator's RSA public key. Plaintext private
logs never appear in public output. Root owns live public bootstrap updates,
package visibility/access setup, callback/privacy acceptance and private policy
migration. Local tests do not establish those live results.

Run `node --test deploy/github/public/scripts/*.test.mjs`, `bun run test:actions`,
`bash -n deploy/github/public/scripts/install-trivy.sh`, and
`bun fmt --check` on changed files from the private development checkout.

`Discover private PR validation` accepts on-demand requests from the trusted
host PR timer; its public 15-minute schedule is a backup. This works independently
of private default-main `pull_request_target` registration. It validates
open same-repository writer PRs, exact merge/base/head metadata and existing
current-base evidence before submitting once per input. Queued markers never
pass gates; finalization completes them from actual results. Recent PRs leave
two minutes for on-demand host or enabled private dispatchers. PR cache keys are isolated
from protected-channel cache exports.

## Executor policy review

The `.github/CODEOWNERS` file assigns every executor file to BANG404. Protect
`main` with required PRs, Code Owner review, stale-approval dismissal, resolved
threads, merge commits, no deletion/force pushes and no bypass actors. Keep the
`release` environment restricted to `main`. Ownership applies only after the
file exists on the PR target; the initial ownership PR bootstraps that policy.
A PR author cannot approve their own PR. Never bypass review for executor updates.

## Private security summaries

Ordinary quality requests without a full matrix also execute the security gate.
Full matrices reuse their independent gate-security job. After private report
export, the trusted runtime publishes a bounded `Security scan summary` Check
through App 5497722 to the private source repository. Only fixed scanner IDs,
completion states and numeric severity counts are published; no source paths,
matched secrets or raw diagnostics enter public output. Source processes never
receive the check-write credential. Missing enhanced reports fail new source
phases; older revisions without the scanner entrypoint retain legacy gates and
have no enhanced summary. Existing required quality and test callbacks remain
authoritative. The private operator collector validates exact source evidence
before feeding the Grafana security dashboard. Monitoring failure never grants
merge permission.
