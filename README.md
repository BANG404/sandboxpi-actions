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
and current base, and have a write/maintain/admin author. Forks are rejected.
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
result and report identifiers. Source environments use an allowlist without
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
GHCR `sandboxpi-ci-data` stores independent `deps-PHASE-v2` caches and
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

`Discover private PR validation` is a public-only 15-minute fallback for channel
branches whose older base workflow lacks the immediate dispatcher. It validates
open same-repository writer PRs, exact merge/base/head metadata and existing
current-base evidence before submitting once per input. Queued markers never
pass gates; finalization completes them from actual results. Recent PRs leave
two minutes for the immediate private dispatcher. PR cache keys are isolated
from protected-channel cache exports.
