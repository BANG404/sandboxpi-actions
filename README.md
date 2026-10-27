# sandboxpi public runners

This repository contains only the reviewed runner workflow and status reporter. It does not contain the private project source, build outputs, full logs, or project caches.

Trusted manual requests select an exact ancestor of the private `BANG404/sandboxpi` main branch. A repository-scoped GitHub App grants short-lived checkout/check tokens, and grants a separate release token only after all quality checks pass. No pull request or fork event runs with these credentials.

Standard GitHub-hosted Ubuntu runners execute formatting, type checking, lint, unit/HTTP/Pi fixture/workflow/Go checks, compilation, and optional image runtime verification and security scans. Public logs show stages and results. Full logs/reports, dependency caches, and Buildx registry caches are private GHCR packages. Verified release images pass through private ACR to the Tencent-only Woodpecker transfer step.

GitHub-hosted compute billing belongs to this public workflow. Standard public runners are free; ordinary service limits still apply. Private cache/package storage has its own policies and access control. Full source and operator documentation remain in the private repository.
