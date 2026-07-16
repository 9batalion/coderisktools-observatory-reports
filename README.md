# CodeRiskTools Observatory Reports

Public Reports repository bootstrap for CodeRiskTools Observatory.

## Current state

- Security/workflow pack: bootstrapped from independently audited GitHub-next v0.1.2.
- Exact local candidate manifest: `0b5e5dd21533c8ef0c69345b0dc75455b94716ac50162369e431aff898d3cb33` (41-file source inventory; this remote layout is a deployment projection, not that inventory).
- Real reports published: **none**.
- Synthetic report candidate: must enter through a reviewer-gated PR.
- Pages deployment and OIDC attestation: **not yet performed**.
- Remote governance: applied only where confirmed through GitHub API; see `governance/repository-policy.json` and repository settings.

## Trust boundaries

- Report PRs may change only `public/` and `operator/`.
- PR verification executes the verifier from the exact protected base SHA against a separate candidate checkout.
- `operator/` is validated by CI and never uploaded to Pages.
- Pages deploy is main-push-only, protected by the `github-pages` environment, and attests the exact public-tree manifest before upload/deploy.
- All GitHub Actions are pinned to full commit SHAs.

No report should be treated as public until its PR is independently reviewed and merged and the protected deployment completes.
