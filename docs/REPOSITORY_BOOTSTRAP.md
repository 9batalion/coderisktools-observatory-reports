# Reports repository bootstrap — applied in solo-maintainer mode

Target: `9batalion/coderisktools-observatory-reports`.

## Applied controls

1. Separate public Reports repository; scanner/firewall engine access is not granted.
2. Audited workflow/governance pack bootstrapped to `main` through an administrator-controlled initial commit.
3. GitHub Pages source is GitHub Actions.
4. `main` requires a PR and strict `validate` check bound to GitHub Actions App ID `15368`.
5. Human approval and a second account are intentionally not required in this solo-maintainer project.
6. Administrators remain subject to branch protection; force pushes and branch deletion are disabled.
7. The `github-pages` environment accepts only protected branches and has `can_admins_bypass=false`; no human deployment reviewer is required.
8. Report PRs may modify only `public/` and `operator/`. Workflow/verifier/governance upgrades use a separately controlled administrative maintenance process.
9. The synthetic PR passed trusted-base verification, changed-path validation, manifest attestation, Pages deployment, full 20-file public read-back, and `operator/` exclusion.
10. Real reports remain opt-in and are not part of the synthetic bootstrap.

## Current evidence

- Synthetic PR: `#1`.
- Merge commit: `2a406aeb2585eed8d65ad949b0fcf664980c1294`.
- Deploy run: `29511311554`.
- Public manifest: `e1ac3f4260a5b76751c555ac76ea2e9307c5fa69cf0ccef9ebc63a79903fa78b`.
- Public files: 20/20 verified.
- `operator/pr-request.json` public read-back: HTTP 404.
- Real reports: none.
