# CodeRiskTools Observatory Reports

Public Reports repository for CodeRiskTools Observatory, operated in **solo-maintainer** mode.

## Current state

- Security/workflow baseline: independently audited GitHub-next v0.1.2.
- Weekly-next candidate: v0.2.0 Named Weekly OSS Review, local implementation pending adversarial audit and remote promotion.
- Named weekly pages intentionally publish exactly three reviewed project names, official GitHub links and SPDX licenses for editorial discovery; technical findings and exact results remain private.
- Exact local source-inventory manifest: `0b5e5dd21533c8ef0c69345b0dc75455b94716ac50162369e431aff898d3cb33` (the remote repository is a deployment projection, not that inventory).
- Synthetic publication set: deployed from PR #1.
- Real reports published: **none**.
- Public-tree manifest: `e1ac3f4260a5b76751c555ac76ea2e9307c5fa69cf0ccef9ebc63a79903fa78b`.
- Pages: https://9batalion.github.io/coderisktools-observatory-reports/

## Solo-maintainer control model

Human approval by a second account is not required. Separation is enforced technically:

- every report payload enters through a PR;
- report PRs may change only `public/` and `operator/`;
- strict required check `validate` is bound to GitHub Actions App ID `15368`;
- PR verification executes the verifier from the exact protected base SHA against a separate candidate checkout;
- `main` rejects force pushes and deletion and includes administrators in protection;
- `operator/` is validated by CI but never uploaded to Pages;
- deploy runs only from protected `main`;
- OIDC provenance attests the exact complete public-tree manifest before artifact upload and Pages deployment;
- all GitHub Actions are pinned to full commit SHAs;
- workflow permissions default to read and workflows cannot approve pull requests.

A report is public only after PR merge, successful protected workflow execution, OIDC attestation, and public Pages read-back. The current deployment contains synthetic evidence only.
