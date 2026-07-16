# Reports repository bootstrap — not applied

Perform only after explicit authorization and replacement of all placeholders.

1. Create a separate public Reports repository. Do not grant its publisher App access to the scanner/firewall repository.
2. Commit this workflow/governance pack to `main` through an administrator-controlled bootstrap.
3. Replace placeholder CODEOWNERS teams with real reviewer teams.
4. Enable GitHub Pages with source `GitHub Actions`.
5. Protect `main`:
   - PR required;
   - at least one approval;
   - code-owner review;
   - stale-review dismissal;
   - strict `validate` check;
   - admins included;
   - no force pushes or deletion.
6. Protect environment `github-pages` with at least one reviewer and prevent self-review.
7. Install a dedicated publisher App/machine identity with the minimum ability to create report branches/PRs, no direct-main push and no engine-repository installation.
8. Keep workflow/verifier/governance changes outside report PRs. The report changed-path gate intentionally rejects them; security-pack upgrades require a separately authorized administrator process.
9. Run one synthetic PR and verify: trusted-base verifier, changed-path gate, no operator files in Pages artifact, manifest attestation before deployment, and Pages URL readback.
10. Only then consider one explicitly opt-in real report.

Current state is `NOT_APPLIED`. No remote target, team or identity has been selected.
