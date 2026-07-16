# Controlled security-pack bootstrap — v0.2.0

## Why this is out-of-band once

Protected `main` currently trusts GitHub-next v0.1.2. That trusted base intentionally permits report PR changes only under `public/` and `operator/`; it does not contain the weekly verifier scripts. Therefore v0.2.0 cannot truthfully validate itself through the report-only gate. Treating candidate scripts as trusted would be circular.

This document defines a one-time, controlled administrative bootstrap. It never grants a report workflow permission to update its own verifier.

## Frozen scope

The bootstrap may change only the exact allowlist encoded in `scripts/verify_security_pack_upgrade.py`. In particular:

- `public/` must be byte-identical to protected base;
- `operator/` must be byte-identical to protected base;
- no existing file may be deleted;
- no engine, trial evidence, target-source identifier or credential may enter the Reports repository;
- candidate version is exactly `0.2.0` with `remote_promoted=false` before merge.

## Mandatory preconditions

1. Record exact protected remote `main` SHA and clone it into a clean base directory.
2. Verify there are zero open pull requests and no concurrent administrative operation.
3. Freeze the candidate and its complete source-inventory digest.
4. Run:
   - `python3 scripts/verify_security_pack_upgrade.py --base <base> --candidate <candidate> --run-tests`;
   - normal and `python -O` suites;
   - deterministic builder comparison;
   - independent read-only audit requiring `PASS B0/H0/M0`.
5. Create branch `security-pack/v0.2.0` containing one exact reviewed commit and open one administrative PR.
6. Re-fetch the PR head and prove it equals the frozen reviewed commit. Do not use a mutable local branch as evidence.

## Controlled merge window

The existing required `validate` check will fail by design because v0.1.2 rejects self-modification. For this single bootstrap:

1. Keep required PR, linear history, enforce-admins, conversation resolution, no-force-push and no-deletion controls enabled.
2. Temporarily remove only the required status-check entry after all preconditions pass and the exact PR head is frozen.
3. Merge only the frozen `security-pack/v0.2.0` PR by expected head OID.
4. Immediately restore strict required check `validate` bound to GitHub Actions App ID `15368`.
5. If merge or restoration fails, stop all publication work and restore branch protection before any other action.
6. Verify branch protection by authenticated read-back and confirm zero unexpected open PRs.

The window is not a normal publication route and must not be reused for weekly report payloads.

## Post-bootstrap proof

Before real weekly publication:

1. Open a synthetic weekly rehearsal PR with exact neutral metadata and six allowed payload paths.
2. Confirm the verifier is loaded from exact v0.2.0 protected base.
3. Require strict `validate` PASS.
4. Confirm backfill, historical mutation, mixed payload and metadata-channel negative probes fail.
5. Merge or close the rehearsal according to whether synthetic content is intended to remain public.
6. Verify Pages excludes `operator/` and attests only the sanitized Reports `public/SHA256SUMS.txt`.

OIDC provenance may identify the public Reports repository and sanitized publication commit. It must never attest target-source archives, target commits or private trial evidence.
