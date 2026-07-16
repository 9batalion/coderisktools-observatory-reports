# Remote publication handoff contract

A report PR contains two top-level payloads:

- `public/` — the only Pages upload root;
- `operator/` — approval/retraction evidence used by CI and excluded from Pages.

Required operator shape:

```text
operator/
  pr-request.json
  approval-records/<raw-approval-json-sha256>.json
  retraction-records/<raw-retraction-json-sha256>.json  # only for withdrawn items
```

Each record filename must equal SHA-256 of its exact raw bytes. The request must reference that digest. CI recomputes the raw digest and all semantic bindings.

For publication-next v0.3.1 evidence (whose publication bytes are unchanged from v0.3.0), the remote handoff combines:

- `build-one/public/`;
- `build-one/operator/pr-request.json`;
- each input package's raw `approval.json` under `operator/approval-records/`;
- each withdrawal's raw `retraction.json` under `operator/retraction-records/`.

The integration verifier accepts the resulting three-item/one-retraction handoff with exact public manifest `e1ac3f4260a5b76751c555ac76ea2e9307c5fa69cf0ccef9ebc63a79903fa78b`.

Authorization is solo-maintainer PR + trusted-base CI gating, not a second-person signature and not a signature by the local publisher. After merge, GitHub OIDC attests the exact complete public manifest before Pages deployment. Verification is available through the repository Attestations view or:

```bash
gh attestation verify SHA256SUMS.txt \
  --repo 9batalion/coderisktools-observatory-reports \
  --signer-workflow 9batalion/coderisktools-observatory-reports/.github/workflows/deploy-pages.yml \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners
```
