# Popularity cohort scan coverage v1

## Purpose

This page publishes a deterministic cohort ordered by the GitHub `stargazers_count` snapshot. It is a coverage index for the local Observatory trial, not a security ranking.

## Public paths

- immutable: `public/rankings/YYYY-Www/report.json`
- immutable: `public/rankings/YYYY-Www/index.html`
- derived: `public/rankings/index.json`
- derived: `public/rankings/latest.json`

## Contract

`report.json` uses `coderisktools.observatory.popularity-ranking.v1` and contains exactly 15 entries. Each entry binds:

- canonical GitHub repository identity;
- official URL;
- full target head SHA;
- stars snapshot value and rank;
- license value when recognized;
- bounded scan status: `complete` or `partial`;
- fixed `NOT_PUBLISHED` publication status.

The list is sorted by stars descending. Equal-star ties must be resolved by repository name ascending in the producer and remain stable in the published order.

## Provenance and boundary

The contract binds Scanner `3.0.1`, the exact scanner source commit, and the canonical ruleset digest. It explicitly states:

- `security_ranking=false`;
- raw findings are not published;
- Firewall results are not published;
- partial/failed scans are not interpreted as clean or vulnerable.

No score, grade, category, severity, finding count, rule ID, path, line, snippet, matched text, secret, or security conclusion is public. The current contract is intentionally a cohort/coverage publication until calibration, Firewall integration, and methodology approval exist.

## Lifecycle

A ranking binding is appended in a `pr-request.v5` operator request on branch `ranking/YYYY-Www`. The trusted verifier checks canonical JSON, deterministic HTML, exact digests, full target SHAs, sorted ranks, closed fields, and the complete public tree manifest. Pages deploys remain main-only after protected CI and OIDC manifest attestation.
