# Named Weekly OSS Review v1

## Purpose

Publish an immutable weekly editorial index naming exactly three popular public OSS repositories reviewed by CodeRiskTools. Project names and official links are public for discovery and SEO. Technical findings and exact project-level results remain outside this publication channel.

## Public paths

- immutable: `public/weekly/YYYY-Www/report.json`
- immutable: `public/weekly/YYYY-Www/index.html`
- derived mutable index: `public/weekly/index.json`
- derived mutable pointer: `public/weekly/latest.json`

No weekly archive, Markdown, badge, raw evidence, source snapshot, operator record, target commit, target digest, finding count, severity distribution, rule ID, path, line, snippet, matched value or credential-like value is public.

## Closed report

`report.json` uses schema `coderisktools.observatory.named-weekly-review.v1` and exact closed fields:

- ISO week plus exact Monday/Sunday period;
- exactly three projects, unique and canonically sorted;
- canonical `owner/repository` name;
- official URL derived exactly as `https://github.com/owner/repository`;
- recognized SPDX license and fixed `REVIEW_COMPLETED` status;
- allowlisted Scanner and Firewall versions;
- fixed isolation truth: worker network `NONE`, target code not executed;
- fixed publication boundary: project names published for editorial indexing; technical findings and exact results not published; no project-level conclusion;
- fixed result `NAMED_PROJECT_REVIEWS_COMPLETED_NO_PROJECT_LEVEL_SECURITY_CONCLUSION`;
- exact fixed limitations.

Arbitrary prose and per-project result fields are forbidden. A report is not emitted unless exactly three unique completed private trial inputs pass builder eligibility.

## Public attribution and disclosure boundary

Public JSON and deterministic HTML intentionally include:

- project `owner/repository` names;
- official GitHub repository links;
- SPDX license;
- neutral review-completion status.

They must not include:

- target commit, tree or archive identity;
- private-evidence digest;
- finding, rejection, severity or per-project counts;
- rule IDs, categories, paths, lines, snippets, matched text or secrets;
- maintainer identity, private correspondence, issue details or a new vulnerability claim;
- exploit instructions or uncoordinated disclosure details;
- project logos or endorsement language.

The required near-content disclaimer is:

> Inclusion means only that the named public repository was processed by the stated review workflow. It does not indicate a vulnerability, endorsement, certification, ranking, accusation, or guarantee of security.

Newly discovered critical signals stay private until confirmation and coordinated disclosure. Public CVE/GHSA-based signals and the future posture index require a separate versioned contract and independent audit.

## Deterministic SEO rendering

- The HTML title and H1 are deterministically generated from the three canonical project names.
- The meta description is deterministic and states that no project-level vulnerability conclusion or technical findings are published.
- Each project name is a nominative text link to its exact official GitHub URL.
- There are no arbitrary metadata fields, comments, scripts or external active resources.
- Weekly pages are the initial canonical editorial history. Future `/projects/owner/repository/` projections must derive from verified history, not hand-written claims.

## History and binding

- Existing week directories are immutable after merge.
- Weeks are unique and strictly ordered in derived `index.json`.
- `latest.json` exactly equals the newest index entry.
- `pr-request.v4` binds each weekly JSON and HTML SHA-256.
- The complete public manifest binds every byte.
- Deterministic exact HTML is rendered solely from the closed JSON.
- Trusted-base CI rejects mutation/deletion of an existing week and backfill before the newest week.
- Weekly PRs change exactly six bound paths and cannot mix project-report payloads.
- PR title, body and head ref remain neutral and fixed. The one raw commit has the exact base parent, fixed identity/time/message, no extra headers/signature/body, and all changed blobs use mode `100644`.
- PR labels, assignees, reviewers, teams and milestone remain exact-empty.
- Historical publication items, retractions and attestation fields are preserved; weekly history is one exact append.
- OIDC provenance attests the sanitized `public/SHA256SUMS.txt` before Pages upload.

## Private builder boundary

Private trial inputs remain owner-controlled mode 0700/0600 outside the Reports repository. The builder validates exactly three unique completed project trials, popularity eligibility, SPDX licenses, worker network none, target code not executed, and one common allowlisted engine pair. It copies only project name and SPDX license into the closed public project objects and derives each official URL. Popularity count and all technical trial evidence remain private.

The source Reports repository is copied from immutable Git `HEAD` blob objects, not mutable worktree bytes. The source must be clean before and after the snapshot.

## Interpretation

A named weekly review proves only that the listed public repositories completed the stated non-executing review workflow during the stated week. It is not a vulnerability report, comparative ranking, certification, endorsement or security guarantee.
