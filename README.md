# py3-bio
[![Build and Push Docker Image](https://github.com/broadinstitute/py3-bio/actions/workflows/docker-build.yml/badge.svg)](https://github.com/broadinstitute/py3-bio/actions/workflows/docker-build.yml)
[![Quay.io](https://img.shields.io/badge/quay.io-py3--bio-blue)](https://quay.io/repository/broadinstitute/py3-bio?tab=tags&tag=latest)

This builds a docker container with just Python3 and commonly used bioinformatic Python packages, including biopython, pysam, dash/pandas/numpy/scipy, etc (see requirements.txt for full list).

## Responding to a failed vulnerability scan

A daily scheduled workflow (09:00 UTC) runs Trivy against the **published**
`quay.io/broadinstitute/py3-bio:latest`. It does not rebuild first. So a red scan almost
always means Debian shipped a security update and the published image has drifted behind
it — not that anything in this repo is wrong.

**To fix it:** Actions → *Build and Push Docker Image* → *Run workflow* → select branch
**`main`** → check `force_rebuild` → *Run workflow*. That rebuilds with `--no-cache`, pushes
a fresh `latest`, and rescans it.

> Dispatch only from `main`. On any other branch nothing is pushed, but the scan job still
> runs and fails when it tries to pull the tag.

### Automated response (`cve-autofix.yml`)

When a scan of `latest` fails on `main`, `docker-build.yml` hands off to `cve-autofix.yml`:

1. **Scheduled or push scan fails:** it dispatches the `force_rebuild` described above,
   without a human. That alone clears most findings.
2. **The scan is still red after that rebuild:** it hands the findings to Claude
   (Sonnet 5.5 on Vertex AI). Claude files one `cve`-labeled issue per new CVE, then decides
   whether *every* open `cve` issue can be closed by one PR that only edits
   `requirements.txt` and/or `.trivyignore.yaml`. If it can, it opens that PR (labeled
   `cve-fix`). If not, it uploads a `cve-fix-decision-log` artifact explaining why. A
   maintainer comment on a `cve` issue steers the next run.

Step 2 needs credentials. Until they exist it logs a warning and skips. The credentials are:

- secrets `AUTOFIX_APP_ID` and `AUTOFIX_APP_PRIVATE_KEY`, for a GitHub App installed on this
  repo with Contents, Pull requests and Issues read/write. App-authored pushes trigger the
  required `build`/`scan` checks; `GITHUB_TOKEN` pushes would not.
- repo variables `GCP_WIP_PROVIDER`, `GCP_SA_EMAIL` and `GCP_PROJECT_ID`, for a service
  account with Vertex AI access through Workload Identity Federation.

To test step 2 without waiting for a real failure, dispatch *CVE Auto-fix* directly with
`test_cve_id` set, plus `dry_run` (no issues filed) or `skip_fix_pr`.

### Do not "fix" a CVE by editing the Dockerfile apt line

`apt-get upgrade -y` already upgrades *every* installed package. The package names listed on
that line are documentation — adding one does not cause it to be upgraded. Earlier
"Upgrade X to patch CVE-Y" commits appeared to work only because editing the line changed the
`RUN` string and invalidated the cached apt layer, which forced apt to re-resolve against a
fresh index. Use `force_rebuild` instead; it does the same thing honestly and leaves no
misleading diff.

### Triaging a finding that a rebuild does not clear

`ignore-unfixed: true` is set, so anything reported already has a fix available upstream. If a
rebuild does not clear it, the finding is either genuinely applicable or genuinely
inapplicable — decide which, then:

| Situation | Where it goes |
|---|---|
| Class-level architectural mitigation (true for every CVE of this shape, now and later) | `.trivy-ignore-policy.rego` — add a documented section |
| One-off false positive (e.g. an SBOM misattribution) | `.trivyignore.yaml` — with `expired_at` and a `statement` |

Both files are applied by the workflow's Trivy steps. To test a change locally without
waiting for CI (`trivy` reads the registry directly, no Docker daemon needed):

```bash
trivy image --ignore-policy .trivy-ignore-policy.rego --ignorefile .trivyignore.yaml \
            --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 \
            quay.io/broadinstitute/py3-bio:latest
```

### Image tags

`latest` tracks `main` and is republished on every merge and every `force_rebuild`. The
`0.1.x` tags are immutable — pin those if you need reproducibility.
