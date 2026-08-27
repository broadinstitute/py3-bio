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
