#!/usr/bin/env python3
"""Answer "can this CVE be fixed, and how?" for each finding, before Claude runs.

Every finding cve-autofix.yml hands to Claude has already survived a no-cache
rebuild (or is being analyzed in a test dispatch). For a py3-bio image that rebuild
already runs `apt-get upgrade -y` and resolves every `>=` floor in requirements.txt
against current PyPI, so a surviving finding has one of a small number of causes.
This script tells them apart deterministically, so the answer is identical run to
run and costs the agent no turns:

  debian      Does the apt index the image sees offer the fixed version yet?
              If not, Debian has not shipped it to trixie(-security): wait, there
              is nothing to change in this repo.
  python-pkg  Does PyPI have the fixed version, which installed distributions
              constrain the package, and does any constraint exclude the fix?
              Is it a top-level requirement, a transitive one, or a vendored copy
              (e.g. inside pip/_vendor) that no requirements pin can reach?

Output is a JSON document with a `summary` list and per-finding detail. The script
is fail-soft per finding: anything it cannot check lands in `probe_errors` rather
than aborting, and the workflow treats a non-zero exit as a loud but non-fatal error.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

# Runs inside the image under test. Prints one JSON object: for each requested
# package, its installed version and every installed distribution that declares a
# requirement on it, with the specifier and whether that specifier admits each
# candidate fix version. Uses pip's vendored `packaging` so nothing extra is needed
# in the image.
IN_IMAGE_PY = r'''
import json, re, sys
from importlib import metadata
try:
    from pip._vendor.packaging.requirements import Requirement
    from pip._vendor.packaging.utils import canonicalize_name
    from pip._vendor.packaging.version import Version
except Exception as e:
    print(json.dumps({"error": "pip vendored packaging unavailable: %s" % e}))
    sys.exit(0)

query = json.loads(sys.stdin.read())  # {name: [fix_version, ...]}
wanted = {canonicalize_name(n): (n, fixes) for n, fixes in query.items()}
out = {canonicalize_name(n): {"installed": None, "required_by": []} for n in query}

for dist in metadata.distributions():
    dname = dist.metadata.get("Name") or ""
    cname = canonicalize_name(dname)
    if cname in out:
        out[cname]["installed"] = dist.version
    for raw in dist.requires or []:
        try:
            req = Requirement(raw)
        except Exception:
            continue
        rname = canonicalize_name(req.name)
        if rname not in wanted:
            continue
        # Skip requirements that only apply to an extra; they constrain nothing
        # unless the extra was requested, which pip does not record.
        if req.marker is not None and "extra" in str(req.marker):
            continue
        admits = {}
        for fv in wanted[rname][1]:
            try:
                admits[fv] = req.specifier.contains(Version(fv), prereleases=True)
            except Exception:
                admits[fv] = None
        out[rname]["required_by"].append({
            "dist": dname,
            "dist_version": dist.version,
            "specifier": str(req.specifier) or "(any)",
            "admits_fix": admits,
        })

print(json.dumps(out))
'''

# Runs inside the image as root. For each "pkg fixed_version" line on stdin, prints
# "pkg|installed|candidate|candidate_ge_fixed".
IN_IMAGE_SH = r'''
apt-get update -qq >/dev/null 2>&1 || echo "__APT_UPDATE_FAILED__"
while read -r pkg fixed; do
  [ -z "$pkg" ] && continue
  pol=$(apt-cache policy "$pkg" 2>/dev/null)
  inst=$(printf '%s\n' "$pol" | awk '/Installed:/ {print $2; exit}')
  cand=$(printf '%s\n' "$pol" | awk '/Candidate:/ {print $2; exit}')
  ge=unknown
  if [ -n "$cand" ] && [ "$cand" != "(none)" ]; then
    if dpkg --compare-versions "$cand" ge "$fixed"; then ge=yes; else ge=no; fi
  fi
  echo "$pkg|$inst|$cand|$ge"
done
'''


def split_fixed(fixed):
    """Trivy's FixedVersion may list several, e.g. "2.8.0, 1.26.21"."""
    return [v.strip() for v in (fixed or "").split(",") if v.strip()]


def run_in_image(image, args, stdin_text, user=None):
    cmd = ["docker", "run", "--rm", "-i"]
    if user:
        cmd += ["--user", user]
    cmd += [image] + args
    proc = subprocess.run(cmd, input=stdin_text, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:1])} in image exited {proc.returncode}: {proc.stderr.strip()[-500:]}")
    return proc.stdout


def pypi_releases(name):
    url = f"https://pypi.org/pypi/{name}/json"
    with urllib.request.urlopen(url, timeout=30) as resp:
        data = json.load(resp)
    releases = {v for v, files in data.get("releases", {}).items() if files}
    return releases, data.get("info", {}).get("version")


def top_level_requirements(path):
    names = set()
    try:
        with open(path) as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
                if m:
                    names.add(re.sub(r"[-_.]+", "-", m.group(1)).lower())
    except OSError:
        pass
    return names


def canon(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--trivy-json", required=True)
    ap.add_argument("--cve-ids", required=True, help="space-separated CVE IDs")
    ap.add_argument("--image", required=True)
    ap.add_argument("--requirements", default="requirements.txt")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    wanted = set(a.cve_ids.split())
    with open(a.trivy_json) as fh:
        trivy = json.load(fh)

    findings = []
    for result in trivy.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            if v.get("VulnerabilityID") in wanted:
                findings.append({
                    "cve": v["VulnerabilityID"],
                    "severity": v.get("Severity"),
                    "class": result.get("Class"),
                    "type": result.get("Type"),
                    "target": result.get("Target"),
                    "pkg": v.get("PkgName"),
                    "pkg_path": v.get("PkgPath"),
                    "installed": v.get("InstalledVersion"),
                    "fixed": v.get("FixedVersion"),
                    "purl": (v.get("PkgIdentifier") or {}).get("PURL"),
                })

    probe_errors = []
    found_ids = {f["cve"] for f in findings}
    for cve in sorted(wanted - found_ids):
        probe_errors.append({"cve": cve, "error": "not present in trivy JSON (test mode, or already cleared)"})

    top_level = top_level_requirements(a.requirements)

    # --- Debian packages: one container run for all of them.
    deb = [f for f in findings if f["class"] == "os-pkgs"]
    if deb:
        lines = "".join(f"{f['pkg']} {split_fixed(f['fixed'])[0] if split_fixed(f['fixed']) else '0'}\n" for f in deb)
        try:
            out = run_in_image(a.image, ["sh", "-c", IN_IMAGE_SH], lines, user="root")
            if "__APT_UPDATE_FAILED__" in out:
                probe_errors.append({"error": "apt-get update failed inside the image; candidate versions may be stale"})
            rows = {}
            for line in out.splitlines():
                parts = line.split("|")
                if len(parts) == 4:
                    rows[parts[0]] = parts
            for f in deb:
                r = rows.get(f["pkg"])
                if not r:
                    probe_errors.append({"cve": f["cve"], "pkg": f["pkg"], "error": "no apt-cache policy output"})
                    continue
                f["apt_installed"], f["apt_candidate"], ge = r[1], r[2], r[3]
                f["fix_in_apt_index"] = {"yes": True, "no": False}.get(ge)
                if ge == "yes":
                    f["fix_shape"] = "rebuild"  # a fresh no-cache build would pick it up
                elif ge == "no":
                    f["fix_shape"] = "wait-for-debian"
                else:
                    f["fix_shape"] = "unknown"
        except Exception as e:
            probe_errors.append({"error": f"debian probe failed: {e}"})

    # --- Python packages.
    py = [f for f in findings if f["type"] == "python-pkg"]
    if py:
        query = {}
        for f in py:
            query.setdefault(f["pkg"], set()).update(split_fixed(f["fixed"]))
        # The in-image script reads its query from stdin, so pass the program via -c.
        try:
            raw = run_in_image(
                a.image, ["python3", "-c", IN_IMAGE_PY],
                json.dumps({k: sorted(v) for k, v in query.items()}),
            )
            image_info = json.loads(raw)
            if "error" in image_info:
                probe_errors.append({"error": image_info["error"]})
                image_info = {}
        except Exception as e:
            probe_errors.append({"error": f"in-image python probe failed: {e}"})
            image_info = {}

        pypi_cache = {}
        for f in py:
            name = canon(f["pkg"])
            fixes = split_fixed(f["fixed"])
            info = image_info.get(name, {})
            f["required_by"] = info.get("required_by", [])
            f["top_level_requirement"] = name in top_level
            path = f["pkg_path"] or ""
            f["vendored"] = "/_vendor/" in path or "/_vendored/" in path
            f["no_pkg_path"] = not path  # SBOM-derived; only `purls` can scope a .trivyignore entry
            if name not in pypi_cache:
                try:
                    pypi_cache[name] = pypi_releases(f["pkg"])
                except (urllib.error.URLError, ValueError, OSError) as e:
                    pypi_cache[name] = None
                    probe_errors.append({"cve": f["cve"], "pkg": f["pkg"], "error": f"PyPI lookup failed: {e}"})
            rel = pypi_cache[name]
            if rel is not None:
                releases, latest = rel
                f["pypi_latest"] = latest
                f["pypi_has_fix"] = {fv: fv in releases for fv in fixes}
            blockers = [r for r in f["required_by"]
                        if r["admits_fix"] and not any(x for x in r["admits_fix"].values())]
            f["blocking_constraints"] = blockers

            if f["vendored"] or f["no_pkg_path"]:
                f["fix_shape"] = "vendored-or-sbom"  # no requirements pin reaches it
            elif rel is not None and not any(f["pypi_has_fix"].values()):
                f["fix_shape"] = "wait-for-pypi"
            elif blockers:
                f["fix_shape"] = "constrained"  # a dependent caps it below the fix
            else:
                f["fix_shape"] = "requirements-floor"

    for f in findings:
        if f["class"] != "os-pkgs" and f["type"] != "python-pkg":
            f["fix_shape"] = "other"
        f.setdefault("fix_shape", "unknown")

    summary = []
    for f in findings:
        line = {"cve": f["cve"], "pkg": f["pkg"], "installed": f["installed"],
                "fixed": f["fixed"], "type": f["type"], "fix_shape": f.get("fix_shape", "unknown")}
        if f.get("blocking_constraints"):
            line["blocked_by"] = [f"{b['dist']} {b['specifier']}" for b in f["blocking_constraints"]]
        summary.append(line)

    doc = {
        "image": a.image,
        "fix_shape_legend": {
            "rebuild": "fixed version is in the image's apt index; a no-cache rebuild absorbs it",
            "wait-for-debian": "Debian has not published the fixed version to the suite the image uses",
            "requirements-floor": "fixed version is on PyPI and nothing installed excludes it; add/raise a floor in requirements.txt",
            "constrained": "an installed distribution's requirement excludes the fixed version (see blocking_constraints)",
            "wait-for-pypi": "the fixed version is not on PyPI yet",
            "vendored-or-sbom": "vendored copy or SBOM-derived finding; no requirements pin reaches it",
            "other": "not a Debian or Python package; investigate manually",
            "unknown": "probe could not determine; see probe_errors",
        },
        "summary": summary,
        "findings": findings,
        "probe_errors": probe_errors,
    }
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w") as fh:
        json.dump(doc, fh, indent=2)
    print(json.dumps(summary, indent=2))
    if probe_errors:
        print(f"{len(probe_errors)} probe error(s); see {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
