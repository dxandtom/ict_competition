#!/usr/bin/env python3
"""sca_normalize.py — fold all SCA tool outputs into one canonical findings JSON.

BLACK-BOX NOTE: operates purely on (component, version, vuln_id) for THIRD-PARTY deps.
No host-identity reasoning. Alias-aware cross-tool merging: e.g. grype's CVE-... and
osv-scanner's GHSA-... for the same component coalesce into ONE finding carrying the
canonical CVE id plus both detectors, raising confidence to "high".

Usage: sca_normalize.py <raw_dir> <vendored.json> > findings.json
Output schema: {"schema_version":"sca-1.0","findings":[SCAFinding...],
                "vendored_unidentified":[...]}
SCAFinding fields: id, aliases[], component, version, ecosystem, purl, severity,
  cvss{score,vector}, summary, fixed_versions[], introduced, source_manifest,
  detectors[], confidence, references[], notes
"""
import json, sys, glob, os

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
CONF_RANK = {"high": 3, "medium": 2, "low": 1}


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def canon_id(ids):
    """Prefer CVE id as canonical; keep the rest as aliases."""
    cves = [i for i in ids if i.upper().startswith("CVE-")]
    return (cves[0] if cves else (ids[0] if ids else "")), sorted(set(ids))


def add(acc, ids, comp, ver, eco, purl, sev, summary, fixed, det, manifest, refs, cvss):
    key_id, aliases = canon_id([i for i in ids if i])
    # merge key: prefer canonical id; fall back to (component,version,any-alias)
    mkey = None
    for existing in acc:
        if key_id and (key_id == existing["id"] or key_id in existing["aliases"]
                       or any(a in existing["aliases"] or a == existing["id"] for a in aliases)):
            if existing["component"].lower() == (comp or "").lower():
                mkey = existing
                break
    if mkey is None:
        mkey = {
            "id": key_id, "aliases": aliases, "component": comp or "", "version": ver or "",
            "ecosystem": eco or "", "purl": purl or "", "severity": sev or "UNKNOWN",
            "cvss": cvss or {}, "summary": summary or "", "fixed_versions": fixed or [],
            "introduced": "0", "source_manifest": manifest or "", "detectors": [],
            "confidence": "low", "references": refs or [], "notes": "",
        }
        acc.append(mkey)
    # merge fields
    mkey["aliases"] = sorted(set(mkey["aliases"]) | set(aliases) | ({key_id} if key_id else set()))
    mkey["aliases"] = [a for a in mkey["aliases"] if a != mkey["id"]]
    for d in det:
        if d not in mkey["detectors"]:
            mkey["detectors"].append(d)
    if SEV_RANK.get(sev, 0) > SEV_RANK.get(mkey["severity"], 0):
        mkey["severity"] = sev
    if fixed:
        mkey["fixed_versions"] = sorted(set(mkey["fixed_versions"]) | set(fixed))
    if refs:
        mkey["references"] = sorted(set(mkey["references"]) | set(refs))
    if cvss and not mkey["cvss"]:
        mkey["cvss"] = cvss


def parse_osv(data, acc):
    for res in (data or {}).get("results", []):
        manifest = res.get("source", {}).get("path", "")
        for pkg in res.get("packages", []):
            p = pkg.get("package", {})
            comp, ver = p.get("name", ""), p.get("version", "")
            eco, purl = p.get("ecosystem", ""), p.get("purl", "")
            for v in pkg.get("vulnerabilities", []):
                ids = [v.get("id", "")] + v.get("aliases", [])
                sev = "UNKNOWN"
                for s in v.get("severity", []):
                    sev = "HIGH"  # OSV uses CVSS vectors; coarse map
                fixed = []
                for af in v.get("affected", []):
                    for r in af.get("ranges", []):
                        for ev in r.get("events", []):
                            if ev.get("fixed"):
                                fixed.append(ev["fixed"])
                add(acc, ids, comp, ver, eco, purl, sev, v.get("summary", ""), fixed,
                    ["osv-scanner"], manifest, [r.get("url", "") for r in v.get("references", [])], {})


def parse_grype(data, acc):
    for m in (data or {}).get("matches", []):
        vuln = m.get("vulnerability", {})
        art = m.get("artifact", {})
        ids = [vuln.get("id", "")] + [r.get("id", "") for r in m.get("relatedVulnerabilities", [])]
        sev = (vuln.get("severity", "UNKNOWN") or "UNKNOWN").upper()
        fixed = vuln.get("fix", {}).get("versions", [])
        cvss = {}
        for c in vuln.get("cvss", []):
            cvss = {"score": c.get("metrics", {}).get("baseScore"), "vector": c.get("vector", "")}
        add(acc, ids, art.get("name", ""), art.get("version", ""),
            art.get("language", "") or art.get("type", ""), art.get("purl", ""),
            sev, vuln.get("description", ""), fixed, ["grype"], "",
            [vuln.get("dataSource", "")], cvss)


def parse_pip_audit(data, acc):
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    if isinstance(deps, dict):
        deps = deps.get("dependencies", [])
    for d in (deps or []):
        name, ver = d.get("name", ""), d.get("version", "")
        for v in d.get("vulns", []):
            ids = [v.get("id", "")] + v.get("aliases", [])
            add(acc, ids, name, ver, "PyPI", f"pkg:pypi/{name}@{ver}", "UNKNOWN",
                v.get("description", ""), v.get("fix_versions", []), ["pip-audit"],
                "requirements.txt", [], {})


def parse_trivy(data, acc):
    for res in (data or {}).get("Results", []):
        manifest = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            ids = [v.get("VulnerabilityID", "")]
            sev = (v.get("Severity", "UNKNOWN") or "UNKNOWN").upper()
            fixed = [v["FixedVersion"]] if v.get("FixedVersion") else []
            add(acc, ids, v.get("PkgName", ""), v.get("InstalledVersion", ""),
                "", "", sev, v.get("Title", ""), fixed, ["trivy"], manifest,
                v.get("References", []), {})


def confidence(f):
    locked = any(k in (f["source_manifest"] or "").lower()
                 for k in ("lock", "module.bazel", "workspace"))
    if len(f["detectors"]) >= 2 or locked:
        return "high"
    if f["source_manifest"]:
        return "medium"
    return "low"


def main():
    raw_dir = sys.argv[1]
    vendored_path = sys.argv[2] if len(sys.argv) > 2 else None
    acc = []
    for path in sorted(glob.glob(os.path.join(raw_dir, "*.json"))):
        name = os.path.basename(path)
        data = load(path)
        if data is None:
            continue
        if name.startswith("osv"):
            parse_osv(data, acc)
        elif name.startswith("grype"):
            parse_grype(data, acc)
        elif name.startswith("pip-audit"):
            parse_pip_audit(data, acc)
        elif name.startswith("trivy") and "sbom" not in name:
            parse_trivy(data, acc)
    for f in acc:
        f["confidence"] = confidence(f)
    acc.sort(key=lambda f: (-SEV_RANK.get(f["severity"], 0),
                            -CONF_RANK.get(f["confidence"], 0), f["component"]))
    vendored = load(vendored_path) if vendored_path else []
    print(json.dumps({"schema_version": "sca-1.0", "findings": acc,
                      "vendored_unidentified": vendored or []}, indent=2))


if __name__ == "__main__":
    main()
