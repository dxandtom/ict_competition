#!/usr/bin/env python3
"""sast_merge.py — 将所有 SAST 工具的不同输出格式归一化为统一 schema，去重并排序。

从 <raw_dir> 读取 bandit.json、ruff.json、semgrep_*.sarif、flawfinder.sarif、cppcheck.xml、
clang-tidy.txt。按 (file, line +/-2, sink_class) 去重。按
严重度 x 跨工具一致性 x sink 类别权重 进行排序。

sink 类别与 templates/sink_taxonomy.md 保持一致。注意：内存破坏类模式
会在通用 int_overflow 模式之前匹配，且 int_overflow 要求带有
*限定词* 的溢出（"integer overflow"/"signed overflow"），因此 "buffer overflow" 会被
正确归入内存安全类，而非 int_overflow。

用法：sast_merge.py <raw_dir> > leads.json
"""
import json, sys, os, glob, re
import xml.etree.ElementTree as ET

# 有序排列：先匹配具体的内存破坏类，再匹配带限定词的整数溢出类。
SINK_PATTERNS = [
    ("oob_rw",        re.compile(r"out.?of.?bounds|buffer overflow|heap overflow|stack overflow|oob|index out of range", re.I)),
    ("use_after_free",re.compile(r"use.after.free|double free|dangling", re.I)),
    ("uninit",        re.compile(r"uninitialized|use of uninitialised", re.I)),
    ("int_overflow",  re.compile(r"integer overflow|signed overflow|unsigned overflow|integer wrap|narrowing", re.I)),
    ("deser",         re.compile(r"pickle|deserial|unmarshal|yaml.load|marshal|eval of", re.I)),
    ("injection",     re.compile(r"command injection|os\.system|subprocess.*shell|sql injection|format string", re.I)),
    ("path_traversal",re.compile(r"path traversal|directory traversal|tarfile|zip slip", re.I)),
    ("weak_crypto",   re.compile(r"md5|sha1|insecure hash|weak (cipher|crypto)", re.I)),
    ("availability",  re.compile(r"denial of service|infinite loop|recursion|null deref|division by zero", re.I)),
]
SINK_WEIGHT = {"oob_rw": 1.0, "use_after_free": 1.0, "uninit": 0.8, "int_overflow": 0.9,
               "deser": 0.9, "injection": 0.85, "path_traversal": 0.7, "weak_crypto": 0.2,
               "availability": 0.6, "other": 0.4}
SEV_SCORE = {"CRITICAL": 1.0, "HIGH": 0.8, "ERROR": 0.8, "MEDIUM": 0.5,
             "WARNING": 0.5, "LOW": 0.3, "NOTE": 0.2, "INFO": 0.2}


def classify(text):
    for name, rx in SINK_PATTERNS:
        if rx.search(text or ""):
            return name
    return "other"


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def add(leads, file, line, sev, msg, tool, rule):
    sink = classify(f"{rule} {msg}")
    leads.append({"file": file or "", "line": int(line or 0), "severity": (sev or "INFO").upper(),
                  "sink_class": sink, "message": (msg or "")[:300], "detectors": [tool],
                  "rule": rule or ""})


def parse_bandit(d, leads):
    for r in (d or {}).get("results", []):
        add(leads, r.get("filename"), r.get("line_number"),
            r.get("issue_severity"), r.get("issue_text"), "bandit", r.get("test_id"))


def parse_ruff(d, leads):
    for r in (d or []):
        loc = r.get("location", {})
        add(leads, r.get("filename"), loc.get("row"), "WARNING",
            r.get("message"), "ruff", r.get("code"))


def parse_sarif(d, tool, leads):
    for run in (d or {}).get("runs", []):
        for res in run.get("results", []):
            sev = res.get("level", "warning")
            msg = (res.get("message", {}) or {}).get("text", "")
            rule = res.get("ruleId", "")
            for loc in res.get("locations", []):
                pl = loc.get("physicalLocation", {})
                f = pl.get("artifactLocation", {}).get("uri", "")
                ln = pl.get("region", {}).get("startLine", 0)
                add(leads, f, ln, sev, msg, tool, rule)


def parse_cppcheck(path, leads):
    try:
        tree = ET.parse(path)
    except Exception:
        return
    for err in tree.getroot().iter("error"):
        sev = err.get("severity", "style")
        msg = err.get("msg", "")
        rule = err.get("id", "")
        loc = err.find("location")
        f = loc.get("file") if loc is not None else ""
        ln = loc.get("line") if loc is not None else 0
        add(leads, f, ln, sev.upper(), msg, "cppcheck", rule)


def dedup_rank(leads):
    buckets = {}
    for L in leads:
        placed = False
        for key, agg in buckets.items():
            kf, kl, ks = key
            if kf == L["file"] and ks == L["sink_class"] and abs(kl - L["line"]) <= 2:
                for d in L["detectors"]:
                    if d not in agg["detectors"]:
                        agg["detectors"].append(d)
                if SEV_SCORE.get(L["severity"], 0) > SEV_SCORE.get(agg["severity"], 0):
                    agg["severity"] = L["severity"]
                placed = True
                break
        if not placed:
            buckets[(L["file"], L["line"], L["sink_class"])] = dict(L)
    out = []
    for agg in buckets.values():
        agreement = 1 + 0.5 * (len(agg["detectors"]) - 1)
        score = round(10 * SEV_SCORE.get(agg["severity"], 0.2)
                      * agreement * SINK_WEIGHT.get(agg["sink_class"], 0.4), 2)
        agg["score"] = min(score, 10.0)
        out.append(agg)
    out.sort(key=lambda a: -a["score"])
    for i, a in enumerate(out):
        a["lead_id"] = f"L{i+1:03d}"
    return out


def main():
    raw = sys.argv[1]
    leads = []
    for p in glob.glob(os.path.join(raw, "*")):
        n = os.path.basename(p)
        if n == "bandit.json":
            parse_bandit(load(p), leads)
        elif n == "ruff.json":
            parse_ruff(load(p), leads)
        elif n.endswith(".sarif"):
            tool = "semgrep" if "semgrep" in n else ("flawfinder" if "flaw" in n else "sarif")
            parse_sarif(load(p), tool, leads)
        elif n == "cppcheck.xml":
            parse_cppcheck(p, leads)
    ranked = dedup_rank(leads)
    print(json.dumps({"schema": "sast-leads-1.0", "leads": ranked}, indent=2))


if __name__ == "__main__":
    main()
