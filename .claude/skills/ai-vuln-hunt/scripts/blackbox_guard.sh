#!/usr/bin/env bash
# blackbox_guard.sh — enforce the black-box contract as a REAL gate (non-zero exit aborts).
#
# Two kinds of "identity":
#   HOST identity   (FORBIDDEN): the target project's own name/version/known-bug status.
#   COMPONENT id    (ALLOWED):   third-party DEPENDENCY name+version, for SCA CVE matching.
#
# What it does:
#   check-path  : default-DENY any path component named `.git`; deny host-identity files
#                 (VERSION*, CHANGELOG*, CHANGES*, RELEASE*, NEWS, HISTORY*, SECURITY*,
#                 NOTICE, AUTHORS, CONTRIBUTORS, *.bazel version files). Dependency manifests
#                 are whitelisted so SCA stays compliant.
#   check-git   : ALLOWLIST (default-deny). Only `git diff|status|ls-files` with simple,
#                 single-token args (for scoping). tag/log/describe/blame/show/rev-* => DENY.
#   scan-file   : HARD gate. Exits 4 if text asserts HOST identity/version or ties a CVE to the
#                 host. `--strict` (use on prompt blobs) also blocks any bare project NAME.
#                 Default mode (use on REPORT.md) lets bare dependency names through but still
#                 blocks identity ASSERTIONS — the actually-disqualifying construct.
#
# Usage:
#   blackbox_guard.sh check-path  <path>            # exit 0 allowed, 3 denied
#   blackbox_guard.sh check-git   <args...>         # exit 0 allowed, 3 denied
#   blackbox_guard.sh scan-file   <file> [--strict] # exit 0 clean, 4 leak
#   blackbox_guard.sh scan-stdin  [--strict]
#   blackbox_guard.sh selftest
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# ---- Host-identity file basenames (deny) ----
DENY_BASENAMES='^(version([._-].*)?|version\.bazel|changelog.*|changes([._-].*)?|release.*|news|history.*|security([._-].*)?|notice([._-].*)?|authors|contributors|maintainers)$'
# ---- Dependency-manifest whitelist (allowed even if a basename rule would match) ----
ALLOW_RE='(requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|Pipfile(\.lock)?|setup\.(py|cfg)|WORKSPACE([.]bazel)?|MODULE\.bazel|/third_party/|/external/|/vendor/|/deps/|/contrib/|package(-lock)?\.json|go\.(mod|sum)|Cargo\.(toml|lock))'

# ---- Project/library NAME denylist (defensive: prevents accidental identity assertions) ----
# Generic list of well-known OSS projects. A bare mention is a *warning*; a mention inside an
# identity ASSERTION (or in --strict mode) is a hard leak.
DENYLIST_FILE="$HERE/blackbox_denylist.txt"
if [ -f "$DENYLIST_FILE" ]; then
  NAMES="$(grep -vE '^\s*(#|$)' "$DENYLIST_FILE" | tr '\n' '|' | sed 's/|$//')"
else
  NAMES='tensorflow|tflite|pytorch|torch|aten|caffe|caffe2|keras|jax|numpy|scipy|scikit-learn|sklearn|pandas|opencv|ffmpeg|libav|abseil|absl|eigen|protobuf|grpc|onnx|onnxruntime|mxnet|paddle|paddlepaddle|cntk|theano|llvm|boost|openssl|libpng|libjpeg|zlib|libxml2|libtiff|freetype|sqlite|curl|nginx|apache|django|flask|requests|pillow|lodash|log4j|spring|jackson|guava|netty'
fi

# ---- Identity-assertion regexes (the disqualifying construct), EN + ZH ----
# The forbidden thing is an ASSERTION that the HOST *is* some named project / version — NOT a
# bare (component, version) pair, which is exactly what allowed SCA dependency reporting emits.
# "<this/the/it's/the target/project/...> ... <is/appears/looks/seems/recognized> ... <name|vN.N>"
ASSERT_EN='(\bthis\b|\bthe\b|\bit'"'"'?s\b|\btarget\b|\bproject\b|\bcodebase\b|\blibrary\b|\brepo\b).{0,40}\b(is|are|appears? to be|looks? like|seems? to be|recognized as|identif(y|ied) as|must be|based on)\b.{0,40}('"$NAMES"'|v?[0-9]+\.[0-9]+)'
# "this/the project|library|version is vulnerable" / "known cve/bug/vuln"
VULNCLAIM='(this|the|that) (project|library|codebase|version|target|release) (is )?(vulnerable|has (a )?(known )?(cve|bug|vulnerabilit))|known (cve|bug|vulnerabilit) (in (this|the))|previously (disclosed|reported) (cve|bug)'
# Chinese identity assertion: 这是/该项目是/目标是/疑似/看起来是 ... 版本/N.N/<name>
ASSERT_ZH='(这是|这个(项目|库|代码|仓库)|该(项目|库|代码|版本)|目标(是|为)|疑似|看起来(像|是)|应该是|版本(号)?(是|为)).{0,20}('"$NAMES"'|版本|[0-9]+\.[0-9]+)'

low() { tr 'A-Z' 'a-z'; }

scan_text() {  # $1=text  $2=strict(0|1)
  local data strict line
  data="$(printf '%s' "$1" | low)"; strict="$2"
  # Hard leaks, line-scoped (so an allowed SCA component line never trips a separate narrative line).
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if printf '%s' "$line" | grep -Eq "$ASSERT_EN"; then echo "LEAK(host-identity-assertion): $line" >&2; return 4; fi
    if printf '%s' "$line" | grep -Eq "$VULNCLAIM"; then echo "LEAK(known-bug-claim): $line" >&2;        return 4; fi
    if printf '%s' "$line" | grep -Eq "$ASSERT_ZH"; then echo "LEAK(host-identity-assertion-zh): $line" >&2; return 4; fi
    # CVE id attributed to HOST code: a CVE on the same line as a code-locus word or host-reasoning.
    # (Allowed SCA lines read "<component> <ver> -> CVE-..., fixed in <ver>" — no code-locus word.)
    if printf '%s' "$line" | grep -Eq 'cve-[0-9]{4}-[0-9]+'; then
      if printf '%s' "$line" | grep -Eq '(parser|kernel|operator|\bop\b|module|function|routine|in (this|the)|affects (this|the)|host (project|code))'; then
        echo "LEAK(cve-tied-to-host-code): $line" >&2; return 4
      fi
    fi
    # Strict mode (prompt blobs): any bare project NAME is a leak.
    if [ "$strict" = 1 ] && printf '%s' "$line" | grep -Eq "\b($NAMES)\b"; then
      echo "LEAK(bare-project-name,strict): $line" >&2; return 4
    fi
  done <<EOF
$data
EOF
  # Soft warning: bare project name in non-strict mode (allowed for SCA deps; flagged for review).
  if printf '%s' "$data" | grep -Eq "\b($NAMES)\b"; then
    echo "WARN(bare-project-name; ok only as an SCA dependency, review context): present" >&2
  fi
  return 0
}

case "${1:-}" in
check-path)
  p="${2:?path}"
  # default-deny anything under a .git directory (any path component == .git)
  case "/$p/" in */.git/*) echo "DENY(.git): $p" >&2; exit 3;; esac
  if printf '%s' "$p" | grep -Eiq "$ALLOW_RE"; then echo "ALLOW(dep-manifest): $p"; exit 0; fi
  base="$(basename "$p" | low)"
  if printf '%s' "$base" | grep -Eq "$DENY_BASENAMES"; then echo "DENY(host-identity): $p" >&2; exit 3; fi
  echo "ALLOW: $p"; exit 0
  ;;
check-git)
  shift; sub="${1:-}"
  # reject compound/whitespace-bearing single args (e.g. 'log -p' as one quoted arg)
  for a in "$@"; do case "$a" in *[[:space:]]*) echo "DENY(compound-arg): git $*" >&2; exit 3;; esac; done
  case "$sub" in
    diff|status|ls-files) echo "ALLOW: git $*"; exit 0;;
    *) echo "DENY(git not on allowlist; identity/history risk): git $*" >&2; exit 3;;
  esac
  ;;
scan-file)
  f="${2:?file}"; strict=0; [ "${3:-}" = "--strict" ] && strict=1
  scan_text "$(cat "$f")" "$strict"; exit $?
  ;;
scan-stdin)
  strict=0; [ "${2:-}" = "--strict" ] && strict=1
  scan_text "$(cat)" "$strict"; exit $?
  ;;
selftest)
  pass=0; fail=0
  ck(){ if eval "$1" >/dev/null 2>&1; then got=0; else got=1; fi
        if [ "$got" = "$2" ]; then echo "ok: $3"; pass=$((pass+1)); else echo "FAIL: $3"; fail=$((fail+1)); fi; }
  # path guard
  ck '"$0" check-path code/VERSION'                 1 'VERSION denied'
  ck '"$0" check-path code/version.bazel'           1 'version.bazel denied'
  ck '"$0" check-path code/CHANGES.txt'             1 'CHANGES.txt denied'
  ck '"$0" check-path code/.git/config'             1 '.git/config denied'
  ck '"$0" check-path code/sub/.git/HEAD'           1 'nested .git denied'
  ck '"$0" check-path code/requirements.txt'        0 'requirements allowed'
  ck '"$0" check-path code/third_party/foo/VERSION' 0 'dependency VERSION allowed'
  ck '"$0" check-path code/core/kernels/conv.cc'    0 'source file allowed'
  # git guard
  ck '"$0" check-git tag'                           1 'git tag denied'
  ck '"$0" check-git log -p'                        1 'git log denied'
  ck '"$0" check-git rev-parse HEAD'               1 'git rev-parse denied'
  ck '"$0" check-git describe'                      1 'git describe denied'
  ck '"$0" check-git diff A..B'                     0 'git diff allowed'
  ck '"$0" check-git status'                        0 'git status allowed'
  # leak scanner — these MUST be blocked
  for s in \
    'This is TensorFlow 2.11' \
    'The target is numpy 1.21.0' \
    'this looks like PyTorch'"'"'s aten' \
    'Based on the structure this is Abseil' \
    'This matches CVE-2022-23559 in the tflite parser' \
    '这是 TensorFlow 2.11 版本' \
    '该项目是 opencv 4.5' \
    'this version is vulnerable to a known CVE'; do
    if printf '%s' "$s" | "$0" scan-stdin >/dev/null 2>&1; then echo "FAIL: leak passed: $s"; fail=$((fail+1));
    else echo "ok: leak blocked: $s"; pass=$((pass+1)); fi
  done
  # these MUST pass (allowed SCA dependency reporting / neutral text)
  for s in \
    'Component numpy 1.21.0 (dependency) -> CVE-2021-41496, fixed in 1.22' \
    'Found an out-of-bounds write in core/kernels/conv_ops.cc:412' \
    'tool versions: python 3.11.0, clang 14.0.0'; do
    if printf '%s' "$s" | "$0" scan-stdin >/dev/null 2>&1; then echo "ok: clean passed: $s"; pass=$((pass+1));
    else echo "FAIL: clean blocked: $s"; fail=$((fail+1)); fi
  done
  echo "selftest: $pass pass, $fail fail"; [ "$fail" = 0 ]
  ;;
*) echo "usage: blackbox_guard.sh {check-path|check-git|scan-file|scan-stdin|selftest} ..." >&2; exit 2;;
esac
