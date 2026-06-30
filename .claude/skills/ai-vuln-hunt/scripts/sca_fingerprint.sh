#!/usr/bin/env bash
# sca_fingerprint.sh — version-fingerprint vendored C/C++ that has no manifest.
#
# BLACK-BOX NOTE: Only walks vendor dirs (third_party/external/deps/vendor/contrib).
# Reads a DEPENDENCY's own embedded version markers (its headers, CMakeLists, AC_INIT).
# These are COMPONENT identities, not the host target's identity — compliant.
#
# Emits a JSON array of {path, library_guess, version_guess, method} at confidence "low".
# Usage: sca_fingerprint.sh <code_dir>
set -euo pipefail
CODE="${1:?usage: sca_fingerprint.sh <code_dir>}"
VEND_RE='/(third_party|external|deps|vendor|contrib|3rdparty)/'

emit_first=1
echo "["
while IFS= read -r f; do
  base="$(basename "$f")"
  guess=""; ver=""; method=""
  # whole-macro:  #define FOO_VERSION "1.2.3"
  line="$(grep -aoE '#define[[:space:]]+[A-Z_]*VERSION[[:space:]]+"[0-9]+(\.[0-9]+)+"' "$f" 2>/dev/null | head -1 || true)"
  if [ -n "$line" ]; then
    ver="$(printf '%s' "$line" | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)"; method="c_version_macro"
  fi
  # split-macro reconstruction
  if [ -z "$ver" ]; then
    maj="$(grep -aoE '#define[[:space:]]+[A-Z_]*VERSION_MAJOR[[:space:]]+[0-9]+' "$f" 2>/dev/null | grep -oE '[0-9]+$' | head -1 || true)"
    min="$(grep -aoE '#define[[:space:]]+[A-Z_]*VERSION_MINOR[[:space:]]+[0-9]+' "$f" 2>/dev/null | grep -oE '[0-9]+$' | head -1 || true)"
    pat="$(grep -aoE '#define[[:space:]]+[A-Z_]*VERSION_PATCH[[:space:]]+[0-9]+' "$f" 2>/dev/null | grep -oE '[0-9]+$' | head -1 || true)"
    if [ -n "$maj" ] && [ -n "$min" ]; then ver="${maj}.${min}.${pat:-0}"; method="c_version_macro_split"; fi
  fi
  # CMake project(... VERSION x.y.z)
  if [ -z "$ver" ] && [ "$base" = "CMakeLists.txt" ]; then
    ver="$(grep -aioE 'project[[:space:]]*\([^)]*VERSION[[:space:]]+[0-9]+(\.[0-9]+)+' "$f" 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+)+' | head -1 || true)"
    [ -n "$ver" ] && method="cmake_project_version"
  fi
  # autoconf AC_INIT
  if [ -z "$ver" ]; then
    ver="$(grep -aoE 'AC_INIT\([^,]+,[[:space:]]*\[?[0-9]+(\.[0-9]+)+' "$f" 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+)+' | head -1 || true)"
    [ -n "$ver" ] && method="autoconf_ac_init"
  fi
  [ -z "$ver" ] && continue
  # library guess = the vendor subdir name
  guess="$(printf '%s' "$f" | sed -E 's#.*/(third_party|external|deps|vendor|contrib|3rdparty)/([^/]+)/.*#\2#')"
  [ "$emit_first" = 1 ] && emit_first=0 || echo ","
  printf '{"path":"%s","library_guess":"%s","version_guess":"%s","method":"%s"}' \
    "$f" "$guess" "$ver" "$method"
done < <(find "$CODE" -type f \( -name '*.h' -o -name '*.hpp' -o -name 'CMakeLists.txt' -o -name 'configure.ac' \) 2>/dev/null | grep -E "$VEND_RE" || true)
echo
echo "]"
