#!/usr/bin/env bash
# X-Security in-sandbox perf harness.
#
# Compiles the *pure Kotlin* surface of the app (engine, YARA/ClamAV parsers, matcher, phishing
# scoring, and — on the fixed tree — the two new hotfix classes) together with tools/perf/src and
# runs the measurements. No Android SDK, no Gradle, no device required.
#
# Usage:
#   tools/perf/run.sh                     # measure the working tree  ("after")
#   REV=HEAD tools/perf/run.sh            # measure a git revision     ("before"/baseline)
#   OUT=docs/perf/hotfix-before.txt tools/perf/run.sh
#
# Toolchain (not vendored in this repo):
#   KOTLINC  path to the kotlinc launcher   (default: `kotlinc` on PATH)
#   JAVA_HOME  JDK/JRE home used by kotlinc (default: inherited)
#
# Getting a toolchain without Maven/Gradle network access:
#   python3 -m pip download --no-deps --dest /tmp/tc jdk4py        # JRE/JDK wheel, unpack it
#   curl -fsSL https://registry.npmjs.org/kotlin-compiler/-/kotlin-compiler-2.4.21.tgz | tar xz -C /tmp/kc
#   KOTLINC=/tmp/kc/package/bin/kotlinc JAVA_HOME=/tmp/tc/jdk4py/java-runtime tools/perf/run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KOTLINC="${KOTLINC:-kotlinc}"
REV="${REV:-}"
OUT="${OUT:-}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- source selection -------------------------------------------------------------------------
PURE_GLOBS=(
  "app/src/main/java/org/xsecurity/scanner/core"
  "app/src/main/java/org/xsecurity/scanner/matcher"
  "app/src/main/java/org/xsecurity/scanner/yara"
  "app/src/main/java/org/xsecurity/scanner/clamav"
  "app/src/main/java/org/xsecurity/scanner/engine"
)
PURE_FILES=(
  "app/src/main/java/org/xsecurity/scanner/phishing/PhishingBlocklist.kt"
  "app/src/main/java/org/xsecurity/scanner/phishing/PhishingHeuristics.kt"
  "app/src/main/java/org/xsecurity/scanner/phishing/PhishingScanner.kt"
  "app/src/main/java/org/xsecurity/scanner/phishing/UrlExtractor.kt"
  "app/src/main/java/org/xsecurity/scanner/autopilot/SystemPackageCache.kt"
)

emit() { # emit <path> -> $WORK/src/<path>
  local path="$1"
  local dest="$WORK/src/$path"
  mkdir -p "$(dirname "$dest")"
  if [[ -n "$REV" ]]; then
    git -C "$ROOT" show "$REV:$path" > "$dest" 2>/dev/null || return 1
  else
    [[ -f "$ROOT/$path" ]] || return 1
    cp "$ROOT/$path" "$dest"
  fi
}

count=0
for glob in "${PURE_GLOBS[@]}"; do
  if [[ -n "$REV" ]]; then
    while IFS= read -r path; do emit "$path" && count=$((count + 1)); done < <(git -C "$ROOT" ls-tree -r --name-only "$REV" | grep "^$glob/.*\.kt$" || true)
  else
    while IFS= read -r path; do emit "$path" && count=$((count + 1)); done < <(ls "$ROOT/$glob"/*.kt 2>/dev/null | sed "s|$ROOT/||" || true)
  fi
done
for path in "${PURE_FILES[@]}"; do emit "$path" && count=$((count + 1)); done

# --- harness (always the worktree copy: the tool is not the code under test) -------------------
mkdir -p "$WORK/src/perf"
cp "$ROOT/tools/perf/src/PerfHarness.kt" "$WORK/src/perf/PerfHarness.kt"
count=$((count + 1))
AFTER_BENCH=""
if [[ -f "$WORK/src/app/src/main/java/org/xsecurity/scanner/autopilot/SystemPackageCache.kt" &&
      -f "$WORK/src/app/src/main/java/org/xsecurity/scanner/core/ProgressCoalescer.kt" ]]; then
  cp "$ROOT/tools/perf/src-after/OptimizationBench.kt" "$WORK/src/perf/OptimizationBench.kt"
  count=$((count + 1))
  AFTER_BENCH="yes"
fi

echo "perf harness: $count source files (rev=${REV:-worktree}, production bench=${AFTER_BENCH:-no})"
echo "kotlinc: $KOTLINC"
echo

"$KOTLINC" -nowarn -jvm-target 17 -include-runtime -d "$WORK/harness.jar" $(find "$WORK/src" -name '*.kt' | sort)

REPORT="$WORK/report.txt"
java -jar "$WORK/harness.jar" "$ROOT" 2>&1 | tee "$REPORT"

if [[ -n "$OUT" ]]; then
  mkdir -p "$(dirname "$ROOT/$OUT")"
  cp "$REPORT" "$ROOT/$OUT"
  echo
  echo "report written: $OUT"
fi
