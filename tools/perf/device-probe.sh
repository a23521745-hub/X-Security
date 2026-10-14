#!/usr/bin/env bash
# X-Security on-device probe — the rows the JVM harness cannot measure.
#
# Produces, for one device+APK combination:
#   cold start p50 (am start -W), Janky frames % + frame times (dumpsys gfxinfo),
#   PSS after a device scan (dumpsys meminfo), scan MB/s (app's own scan record),
#   WorkManager wakeups/hour (dumpsys jobscheduler cadence + batterystats counters),
#   StrictMode violations and the safelist-cache counters (debug build only).
#
# Usage:
#   tools/perf/device-probe.sh before        # run against the pre-hotfix APK
#   tools/perf/device-probe.sh after         # run against the hotfix APK
#   DEVICE=<serial> PKG=org.xsecurity.scanner runs=10 tools/perf/device-probe.sh after
#
# Notes:
#  - the StrictMode/perf line and `run-as` only exist in a DEBUG build; release rows are marked
#    "n/a (release build)" instead of being invented;
#  - the scroll/jank step needs a human finger or `adb shell input swipe` (the script swipes);
#  - drop this output into docs/perf/PERF_AUDIT.md verbatim.
set -euo pipefail

LABEL="${1:?usage: device-probe.sh <before|after>}"
DEVICE="${DEVICE:-}"
PKG="${PKG:-org.xsecurity.scanner}"
ACTIVITY="${ACTIVITY:-$PKG/.ui.MainActivity}"
RUNS="${runs:-10}"
QUARANTINE_SWIPES="${QUARANTINE_SWIPES:-12}"

ADB=(adb)
[[ -n "$DEVICE" ]] && ADB+=( -s "$DEVICE" )
sh() { "${ADB[@]}" shell "$@"; }

echo "## device probe: $LABEL"
echo
echo "device: $("${ADB[@]}" shell getprop ro.product.model | tr -d '\r') " \
     "($("${ADB[@]}" shell getprop ro.board.platform | tr -d '\r'), " \
     "android $("${ADB[@]}" shell getprop ro.build.version.release | tr -d '\r'))"
echo "apk: $(sh dumpsys package "$PKG" | grep -m1 versionName | tr -d '\r' || echo unknown)"
echo

# --- 1. cold start -----------------------------------------------------------------------------
echo "### cold start (am start -W, TotalTime ms, N=$RUNS)"
TIMES=()
for _ in $(seq "$RUNS"); do
  sh am force-stop "$PKG" >/dev/null
  sleep 1
  TOTAL=$(sh am start -W -n "$ACTIVITY" | tr -d '\r' | awk '/^TotalTime:/ {print $2}')
  TIMES+=("${TOTAL:-0}")
done
printf '%s\n' "${TIMES[@]}" | sort -n | awk -v label="$LABEL" '
  { values[NR]=$1 }
  END {
    n=NR
    printf "  p50=%s ms  p90=%s ms  min=%s  max=%s\n", values[int((n+1)/2)], values[int(n*0.9)], values[1], values[n]
  }'

# --- 2. list jank ------------------------------------------------------------------------------
echo
echo "### list scroll jank (dumpsys gfxinfo, $QUARANTINE_SWIPES swipes)"
sh dumpsys gfxinfo "$PKG" reset >/dev/null
for _ in $(seq "$QUARANTINE_SWIPES"); do
  sh input swipe 540 1600 540 400 120 >/dev/null
  sh input swipe 540 400 540 1600 120 >/dev/null
done
sleep 1
sh dumpsys gfxinfo "$PKG" | tr -d '\r' | grep -E "Total frames rendered|Janky frames|50th|90th|95th|99th|Number Missed Vsync|HISTOGRAM" | head -12

# --- 3. memory ---------------------------------------------------------------------------------
echo
echo "### memory after a device scan"
echo "  (start \"Scan device\" in the UI, wait for completion, then re-run just this block)"
sh dumpsys meminfo "$PKG" | tr -d '\r' | grep -E "TOTAL PSS|TOTAL RSS|Java Heap|Native Heap" | head -6

# --- 4. scan throughput ------------------------------------------------------------------------
echo
echo "### scan MB/s (from the app's own scan record: bytesScanned / durationMillis)"
if sh run-as "$PKG" cat files/scan-history.json >/tmp/xsec-history.json 2>/dev/null; then
  python3 - <<'PY'
import json
data = json.load(open('/tmp/xsec-history.json'))
entries = data if isinstance(data, list) else data.get('entries', [])
rows = [e for e in entries if e.get('durationMillis')]
if not rows:
    print("  no completed scan in history yet")
for e in rows[:3]:
    mb = (e.get('bytesScanned') or 0) / 1048576.0
    seconds = e['durationMillis'] / 1000.0
    print(f"  {e.get('type','?')}: {mb:.1f} MiB in {seconds:.2f} s -> {mb/seconds:.1f} MB/s")
PY
else
  echo "  n/a (release build: run-as unavailable; install the debug APK for this row)"
fi

# --- 5. worker wakeups -------------------------------------------------------------------------
echo
echo "### WorkManager cadence (jobscheduler)"
sh dumpsys jobscheduler | tr -d '\r' | grep -E "$PKG" -A 6 | grep -E "$PKG|Interval|periodic|flex" | head -20
echo
echo "### wakeup counters (batterystats; needs the app to have run a while)"
sh dumpsys batterystats --charged "$PKG" 2>/dev/null | tr -d '\r' | grep -iE "wakeup|jobs" | head -10 || echo "  n/a"

# --- 6. probes (debug builds) ------------------------------------------------------------------
echo
echo "### StrictMode violations since boot"
sh logcat -d -s StrictMode:v 2>/dev/null | tr -d '\r' | tail -20 || true
echo
echo "### perf stages + safelist cache counters"
sh logcat -d -s XSecurityPerf:I | tr -d '\r' | tail -20 || true
echo
echo "hint: to verify the hoisted PackageManager cache, open Quarantine, scroll the list up/down,"
echo "      then compare 'lookups=' before/after the scroll — it must not grow."
