# `tools/perf` — measurement kit for the optimization hotfix

Two tools, two very different jobs. Neither of them guesses a number.

| Tool | Runs where | Produces |
| --- | --- | --- |
| `run.sh` | any machine with a JDK + `kotlinc` (no Android SDK, no Gradle) | engine parse cost, scan MB/s, allocation volume, and the two offender counters (PackageManager queries per list render, progress posts per scanned app) — measured on the **production** classes |
| `device-probe.sh` | a USB-attached Android device via `adb` | the rows only a device can answer: cold start p50, janky frames, PSS, on-device MB/s, wakeups/hour, StrictMode violations, safelist cache counters |

The audit pack that consumes both is [`docs/perf/PERF_AUDIT.md`](../../docs/perf/PERF_AUDIT.md);
raw reports live next to it (`hotfix-before.txt`, `hotfix-after.txt`).

## JVM harness

```bash
# "after" (current working tree)
tools/perf/run.sh

# "before" (baseline, read straight out of git — no checkout needed)
REV=HEAD OUT=docs/perf/hotfix-before.txt tools/perf/run.sh
```

The script copies the app's pure-Kotlin surface (engine, YARA/ClamAV parsers, matcher, phishing
scoring, plus `SystemPackageCache`/`ProgressCoalescer` when they exist in the tree under test) into
a temp dir, adds `tools/perf/src/PerfHarness.kt`, and — only when those two production classes are
present — `tools/perf/src-after/OptimizationBench.kt`, which measures the shipped classes
themselves rather than a copy of their logic.

Getting a toolchain without Maven/Gradle network access (the environment this hotfix was produced
in):

```bash
python3 -m pip download --no-deps --dest /tmp/tc jdk4py      # JRE/JDK wheel
cd /tmp/tc && python3 -c "import zipfile,glob;zipfile.ZipFile(glob.glob('jdk4py*.whl')[0]).extractall('jdk')"
chmod -R +x /tmp/tc/jdk/jdk4py/java-runtime/bin /tmp/tc/jdk/jdk4py/java-runtime/lib

mkdir -p /tmp/kc && curl -fsSL https://registry.npmjs.org/kotlin-compiler/-/kotlin-compiler-2.4.21.tgz | tar xz -C /tmp/kc

KOTLINC=/tmp/kc/package/bin/kotlinc \
JAVA_HOME=/tmp/tc/jdk/jdk4py/java-runtime \
PATH=/tmp/tc/jdk/jdk4py/java-runtime/bin:$PATH \
  tools/perf/run.sh
```

Corpora are written to `$TMPDIR/xsec-perf/` (64 MiB random file + a synthetic APK with in-dex
evidence); nothing large is committed to the repository.

## Device probe

```bash
tools/perf/device-probe.sh before   # run against the pre-hotfix APK
tools/perf/device-probe.sh after    # run against the hotfix APK
```

Portions that need a debug build (`run-as`, StrictMode, `XSecurityPerf` counters) print
`n/a (release build)` instead of a fabricated value. Paste both outputs into §4 of the audit pack.
