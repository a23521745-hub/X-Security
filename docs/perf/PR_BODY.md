# perf(p0): Exynos 2400 UI jank hotfix — hoisted safelist queries, lazy lists, coalesced progress, IO cold start

Optimization hotfix for the Exynos 2400 jank report. Measured first, top offenders only, **no
behaviour change beyond update granularity**, and **no change** to the engine, YARA/ClamAV parsers,
rule denylist, verdict/quarantine logic, OTA, `SignatureVerifier` or workflows. **No version bump**
in this patch. `definitions/*` and `app/src/main/assets/signatures/*` are byte-identical to `main`.

Audit pack with the full before/after tables: [`docs/perf/PERF_AUDIT.md`](PERF_AUDIT.md).
Raw harness reports: [`hotfix-before.txt`](hotfix-before.txt) · [`hotfix-after.txt`](hotfix-after.txt).

## Base / rebase (gate item 2)

| Question | Answer |
| --- | --- |
| Is PR #22 merged? | **Yes** — merge commit `b6a0c87`, merged 2026-10-13T22:17:02Z |
| What is `main` now? | `8cebdfc` — the release workflow's *Commit and Push Updated Files* step bumped `versionCode` 19 → 20 and rewrote `update.json`. That commit is a **root commit** (the bot pushed a fresh tree). |
| Base of this PR | rebased onto `8cebdfc`, so it is based on the **updated** main, as required |
| Effect of the rewrite | `git diff main...HEAD` is impossible on this branch (`fatal: no merge base`). The exact patch is `git diff origin/main..HEAD` / `--stat` (see the gate message for the full list). |

## Measurement provenance (nothing here is a guess)

No device/emulator/Android SDK existed in the environment that produced this branch (pip + npm
egress only; Google Maven/Gradle hosts unreachable), so every number is labelled:

* **[JVM]** — `tools/perf/run.sh` compiles the app's *pure Kotlin* surface (production engine,
  parsers, matcher, plus the two new classes) and measures it; the baseline is read from git with
  `REV=HEAD`, so both sides use the same harness. Reports are committed.
* **[CODE]** — deterministic call-site counts read from the source.
* **[SMOKE]** — felt on the owner's phone. `tools/perf/device-probe.sh` stays in the repo as an
  optional numeric deep-dive but is **not** required to close this gate.

**No device figure appears in this PR that was not measured on a device.**

## Before → after

### [JVM] in-sandbox, same harness both sides

| # | Measurement | Before | After | Δ |
| --- | --- | --- | --- | --- |
| J1 | Signature-DB parse, median of 3 (cold first load in parentheses) | 4.0 ms (72.7 ms) | 4.5 ms (75.1 ms) | unchanged — engine byte-identical (guard, not a claim) |
| J2 | Throughput, 64 MiB raw corpus | 199.7 MB/s | 226.0 MB/s | run-to-run noise; engine untouched |
| J3 | Throughput, ZIP/APK corpus with in-dex evidence | 203.9 MB/s | 220.4 MB/s | same noise band |
| J4 | PackageManager queries — 400-row list × 30 recompositions | **12 000** | **400** (11 600 hits) | **30×**; 0 per scroll after warm-up |
| J5 | Progress publications per 400-app scan | **400** | **21** (+start) | **18×** |

### [CODE] offender call sites changed

| Suspect | Evidence before | Fix |
| --- | --- | --- |
| (a) safelist PackageManager query per recomposition | `QuarantineScreen.kt:120` — per row, per recomposition (J4) | `SystemPackageCache` + `rememberSystemPackageCache()` (invalidated on `PACKAGE_ADDED/REMOVED/CHANGED`, fail-safe preserved: blank/unclassifiable ⇒ system, failures never cached) |
| (a′) `currentVersionCode` in composition | `MainActivity.kt:312`, `:360` — per recomposition | resolved once |
| (b) non-lazy lists | `PrivacyAdvisorScreen` (≤400 rows), `QuarantineScreen`, `HistoryScreen` | `LazyColumn` + stable keys |
| (c) main-thread cold-start DB/IO | SQLite open+`all()`, ≤400-entry / ≤200-entry JSON decodes, asset reads, 13 prefs loads, ≤10 `su` stats, WorkManager enqueues — all on main | all moved to `Dispatchers.IO` **in the original order** (proof table in the audit, §2a); Compose-state probes stay on main |
| (d) parsing on the UI thread | engine reload on IO, asset reads were not | phishing blocklist + signature asset work off main (J1 justifies it); engine reload now sequenced **after** the bundled-signature install, closing a first-install race |
| (e) notification spam | `DeviceScanWorker` posted progress once **per app** | `ProgressCoalescer` (5 % step + 500 ms floor, 100 % always published) → 21 (J5); EDR alerts were already deduplicated |
| (f) worker frequency | audited: 96 pulse + 3 daily ≈ **4.1 scheduled wakeups/hour**, all `KEEP` | **unchanged** — shortening the pulse changes detection latency (product decision) |
| (g) verdict-cache misses | inspected: `versionCode` + `lastUpdateTime` must match, system re-checked, mismatch deletes the entry; PM calls only on IO callers | **no defect found**, unchanged |
| (h) asset-size wins | 25 KB of assets in total | **no win available**, unchanged |

## Gate item 3 — confirmations

| Check | Result |
| --- | --- |
| Engine / parser / matcher / denylist change | **none** — no file under `engine/`, `yara/`, `clamav/`, `matcher/`, `core/Digest.kt` is modified (only `core/ProgressCoalescer.kt` is added) |
| `.github/workflows` change | **none** |
| `ota/` change | **none** |
| `SignatureVerifier` change | **none** |
| Version bump | **none in this patch** (the 19 → 20 bump on `main` came from the release bot) |
| TR + EN symmetry | **kept** — no string resource touched in either `values/strings.xml` or `values-tr/strings.xml`; the new code references existing keys only |
| `.gradle/`, build output, handoff artifacts | **none** — the patch adds sources, tests, `docs/perf/*` and `tools/perf/*` only |
| Behaviour change | **none in decisions/values**; only update granularity + lazy row composition + a few ms of state-publication timing (full list in the audit, §5) |

## Acceptance

| Criterion | Status |
| --- | --- |
| Smooth 400-app scroll | 30× fewer binder calls (J4) + lazy rows; **owner phone smoke test pending** |
| Cold start p50 < 2 s | cold-start disk/DB/scheduling off main (F3/F3b/F3c, order proof in audit §2a); **owner phone smoke test pending** |
| StrictMode-clean debug | StrictMode enabled in debug (`penaltyLog`); every main-thread disk/DB/asset call found in the startup path moved; **owner smoke test on a debug build pending** |
| Suite green | 14 new regression locks (`SystemPackageCacheTest`, `ProgressCoalescerTest`); **CI green on the rebased head `e0530b7`** — run [38536642671](https://github.com/a23521745-hub/X-Security/actions/runs/38536642671): `Run Unit Tests` ✓, `Run Android Lint Checks` ✓, `Build Release APK` ✓ (pre-rebase runs: [38478814170](https://github.com/a23521745-hub/X-Security/actions/runs/38478814170), [38479725828](https://github.com/a23521745-hub/X-Security/actions/runs/38479725828)) |

### Owner phone smoke test (replaces `device-probe.sh` for this gate)

Build/install this branch (`./gradlew :app:assembleStandardDebug`) on the Exynos 2400, then judge by
feel — numbers optional:

1. **cold start feel** — force-stop → launch ×10: no perceptible stall;
2. **400-app scroll** — Privacy Advisor full list (and Quarantine) scrolled up/down: smooth, no
   hitch as rows appear;
3. **(debug)** `adb logcat -d -s StrictMode:v` right after launch: empty; optional
   `adb logcat -d -s XSecurityPerf:I` before/after scrolling: `lookups=` must not grow.

Results are recorded in `docs/perf/PERF_AUDIT.md` §4b before merge.

## Scope discipline

* Only visible differences are update granularity (~5 % steps), lazy row composition and a few ms of
  state-publication timing; no decision, verdict, quarantine, notification-content, scheduling,
  gating or string change.
* Rollback = revert this patch; nothing persisted changes shape.
