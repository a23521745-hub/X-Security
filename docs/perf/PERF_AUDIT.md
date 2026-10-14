# Perf hotfix audit — Exynos 2400 UI jank (2026-10-13)

Branch: `arena/7549ff9e-x-security` → PR **#23** (base `main`).
Base commit: **`8cebdfc`** — `main` after PR #22 (`b6a0c87`) **and** after the release workflow's
`Commit and Push Updated Files` step (v19 → v20). See §6 for the main-history note and the rebase.

This hotfix touches **no** engine, YARA/ClamAV parser, rule denylist, verdict, quarantine, OTA,
`SignatureVerifier` or workflow code, and does **not** bump the version.

## 0. Provenance of every number (read this first)

The environment that produced this branch has **no Android device, no emulator and no Android SDK**
(only pip/npm egress; Google Maven/Gradle hosts are unreachable). Numbers are therefore labelled:

* **[JVM]** — `tools/perf/run.sh` compiles the app's *pure Kotlin* surface (production engine,
  parsers, matcher, plus the two new classes) and runs it on the JVM. Baseline is read straight out
  of git (`REV=HEAD`), so before/after use the same harness. Raw reports committed:
  `docs/perf/hotfix-before.txt`, `docs/perf/hotfix-after.txt`.
* **[CODE]** — a deterministic call-site count from the source (e.g. one PackageManager query per
  row per recomposition). A property of the code, not a guess about timing.
* **[SMOKE]** — felt on the owner's phone (scroll feel + cold-start feel), per §4. The accepted
  device evidence for this gate is the owner's smoke test; `tools/perf/device-probe.sh` remains in
  the repo as an *optional* deep-dive (it prints the same rows as numbers) but is no longer required.

No device figure is extrapolated from a JVM figure anywhere in this document.

## 1. Baseline (measured before the change)

### 1a. [JVM] work that must not run on the UI thread (also a regression guard)

| # | Measurement | Before | After | Δ |
| --- | --- | --- | --- | --- |
| J1 | Signature-DB parse (`assets/signatures`: 3 211 B YARA + 1 847 B `.ndb` + 4 462 B `.hsb`), median of 3 loads (cold first load in parentheses) | **4.0 ms** (72.7 ms) | **4.5 ms** (75.1 ms) | unchanged — the engine is byte-identical (guard, not a claim) |
| J2 | Throughput, 64 MiB raw corpus, median of 3 | 199.7 MB/s | 226.0 MB/s | run-to-run noise (±10 % between JVM repeats); engine untouched |
| J3 | Throughput, ZIP/APK corpus (8 MiB `classes.dex` + manifest + asset, in-dex evidence matches) | 203.9 MB/s | 220.4 MB/s | same noise band |

J1 is why the bundled-signature install and the engine parse must stay off the main thread — see §3(c).

### 1b. [CODE] offender call-site inventory (baseline)

| # | Offender | Baseline count | Evidence |
| --- | --- | --- | --- |
| O1 | `SystemPackageSafelist.isSystemPackage` called from a row composable (`QuarantineScreen` row body) | 1 PackageManager binder query **per row, per recomposition** — 400 rows × 30 recompositions = **12 000** | call site `QuarantineScreen.kt:120`; counted in the harness |
| O1b | `OtaController.currentVersionCode(this)` inside `setContent` | 1 PackageManager query **per recomposition** of the dashboard/settings branch | `MainActivity.kt:312`, `:360` |
| O2 | Non-lazy lists (every row composed at once) | `PrivacyAdvisorScreen` (**≤400 rows**), `QuarantineScreen`, `HistoryScreen` (≤200) | `verticalScroll` + `forEach(Indexed)` |
| O3 | Main-thread cold-start disk/DB | SQLite open + `all()`, JSON decode of ≤400 device-scan entries, file read + JSON decode of ≤200 history entries, phishing asset read + parse, ≤10 `su`-path `stat`s, 13 `SharedPreferences` loads, WorkManager enqueues | `onCreate`/`onResume` call order |
| O4 | Device-scan progress republication | **400** notifications + **400** whole-list republishes per 400-app scan | `DeviceScanWorker.kt:166-171` (no gate; the single-file path already gated at 5 %, `ApkScanWorker.kt:104`) |
| O5 | `PhishingStore.blocklist()` called from composition (asset/file read on first call) | 1 main-thread asset read per process | `MainActivity.kt:337` |
| O6 | EDR alert notifications | already deduplicated 60 s per package+op (`EdrTriggerPolicy.Deduplicator`) | no change needed |
| O7 | Worker cadence | 96 pulse/day (15 min) + 3 daily jobs ≈ **4.1 scheduled wakeups/hour**, all `KEEP`, scans are unique one-time work | `AutopilotSensor.kt:90`, `AutopilotDigestWorker.kt:28`, `OtaController.kt:104`, `DefinitionsController.kt:184` |
| O8 | Bundled payload size | 25 KB of assets in total (16.3 KB signatures + 719 B blocklist + JSON) | `du` of `app/src/main/assets` |

## 2. Changes (each with the measurement that justifies it)

| Fix | Change | Measurement cited |
| --- | --- | --- |
| F1 (`SystemPackageCache`, new) | Safelist answers memoized outside composition, invalidated by `ACTION_PACKAGE_ADDED/REMOVED/CHANGED`; fail-safe kept (blank/unclassifiable ⇒ system ⇒ "no action taken", failures never cached) | O1: **12 000 → 400** binder queries for the 400-row × 30-recomposition case; [JVM] 400 lookups / 11 600 hits / **30×** reduction, 3.78 ms of pure-Kotlin cache cost for all 12 000 answers |
| F1b | `installedVersionCode` resolved once instead of per recomposition | O1b [CODE] |
| F2 | `PrivacyAdvisorScreen`, `QuarantineScreen`, `HistoryScreen` → `LazyColumn` + stable keys | O2 [CODE]: 400-row screen composed all rows per frame before, ~10 after |
| F3 | Cold-start restores moved off the main thread (`Dispatchers.IO`), **order preserved** (see §2a); system probes that publish Compose state stay on main | O3 [CODE] + J1 |
| F3b | `AutopilotScheduler.schedule` + `OtaController/DefinitionsController.schedulePeriodicCheck` moved into the same IO block, still **after** the restores (both read prefs directly — `UpdatePreferences.isAutoCheckEnabled(context)` / `AutopilotSettings.isEnabled(context)` call `getSharedPreferences(...).getBoolean(...)`, never the restored in-memory state — so their values are order-independent; they are kept after the restores anyway) | O3/O7 [CODE] |
| F3c | Engine reload moved **behind** the restore (fix found during gate review): the pre-hotfix order guaranteed `SignatureStore.ensureBundledDefaults` had installed the bundled signatures before the engine read them. With both steps on IO they could race on a **first** install; sequencing them removes the race while keeping the engine load off the main thread | J1 + first-install correctness |
| F4 | `ProgressCoalescer` (5 % step + 500 ms floor; 100 % always published) used by `DeviceScanWorker` and `ApkScanWorker` | O4: **400 → 21** notification posts *and* **400 → 21** list republishes per 400-app scan ([JVM] against the production class) |
| F5 | `PhishingStore.blocklist()` via `produceState` on `Dispatchers.IO` (was an asset read in composition) | O5 [CODE] |
| F6 (probe, debug only) | `PerfProbe`: StrictMode `penaltyLog` (disk/network/slow calls + leaked closables), `cold_start_restore_ms` stage timing, safelist cache counters in logcat; every entry point gated by `BuildConfig.DEBUG` | makes the StrictMode row and the cache-flatness row observable on the phone |
| — | O6 EDR alerts: **no change** | O6 [CODE] |
| — | O7 worker cadence: **no change** (4.1 wakeups/hour; lowering the 5 min pulse changes detection latency = product decision) | O7 [CODE] |
| — | O8 assets: **no change** (25 KB total — no win available) | O8 |

### 2a. Cold-start IO move — order/values proof

The pre-hotfix main-thread sequence in `onCreate` and the post-hotfix sequence, side by side. The
IO block is a single coroutine, so the order **inside** it is exactly the old order; the continuation
runs after it completes, so nothing observes a half-restored state:

| # | Before (main thread, `onCreate`) | After (gate) |
| --- | --- | --- |
| 1 | `enableEdgeToEdge()` | `enableEdgeToEdge()`, `PerfProbe.installDebugProbes()` (debug) |
| 2 | `SignatureStore.ensureBundledDefaults` → … → `QuarantineRepository.restore` (13 stores, in order) | **same 13 calls, same order, inside `withContext(Dispatchers.IO) { restoreLaunchState() }`** |
| 3 | `CommunityStore.publish` | same call, same position (end of the IO block) |
| 4 | `AutopilotScheduler.schedule` → `OtaController.schedulePeriodicCheck` → `DefinitionsController.schedulePeriodicCheck` | same three calls, same order, still after the restores (inside the IO block) |
| 5 | notification channels (`ScanNotifications`/`OtaNotifications`/`AutopilotNotifications`) | unchanged, still main, still before the restores |
| 6 | `refreshEdrSnapshot`, `refreshAutopilotStatus`, `applyProtectionMode`, `requestNotificationPermissionIfNeeded`, `maybeShowAllFilesOnboarding` | same five, same order, on main in `refreshStartupUi(probe)` **after** the IO block |
| 7 | `handleOpenQuarantine(intent)` | unchanged, still main, still before `setContent` |
| 8 | `VaultDeleteFlow.refreshPendingNotifications` (IO) | unchanged (own IO coroutine) |
| 9 | `reloadEngine()` | same call, on main, after the IO block (F3c) — engine parse still on IO |

`onResume` follows the same pattern: the seven store re-reads plus
`QuarantinePendingActionStore.consumeUninstall` run in one IO block; the three system probes
(`refreshEdrSnapshot`, `refreshAutopilotStatus`, `refreshProtection`) and the pending-uninstall
bookkeeping run on main afterwards, exactly as before.

Values: every restore writes the same state objects from the same persisted sources; no store reads
Compose state; no viewer/Compose state is touched from a background thread (`refreshStartupUi` and
the `mutableStateOf` assignments stay on main).

## 3. Suspect list → verdict

| Suspect | Verdict | Basis |
| --- | --- | --- |
| (a) safelisted system PackageManager query per recomposition | **FIXED** (F1, F1b) | instrumented count: 12 000 → 400 over 30 recompositions of a 400-row list; 0 queries while scrolling afterwards |
| (b) non-lazy lists | **FIXED** for the three full-screen lists (F2); deferred for the dashboard's "show all apps" sub-list (nested-scroll UX decision, not a hotfix) | O2 [CODE] |
| (c) main-thread DB/IO | **FIXED** (F3/F3b/F3c): SQLite, JSON decodes, asset reads, prefs, `su` stats and WorkManager enqueues are off main, in the original order; StrictMode is enabled in debug builds to prove it on the phone | O3 [CODE] + [SMOKE] |
| (d) scan parsing on the UI thread | **FIXED** (F3/F5): engine parse and asset reads off-main; measured parse cost J1; engine code itself unchanged | J1 |
| (e) notification spam | **FIXED** (F4): 400 → 21 per 400-app scan; EDR alerts were already deduplicated (O6) | O4, O6 |
| (f) worker frequency review | **AUDITED, unchanged**: 4.1 scheduled wakeups/hour, all periodic work `KEEP`, scans unique one-time work, no duplicate scheduling on cold start | O7 [CODE] |
| (g) verdict-cache misses | **INSPECTED, no defect found**: `KnownBadVerdictCache.get` requires matching `versionCode` + `lastUpdateTime` and re-validates the system safelist; a mismatch deletes the entry (conservative, correct); its PackageManager lookups only happen on `Dispatchers.IO` callers | `KnownBadVerdictCache.kt`, `ForegroundInterceptionPolicy.matchesInstalled` |
| (h) asset-size quick wins | **NO WIN AVAILABLE**: 25 KB of assets in total | O8 |

## 4. Acceptance criteria

| Criterion | Status | Evidence |
| --- | --- | --- |
| Smooth 400-app scroll | structural fix shipped ([JVM] 30× fewer binder calls, lazy rows); **owner phone smoke test pending** | F2/F4 + §4b |
| Cold start p50 < 2 s | cold-start disk/DB/scheduling path cleared (J1 + F3/F3b/F3c + §2a); **owner phone smoke test pending** | F3 + §4b |
| StrictMode-clean debug | StrictMode (`penaltyLog`) enabled in debug; every main-thread disk/DB/asset call found in the startup path moved; **owner smoke test on a debug build pending** | F6 + F3 + §4b |
| Suite green | 14 new regression locks (`SystemPackageCacheTest`, `ProgressCoalescerTest`); CI green on the code commit and on the docs commit of this branch (run URLs in §6) | CI |

### 4a. What the JVM harness can and cannot say

`tools/perf/run.sh` measures engine parse cost, throughput, and the two offender mechanisms. It
cannot feel a frame or a launch: absolute cold-start time, jank percentage and PSS exist only on a
device. They are **not** claimed here.

### 4b. Owner phone smoke test (accepted gate evidence)

Supersedes the `device-probe.sh` requirement for this gate. Owner: build/install this branch on the
Exynos 2400 and judge two things by feel; numbers optional.

| Step | What to do | Pass criteria |
| --- | --- | --- |
| S1 build | `./gradlew :app:assembleStandardDebug` and install (debug enables the StrictMode + perf counters; release artifact also acceptable for the feel checks) | installs and starts |
| S2 cold start feel | force-stop → launch ×10 | no perceptible stall/"white" wait; app visibly ready on first frame-ish |
| S3 400-app scroll | open **Privacy Advisor** with a full list (and Quarantine if it has many records); scroll up/down ×10 | smooth; no hitch when rows appear |
| S4 StrictMode (debug only) | `adb logcat -d -s StrictMode:v` right after S2 | empty (no `StrictMode policy violation`) |
| S5 cache flatness (debug only, optional) | `adb logcat -d -s XSecurityPerf:I` before/after S3 | `lookups=` does not grow while scrolling |
| S6 verdict | report pass/fail per step + free-text note | recorded in this doc before merge |

`tools/perf/device-probe.sh before|after` stays available if a numeric row is ever wanted
(`am start -W` p50, `dumpsys gfxinfo` janky frames, `dumpsys meminfo` PSS, jobscheduler/batterystats
counters); it is simply not required to close this gate.

## 5. Behaviour change list (expected: none — these are the only differences)

| Surface | Difference | Why it is safe |
| --- | --- | --- |
| Device-scan progress notification/list | updates arrive at ~5 % steps, ≥500 ms apart (400 → 21 per 400-app scan) instead of once per app | same start state, same final state, same texts/ids; only intermediate update frequency changes |
| Quarantine / Privacy / History lists | rows are composed lazily while scrolling | same composables, same content, same order, stable keys |
| Cold start | the very first frames may render the pre-restore default state (e.g. an empty list) for the few ms the IO block takes; opening the quarantine screen straight from a notification can show its "empty" text for those few ms before records arrive | purely transient rendering; values identical once the IO block completes (≤ tens of ms) |
| Everything else | **no change** | no decision, verdict, quarantine, notification-content, scheduling, gating or string change; `definitions/*` and `app/src/main/assets/signatures/*` byte-identical |

## 6. Base, rebase and CI

* **PR #22: MERGED** — merge commit `b6a0c87`, merged 2026-10-13T22:17:02Z.
* `main` then moved to **`8cebdfc`** ("chore(release): Auto-build X-Security v20 [skip ci]"), created
  by the release workflow's *Commit and Push Updated Files* step: `versionCode` 19 → 20 and
  `update.json` rewritten. `8cebdfc` is a **root commit** (the bot pushed a fresh tree), so it shares
  no merge base with `b6a0c87`.
* Consequence: `git diff main...HEAD` is **not** a meaningful command on this branch
  (`fatal: main...HEAD: no merge base`). The patch is therefore expressed as
  **`git diff origin/main..HEAD --stat`** / `git diff origin/main..HEAD`, which is exact after the
  rebase onto `8cebdfc`.
* This branch was rebased onto `8cebdfc` so it is based on the *updated* main, as required.
* CI (unit tests + Android lint + release APK build, all green):
  * code commit (pre-rebase) — run [38478814170](https://github.com/a23521745-hub/X-Security/actions/runs/38478814170)
  * docs commit (pre-rebase) — run [38479725828](https://github.com/a23521745-hub/X-Security/actions/runs/38479725828)
  * the rebased head's own run is linked from the PR checks page and quoted in the gate message.

## 7. Scope discipline

* No engine, parser, matcher, rule denylist, `SignatureVerifier`, OTA, workflow or manifest change.
* No version bump in this patch (the 19 → 20 bump on `main` came from the release bot).
* No `.gradle/`, build output or handoff artifacts; only sources, tests, the two docs and
  `tools/perf/*` are added.
* TR + EN symmetric: **no** string resource and **no** `strings.xml` touched; the new code references
  existing keys only (the quarantine notice keeps coming from `scan_result_system_package_notice`
  in both languages).
* Fail-safe kept: `SystemPackageCache` answers "system" for a blank name and for a lookup that
  throws, and does not cache the failure, so a transient PackageManager error cannot pin a package
  out of the safelist.
* Rollback: revert this patch; no persisted data changes shape.
