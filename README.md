# X-Security 0.91 Pre-Release

A small, fully on-device Android APK scanner: it parses YARA rules and ClamAV `.ndb`
signature files locally and scans files with a memory-bounded streaming matcher.
No network permission is requested at all.

## What the engine actually does

| Layer | Supported today | Not supported (counted and reported, never silently dropped) |
| --- | --- | --- |
| YARA | `rule` / `private rule` / `global rule`, tags, `meta:` (`description`), text strings with `ascii`, `wide`, `nocase`, hex strings with `??`/`A?` nibble wildcards, `condition:` subset: `any/all/none of them`, `N of them`, `any/all/none of ($a, $b*)`, `$a and $b`, `$a or $b`, `not $a` | regex strings (`/.../`), `xor()`, `base64/base64wide`, `fullword`, string arrays, and the full YARA grammar (`for`, `at`, `uint16()`, modifiers on hex strings). Unparsable conditions fall back to `any of them` and are flagged as *approximated*. |
| ClamAV `.ndb` | `Name:TargetType:Offset:Hex[:MinSize,MaxSize]`, `??`/`A?`/`?B` nibble wildcards, numeric offsets (`n`, `n,len`) enforced as real position constraints | variable-length `*` wildcards, `|n-m|` jumps, `(a|b)` alternatives, symbolic offsets (`e`, `x`, `le`, `be`, `"str"#n` — matched anywhere and counted), `TargetType` filtering (all signatures are searched file-wide, counted as possible false positives) |
| Scanning | whole-file streaming in 64 KiB chunks with an overlap window so patterns that cross a chunk boundary are found; first-byte bucketing; content hashed with SHA-256 for dedup | `condition` features above; a hard `maxBytesToScan` guard (512 MiB default) that reports truncation instead of silently under-scanning |

**This is a pattern scanner, not a libyara/libclamav binding.** It cannot be your only
protection, and an "engine unavailable" result is reported as a failure — never as
"clean".

## Structure

```
app/src/main/java/org/xsecurity/scanner/
  ui/MainActivity.kt              launcher activity, SAF pickers, engine bootstrap
  ui/screens/DashboardScreen.kt   state-driven dashboard (no fake statuses)
  ui/theme/                       Material 3 colour scheme + typography
  data/SignatureStore.kt          bundled + user-supplied signature files in app storage
  data/ScanController.kt          stages the picked file, enqueues WorkManager work
  data/ScanStore.kt               in-process state + persisted last result (JSON in prefs)
  data/ScanNotifications.kt       progress/result notification
  engine/ApkScannerEngine.kt      orchestrates both layers, produces ScanResult
  engine/ScanEngines.kt           fingerprint-aware engine cache (invalidates on change)
  yara/                           YaraRuleParser, YaraCondition, YaraScanner
  clamav/                         ClamAvDatabaseParser, ClamAvScanner
  matcher/                        BytePattern, BytePatternMatcher, HexPatternCodec (shared)
  worker/ApkScanWorker.kt         CoroutineWorker: never crashes the app, small output
app/src/main/assets/signatures/   sample .yar + .ndb used by tests and first launch
app/src/test/java/...             JVM unit tests for the parser/matcher/engine
```

## Signature files

On first launch the app copies `assets/signatures/sample-rules.yar` and
`assets/signatures/sample-signatures.ndb` into `filesDir/signatures/`. Use the
"Pick .yar" / "Pick .ndb" buttons in the app to install your own rule set (for example a
real ClamAV `daily.ndb`, filtered to the supported syntax). Copies are made into app
private storage, so no storage permission is required under scoped storage.

## Resource decisions

- Streaming scan with a fixed chunk plus a `longestPattern - 1` carry window (no
  whole-file buffering, and patterns that straddle a chunk boundary are still found).
- First-byte bucketing so most bytes are rejected with one hash lookup.
- 512 MiB per-file scan guard, surfaced as a warning in the result.
- Staged copies live in `cacheDir/scans/`, are deduplicated by SHA-256 and deleted after
  a successful scan; stale copies are purged.
- `WorkManager` with `ExistingWorkPolicy.KEEP`, no `INTERNET`, no foreground service.

## Building

Requires JDK 17 and an Android SDK with `platforms;android-35` and `build-tools;34.0.0`.
`local.properties` is machine-local and ignored by git — set `sdk.dir` yourself or export
`ANDROID_HOME`.

```bash
./gradlew :app:assembleDebug          # debug APK
./gradlew :app:testDebugUnitTest      # engine/parser unit tests (pure JVM)
./gradlew :app:lintDebug              # lint, incl. fatal MissingClass check
./gradlew :app:assembleRelease        # unsigned unless signing is configured
```

### Release signing

`app/build.gradle.kts` reads signing material from Gradle properties or environment
variables; with none set, the release build stays unsigned and Gradle logs a warning:

```
-DxsecKeystore=/path/release.jks -DxsecKeystorePassword=... -DxsecKeyAlias=... -DxsecKeyPassword=...
# or: XSEC_KEYSTORE, XSEC_KEYSTORE_PASSWORD, XSEC_KEY_ALIAS, XSEC_KEY_PASSWORD
```

R8 is intentionally **off** for this pre-release (`isMinifyEnabled = false`): obfuscation
adds no real security here, and an unverified optimizer could change scan behaviour.
`app/proguard-rules.pro` already contains the keep rules you would need if you turn it on.

## CI

The repaired pipeline lives in **`.github/ci/android-release-apk.yml`**, outside
`.github/workflows/`: the automation account used to prepare this branch has no
`workflows` permission, so GitHub rejects any push that touches that directory.
Activate it with:

```bash
git mv .github/ci/android-release-apk.yml .github/workflows/android-release-apk.yml
git commit -m "ci: enable the JDK 17 + unit test + lint + release pipeline"
```

It runs unit tests and lint, then `:app:assembleRelease` (signed when the `XSEC_*`
secrets exist, unsigned otherwise) and uploads the APK plus lint/test reports on
failure. The workflow currently still under `.github/workflows/` is the old, broken one
(wrong job id, no SDK setup, no tests) and is only kept so this branch could be pushed.

## Before publishing on Google Play

- Play requires new apps/app updates to target **Android 16 (API 36)** from
  31 Aug 2026 (existing apps at least API 35). This project compiles and targets
  **API 35**; moving to 36 needs an AGP upgrade (8.6+ for API 35, 8.9+ for API 36) —
  `compileSdk`/`targetSdk` are the only knobs, but remember that API 35+ forces
  edge-to-edge (already handled in `MainActivity` via `enableEdgeToEdge()`).
- `android:usesCleartextTraffic`/network config is not needed: the app has no network
  permission.

## Pre-release status

- Unit tests cover the YARA parser (the rule shapes the old line-based parser dropped),
  the chunk-boundary matcher, `.ndb` offset/mask handling and the engine's
  "no signatures → error, never clean" contract.
- On-device verification still requires running the app; the CI build is the automated gate.
