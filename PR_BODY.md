# fix + feat: repair broken engine/OTA code and upgrade to a professional OTA pipeline

This branch does two things:

1. **Repairs the broken tree** — the last commit left the pure-Kotlin engine and OTA
   layers uncompilable (missing APIs, mismatched constructors, wrong filter types).
2. **Upgrades the updater to a professional OTA pipeline** — resumable verified
   downloads, Ed25519 support, extended manifest schema, background checks via
   WorkManager, and fail-safe error handling with fallback behaviour.

## Part 1 — breakages found and fixed (all confirmed by compiling the sources)

| Breakage | Symptom | Fix |
| --- | --- | --- |
| `HexPatternCodec.looksUnsupported()` and `Decoded.length` missing | `ClamAvDatabaseParser` + `YaraRuleParser` did not compile | restored both (detects `*`/`\|n-m\|`/`(a\|b)`/`[n-m]` syntax and reports it as unsupported instead of silently dropping signatures) |
| `YaraString` was an old, incompatible class | `YaraRuleParser` couldn't construct strings (`bytes`/`isText`/`ascii`/`wide`/`nocase` params didn't exist), `YaraScanner`/`ApkScannerEngine` couldn't call `variants()`/`ignoreCase()` | rewrote it with the parser/scanner contract + correct YARA `ascii`/`wide` variant semantics (incl. wide-mask interleaving) |
| `BytePatternMatcher` lost its `maxBytesToScan` constructor parameter | `YaraScanner`/`ClamAvScanner` 3-arg constructor calls failed to compile | restored the parameter; `scan()` now defaults to it (per-scanner limits work again); default re-aligned with the documented 512 MiB guard |
| `positionFilter` type mismatch | `ClamAvScanner` indexed the signature list with a `BytePattern` | filter now receives the pattern **id**, consistent with `matchedIds`/`positions` |
| `consumed` flag leaked across scans | reusing a matcher (same rules, new file) found nothing; a filtered-out first occurrence masked later valid ones | candidates are reset at the start of every `scan()` |
| `any of ($a*)` selector lost its `*` | prefix selectors never matched anything | the parser keeps the trailing `*`; only the `$` prefix is stripped |
| `PackageInfo.longVersionCode` used without an API-28 guard | `NewApi` lint failure (fatal in CI) + `NoSuchMethodError` crash on Android 8.x devices | guarded with `Build.VERSION.SDK_INT >= P`, falling back to the deprecated `versionCode` |
| CI-generated `update.json` used `url`/`sha256` field names and was never signed | the app would reject every CI-published manifest (schema mismatch + missing signature) | CI now emits the real schema (`apkUrl`, `apkSha256`, `apkSizeBytes`, `minSdk`, `forceUpdate`, `changelog`) and signs it with `XSEC_OTA_SIGNING_KEY` |
| `YaraRuleParserTest.escapeSequences…` asserted 4 bytes for `"A\tb\x90C"` | internally inconsistent expectation (the literal `b` cannot vanish) | test corrected to 5 bytes (YARA reference behaviour) |

## Part 2 — professional OTA pipeline

1. **Cryptographic signature verification** (`SignatureVerifier`, renamed from
   `RsaVerifier`): manifest bytes must verify against the embedded key before parsing.
   Algorithms are selected from the key type — **RSA-2048/`SHA256withRSA`** (default,
   all devices) or **Ed25519** (modern devices). Fail-closed everywhere; signature
   mismatch = hard rejection.
2. **Resilient download manager** (`ApkDownloader`): HTTP `Range: bytes=N-` +
   `If-Range: <etag>` resume (`206` → append, `200` → representation changed → restart,
   `416` on a complete part → verify-only). Downloads stream into a `.part` file and
   are only atomically renamed into place after SHA-256 + size verification; network
   interruptions keep the partial file for the retry, integrity failures delete it.
   WorkManager retries with exponential backoff.
3. **Background service & notifications**: daily network-constrained update check
   (`OtaCheckWorker`, `PeriodicWorkRequest`) and the download job run via WorkManager —
   no foreground service, no polling. Progress is shown transparently as a percent
   progress-bar notification, with ready/error notifications afterwards.
4. **Version protocol (JSON schema)**: `versionCode`, `versionName`, `apkUrl`,
   `apkSha256`, `apkSizeBytes`, `minSdk` (device below it never sees the update),
   `forceUpdate` (server-marked mandatory update, shown prominently in the UI) and
   `changelog` (detailed notes; `releaseNotes` still supported). All fields validated.
5. **Error handling & fallback**: every stage reports user-readable state instead of
   crashing (workers wrap their whole body, `Throwable`-safe); the installer
   re-verifies the file hash right before the system prompt and offers a clean
   re-download if the cached file was corrupted; no failure path can remove or break
   the currently installed version.

Also: version bumped to `0.93.0` (versionCode 5), a fresh development OTA keypair +
newly signed sample manifest (`changelog`/`forceUpdate` demonstrated), READMEs
updated, and the CI workflow fixed to emit + sign a valid manifest.

## Test plan

- [x] All JVM unit tests pass (100 tests, incl. 15 new: Ed25519 verification, resume
      decisions, file re-verification, forceUpdate/changelog parsing, minSdk gating).
- [x] `SignatureVerifier` + `UpdateInfo` verified against the committed signed sample
      manifest using the app's own code paths.
- [x] CI: `testDebugUnitTest` + `lintDebug` (fatal `MissingClass`/`NewApi`) + release
      build + signed manifest publication (fixed pipeline staged in
      `.github/ci/` — activating it needs one `git mv` with a `workflows`-enabled
      account; the push bot cannot touch `.github/workflows/`).
- [ ] On-device: check → download (kill mid-download → resume) → verify → Install;
      tampered manifest/APK rejection; unknown-sources routing.
- [ ] Configure a real allowlisted host + production keypair before release.
