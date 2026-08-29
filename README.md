# X-Security 0.93 Pre-Release

A small, fully on-device Android APK scanner: it parses YARA rules, ClamAV `.ndb`
byte signatures and ClamAV `.hsb` file-hash signatures (MD5/SHA-1/SHA-256)
signature files locally and scans files with a memory-bounded streaming matcher.

**Network use:** all scanning and signature matching happens on-device. Network
features are limited to a **cryptographically verified update channel**
(`org.xsecurity.scanner.ota`): it contacts an allowlisted HTTPS host, only
accepts a manifest signed by the embedded RSA key, verifies the downloaded APK's
SHA-256, and never installs anything without the user's explicit confirmation via the
system installer. The same signed channel also delivers **signature database
(definitions) packages**, which are verified and applied automatically
(`org.xsecurity.scanner.definitions`). See [Over-the-air updates](#over-the-air-updates).

## What the engine actually does

| Layer | Supported today | Not supported (counted and reported, never silently dropped) |
| --- | --- | --- |
| YARA | `rule` / `private rule` / `global rule`, tags, `meta:` (`description`), text strings with `ascii`, `wide`, `nocase`, hex strings with `??`/`A?` nibble wildcards, `condition:` subset: `any/all/none of them`, `N of them`, `any/all/none of ($a, $b*)`, `$a and $b`, `$a or $b`, `not $a` | regex strings (`/.../`), `xor()`, `base64/base64wide`, `fullword`, string arrays, and the full YARA grammar (`for`, `at`, `uint16()`, modifiers on hex strings). Unparsable conditions fall back to `any of them` and are flagged as *approximated*. |
| ClamAV `.ndb` | `Name:TargetType:Offset:Hex[:MinSize,MaxSize]`, `??`/`A?`/`?B` nibble wildcards, numeric offsets (`n`, `n,len`) enforced as real position constraints | variable-length `*` wildcards, `|n-m|` jumps, `(a|b)` alternatives, symbolic offsets (`e`, `x`, `le`, `be`, `"str"#n` — matched anywhere and counted), `TargetType` filtering (all signatures are searched file-wide, counted as possible false positives) |
| Scanning | whole-file streaming in 64 KiB chunks with an overlap window so patterns that cross a chunk boundary are found; first-byte bucketing; content hashed with SHA-256 for dedup; **APK/ZIP entry scanning** — deflated entries (`classes.dex`, `AndroidManifest.xml`, `assets/`, …) are decompressed within a fixed budget (64 MiB total, 32 MiB per entry, 384 entries) and scanned with the same pattern set, so in-dex evidence like `com/metasploit/...` is not lost to compression | `condition` features above; a hard `maxBytesToScan` guard (512 MiB default) that reports truncation instead of silently under-scanning; entries beyond the ZIP content budget are skipped with a warning |

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
  definitions/                    signed definitions (signature database) OTA channel
  worker/ApkScanWorker.kt         CoroutineWorker: never crashes the app, small output
  worker/OtaCheckWorker.kt        daily signed-manifest check (WorkManager, network-constrained)
  worker/OtaDownloadWorker.kt     resumable, verified APK download (WorkManager + backoff)
  worker/DefinitionsUpdateWorker.kt  daily/one-shot definitions check + verified install
app/src/main/assets/signatures/   curated .yar + .ndb + .hsb (mirrors definitions/), used at first launch
definitions/                      curated signature package + versioning + content policy
app/src/test/java/...             JVM unit tests for the parser/matcher/engine
```

## Signature files

On first launch the app copies the curated package `assets/signatures/rules.yar`,
`assets/signatures/signatures.ndb` and `assets/signatures/hashes.hsb`
(mirroring the repo's `definitions/` directory) into `filesDir/signatures/`.
Use the "Pick .yar" / "Pick .ndb" buttons in the app to install your own rule
set (a manually imported database is never overwritten by the automatic
definitions channel). The hash layer (`.hsb`) arrives via the signed
definitions channel — the OTA feed grows it from the ~30-signature starter
selection to the full stalkerware set (`tools/definitions/update-hash-db.sh`).
Signed definition updates are fetched from the same release channel as app
updates and applied automatically after RSA signature + SHA-256 verification —
see `definitions/README.md` for the content policy and the CI quality gate.

### Community sources (direct)

Besides the signed channel, the **Check for updates** button also refreshes
**community sources** directly (toggle per source in the app):

- **Echap stalkerware-indicators** — `samples.csv` (APK SHA-256 digests, ~2000+)
  converted on-device into ClamAV `.hsb` lines, plus the repo's `rules.yar`
  YARA rules (the engine's `N of them` condition support loads these as-is).
  Both CC BY 4.0, attribution shown in the app.

Security model (deliberately different from the RSA channel, stated in the UI):
the source registry is **baked into the APK** (URLs can only change via the
signed channel), all downloads go through the HTTPS host allowlist
(`UrlPolicy`), payloads are size-capped, and **nothing installs without passing
the engine's own parsers** — CSV→`.hsb` output is re-parsed, YARA files are
probe-parsed and rejected if zero rules survive. Curated/OTA signatures always
win over community duplicates. Sources requiring personal API keys
(MalwareBazaar/ThreatFox since the abuse.ch Auth-Key requirement) are
deliberately excluded; ClamAV's official `.cvd` container is not
redistributable and HypatiaDatabases' Guava-serialized bloom blobs are not
consumed.

## Resource decisions

- Streaming scan with a fixed chunk plus a `longestPattern - 1` carry window (no
  whole-file buffering, and patterns that straddle a chunk boundary are still found).
- First-byte bucketing so most bytes are rejected with one hash lookup.
- 512 MiB per-file scan guard, surfaced as a warning in the result.
- Staged copies live in `cacheDir/scans/`, are deduplicated by SHA-256 and deleted after
  a successful scan; stale copies are purged.
- `WorkManager` with `ExistingWorkPolicy.KEEP`, no foreground service. Network access
  exists **only** for the signed updater described below; the scanner itself is offline.

## Over-the-air updates

The updater lives in `app/src/main/java/org/xsecurity/scanner/ota/`
(`UrlPolicy`, `OtaChecker`, `ApkDownloader`/`ApkVerifier`, `SignatureVerifier`,
`UpdateInfo`, `OtaStore`/`OtaController`, installer, notifications) plus two
WorkManager jobs (`OtaCheckWorker`, `OtaDownloadWorker`) and a UI card. It is
deliberately conservative:

- **HTTPS-only + host allowlist** (`UrlPolicy`): manifest and APK URLs must be
  `https://` on a compile-time allowlisted host; redirects are followed manually and
  each hop is re-checked; cleartext is also blocked by `@xml/network_security_config`.
- **Signature before parse** (`OtaChecker` + `SignatureVerifier`): the raw `update.json`
  bytes must verify against the embedded public key using a strong algorithm selected
  by the key type — **RSA-2048 / `SHA256withRSA`** (default, works on every supported
  device) or **Ed25519** (modern devices; unsupported providers fail closed, never
  "valid"). An unsigned or tampered manifest is rejected before it is ever parsed.
  The signing key is injected at build time (see `tools/ota/README.md`); builds that
  don't inject one ship with a clearly-labelled **development** key.
- **Resumable, atomically-published downloads** (`ApkDownloader` + `ApkVerifier`): the
  APK is streamed to a `<name>.part` file while its SHA-256 and length are computed
  against the manifest, with a hard size cap. Interruptions (network loss, process
  death) keep the `.part` file; the retry continues from where it left off via
  `Range: bytes=N-` + `If-Range: <etag>` (`206` → append, `200` → the representation
  changed and the download restarts, `416` on a complete part → verify only). Only a
  fully hash-verified file is atomically renamed into place — a partial file can never
  reach the installer. Integrity failures (hash/size mismatch, cap exceeded) delete
  the partial data instead of resuming from it.
- **Identity & no downgrade** (`OtaInstaller`): package name must equal
  `org.xsecurity.scanner` and `versionCode` must increase; Android additionally refuses
  to install an APK that isn't signed with the same release key as the installed app.
- **Background work via WorkManager**: the daily signed-update check
  (`OtaCheckWorker`, network-constrained, silent) and the download
  (`OtaDownloadWorker`, network-constrained, exponential backoff) both run through
  WorkManager — no foreground service, no battery-draining polling. Download progress
  is shown transparently as a progress-bar notification (percent), with
  ready/error notifications afterwards.
- **Manifest schema** (`UpdateInfo`): `versionCode`, `versionName`, `apkUrl`,
  `apkSha256`, `apkSizeBytes`, `minSdk` (updates requiring a newer Android version
  than the device are rejected), `forceUpdate` (server-marked mandatory update,
  surfaced prominently in the UI), `changelog` (detailed notes; `releaseNotes` remains
  supported as the short form).
- **No silent install**: after a verified download the user taps **Install**, which
  opens the standard Android package installer (and routes to the "install unknown
  apps" settings on Android 8+ if needed). Nothing installs in the background.
- **Fail-safe error handling & fallback**: every stage reports failures as
  user-readable state instead of crashing — the workers wrap their whole body in
  safe catch blocks, the installer re-verifies the file hash right before launching
  the system prompt (deleting and offering a re-download if the cached file was
  corrupted or tampered with), and the currently installed app is never touched by
  any update failure: a rejected/failed update simply leaves the working version in
  place (the OS installer itself guarantees atomic, same-key, no-downgrade installs).

Operator key/sign tooling and the manifest format are documented in
[`tools/ota/README.md`](tools/ota/README.md). The endpoint URL, verification key and
host list are supplied at build time via `xsecOtaManifestUrl` /
`xsecOtaPublicKeyPem` / `xsecOtaAllowedHosts` (or the `XSEC_OTA_*` env vars); an empty
manifest URL disables the feature and the UI reports "not configured".

## Definition updates (signature database)

The definitions channel (`org.xsecurity.scanner.definitions`) reuses the OTA trust
chain **without any extra build configuration**: the manifest URL is derived from the
OTA manifest URL (`…/update.json` → `…/definitions.json`), the same embedded public
key verifies `definitions.json.sig`, and the same host allowlist applies. Unlike app
updates, a **verified** definitions package (`rules.yar` + `signatures.ndb` +
`hashes.hsb`, each SHA-256-checked) is installed automatically — classic
freshclam behaviour. A manually imported database (SAF picker) is never
overwritten.

Definitions content lives in `definitions/` at the repo root, is mirrored into
`app/src/main/assets/signatures/` for first launch, and is published as release
assets by CI. `DefinitionsQualityTest` acts as a **CI quality gate**: unparsable
rules, unsupported string syntax, approximated conditions, malformed `.ndb`/`.hsb`
lines or
asset/`definitions/` drift fail the build. Content policy, versioning
(`db-version.txt`) and provenance/licensing rules: [`definitions/README.md`](definitions/README.md).

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

The **fixed** pipeline is staged in **`.github/ci/android-release-apk.yml`**: the
automation account used to prepare this branch has no `workflows` permission, so
GitHub rejects any push that touches `.github/workflows/`. Activate it with:

```bash
git checkout .github/workflows/android-release-apk.yml  # eski (kusurlu) surumden kurtul
git mv .github/ci/android-release-apk.yml .github/workflows/android-release-apk.yml
git commit -m "ci: enable the fixed test/lint/release pipeline (signed update.json)"
```

The staged pipeline sets up JDK 17 + the Android SDK, runs the JVM unit tests and
lint (both abort the build on failure), builds the release APK (signed when the
`XSEC_KEYSTORE_*` secrets exist), computes its SHA-256, writes an `update.json`
**with the correct schema and signs it** with the `XSEC_OTA_SIGNING_KEY` secret
(base64 PEM of the OTA private key — without it the manifest stays unsigned and the
app will refuse it), and publishes the APK + manifest + signature as a GitHub
Release. Test/lint reports are uploaded as artifacts on failure.

> The workflow currently still under `.github/workflows/` is the older revision:
> it emits `update.json` with wrong field names (`url`/`sha256`) and never signs
> it, so OTA clients would reject those manifests. Activate the staged fix above
> (a one-time action that needs an account with `workflows` permission).

## Before publishing on Google Play

- Play requires new apps/app updates to target **Android 16 (API 36)** from
  31 Aug 2026 (existing apps at least API 35). This project compiles and targets
  **API 35**; moving to 36 needs an AGP upgrade (8.6+ for API 35, 8.9+ for API 36) —
  `compileSdk`/`targetSdk` are the only knobs, but remember that API 35+ forces
  edge-to-edge (already handled in `MainActivity` via `enableEdgeToEdge()`).
- Cleartext traffic is disabled app-wide via `@xml/network_security_config`
  (`cleartextTrafficPermitted="false"`); the only network caller is the signed
  updater, which is HTTPS + allowlist-only. (For production, consider pinning the
  update host's certificate there as well.)

## Pre-release status

- Unit tests cover the YARA parser (the rule shapes the old line-based parser dropped),
  the chunk-boundary matcher, `.ndb` offset/mask handling and the engine's
  "no signatures → error, never clean" contract.
- On-device verification still requires running the app; the CI build is the automated gate.
