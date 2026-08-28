# feat: cryptographically verified, user-driven in-app updater (OTA)

Adds an opt-in over-the-air update channel in a new package
`org.xsecurity.scanner.ota`, plus a dashboard card, a WorkManager download job, and
operator tooling. The scanner itself remains fully on-device; the network is used
**only** for signed updates.

## Security model (defence in depth)

An update is accepted only when **all** of these hold:

1. **HTTPS + host allowlist** (`UrlPolicy`): manifest and APK URLs must be `https://`
   on a compile-time allowlisted host. Redirects are followed manually (max 3) and
   every hop is re-checked; cleartext is blocked in code **and** via
   `@xml/network_security_config` (`cleartextTrafficPermitted="false"`).
2. **Signature before parse** (`RsaVerifier` + `OtaChecker`): the raw `update.json`
   bytes must verify against the embedded RSA-2048 public key using `SHA256withRSA`.
   An unsigned/tampered manifest is rejected before it is ever parsed.
3. **APK integrity during download** (`ApkVerifier`/`ApkDownloader`): the file is
   streamed to disk while SHA-256 and length are checked against the manifest, with a
   hard ~200 MiB cap. Any mismatch aborts and deletes the partial file.
4. **Identity & no downgrade** (`OtaInstaller`): package name must equal
   `org.xsecurity.scanner` and `versionCode` must increase. Android additionally
   refuses to install an APK not signed with the same release key as the installed app.
5. **No silent install**: after a verified download the user taps **Install**, which
   opens the standard Android package installer (and routes to "install unknown apps"
   settings on Android 8+ if needed). Nothing installs in the background.

## What changed

- New `ota/` package: `UpdateInfo`, `RsaVerifier`, `UrlPolicy`, `OtaConfig`,
  `OtaChecker`, `ApkVerifier`, `ApkDownloader`, `OtaInstaller`, `OtaStore`,
  `OtaNotifications`, `OtaController`.
- `worker/OtaDownloadWorker.kt` – download + verify job (never auto-installs).
- UI: `ui/screens/OtaUpdateCard.kt` wired into `DashboardScreen` and `MainActivity`.
- Manifest: `INTERNET` + `REQUEST_INSTALL_PACKAGES` permissions, a `FileProvider`
  (shares only `cache/ota/`), and `@xml/network_security_config`.
- `build.gradle.kts`: `buildConfig` enabled; OTA endpoint/key/hosts injected from
  `xsecOta*` Gradle properties or `XSEC_OTA_*` env vars (empty manifest URL = feature
  disabled); `org.json:json` added for JVM unit tests; version bumped to `0.92.0`
  (versionCode 4).
- Strings added in English and Turkish; the previous "no network permission" copy was
  corrected (network is now used solely for signed updates).
- Unit tests (pure JVM) covering URL policy, RSA verification, manifest parsing,
  streaming APK verification, and the verify-before-parse decision path.
- `tools/ota/`: `generate-ota-key.sh`, `sign-manifest.sh`, a signed sample manifest,
  and a README documenting the operator flow and key hygiene. The dev public key is
  included; the private key is never committed.

## Configuration

```
xsecOtaManifestUrl / XSEC_OTA_MANIFEST_URL   https://…/update.json (empty = disabled)
xsecOtaPublicKeyPem / XSEC_OTA_PUBLIC_KEY_PEM RSA public key (PEM or single-line base64)
xsecOtaAllowedHosts / XSEC_OTA_ALLOWED_HOSTS comma-separated host allowlist
```

Builds that don't inject a key ship with a clearly-labelled **development** key.
The OTA signing key is separate from the existing APK release keystore
(`XSEC_KEYSTORE_*`); both are required to ship an accepted update to existing installs.

## Test plan

- [x] `:app:testDebugUnitTest` – new `ota/` JVM tests + existing engine tests pass
      (CI; no JDK/SDK in the authoring sandbox).
- [x] `:app:lintDebug` / `:app:assembleRelease` via CI.
- [ ] On-device: check → download → verify → Install opens system prompt; decline flow;
      unknown-sources settings routing; tampered manifest/APK rejection.
- [ ] Configure a real allowlisted host + production keypair before release.
