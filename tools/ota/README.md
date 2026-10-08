# OTA (over-the-air) updater — operator tooling & security model

X-Security runs entirely on-device; the **only** thing it ever uses the network for
is its own signed, user-driven update channel (`org.xsecurity.scanner.ota`). This
directory holds the operator tooling for that channel.

## Threat model / guarantees

An update is accepted **only** when **all** of these hold:

1. **Transport** — the manifest *and* the APK are fetched over **HTTPS** from a host
   in a compile-time **allowlist** (`UrlPolicy`). Redirects are followed manually and
   every hop is re-checked against the allowlist (max 3 hops); cleartext is blocked
   both in code and by `@xml/network_security_config`.
2. **Manifest authenticity** — the raw `update.json` bytes must carry a valid
   signature that verifies against the public key embedded in the build
   (`SignatureVerifier`). Supported algorithms: **RSA-2048 / SHA-256 (PKCS#1 v1.5)**
   (default; works on every supported device) and **Ed25519** (shorter signatures on
   modern devices — unsupported crypto providers fail closed, never "valid"). The
   manifest is *never parsed before the signature is verified* — an unsigned or
   tampered manifest is rejected outright, and so is one signed with a different key.
3. **APK integrity & resumable transport** — the APK is streamed to a `.part` file
   while its SHA-256 and length are computed; the bytes must match
   `apkSha256` / `apkSizeBytes`, and a hard size cap (~200 MiB) applies. Interrupted
   downloads resume where they stopped (`Range: bytes=N-` + `If-Range: <etag>`);
   a `200` answer means the file changed on the server and the download restarts.
   Any integrity mismatch aborts and deletes the partial file. Only a fully verified
   file is atomically renamed into place — a partial file never reaches the installer.
4. **Identity & no-downgrade** — before install the package's `packageName` must equal
   `org.xsecurity.scanner` and its `versionCode` must be *higher* than the installed
   one. Android itself additionally requires the update to be signed with the **same
   release signing key** as the installed app, or the OS refuses to install it.
5. **User consent** — there is **no silent install**. After a verified download the app
   shows an "Install" action; tapping it opens Android's standard package-installer
   prompt (and, on Android 8+, routes the user to the "install unknown apps" settings
   if the permission is missing). The final decision is always the user's.

In short: a network attacker cannot swap the APK (HTTPS + allowlist + RSA + SHA-256),
and a hostile manifest hosted on an allowlisted domain cannot install anything without
the matching signature key **and** a user tap.

## Files

| File | Purpose |
| --- | --- |
| `generate-ota-key.sh` | Creates an RSA-2048 keypair (`ota-signing-private.pem` / `ota-signing-public.pem`). For an Ed25519 keypair instead: `openssl genpkey -algorithm ed25519 -out ota-signing-private.pem && openssl pkey -pubout -in ota-signing-private.pem -out ota-signing-public.pem` (Ed25519 needs Android 13+ / JVM 15+ on the client — keep RSA for broad device coverage). The private key is secret and stays offline — never commit it. |
| `sign-manifest.sh <update.json> <private.pem>` | Signs the manifest and writes `update.json.sig` next to it. Signs the **exact file bytes** — re-sign after any edit. |
| `sample/update.json` + `sample/update.json.sig` | A worked example, signed with the bundled **development** key. |
| `ota-signing-dev-public.pem` | The development public key. This is the key compiled in as `OtaConfig.SAMPLE_PUBLIC_KEY_PEM` for builds that don't inject their own. **Do not use for production releases.** |

## Publishing an update

1. Build the signed release APK (existing `XSEC_*` keystore secrets).
2. Compute its checksum: `sha256sum app-release.apk`.
3. Write `update.json`:

   ```json
   {
     "versionCode": 5,
     "versionName": "0.93.0",
     "apkUrl": "https://updates.example.com/x-security/app-release.apk",
     "apkSha256": "<64 hex chars>",
     "apkSizeBytes": 1234567,
     "minSdk": 26,
     "forceUpdate": false,
     "changelog": "- fix A\n- feature B",
     "releaseNotes": "Short, user-facing notes."
   }
   ```

   Schema notes (all fields are validated on-device):

   | Field | Meaning |
   | --- | --- |
   | `versionCode` | required, positive, must **increase** — downgrades are refused |
   | `versionName` | required, non-blank human version |
   | `apkUrl` | required, `https://` on an allowlisted host |
   | `apkSha256` | required, exactly 64 lowercase hex chars |
   | `apkSizeBytes` | required, positive; checked against the downloaded length |
   | `minSdk` | lowest Android API the update supports; a device below it never sees the update |
   | `forceUpdate` | optional (default `false`): server marks the update as mandatory; the app shows it prominently (there is still no silent install) |
   | `changelog` | optional detailed change log shown in the update card |
   | `releaseNotes` | optional short note (legacy field, still supported) |

4. Sign it: `tools/ota/sign-manifest.sh update.json /secure/path/ota-signing-private.pem`.
5. Upload **both** `update.json` and `update.json.sig` to the allowlisted host, and the
   APK to `apkUrl`. Serve them over HTTPS. Do **not** re-encode or re-save
   `update.json` after signing (it would invalidate the signature).

> **Server tip:** keep `ETag` (or `Last-Modified`) and `Accept-Ranges: bytes` enabled
> on the APK URL. The client stores the `ETag` and resumes with
> `Range: bytes=N-` + `If-Range: <etag>` after an interruption, so users on flaky
> connections don't restart a 100 MB download from zero.

## Build configuration

The update endpoint and verification key are injected at build time — never hard-coded
in source (see `app/build.gradle.kts`):

| Gradle property | Env var | Meaning |
| --- | --- | --- |
| `xsecOtaManifestUrl` | `XSEC_OTA_MANIFEST_URL` | Full `https://…/update.json` URL. Empty = OTA disabled ("not configured"). |
| `xsecOtaPublicKeyPem` | `XSEC_OTA_PUBLIC_KEY_PEM` | Public key (PEM or single-line base64). Empty falls back to the dev sample key. |
| `xsecOtaAllowedHosts` | `XSEC_OTA_ALLOWED_HOSTS` | Comma-separated host allowlist. The manifest host is added automatically. |

Example:

```bash
./gradlew :app:assembleRelease \
  -PxsecOtaManifestUrl='https://updates.example.com/x-security/update.json' \
  -PxsecOtaPublicKeyPem="$(tr -d '\n' < ota-signing-public.pem)" \
  -PxsecOtaAllowedHosts='updates.example.com,cdn.example.org'
```

> For CI, store these as GitHub secrets/env vars (the public key is not secret; the
> manifest URL and host list simply ship in the build). The APK **release signing**
> key is separate and continues to use the existing `XSEC_KEYSTORE_*` secrets.

## Key hygiene

- The OTA *signing* key (manifest signatures) and the APK *release signing* keystore
  are **two different secrets**. Compromise of either alone is not enough to ship an
  accepted update to existing installs (you need both to pass OS install checks).
- Rotate by generating a new OTA keypair and shipping a release whose embedded public
  key is the new one; subsequently sign manifests with the new private key.
- Consider certificate pinning of the update host in `network_security_config.xml` for
  production, as a further layer on top of the allowlist.
