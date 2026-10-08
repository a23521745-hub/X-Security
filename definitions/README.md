# X-Security definitions package

This directory is the **curated signature database** that ships with the app
(`app/src/main/assets/signatures/`) and is published as an **RSA-signed
definitions package** on every release (`definitions.json` + `definitions.json.sig`,
served next to `update.json`).

```
definitions/
  rules.yar          curated YARA rules (engine's supported subset only)
  signatures.ndb     curated ClamAV-format .ndb signatures
  hashes.hsb         curated ClamAV-format .hsb file-hash signatures
                     (MD5/SHA-1/SHA-256 in one file; algorithm inferred
                     from hash length: 32/40/64 hex chars)
  db-version.txt     monotonically increasing definition version (integer)
  README.md          this file: content policy, provenance, versioning
```

The app fetches `definitions.json` from the same release channel as the OTA app
update, verifies it with the **same embedded public key** (RSA-SHA256), then
downloads and SHA-256-verifies each listed file and installs it atomically.
See `org.xsecurity.scanner.definitions` in the app source.

## Quality gate (CI-enforced)

`DefinitionsQualityTest` runs in the normal unit-test job and fails the build when:

- any YARA rule is unparsable, uses unsupported string syntax (regex/xor/base64/
  fullword) or has an approximated condition,
- any `.ndb` line is malformed or uses unsupported wildcard patterns,
- any `.hsb` line is malformed (bad hex length, bad size field, empty name)
  or the hash database loads fewer than 30 signatures,
- the bundled assets drift from this directory (byte-for-byte equality),
- `db-version.txt` is missing or not a positive integer.

So a pull request that adds rules the engine cannot fully load **cannot pass CI**.

## Versioning

- Bump `db-version.txt` by **+1** in the same commit that changes `rules.yar`,
  `signatures.ndb` or `hashes.hsb`. Clients only accept `defVersion` strictly
  greater than what they have.
- `minAppVersionCode` (written into `definitions.json` by the release workflow)
  gates definitions that need a newer engine; v1 requires app versionCode 8
  (the first release with the ZIP-content scanner).

## Content policy

1. **No blind imports.** Upstream rule sets are *curation sources*, not
   drop-ins. Most public YARA rules use `pe.`/`androguard.` modules, `filesize`,
   `#`/`@`/`for ... of` conditions or regex strings — none of which this engine
   supports. Imported rules must be rewritten into the supported subset and
   individually justified.
2. **Provenance and licenses are recorded here.** When a rule or signature is
   derived from an upstream project, add a `SOURCES` entry below with the
   upstream repo, license, and what was changed. Ship the upstream license text
   alongside (`LICENSE-*` files) when the license requires it.
3. **Prefer few, precise signatures.** A signature that fires on ordinary apps
   (false positives) is worse than no signature. Heuristic rules must say so in
   their `description` and be named `Android_Suspicious_*`.
4. **Hash signatures (`hashes.hsb`).** A file hash matches the *whole* file —
   one byte changed and the signature misses. This layer is therefore the
   complement, not the replacement, of the pattern layers: it detects
   *known, unmodified* samples (stalkerware APKs distributed as-is) with
   essentially zero false positives, while YARA/`.ndb` patterns catch
   per-build payloads (e.g. msfvenom) that never reuse a hash. Keep the
   mobile-realistic budget in mind: the engine refuses databases above
   200,000 entries (`ClamHashDatabaseParser.DEFAULT_MAX_ENTRIES`); curate
   Android-relevant hashes instead of importing desktop-scale sets.
5. **Direct community sources are a separate layer, never a replacement.**
   The app also refreshes community repos directly (Echap stalkerware-indicators:
   `samples.csv` → on-device `.hsb` conversion + `rules.yar`; registry:
   `app/src/main/assets/community-sources.json`). These files live in
   `filesDir/signatures/community/`, never overwrite curated/OTA files, and are
   validated by the engine's own parsers before install (see
   `org.xsecurity.scanner.community`). Sources needing per-user API keys
   (abuse.ch MalwareBazaar/ThreatFox) are excluded on purpose.
6. **Raw-byte vs content signatures.** Signatures for bytes that live in the
   *ZIP directory structure* (entry names such as `META-INF/SIGNFILE.RSA`) match
   the raw file; signatures for bytes inside `classes.dex` (ASCII) or the binary
   `AndroidManifest.xml` (UTF-16LE — use YARA `wide` or a UTF-16LE hex pattern)
   only match thanks to the ZIP-content scanner.

## SOURCES (v1)

All v1 rules and signatures are **original work** for X-Security, based on
publicly documented, verifiable facts:

- Metasploit's Android payload generation (`rapid7/metasploit-framework`,
  `lib/msf/core/payload/android.rb` + `Rex::Zip`): entry layout, hardcoded
  `META-INF/SIGNFILE.SF`/`SIGNFILE.RSA` signature names, `com/metasploit/stage`
  and `com/metasploit/androidpayload` packages, and the stageless root class
  `com.metasploit.meterpreter.AndroidMeterpreter`. Metasploit is BSD-licensed;
  only factual identifiers are used, no code or rule text copied.
- Packer library file names (`libjiagu*.so`, `ijiami.dat`, `libexecmain.so`,
  `libDexHelper.so`, `secData0.jar`) are widely documented Android packer
  markers (attribution: 360 Jiagu, Ijiami, SecNeo/Bangcle respectively).
- EICAR test string (industry-standard test vector, eicar.org): the three
  `Eicar.Test-File` lines in `hashes.hsb` are the MD5/SHA-1/SHA-256 digests of
  the standard 68-byte test file.
- `hashes.hsb` stalkerware lines (v1 ships a 4-family sample selection:
  1TopSpy, AllTracker, GuestSpy, HelloSpy) are **verbatim SHA-256 APK digests**
  from AssoEchap's `stalkerware-indicators` project
  (https://github.com/AssoEchap/stalkerware-indicators, **CC BY 4.0**).
  Attribution is preserved in the file header; keep it when regenerating.
  Regenerate the full set with `tools/definitions/update-hash-db.sh`
  (fetches `samples.csv`, validates/deduplicates, keeps the EICAR lines,
  writes the header comments).

Future hash-layer curation upstreams (mirroring what HypatiaDatabases
consumes, but always regenerated into plain `.hsb` under our own signing
chain — never shipping their AGPL build pipeline or binary bloom filters):
ClamAV `main/daily` `.hdb/.hsb` (GPL-2.0), abuse.ch MalwareBazaar/ThreatFox
(CC0), ESET's Android stalkerware lists (BSD-2). Do not consume
HypatiaDatabases' `.bin` outputs directly (Guava-serialized, no signature
names, outside our trust chain).

Planned curation upstreams for future versions (each with license obligations —
see policy above): `Yara-Rules/rules` (GPLv2), `Neo23x0/signature-base`
(DRL 1.1), `Raspirus/yara-rules` (curated-distribution model). Do **not** use
`Koodous/rules` (archived 2022) or redistribute ClamAV's official `.cvd`
database (signed container, ~hundreds of MB, not `.ndb`).
