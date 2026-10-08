#!/usr/bin/env bash
#
# Tanim paketini (definitions/) elle olusturur, imzalar ve mevcut bir GitHub
# release'ine yukler. Normalde CI bunu her release'de otomatik yapar; bu betik
# CI beklemeden (veya CI bozulursa) manual yayinlama icin yedek yoldur.
#
# Kullanim:
#   tools/definitions/publish-definitions.sh <ota-private.pem> <tag> [repo]
#
# Ornegin:
#   tools/definitions/publish-definitions.sh ~/keys/ota-private.pem v8
#
# Not: <tag> mevcut bir release etiketi olmali (`gh release view <tag>`).
#      Imza, definitions.json dosyasinin TAM baytlari uzerinde RSA-SHA256 ile
#      atilir; imzaladiktan sonra dosyayi degistirmeyin.
set -euo pipefail

KEY="${1:?Kullanim: publish-definitions.sh <ota-private.pem> <tag> [repo]}"
TAG="${2:?Kullanim: publish-definitions.sh <ota-private.pem> <tag> [repo]}"
REPO="${3:-a23521745-hub/X-Security}"

[[ -f "$KEY" ]] || { echo "Private anahtar bulunamadi: $KEY" >&2; exit 1; }
[[ -f definitions/rules.yar ]] || { echo "definitions/rules.yar yok (repo kokunde calisin)" >&2; exit 1; }
[[ -f definitions/signatures.ndb ]] || { echo "definitions/signatures.ndb yok" >&2; exit 1; }
[[ -f definitions/hashes.hsb ]] || { echo "definitions/hashes.hsb yok" >&2; exit 1; }
[[ -f definitions/db-version.txt ]] || { echo "definitions/db-version.txt yok" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl gerekli" >&2; exit 1; }
command -v gh >/dev/null || { echo "gh CLI gerekli" >&2; exit 1; }

DEF_VERSION="$(tr -d '[:space:]' < definitions/db-version.txt)"
YAR_SHA="$(sha256sum definitions/rules.yar | awk '{print $1}')"
NDB_SHA="$(sha256sum definitions/signatures.ndb | awk '{print $1}')"
HSB_SHA="$(sha256sum definitions/hashes.hsb | awk '{print $1}')"
YAR_SIZE="$(stat -c%s definitions/rules.yar)"
NDB_SIZE="$(stat -c%s definitions/signatures.ndb)"
HSB_SIZE="$(stat -c%s definitions/hashes.hsb)"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"

# minAppVersionCode: paketin gerektirdigi en dusuk uygulama surumu.
# Motorun ZIP-icerik tarayicisi versionCode 8 ile geldi; v1 paketi bunu ister.
MIN_APP="8"

cat << EOF > definitions.json
{
  "schemaVersion": 1,
  "defVersion": ${DEF_VERSION},
  "minAppVersionCode": ${MIN_APP},
  "generatedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "files": [
    {
      "kind": "YARA",
      "name": "rules.yar",
      "url": "${BASE_URL}/rules.yar",
      "sha256": "${YAR_SHA}",
      "sizeBytes": ${YAR_SIZE}
    },
    {
      "kind": "CLAM_AV",
      "name": "signatures.ndb",
      "url": "${BASE_URL}/signatures.ndb",
      "sha256": "${NDB_SHA}",
      "sizeBytes": ${NDB_SIZE}
    },
    {
      "kind": "CLAM_HASHES",
      "name": "hashes.hsb",
      "url": "${BASE_URL}/hashes.hsb",
      "sha256": "${HSB_SHA}",
      "sizeBytes": ${HSB_SIZE}
    }
  ]
}
EOF

openssl dgst -sha256 -sign "$KEY" -out definitions.json.sig definitions.json
echo "definitions.json imzalandi (definitions.json.sig)."

# Yaninda public anahtar varsa dogrulama da yap.
PUB="$(dirname "$KEY")/ota-signing-public.pem"
if [[ -f "$PUB" ]]; then
  openssl dgst -sha256 -verify "$PUB" -signature definitions.json.sig definitions.json >/dev/null \
    && echo "Imza dogrulandi ($PUB)."
fi

gh release upload "$TAG" \
  definitions/rules.yar definitions/signatures.ndb definitions/hashes.hsb definitions.json definitions.json.sig \
  --repo "$REPO" --clobber

echo "Yuklendi: ${BASE_URL}/definitions.json (+ .sig, rules.yar, signatures.ndb, hashes.hsb)"
echo "Uygulamada tanim surumu v${DEF_VERSION} olarak gorunecek."
