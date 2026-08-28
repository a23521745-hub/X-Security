#!/usr/bin/env bash
#
# Bir OTA manifestini (update.json) RSA-SHA256 ile imzalar ve ayni dizine
# "<manifest>.sig" dosyasini yazar. Uygulama, indirdigi manifestin HAM baytlarini
# bu imza ile dogrular; imza gecerli degilse manifest hic ayrıştırılmadan reddedilir.
#
# Kullanim:
#   tools/ota/sign-manifest.sh <manifest.json> <private-key.pem>
#
set -euo pipefail

MANIFEST="${1:?Kullanim: sign-manifest.sh <update.json> <private.pem>}"
KEY="${2:?Kullanim: sign-manifest.sh <update.json> <private.pem>}"

[[ -f "$MANIFEST" ]] || { echo "Manifest bulunamadi: $MANIFEST" >&2; exit 1; }
[[ -f "$KEY" ]]      || { echo "Private anahtar bulunamadi: $KEY" >&2; exit 1; }

SIG="${MANIFEST}.sig"

# Not: imza manifest dosyasinin tam baytlari uzerinden hesaplanir. Manifesti
# imzaladiktan sonra HICBIR sekilde degistirmeyin (tek bir bayt bile imzayi bozar);
# degisiklik yaparsaniz yeniden imzalayin.
openssl dgst -sha256 -sign "$KEY" -out "$SIG" "$MANIFEST"

# Dogrulama (public anahtar yan dosyada varsa):
PUB="$(dirname "$KEY")/ota-signing-public.pem"
if [[ -f "$PUB" ]]; then
  openssl dgst -sha256 -verify "$PUB" -signature "$SIG" "$MANIFEST" >/dev/null \
    && echo "Imza dogrulandi ($PUB)."
fi

echo "Imza yazildi: $SIG"
echo "Manifest ve .sig dosyasini BIRLIKTE, byte byte ayni icerikle yayinlayin."
