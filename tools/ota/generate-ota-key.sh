#!/usr/bin/env bash
#
# OTA imzalama anahtari uretir (RSA-2048).
#
# CIKTI:
#   <out>/ota-signing-private.pem  -> GIZLI! Asla depoya commit etmeyin, cevrimdisi saklayin.
#   <out>/ota-signing-public.pem   -> Uygulamaya gomulen/derlemeye verilen public anahtar.
#
# Kullanim:
#   tools/ota/generate-ota-key.sh [cikti-dizini]   (varsayilan: ~/ota_keys)
#
set -euo pipefail

OUT_DIR="${1:-$HOME/ota_keys}"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

PRIV="$OUT_DIR/ota-signing-private.pem"
PUB="$OUT_DIR/ota-signing-public.pem"

if [[ -f "$PRIV" ]]; then
  echo "HATA: $PRIV zaten var. Anahtari yenilemek icin once elle silin." >&2
  exit 1
fi

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$PRIV"
chmod 600 "$PRIV"
openssl rsa -pubout -in "$PRIV" -out "$PUB" 2>/dev/null

echo
echo "Anahtarlar olusturuldu:"
echo "  private (GIZLI):  $PRIV"
echo "  public (gomulur): $PUB"
echo
echo "Public anahtari derlemeye vermek icin:"
echo "  ./gradlew :app:assembleRelease \\"
echo "    -PxsecOtaPublicKeyPem=\"\$(tr -d '\n' < \"$PUB\")\" \\"
echo "    -PxsecOtaManifestUrl='https://updates.example.com/x-security/update.json' \\"
echo "    -PxsecOtaAllowedHosts='updates.example.com'"
echo
echo "CI icin ortam degiskenleri:"
echo "  XSEC_OTA_PUBLIC_KEY_PEM, XSEC_OTA_MANIFEST_URL, XSEC_OTA_ALLOWED_HOSTS"
