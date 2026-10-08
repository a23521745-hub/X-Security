#!/usr/bin/env bash
#
# AssoEchap "stalkerware-indicators" CSV'sinden ClamAV .hsb hash veritabani
# uretir: her satirdaki APK tam-dosya SHA-256 ozeti `hash:-1:Android.Stalkerware.<App>`
# satirina donusur (-1 = boyut bilinmiyor; hash eslesmesi tek basina yeterli).
#
# Bu, HypatiaDatabases'in CI'indaki uretim adiminin X-Security karsiligidir:
# Hypatia Guava-serilestirilmis bloom .bin'ler uretir; biz ise motorun dogrudan
# okudugu duz-metin .hsb uretip kendi RSA kanalimizla yayinlariz.
#
# Kullanim:
#   tools/definitions/update-hash-db.sh [csv-url] [cikti] [max-entries]
#
# Varsayilanlar:
#   csv-url     https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/samples.csv
#   cikti       definitions/hashes.hsb   (kuratorluk secim dosyasini UZERINE YAZAR)
#   max-entries 200000                   (ClamHashDatabaseParser.DEFAULT_MAX_ENTRIES ile ayni)
#
# Notlar:
#   - Alistirici ortamda ag kisitli olabilir; betik CSV'yi once indirir, sonra
#     isler. Elle indirdiginiz bir CSV'yi de ilk arguman olarak verebilirsiniz.
#   - Uretimden SONRA definitions/db-version.txt'yi +1 yapmayi unutmayin;
#     yoksa istemciler (ayni defVersion) yeni paketi KURMAZ.
#   - Kaynak lisansi CC BY 4.0: dosya basindaki atif yorumlari silmeyin.
set -euo pipefail

CSV_URL="${1:-https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/samples.csv}"
OUT="${2:-definitions/hashes.hsb}"
MAX_ENTRIES="${3:-200000}"

command -v curl >/dev/null || { echo "curl gerekli (Termux: pkg install curl)" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 gerekli (Termux: pkg install python)" >&2; exit 1; }

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

if [[ -f "$CSV_URL" ]]; then
    cp "$CSV_URL" "$TMP"
else
    echo "CSV indiriliyor: $CSV_URL"
    curl -fsSL "$CSV_URL" -o "$TMP" || { echo "CSV indirilemedi: $CSV_URL" >&2; exit 1; }
fi

python3 - "$TMP" "$OUT" "$MAX_ENTRIES" <<'PYEOF'
import csv
import hashlib
import re
import sys
from datetime import datetime, timezone

src, out_path, max_entries = sys.argv[1], sys.argv[2], int(sys.argv[3])
HEX64 = re.compile(r"[0-9a-f]{64}")

# EICAR standart antivirus test dizisi: ozetler burada hesaplanir, elle kopyalanmaz.
EICAR = rb'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

entries = []          # (hash, size, name) sirasiyla
seen = set()
skipped_bad_hash = 0
skipped_bad_name = 0
duplicates = 0

with open(src, newline='', encoding='utf-8', errors='replace') as fh:
    reader = csv.reader(fh)
    header = next(reader, None)
    for row in reader:
        if not row:
            continue
        # Beklenen kolonlar: SHA256, Package Name, Certificate, Version, App
        sha = row[0].strip().lower() if len(row) > 0 else ''
        app = row[4].strip() if len(row) > 4 else ''
        if not HEX64.fullmatch(sha):
            skipped_bad_hash += 1
            continue
        if not app:
            skipped_bad_name += 1
            continue
        if sha in seen:
            duplicates += 1
            continue
        seen.add(sha)
        # Isimde ':' sorun degil (parser limit=3 split ismin icindekileri korur)
        # ama satir formatini bozan kontrol karakterlerini eleyelim.
        name = 'Android.Stalkerware.' + re.sub(r'[\r\n\t:]', '', app).strip()
        entries.append((sha, -1, name))

# EICAR uc ozeti basa ekle (boyut biliniyor: 68 bayt).
eicar_entries = [
    (hashlib.md5(EICAR).hexdigest(), len(EICAR), 'Eicar.Test-File'),
    (hashlib.sha1(EICAR).hexdigest(), len(EICAR), 'Eicar.Test-File'),
    (hashlib.sha256(EICAR).hexdigest(), len(EICAR), 'Eicar.Test-File'),
]
entries = eicar_entries + entries

if len(entries) > max_entries:
    print(f"HATA: {len(entries)} girdi limiti ({max_entries}) asiyor; "
          f"motor bu dosyayi yuklemeyi reddeder. Kaynagi daraltin.", file=sys.stderr)
    sys.exit(1)

lines = [
    "# X-Security hash imza veritabani (ClamAV .hsb sozdizimi) - OTOMATIK URETIM",
    f"# Uretim: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} (tools/definitions/update-hash-db.sh)",
    "# Satir formati: <hash>:<boyut>:<isim>  (hash uzunlugu algoritmayi belirler:",
    "#   32=MD5, 40=SHA-1, 64=SHA-256; boyut -1/* = bilinmiyor)",
    "#",
    "# Kaynak: AssoEchap stalkerware-indicators, https://github.com/AssoEchap/stalkerware-indicators",
    "#         (APK tam-dosya SHA-256 ozetleri, samples.csv)",
    "# Lisans: CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/",
    "#         (kaynak belirtilerek yeniden dagitilir; bu atif yorumlarini koruyun)",
    "#",
    "# Eicar.Test-File satirlari betikte hesaplanan sabit ozetlerdir.",
    "",
]
lines += [f"{h}:{s}:{n}" for (h, s, n) in entries]
lines.append("")

with open(out_path, 'w', encoding='utf-8', newline='\n') as fh:
    fh.write("\n".join(lines))

print(f"Yazildi: {out_path}")
print(f"  toplam imza : {len(entries)} (3 EICAR + {len(entries) - 3} stalkerware)")
print(f"  atlanan     : {skipped_bad_hash} gecersiz hash, {skipped_bad_name} isimsiz, {duplicates} tekrar")
PYEOF

echo "Sonraki adim: definitions/db-version.txt'yi +1 yapin ve publish-definitions.sh ile yayinlayin."
