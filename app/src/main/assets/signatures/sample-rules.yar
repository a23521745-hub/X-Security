/*
 * X-Security ornek YARA kural seti.
 *
 * BU DOSYA BIR TEHDIT ISTIHBARATI DEGILDIR. Amaci, motorun uctan uca (parser ->
 * kalip derleme -> chunk'li tarama -> condition degerlendirme) calistigini
 * dogrulanabilir kilmaktir. EICAR, antiviirus urunlerini test etmek icin
 * standardlastirilmis zararsiz bir vektordur.
 *
 * Not: `strings:` bolumunde yalnizca tirmakli metin ve hex kaliplari desteklenir;
 * regex (/.../), xor(...), base64(...) ve fullword kullanan kurallar yuklenirken
 * "desteklenmeyen string" sayaciyla raporlanir.
 */

rule Eicar_Test_File
{
    meta:
        description = "EICAR standard anti-malware test file"
        author = "X-Security sample"
        severity = "info"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        any of them
}

rule Android_Suspicious_Packer_Layout
{
    meta:
        description = "Ucuncu taraf sarmalayici/droidbox izleri birakan yayin dosyalari"
    strings:
        $a = "libDexHelper.so"
        $b = "assets/shell.ugc" ascii
        $c = "StubApp" wide nocase
        $d = { 63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 64 65 78 ?? 69 6e 63 65 72 }
    condition:
        any of them
}

rule Zip_Entry_Name_Leak
{
    meta:
        description = "META-INF icinde birakilan gelistirici yollari"
    strings:
        $win = "C:\\Users\\"
        $nix = "/home/build/"
    condition:
        1 of them
}

rule All_Of_Them_Example
{
    meta:
        description = "Iki kalibin BIRLIKTE bulunmasini isteyen kural (all of them)"
    strings:
        $marker = "XSEC-DEMO-MARKER"
        $tail = "XSEC-DEMO-TAIL"
    condition:
        all of them
}
