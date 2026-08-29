/*
 * X-Security curated YARA rule set — definitions v1
 *
 * This file is REAL detection content (unlike the old sample rules): every rule
 * below is written for the engine's supported YARA subset (text strings with
 * ascii/wide/nocase, hex strings, and simple conditions) so that the CI quality
 * gate (DefinitionsQualityTest) can enforce zero unparsable rules, zero
 * unsupported strings and zero approximated conditions.
 *
 * Maintenance rules for this package (see definitions/README.md):
 *  - bump definitions/db-version.txt whenever this file changes;
 *  - keep rules inside the supported subset;
 *  - document provenance for imported rules and keep license notices.
 */

rule Android_Metasploit_Stage_Payload
{
    meta:
        description = "Metasploit android payload classes (com.metasploit.stage / com.metasploit.androidpayload); matches inside the decompressed dex/manifest"
    strings:
        $stage = "com/metasploit/stage" ascii
        $payload = "com/metasploit/androidpayload" ascii
        $manifest = "com.metasploit.stage" wide
    condition:
        any of them
}

rule Android_Metasploit_Jar_Signfile
{
    meta:
        description = "msfvenom APK signature entries (Rex::Zip hardcodes META-INF/SIGNFILE.*); visible in the raw ZIP structure"
    strings:
        $sf = "META-INF/SIGNFILE.SF" ascii
        $rsa = "META-INF/SIGNFILE.RSA" ascii
    condition:
        any of them
}

rule Android_Meterpreter_Stageless
{
    meta:
        description = "Stageless Android Meterpreter root class (com.metasploit.meterpreter.AndroidMeterpreter)"
    strings:
        $class = "com.metasploit.meterpreter.AndroidMeterpreter" ascii
    condition:
        any of them
}

rule Android_Packer_Jiagu
{
    meta:
        description = "Qihoo 360 Jiagu packer native library names (libjiagu*.so)"
    strings:
        $lib = "libjiagu" ascii
    condition:
        any of them
}

rule Android_Packer_Ijiami
{
    meta:
        description = "Ijiami packer markers (ijiami.dat / ijiami.ajm / libexecmain.so)"
    strings:
        $dat = "ijiami.dat" ascii
        $ajm = "ijiami.ajm" ascii
        $exec = "libexecmain.so" ascii
    condition:
        any of them
}

rule Android_Packer_SecNeo_Bangcle
{
    meta:
        description = "SecNeo/Bangcle packer markers (libDexHelper.so / secData0.jar)"
    strings:
        $lib = "libDexHelper.so" ascii
        $jar = "secData0.jar" ascii
    condition:
        any of them
}

rule Android_Suspicious_Accessibility_Overlay_Combo
{
    meta:
        description = "Suspicious permission combo typical of Android banking trojans (accessibility + overlay + boot + SMS); heuristic indicator, not a verdict"
    strings:
        $acc = "android.permission.BIND_ACCESSIBILITY_SERVICE" wide
        $overlay = "android.permission.SYSTEM_ALERT_WINDOW" wide
        $boot = "android.permission.RECEIVE_BOOT_COMPLETED" wide
        $sms = "android.permission.RECEIVE_SMS" wide
    condition:
        3 of them
}

rule Eicar_Test_File
{
    meta:
        description = "EICAR standard anti-malware test file"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        any of them
}
