"""
Bundled YARA rules, tuned for precision.

Design rules
------------
* A bundled rule must never fire on ordinary binaries, source code, or
  documentation.  False positives destroy trust faster than a missed heuristic,
  so ambiguous indicators are either removed or demoted to ``low`` (recorded but
  not reported as a finding).
* Binary rules require a real PE header (``uint16(0) == 0x5A4D``) and at least
  two specific indicators.  A bare API name or a single family name is not
  evidence.
* Script/web rules require an actual code construct (``eval($_POST``,
  ``/dev/tcp/``) and are gated to non-PE content, so a security article quoting
  a string does not become a finding.
* Removed outright: ``ransomware_extensions`` (four extension strings matched
  security tooling and notes far more often than ransomware) and
  ``suspicious_child_process`` (file content cannot express a process tree; the
  behavioural check in the process scanner covers that case).

These files are written to ``yara_rules/`` at startup and refreshed whenever
``BUILTIN_RULES_VERSION`` changes.  User-supplied rule files are never touched.
"""

DEFAULT_RULES = {
    "anti_analysis.yar": r'''// Anti-analysis heuristics (informational, never reported on their own)
rule anti_debug {
    meta:
        description = "Debugger checks (heuristic, low confidence)"
        author = "CyberGuardian"
        severity = "low"
    strings:
        $dbg1 = "IsDebuggerPresent" nocase
        $dbg2 = "CheckRemoteDebuggerPresent" nocase
        $dbg3 = "NtGlobalFlag" nocase
        $dbg4 = "OutputDebugString" nocase
    condition:
        any of them
}

rule anti_vm {
    meta:
        description = "Virtual machine detection strings (heuristic)"
        author = "CyberGuardian"
        severity = "low"
    strings:
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $vm3 = "QEMU" nocase
        $vm4 = "Sandboxie" nocase
        $vm5 = "Cuckoo" nocase
    condition:
        2 of them
}

rule anti_sandbox {
    meta:
        description = "Sandbox timing checks (heuristic)"
        author = "CyberGuardian"
        severity = "low"
    strings:
        $sb1 = "Sleep(" nocase
        $sb2 = "GetTickCount" nocase
        $sb3 = "QueryPerformanceCounter" nocase
        $sb4 = "InternetGetConnectedState" nocase
    condition:
        2 of them
}
''',

    "backdoor.yar": r'''// Backdoor and reverse-shell indicators
rule reverse_shell {
    meta:
        description = "Reverse shell one-liner with a network channel"
        author = "CyberGuardian"
        severity = "critical"
    strings:
        $devtcp = "/dev/tcp/" ascii
        $bash = "bash -i" nocase ascii
        $nc = "nc -e" nocase ascii
        $sh = "/bin/sh" ascii
    condition:
        uint16(0) != 0x5A4D and (($devtcp and $bash) or ($nc and $sh))
}

rule backdoor_c2 {
    meta:
        description = "Beacon-style command and control strings (heuristic)"
        author = "CyberGuardian"
        severity = "low"
    strings:
        $c2_1 = "beacon" nocase
        $c2_2 = "checkin" nocase
        $c2_3 = "heartbeat" nocase
        $c2_4 = "get_task" nocase
        $c2_5 = "post_result" nocase
    condition:
        2 of them
}
''',

    "credentials.yar": r'''// Credential theft indicators
rule credential_dumping_tool {
    meta:
        description = "Mimikatz-style credential dumping binary"
        author = "CyberGuardian"
        severity = "critical"
    strings:
        $mimi = "mimikatz" nocase ascii wide
        $sekurlsa = "sekurlsa::" nocase ascii wide
        $lsadump = "lsadump::" nocase ascii wide
        $ntds = "ntds.dit" nocase ascii wide
    condition:
        uint16(0) == 0x5A4D and $mimi and ($sekurlsa or $lsadump or $ntds)
}

rule sam_dump_command {
    meta:
        description = "Registry hive export commands used to dump credentials"
        author = "CyberGuardian"
        severity = "medium"
    strings:
        $save1 = "reg save hklm\\sam" nocase
        $save2 = "reg save hklm\\system" nocase
        $save3 = "reg save hklm\\security" nocase
    condition:
        2 of them
}

rule keylogger_indicators {
    meta:
        description = "Keyboard hooking APIs (heuristic)"
        author = "CyberGuardian"
        severity = "low"
    strings:
        $key1 = "GetAsyncKeyState" nocase
        $key2 = "SetWindowsHookEx" nocase
        $key3 = "CallNextHookEx" nocase
        $key4 = "keylog" nocase
    condition:
        2 of them
}

rule browser_stealer {
    meta:
        description = "Browser credential store references (heuristic)"
        author = "CyberGuardian"
        severity = "low"
    strings:
        $br1 = "Login Data" nocase
        $br2 = "Web Data" nocase
        $br3 = "Cookies" nocase
        $br4 = "sqlite3" nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}
''',

    "crypto_mining.yar": r'''// Cryptocurrency mining indicators
rule crypto_miner_binaries {
    meta:
        description = "Miner binary with a stratum pool endpoint"
        author = "CyberGuardian"
        severity = "high"
    strings:
        $stratum = "stratum+tcp://" nocase
        $xmrig = "xmrig" nocase
        $cpuminer = "cpuminer" nocase
        $ethminer = "ethminer" nocase
        $minerd = "minerd" nocase
    condition:
        uint16(0) == 0x5A4D and $stratum and any of ($xmrig, $cpuminer, $ethminer, $minerd)
}

rule crypto_miner_config {
    meta:
        description = "Miner configuration with a pool and donate flag (heuristic)"
        author = "CyberGuardian"
        severity = "low"
    strings:
        $stratum = "stratum+tcp://" nocase
        $donate = "--donate-level" nocase
    condition:
        $stratum and $donate
}
''',

    "dropper.yar": r'''// Dropper / downloader indicators
rule dropper_patterns {
    meta:
        description = "Downloader API cluster in a PE file"
        author = "CyberGuardian"
        severity = "low"
    strings:
        $drop1 = "URLDownloadToFile" nocase
        $drop2 = "WinHttp" nocase
        $drop3 = "WinINet" nocase
        $drop4 = "HttpOpenRequest" nocase
        $drop5 = "InternetReadFile" nocase
        $drop6 = "ShellExecute" nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}
''',

    "packed_executable.yar": r'''// Packed executable detection (informational)
import "math"

rule packed_executable {
    meta:
        description = "Packer name present in the binary (heuristic)"
        author = "CyberGuardian"
        severity = "low"
    strings:
        $pack1 = "UPX" nocase
        $pack2 = "ASPack" nocase
        $pack3 = "PECompact" nocase
        $pack4 = "Themida" nocase
        $pack5 = "VMProtect" nocase
        $pack6 = "Armadillo" nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule high_entropy_section {
    meta:
        description = "Whole-file entropy typical of packed or encrypted content"
        author = "CyberGuardian"
        severity = "low"
    condition:
        uint16(0) == 0x5A4D and filesize < 50MB and math.entropy(0, filesize) > 7.2
}
''',

    "powershell_suspicious.yar": r'''// Suspicious PowerShell content (scripts, not the interpreter binary)
rule powershell_encoded_command {
    meta:
        description = "Encoded or obfuscated PowerShell command"
        author = "CyberGuardian"
        severity = "low"
    strings:
        $enc1 = "-encodedcommand" nocase
        $enc2 = "FromBase64String" nocase
    condition:
        uint16(0) != 0x5A4D and 2 of them
}

rule powershell_download {
    meta:
        description = "PowerShell download cradle"
        author = "CyberGuardian"
        severity = "low"
    strings:
        $dl1 = "Net.WebClient" nocase
        $dl2 = "DownloadString" nocase
        $dl3 = "DownloadFile" nocase
        $dl4 = "Invoke-WebRequest" nocase
    condition:
        uint16(0) != 0x5A4D and 2 of them
}

rule powershell_execution_policy {
    meta:
        description = "Execution policy bypass in a script"
        author = "CyberGuardian"
        severity = "low"
    strings:
        $ep1 = "ExecutionPolicy" nocase
        $ep2 = "Bypass" nocase
    condition:
        uint16(0) != 0x5A4D and 2 of them
}
''',

    "ransomware.yar": r'''// Ransomware indicators
rule ransomware_note {
    meta:
        description = "Ransom note wording with a payment demand"
        author = "CyberGuardian"
        severity = "high"
    strings:
        $phrase1 = "your files are encrypted" nocase
        $phrase2 = "all your files have been encrypted" nocase
        $phrase3 = "your files have been encrypted" nocase
        $bitcoin = "bitcoin" nocase
        $monero = "monero" nocase
        $decrypt = "decrypt" nocase
        $address = /(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})/ nocase
    condition:
        ($phrase1 or $phrase2 or $phrase3) and ($bitcoin or $monero) and $decrypt and $address
}
''',

    "suspicious_apis.yar": r'''// Injection-oriented API clusters (informational)
rule suspicious_api_calls {
    meta:
        description = "Cluster of injection-related Windows APIs"
        author = "CyberGuardian"
        severity = "low"
    strings:
        $api1 = "VirtualAlloc" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "CreateRemoteThread" nocase
        $api4 = "NtUnmapViewOfSection" nocase
        $api5 = "QueueUserAPC" nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule process_injection_indicators {
    meta:
        description = "Process injection API cluster"
        author = "CyberGuardian"
        severity = "low"
    strings:
        $inject1 = "CreateRemoteThread" nocase
        $inject2 = "VirtualAllocEx" nocase
        $inject3 = "WriteProcessMemory" nocase
        $inject4 = "NtQueueApcThread" nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}
''',

    "webshell.yar": r'''// Web shell detection (server-side scripts only)
rule php_webshell_eval {
    meta:
        description = "PHP web shell executing request data"
        author = "CyberGuardian"
        severity = "critical"
    strings:
        $post = "eval($_POST" nocase
        $request = "eval($_REQUEST" nocase
        $assert = "assert($_POST" nocase
        $get = "system($_GET" nocase
    condition:
        uint16(0) != 0x5A4D and any of them
}

rule php_webshell_encoded {
    meta:
        description = "PHP web shell with layered obfuscation"
        author = "CyberGuardian"
        severity = "high"
    strings:
        $b64 = "base64_decode" nocase
        $gzip = "gzinflate" nocase
        $rot = "str_rot13" nocase
        $shell = "shell_exec" nocase
        $pass = "passthru" nocase
    condition:
        uint16(0) != 0x5A4D and 3 of them
}

rule asp_webshell {
    meta:
        description = "Classic ASP web shell with command execution"
        author = "CyberGuardian"
        severity = "high"
    strings:
        $form = "Request.Form" nocase
        $exec = "ExecuteGlobal" nocase
        $wscript = "WScript.Shell" nocase
        $create = "Server.CreateObject" nocase
    condition:
        uint16(0) != 0x5A4D and $form and (($exec and $create) or $wscript)
}
''',
}
