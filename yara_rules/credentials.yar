// Credential theft indicators
rule keylogger_indicators {
    meta:
        description = "Detects keylogger-related functionality"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $key1 = "GetAsyncKeyState" nocase
        $key2 = "GetKeyState" nocase
        $key3 = "SetWindowsHookEx" nocase
        $key4 = "CallNextHookEx" nocase
        $key5 = "keylog" nocase
        
    condition:
        2 of ($key*)
}

rule credential_dumping {
    meta:
        description = "Detects credential dumping tools"
        author = "CyberGuardian"
        severity = "critical"
    
    strings:
        $cred1 = "mimikatz" nocase
        $cred2 = "lsass.exe" nocase
        $cred3 = "SAM" nocase
        $cred4 = "SYSTEM" nocase
        $cred5 = "SECURITY" nocase
        $cred6 = "NTDS.dit" nocase
        
    condition:
        2 of ($cred*)
}

rule browser_stealer {
    meta:
        description = "Detects browser credential stealing"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $br1 = "Login Data" nocase
        $br2 = "Web Data" nocase
        $br3 = "Cookies" nocase
        $br4 = "sqlite3" nocase
        $br5 = "chrome.dll" nocase
        $br6 = "firefox" nocase
        
    condition:
        2 of ($br*)
}
