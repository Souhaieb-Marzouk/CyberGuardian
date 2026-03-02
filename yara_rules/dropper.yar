// Dropper/Downloader indicators
rule dropper_patterns {
    meta:
        description = "Detects dropper patterns"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $drop1 = "URLDownloadToFile" nocase
        $drop2 = "WinHttp" nocase
        $drop3 = "WinINet" nocase
        $drop4 = "HttpOpenRequest" nocase
        $drop5 = "InternetReadFile" nocase
        $drop6 = "ShellExecute" nocase
        
    condition:
        2 of ($drop*)
}

rule suspicious_child_process {
    meta:
        description = "Detects suspicious parent-child process relationships"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $proc1 = "winword.exe" nocase
        $proc2 = "excel.exe" nocase
        $proc3 = "powerpnt.exe" nocase
        $proc4 = "outlook.exe" nocase
        $child1 = "powershell.exe" nocase
        $child2 = "cmd.exe" nocase
        $child3 = "wscript.exe" nocase
        $child4 = "cscript.exe" nocase
        
    condition:
        any of ($proc*) and any of ($child*)
}
