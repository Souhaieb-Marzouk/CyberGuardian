// Suspicious PowerShell patterns
rule powershell_encoded_command {
    meta:
        description = "Detects encoded PowerShell commands"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $enc1 = "-enc" nocase
        $enc2 = "-encodedcommand" nocase
        $enc3 = "-e " nocase
        $enc4 = "FromBase64String" nocase
        
    condition:
        any of ($enc*)
}

rule powershell_download {
    meta:
        description = "Detects PowerShell download cradles"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $dl1 = "Net.WebClient" nocase
        $dl2 = "DownloadString" nocase
        $dl3 = "DownloadFile" nocase
        $dl4 = "Invoke-WebRequest" nocase
        $dl5 = "iwr " nocase
        $dl6 = "curl " nocase
        $dl7 = "wget " nocase
        
    condition:
        any of ($dl*)
}

rule powershell_execution_policy {
    meta:
        description = "Detects execution policy bypass attempts"
        author = "CyberGuardian"
        severity = "medium"
    
    strings:
        $ep1 = "Bypass" nocase
        $ep2 = "Unrestricted" nocase
        $ep3 = "ExecutionPolicy" nocase
        $ep4 = "-ep " nocase
        
    condition:
        2 of ($ep*)
}
