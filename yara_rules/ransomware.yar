// Ransomware indicators
rule ransomware_extensions {
    meta:
        description = "Detects common ransomware file extensions"
        author = "CyberGuardian"
        severity = "critical"
    
    strings:
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypto" nocase
        $ext4 = ".ransom" nocase
        $ext5 = ".wannacry" nocase
        $ext6 = ".ryuk" nocase
        $ext7 = ".locky" nocase
        $ext8 = ".cryptolocker" nocase
        
    condition:
        any of ($ext*)
}

rule ransomware_strings {
    meta:
        description = "Detects ransomware-related strings"
        author = "CyberGuardian"
        severity = "critical"
    
    strings:
        $ransom1 = "YOUR FILES ARE ENCRYPTED" nocase
        $ransom2 = "PAY RANSOM" nocase
        $ransom3 = "BITCOIN" nocase
        $ransom4 = "DECRYPT_INSTRUCTIONS" nocase
        $ransom5 = "RESTORE_FILES" nocase
        
    condition:
        2 of ($ransom*)
}
