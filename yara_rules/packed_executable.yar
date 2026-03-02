// Packed executable detection
rule packed_executable {
    meta:
        description = "Detects packed/obfuscated executables"
        author = "CyberGuardian"
        severity = "medium"
    
    strings:
        $pack1 = "UPX" nocase
        $pack2 = "ASPack" nocase
        $pack3 = "PECompact" nocase
        $pack4 = "Themida" nocase
        $pack5 = "VMProtect" nocase
        $pack6 = "Armadillo" nocase
        $pack7 = "Petite" nocase
        $pack8 = "NSPack" nocase
        
    condition:
        any of ($pack*)
}

rule high_entropy_section {
    meta:
        description = "Detects high entropy sections (packed/encrypted)"
        author = "CyberGuardian"
        severity = "medium"
    
    condition:
        uint16(0) == 0x5A4D
}
