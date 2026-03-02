// Cryptocurrency mining indicators
rule crypto_miner_stratum {
    meta:
        description = "Detects cryptocurrency mining stratum protocol"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $stratum = "stratum+tcp://" nocase
        $pool1 = "pool.minero.cc" nocase
        $pool2 = "xmrpool.eu" nocase
        $pool3 = "nanopool.org" nocase
        $pool4 = "ethermine.org" nocase
        
    condition:
        any of them
}

rule crypto_miner_binaries {
    meta:
        description = "Detects common cryptocurrency miner binaries"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $miner1 = "xmrig" nocase
        $miner2 = "minerd" nocase
        $miner3 = "cpuminer" nocase
        $miner4 = "ethminer" nocase
        $miner5 = "claymore" nocase
        
    condition:
        any of ($miner*)
}
