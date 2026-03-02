// Backdoor indicators
rule reverse_shell {
    meta:
        description = "Detects reverse shell patterns"
        author = "CyberGuardian"
        severity = "critical"
    
    strings:
        $shell1 = "nc -e" nocase
        $shell2 = "/bin/sh -i" nocase
        $shell3 = "cmd.exe" nocase
        $shell4 = "powershell -nop" nocase
        $shell5 = "socket.connect" nocase
        $shell6 = "subprocess.call" nocase
        
    condition:
        2 of ($shell*)
}

rule backdoor_c2 {
    meta:
        description = "Detects common C2 patterns"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $c2_1 = "beacon" nocase
        $c2_2 = "checkin" nocase
        $c2_3 = "heartbeat" nocase
        $c2_4 = "get_task" nocase
        $c2_5 = "post_result" nocase
        
    condition:
        2 of ($c2*)
}
