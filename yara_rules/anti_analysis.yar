// Anti-analysis techniques
rule anti_debug {
    meta:
        description = "Detects anti-debugging techniques"
        author = "CyberGuardian"
        severity = "medium"
    
    strings:
        $dbg1 = "IsDebuggerPresent" nocase
        $dbg2 = "CheckRemoteDebuggerPresent" nocase
        $dbg3 = "NtGlobalFlag" nocase
        $dbg4 = "OutputDebugString" nocase
        $dbg5 = "BeingDebugged" nocase
        
    condition:
        any of ($dbg*)
}

rule anti_vm {
    meta:
        description = "Detects anti-VM techniques"
        author = "CyberGuardian"
        severity = "medium"
    
    strings:
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $vm3 = "Vbox" nocase
        $vm4 = "QEMU" nocase
        $vm5 = "Sandboxie" nocase
        $vm6 = "Cuckoo" nocase
        $vm7 = "JoeSandbox" nocase
        
    condition:
        2 of ($vm*)
}

rule anti_sandbox {
    meta:
        description = "Detects sandbox evasion techniques"
        author = "CyberGuardian"
        severity = "medium"
    
    strings:
        $sb1 = "Sleep(" nocase
        $sb2 = "GetTickCount" nocase
        $sb3 = "QueryPerformanceCounter" nocase
        $sb4 = "InternetGetConnectedState" nocase
        
    condition:
        2 of ($sb*)
}
