// Suspicious Windows API calls
rule suspicious_api_calls {
    meta:
        description = "Detects suspicious Windows API calls commonly used by malware"
        author = "CyberGuardian"
        severity = "medium"
        date = "2024-01-01"
    
    strings:
        $api1 = "VirtualAlloc" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "CreateRemoteThread" nocase
        $api4 = "NtUnmapViewOfSection" nocase
        $api5 = "QueueUserAPC" nocase
        $api6 = "SetWindowsHookEx" nocase
        $api7 = "GetAsyncKeyState" nocase
        $api8 = "CreateToolhelp32Snapshot" nocase
        $api9 = "OpenProcess" nocase
        $api10 = "VirtualProtect" nocase
    
    condition:
        any of ($api*)
}

rule process_injection_indicators {
    meta:
        description = "Detects process injection indicators"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $inject1 = "CreateRemoteThread" nocase
        $inject2 = "VirtualAllocEx" nocase
        $inject3 = "WriteProcessMemory" nocase
        $inject4 = "NtQueueApcThread" nocase
        
    condition:
        2 of ($inject*)
}
