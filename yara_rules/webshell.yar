// Webshell detection
rule php_webshell {
    meta:
        description = "Detects PHP webshell patterns"
        author = "CyberGuardian"
        severity = "critical"
    
    strings:
        $php1 = "eval($_POST" nocase
        $php2 = "assert($_POST" nocase
        $php3 = "base64_decode" nocase
        $php4 = "gzinflate" nocase
        $php5 = "str_rot13" nocase
        $php6 = "shell_exec" nocase
        $php7 = "passthru" nocase
        $php8 = "system($_" nocase
        
    condition:
        2 of ($php*)
}

rule asp_webshell {
    meta:
        description = "Detects ASP webshell patterns"
        author = "CyberGuardian"
        severity = "critical"
    
    strings:
        $asp1 = "WScript.Shell" nocase
        $asp2 = "cmd.exe" nocase
        $asp3 = "Request.Form" nocase
        $asp4 = "ExecuteGlobal" nocase
        
    condition:
        2 of ($asp*)
}
