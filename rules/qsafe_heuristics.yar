rule QSAFE_Python_Obfuscated_Dynamic_Execution
{
    meta:
        description = "Low-confidence triage for Python dynamic execution combined with base64 decoding"
        author = "Q-SAFE"
        confidence = "low"
        category = "script-obfuscation"
    strings:
        $exec1 = "exec(" ascii wide nocase
        $exec2 = "eval(" ascii wide nocase
        $decode1 = "b64decode" ascii wide nocase
        $decode2 = "base64" ascii wide nocase
    condition:
        filesize < 5MB and any of ($exec*) and any of ($decode*)
}

rule QSAFE_PowerShell_Encoded_Execution
{
    meta:
        description = "Low-confidence triage for encoded PowerShell plus dynamic invocation"
        author = "Q-SAFE"
        confidence = "low"
        category = "script-obfuscation"
    strings:
        $encoded = "-EncodedCommand" ascii wide nocase
        $decode = "FromBase64String" ascii wide nocase
        $invoke = "Invoke-Expression" ascii wide nocase
    condition:
        2 of them
}

rule QSAFE_PE_Process_Injection_API_Cluster
{
    meta:
        description = "Triage for PE files containing multiple process-injection APIs"
        author = "Q-SAFE"
        confidence = "medium"
        category = "process-injection"
    strings:
        $alloc = "VirtualAllocEx" ascii wide
        $write = "WriteProcessMemory" ascii wide
        $thread = "CreateRemoteThread" ascii wide
        $ntwrite = "NtWriteVirtualMemory" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
