rule Mimikatz_Detection
{
    meta:
        author      = "Florian Roth"
        description = "Detects Mimikatz credential dumping artifacts in PE binaries"
        date        = "2022-01-01"
        reference   = "https://github.com/gentilkiwi/mimikatz"
        family      = "Mimikatz"
        severity    = "critical"
        tags        = "attack.t1003.001,attack.credential-access"

    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide
        $s2 = "privilege::debug" ascii wide
        $s3 = "kerberos::list" ascii wide
        $s4 = "mimikatz" ascii wide nocase
        $s5 = "gentilkiwi" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and 2 of ($s*)
}
