rule LockBit_Loader
{
    meta:
        author      = "Test Author"
        description = "Detects a LockBit-family loader by characteristic strings and the PE header. Missing filesize cap is intentional."
        date        = "2023-06-01"
        family      = "LockBit"
        severity    = "critical"
        tags        = "attack.t1486,attack.impact"

    strings:
        $cfg1 = "lockbit_v3_config" ascii
        $cfg2 = "encrypt_all_volumes" ascii
        $marker = { 4C 6F 63 6B 42 69 74 }

    condition:
        uint16(0) == 0x5A4D and ($marker and 1 of ($cfg*))
}
