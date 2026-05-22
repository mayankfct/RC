rule SingleString_Bad
{
    meta:
        author      = "Test"
        description = "Intentionally bad single-string YARA rule. Should be rejected by RuleForge."
        date        = "2024-01-01"
        family      = "Generic"
        severity    = "low"
        tags        = "attack.t1059"

    strings:
        $a = "evil_marker_string" ascii

    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and $a
}
