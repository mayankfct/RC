rule APT_Family_NoAnchor
{
    meta:
        author      = "Test Author"
        description = "Synthetic APT-style rule with no PE/ELF anchor and no filesize cap. Should now convert with auto-injected filesize and a WARN."
        date        = "2024-09-01"
        family      = "APTFamily"
        severity    = "high"
        tags        = "attack.t1071,attack.command-and-control"

    strings:
        $s1 = "covert_channel_marker" ascii
        $s2 = "x_beacon_token"        ascii wide
        $s3 = "/etc/aptconfig"        ascii

    condition:
        2 of them
}
