import "pe"

/*
    BugSleep (MuddyWater) YARA — tuned for precision.
    Author: Anas  |  Date: 2026-07-08  |  TLP:CLEAR
    Sample: 73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e

    Logic:
      - _file   : require the subtract-6 decrypt loop AND the process hit-list
                  together. Neither is safe alone (the loop can appear in legit
                  crypto/packers; the process names appear everywhere) - the
                  combination in one small PE is what's specific to BugSleep.
      - _memory : the decrypted config in a process dump - require ALL config
                  strings present, so it only fires on the real payload.

    TODO: refine the string set against more BugSleep samples - strings that are
    common across samples are the durable ones (a single sample can mislead).
*/

rule BugSleep_MuddyWater_file
{
    meta:
        description = "MuddyWater BugSleep on-disk PE - subtract-6 decrypt loop AND process hit-list together"
        author      = "Anas"
        date        = "2026-07-08"
        reference   = "73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e"
        imphash     = "5d30c32f609687ca146ba5bde4bc6d09"   // pivot only
        actor       = "MuddyWater"
        tlp         = "CLEAR"
    strings:
        // injection / masquerade target list
        $s1 = "msedge.exe"     ascii wide nocase
        $s2 = "opera.exe"      ascii wide nocase
        $s3 = "chrome.exe"     ascii wide nocase
        $s4 = "anydesk.exe"    ascii wide nocase
        $s5 = "Onedrive.exe"   ascii wide nocase
        $s6 = "svchost.exe"    ascii wide nocase
        $s7 = "powershell.exe" ascii wide nocase
        // subtract-6 config/payload decrypt loop (RVA ~0x24af0):
        //   MOVDQU XMM0,[RAX+RSI] / PSUBB XMM0,XMM6 / MOVDQU [RAX+RSI],XMM0 / ADD RAX,0x10 / CMP RAX,0x30 / JL
        // only the JL displacement is wildcarded, so a recompile that shifts the loop still matches.
        $decrypt = { F3 0F 6F 04 30 66 0F F8 C6 F3 0F 7F 04 30 48 83 C0 10 48 83 F8 30 7C ?? }
    condition:
        uint16(0) == 0x5A4D
        and filesize < 400KB
        and $decrypt
        and 5 of ($s*)
}

rule BugSleep_MuddyWater_memory
{
    meta:
        description = "MuddyWater BugSleep decrypted config in memory / process dump - run on memory, NOT disk"
        author      = "Anas"
        date        = "2026-07-08"
        reference   = "decrypted config recovered from an injected msedge.exe region"
        actor       = "MuddyWater"
        tlp         = "CLEAR"
        note        = "Requires ALL config strings, so it only matches the fully-decrypted payload."
    strings:
        $c2   = "91.235.234.202"                             ascii wide
        $per1 = "packagemanager.exe"                         ascii wide nocase
        $per2 = "\\ProgramData\\PackageManager\\"            ascii wide nocase
        $stg  = "\\Users\\Public\\a.txt"                     ascii wide nocase
        $inj  = "\\Microsoft\\Edge\\Application\\msedge.exe" ascii wide nocase
        $mtx  = "PackageManager"                             wide fullword
    condition:
        all of them
}
