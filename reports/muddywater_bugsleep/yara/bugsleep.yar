import "pe"

/*
    BugSleep (MuddyWater) YARA rules
    Author: Anas  |  Date: 2026-07-07  |  TLP:CLEAR
    Sample: 73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e

    Two rules, two surfaces:
      - _file   : the on-disk sample. Config is ENCRYPTED on disk, so this keys on
                  the plaintext process hit-list + imphash (the durable, unencrypted traits).
      - _memory : the DECRYPTED payload after injection (process dump / live memory).
                  Keys on config strings that only appear once decrypted.
*/

rule BugSleep_MuddyWater_file
{
    meta:
        description = "MuddyWater BugSleep backdoor - on-disk PE (config encrypted; keys on hit-list + imphash)"
        author      = "Anas"
        date        = "2026-07-07"
        reference   = "73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e"
        imphash     = "5d30c32f609687ca146ba5bde4bc6d09"
        actor       = "MuddyWater"
        tlp         = "CLEAR"
    strings:
        // injection / masquerade target list - plaintext even in the encrypted-config sample.
        // the combination of these seven in one small (<400KB) PE is the discriminator.
        $p1 = "msedge.exe"     ascii wide nocase
        $p2 = "opera.exe"      ascii wide nocase
        $p3 = "chrome.exe"     ascii wide nocase
        $p4 = "anydesk.exe"    ascii wide nocase
        $p5 = "Onedrive.exe"   ascii wide nocase
        $p6 = "svchost.exe"    ascii wide nocase
        $p7 = "powershell.exe" ascii wide nocase
        // subtract-6 config/payload decrypt loop (RVA ~0x24af0), unencrypted stub:
        //   MOVDQU XMM0,[RAX+RSI] / PSUBB XMM0,XMM6 / MOVDQU [RAX+RSI],XMM0 / ADD RAX,10 / CMP RAX,30 / JL
        // durable code signature - survives config/C2 changes.
        $decrypt = { F3 0F 6F 04 30 66 0F F8 C6 F3 0F 7F 04 30 48 83 C0 10 48 83 F8 30 7C E8 }
    condition:
        uint16(0) == 0x5A4D
        and filesize < 400KB
        and ( $decrypt or pe.imphash() == "5d30c32f609687ca146ba5bde4bc6d09" or 5 of ($p*) )
}

rule BugSleep_MuddyWater_memory
{
    meta:
        description = "MuddyWater BugSleep - DECRYPTED config in memory / process dump (e.g. injected msedge region)"
        author      = "Anas"
        date        = "2026-07-07"
        reference   = "decrypted config recovered from injected msedge.exe region via HollowsHunter"
        actor       = "MuddyWater"
        tlp         = "CLEAR"
        note        = "Run against process memory / dumps, not disk. On-disk sample will NOT match (config encrypted)."
    strings:
        $c2   = "91.235.234.202"                             ascii wide
        $per1 = "packagemanager.exe"                         ascii wide nocase
        $per2 = "\\ProgramData\\PackageManager\\"            ascii wide nocase
        $stg  = "\\Users\\Public\\a.txt"                     ascii wide nocase
        $inj  = "\\Microsoft\\Edge\\Application\\msedge.exe" ascii wide nocase
        $mtx  = "PackageManager"                             wide fullword
    condition:
        3 of them
}
