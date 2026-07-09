import "pe"

/*
    BugSleep (MuddyWater) YARA — tuned for PRECISION.
    Author: Anas  |  Date: 2026-07-08  |  TLP:CLEAR
    Sample: 73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e

    Design note: the ONLY signal here strong enough to stand on its own is the
    subtract-6 decrypt loop (specific code). Generic strings - process names,
    msedge / PackageManager paths - are deliberately NOT used as standalone
    matches, because on their own they hit huge numbers of benign and unrelated
    files. A rule is only as precise as its loosest standalone condition.
*/

rule BugSleep_MuddyWater_file
{
    meta:
        description = "MuddyWater BugSleep on-disk PE - keys on the subtract-6 decrypt loop (specific code, not generic strings)"
        author      = "Anas"
        date        = "2026-07-08"
        reference   = "73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e"
        imphash     = "5d30c32f609687ca146ba5bde4bc6d09"   // pivot only - not a match condition
        actor       = "MuddyWater"
        tlp         = "CLEAR"
    strings:
        // Subtract-6 config/payload decrypt loop (RVA ~0x24af0), in the unencrypted stub:
        //   MOVDQU XMM0,[RAX+RSI] / PSUBB XMM0,XMM6 / MOVDQU [RAX+RSI],XMM0 / ADD RAX,0x10 / CMP RAX,0x30 / JL
        // PSUBB (66 0F F8) inside an SSE copy loop with these exact bounds is distinctive to BugSleep.
        // Only the JL displacement is wildcarded, so it survives a recompile that shifts the loop.
        $decrypt = { F3 0F 6F 04 30 66 0F F8 C6 F3 0F 7F 04 30 48 83 C0 10 48 83 F8 30 7C ?? }
    condition:
        uint16(0) == 0x5A4D
        and filesize < 400KB
        and $decrypt
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
        note        = "Anchored on the unique C2, or the PackageManager-folder + Public\\a.txt path PAIR. Single generic strings never match alone."
    strings:
        $c2     = "91.235.234.202"                  ascii wide            // unique - strongest anchor
        $folder = "\\ProgramData\\PackageManager\\"  ascii wide nocase
        $stg    = "\\Users\\Public\\a.txt"           ascii wide nocase
    condition:
        $c2 or ($folder and $stg)
}
