rule Payload_DesktopBKFJ38L_MultiStageAttack
{
    meta:
        description = "Detects malicious payload.exe used in multi-stage attack (initial access, persistence, privilege escalation, exfiltration) on Windows 10 host desktop-bkfj38l"
        author = "Piyush Singh"
        date = "2025-08-10"
        md5 = "b8e65d5320b676741a7d3988904ffe75"
        sha1 = "7f6436096fa1df98059a96e796d3a212ba3c6926"
        sha256 = "a78acea453c68a684917b967162a599f9881eba69471c202c071b86e72066037"
        file_size = "73802 bytes"

    strings:
        $s1 = "!This program cannot be run in DOS mode."
        $s2 = "`.rdata"
        $s3 = "@.data"
        $s4 = "@2P7DF"
        $s5 = "@<ALhK"

    condition:
        filesize == 73802 and
        (all of ($s*) or
        hash.md5(0, filesize) == "b8e65d5320b676741a7d3988904ffe75")
}

