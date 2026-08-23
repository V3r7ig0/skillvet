/*
  skillvet bundled YARA rules.

  Signature layer for the static engine. These target the kind of content that
  shows up in malicious Agent Skills (scripts, not compiled binaries). Each rule
  carries a `severity` meta the scanner maps to its severity levels.

  This file is optional: the scanner runs YARA only when the `yara` Python
  module is installed. Contributions welcome — add a rule, set its severity meta,
  and add a matching sample under samples/ or benchmark/malicious/.
*/

rule Skillvet_Reverse_Shell
{
    meta:
        severity = "critical"
        category = "yara"
        description = "Reverse shell payload (interactive shell to a remote host)"
    strings:
        $a = "/dev/tcp/"
        $b = "bash -i" nocase
        $c = "nc -e" nocase
        $d = "ncat -e" nocase
        $e = "socket.socket"
        $f = "pty.spawn" nocase
        $g = "sh -i >&"
    condition:
        $a or $c or $d or $g or ($b and ($e or $f)) or ($e and $f)
}

rule Skillvet_Downloader_Exec
{
    meta:
        severity = "critical"
        category = "yara"
        description = "Downloads remote content and pipes it into a shell/interpreter"
    strings:
        $curl = /curl[^\n|]{0,120}\|\s*(sudo\s+)?(ba)?sh/ nocase
        $wget = /wget[^\n|]{0,120}\|\s*(ba)?sh/ nocase
        $iex  = /iex\s*\(\s*(new-object\s+net\.webclient)/ nocase
        $ps   = /downloadstring\s*\(/ nocase
    condition:
        any of them
}

rule Skillvet_Cryptominer
{
    meta:
        severity = "high"
        category = "yara"
        description = "Cryptcurrency miner indicators (pool/stratum/known miners)"
    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "xmrig" nocase
        $s3 = "minerd" nocase
        $s4 = "cryptonight" nocase
        $s5 = "--donate-level" nocase
        $s6 = "nicehash" nocase
    condition:
        2 of them or $s2 or $s4
}

rule Skillvet_Credential_Stealer
{
    meta:
        severity = "critical"
        category = "yara"
        description = "Reads private keys / credential stores together with network egress"
    strings:
        $k1 = ".ssh/id_rsa"
        $k2 = ".aws/credentials"
        $k3 = ".config/gcloud"
        $k4 = ".git-credentials"
        $k5 = "Login Data"          // chromium creds db
        $k6 = "cookies.sqlite"
        $net1 = "requests.post" nocase
        $net2 = "urlopen" nocase
        $net3 = "curl " nocase
        $net4 = "socket" nocase
    condition:
        (any of ($k*)) and (any of ($net*))
}

rule Skillvet_Webshell
{
    meta:
        severity = "high"
        category = "yara"
        description = "Web shell pattern: request parameter passed to code execution"
    strings:
        $php1 = /(system|exec|passthru|shell_exec|popen)\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $php2 = /eval\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $py   = /(os\.system|subprocess\.\w+)\s*\(\s*(request|flask\.request|params)/ nocase
    condition:
        any of them
}

rule Skillvet_Base64_Payload_Exec
{
    meta:
        severity = "high"
        category = "yara"
        description = "Base64 blob decoded and executed"
    strings:
        $py  = /(exec|eval)\s*\(\s*[^)\n]{0,40}(b64decode|base64\.b64decode)/ nocase
        $js  = /eval\s*\(\s*atob\s*\(/ nocase
        $sh  = /base64\s+-d[^\n|]{0,40}\|\s*(ba)?sh/ nocase
        $ps  = /frombase64string/ nocase
    condition:
        any of them
}

rule Skillvet_Keylogger
{
    meta:
        severity = "high"
        category = "yara"
        description = "Keylogging indicators"
    strings:
        $k1 = "pynput.keyboard" nocase
        $k2 = "keyboard.on_press" nocase
        $k3 = "SetWindowsHookEx" nocase
        $k4 = "GetAsyncKeyState" nocase
        $k5 = "import keylogger" nocase
    condition:
        any of them
}
