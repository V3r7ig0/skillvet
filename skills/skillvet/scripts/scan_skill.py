#!/usr/bin/env python3
"""
scan_skill.py — Static security scanner for Agent Skills (Claude Code / Cowork).

Scans a skill directory (or a packaged .skill / .zip) for malicious code,
dangerous shell commands, data-exfiltration patterns, prompt-injection
instructions, obfuscation, over-broad permissions, and supply-chain risks.

Dependency-free: uses only the Python standard library so it runs anywhere,
including inside a Claude Code / Cowork sandbox.

Usage:
    python3 scan_skill.py <path-to-skill-dir-or-zip> [options]

Options:
    --json <file>       Write structured findings as JSON to <file> (default: stdout summary only when omitted)
    --markdown <file>   Write a human-readable Markdown report to <file>
    --min-severity L    Only report findings at or above L (info|low|medium|high|critical). Default: info
    --fail-on L         Exit non-zero if any finding at or above severity L is found (for CI). Default: high
    --quiet             Suppress the stdout summary table

Exit codes:
    0  scan completed, nothing at/above --fail-on
    1  findings at/above --fail-on were reported
    2  usage / IO error

The absence of findings does NOT prove a skill is safe. A human (or Claude,
via the skillvet SKILL.md workflow) should always review the results in
context. This engine is deliberately high-recall: it errs toward flagging.
"""

import argparse
import ast
import json
import os
import re
import sys
import tempfile
import zipfile

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# File extensions we treat as executable/script content (deeper checks apply).
CODE_EXTS = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts",
             ".rb", ".pl", ".php", ".ps1", ".psm1", ".bat", ".cmd", ".fish"}
# Text files we scan line-by-line for patterns (includes markdown/yaml/config).
TEXT_EXTS = CODE_EXTS | {".md", ".markdown", ".yaml", ".yml", ".json", ".txt",
                         ".toml", ".cfg", ".ini", ".env", ".conf", ".xml", ".html"}
# Binaries we flag by presence rather than scan.
SUSPICIOUS_BINARY_EXTS = {".exe", ".dll", ".so", ".dylib", ".bin", ".o",
                          ".pyc", ".pyd", ".jar", ".class", ".wasm", ".scr"}

MAX_SNIPPET = 200


# ---------------------------------------------------------------------------
# Regex rule table.  Each rule: id, category, severity, human title,
# recommendation, and a compiled pattern.  `applies` narrows a rule to certain
# file kinds: "code", "text", "markdown", "any".
# ---------------------------------------------------------------------------
def _r(pattern, flags=re.IGNORECASE):
    return re.compile(pattern, flags)


RULES = [
    # ---- Remote code execution / dangerous shell ----
    dict(id="CE-REMOTE-EXEC", cat="malicious-code", sev="critical", applies="any",
         title="Remote code piped into a shell (curl|bash / wget|sh)",
         rec="Never download and execute code in one step. Vendor the code into the skill and review it.",
         pat=_r(r"(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba)?sh\b")),
    dict(id="CE-REMOTE-EXEC-PS", cat="malicious-code", sev="critical", applies="any",
         title="Remote code executed via PowerShell IEX / DownloadString",
         rec="Downloading and invoking remote script text is a classic dropper. Remove it.",
         pat=_r(r"(?:iex|invoke-expression)\b.{0,80}(?:downloadstring|downloadfile|new-object\s+net\.webclient)")),
    dict(id="CE-REVERSE-SHELL", cat="malicious-code", sev="critical", applies="any",
         title="Reverse-shell pattern",
         rec="This opens an interactive shell to a remote host. There is no legitimate reason for a skill to do this.",
         pat=_r(r"(?:/dev/tcp/|bash\s+-i\b|nc\s+-e\b|ncat\s+-e\b|socket\.socket\([^)]*\)[^\n]{0,120}connect|sh\s+-i\s*>&)")),
    dict(id="CE-DESTRUCTIVE", cat="malicious-code", sev="high", applies="any",
         title="Destructive filesystem command",
         rec="Confirm this is scoped and intentional; rm -rf on broad paths, mkfs, or dd to a device can wipe data.",
         pat=_r(r"(?:\brm\s+-rf?\s+(?:/|~|\$HOME|\*|\.\.)|\bmkfs\b|\bdd\s+if=.{0,60}of=/dev/|>\s*/dev/sd[a-z])")),
    dict(id="CE-FORKBOMB", cat="malicious-code", sev="high", applies="any",
         title="Fork-bomb / resource-exhaustion pattern",
         rec="Denial-of-service pattern. Remove it.",
         pat=_r(r":\(\)\s*\{\s*:\|:&\s*\}\s*;|while\s+True:\s*os\.fork\(\)")),

    # ---- Dynamic / obfuscated execution ----
    dict(id="CE-DYNAMIC-EXEC", cat="malicious-code", sev="high", applies="code",
         title="Dynamic code execution (eval / exec / Function constructor)",
         rec="Dynamic execution of strings hides behavior from review. Replace with explicit code.",
         pat=_r(r"\b(?:eval|exec)\s*\(|\bFunction\s*\(\s*['\"]|\bnew\s+Function\s*\(|\bcompile\s*\([^)]*,\s*['\"]?<|__import__\s*\(")),
    dict(id="CE-OBFUSCATION-B64", cat="obfuscation", sev="high", applies="any",
         title="Base64/hex blob decoded and executed",
         rec="Decoding an encoded blob and running it is a hallmark of hidden payloads. Decode and inspect it.",
         pat=_r(r"(?:b64decode|base64\s+-d|atob|frombase64string|fromhex|bytes\.fromhex)[^\n]{0,120}(?:exec|eval|iex|\|\s*sh|subprocess|os\.system|child_process)")),
    dict(id="CE-OBFUSCATION-BLOB", cat="obfuscation", sev="medium", applies="code",
         title="Large encoded string literal (possible packed payload)",
         rec="A long opaque base64/hex literal may hide code or data. Decode and confirm what it is.",
         pat=_r(r"['\"][A-Za-z0-9+/]{200,}={0,2}['\"]|['\"](?:\\x[0-9a-fA-F]{2}){40,}['\"]")),
    dict(id="CE-SHELL-TRUE", cat="malicious-code", sev="medium", applies="code",
         title="subprocess with shell=True (command-injection surface)",
         rec="shell=True with interpolated input allows command injection. Pass an argument list instead.",
         pat=_r(r"subprocess\.(?:run|call|Popen|check_output|check_call)\([^)]*shell\s*=\s*True")),
    dict(id="CE-OS-SYSTEM", cat="malicious-code", sev="low", applies="code",
         title="Direct shell invocation (os.system / child_process.exec)",
         rec="Prefer argument-list APIs; confirm the command string is not attacker-controlled.",
         pat=_r(r"\bos\.system\s*\(|child_process\.(?:exec|execSync)\s*\(|\bos\.popen\s*\(")),

    # ---- Data exfiltration: sending data out ----
    dict(id="EX-NET-POST", cat="data-exfiltration", sev="medium", applies="code",
         title="Outbound network request from a bundled script",
         rec="Confirm the destination and payload. Skills rarely need to phone home; this is the main exfil channel.",
         pat=_r(r"\b(?:requests\.(?:post|put|get)|urllib\.request\.urlopen|urlopen|http\.client|httpx\.|aiohttp\.|fetch\s*\(|axios\.|net\.WebClient|Invoke-RestMethod|Invoke-WebRequest|socket\.socket)\b")),
    dict(id="EX-NET-RAWSOCK", cat="data-exfiltration", sev="medium", applies="code",
         title="Raw socket / low-level network connection",
         rec="Raw sockets bypass normal HTTP review. Confirm host, port, and what is sent.",
         pat=_r(r"socket\.(?:socket|create_connection)\s*\(|\.connect\(\(?['\"]?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")),
    dict(id="EX-HARDCODED-IP", cat="data-exfiltration", sev="medium", applies="any",
         title="Hardcoded external IP address",
         rec="A literal IP as a destination is suspicious in a shareable skill. Verify why it's there.",
         pat=_r(r"(?<!\d)(?:https?://)?(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?\b")),
    dict(id="EX-WEBHOOK", cat="data-exfiltration", sev="high", applies="any",
         title="Data sent to a webhook / paste / tunnelling service",
         rec="These are common drop points for stolen data. Confirm this is expected.",
         pat=_r(r"(?:hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|webhook\.site|requestbin|pipedream\.net|ngrok\.io|trycloudflare\.com|pastebin\.com/api|paste\.ee|transfer\.sh|termbin\.com|0x0\.st|burpcollaborator|oast\.(?:fun|live|site|pro)|interactsh)")),

    # ---- Data exfiltration: harvesting secrets/sources ----
    dict(id="EX-ENV-HARVEST", cat="data-exfiltration", sev="medium", applies="code",
         title="Bulk environment-variable access (credential harvesting)",
         rec="Reading the whole environment often means scooping up API keys/tokens. Read only the specific vars needed.",
         pat=_r(r"os\.environ(?:\.copy\(\)|\b(?!\[))|dict\(os\.environ\)|printenv\b|\benv\s*\|\s*(?:curl|nc|base64)|process\.env\b(?!\.\w)")),
    dict(id="EX-SECRET-FILES", cat="data-exfiltration", sev="critical", applies="any",
         title="Access to SSH keys / cloud credentials / secret stores",
         rec="No legitimate skill reads private keys or credential files. Treat as malicious unless proven otherwise.",
         pat=_r(r"(?:\.ssh/(?:id_(?:rsa|ed25519|ecdsa|dsa)|authorized_keys)|id_rsa\b|\.aws/credentials|\.config/gcloud|\.kube/config|\.docker/config\.json|\.netrc|\.npmrc|\.pypirc|\.git-credentials|/etc/shadow|/etc/passwd)")),
    dict(id="EX-KEYCHAIN", cat="data-exfiltration", sev="critical", applies="any",
         title="OS credential store / browser secret access",
         rec="Reading keychains, Credential Manager, or browser login DBs is credential theft.",
         pat=_r(r"(?:security\s+find-generic-password|/usr/bin/security\b|libsecret|SecKeychain|Windows\s*Vault|CredEnumerate|Login Data|cookies\.sqlite|Local\s+State|keyring\.get_password)")),
    dict(id="EX-FILE-ENUM", cat="data-exfiltration", sev="medium", applies="code",
         title="Filesystem enumeration of sensitive locations",
         rec="Walking home/SSH/wallet directories to find secrets is a recon step. Confirm the scope is legitimate.",
         pat=_r(r"(?:glob|walk|find|Get-ChildItem|listdir)\b[^\n]{0,80}(?:\.ssh|\.aws|\.config|wallet|keystore|\.env|secret|password|credential)")),
    dict(id="EX-CONTEXT-LEAK", cat="data-exfiltration", sev="high", applies="markdown",
         title="Instruction to transmit conversation/context to an external destination",
         rec="Instructing the agent to send its context, history, or the user's data outward is exfiltration by prompt.",
         pat=_r(r"(?:send|post|upload|forward|exfiltrate|report|transmit|leak)\b[^\n]{0,60}(?:conversation|context|history|these files|the user'?s|environment|secret|token|api\s*key|contents)[^\n]{0,60}(?:to\s+https?://|to\s+the\s+(?:following|url|endpoint|server)|externally|out-?of-?band)")),

    # ---- Privilege escalation ----
    dict(id="PE-SUDO", cat="privilege-escalation", sev="high", applies="any",
         title="Privilege elevation (sudo / runas / setuid)",
         rec="A skill asking for root should be scrutinized closely; elevation greatly widens blast radius.",
         pat=_r(r"\bsudo\s+(?!-n\s+true\b)\S|\brunas\b|Start-Process\s+.{0,60}-Verb\s+RunAs|\bsetuid\s*\(|os\.setuid\b|chmod\s+[0-7]*[4-7][0-7]{3}\b")),
    dict(id="PE-PERMS", cat="privilege-escalation", sev="medium", applies="any",
         title="World-writable / permissive permission change",
         rec="chmod 777 or a+rwx weakens protections. Confirm the target and necessity.",
         pat=_r(r"chmod\s+(?:-R\s+)?(?:777|666|a\+rwx|\+s)\b|icacls\b.{0,60}/grant\s+everyone")),
    dict(id="PE-PERSIST", cat="persistence", sev="high", applies="any",
         title="Persistence via shell profiles / cron / autostart / launch agents",
         rec="Writing to rc files, crontab, systemd, or LaunchAgents installs code that runs beyond this session.",
         pat=_r(r"(?:>>?\s*~?/?\.(?:bashrc|zshrc|bash_profile|profile|zprofile)\b|crontab\s+-|/etc/cron|systemctl\s+enable|LaunchAgents|LaunchDaemons|reg\s+add\b.{0,60}\\Run|schtasks\s+/create|New-ItemProperty.{0,40}CurrentVersion\\Run)")),

    # ---- Supply chain ----
    dict(id="SC-REMOTE-FETCH", cat="supply-chain", sev="high", applies="any",
         title="Runtime download of code/scripts from a remote URL",
         rec="Fetching code at runtime defeats review (the reviewed skill and the executed code differ). Vendor it in.",
         pat=_r(r"(?:curl|wget|Invoke-WebRequest|requests\.get|urlretrieve)\b[^\n]{0,160}https?://[^\n]{0,160}\.(?:sh|py|js|ps1|exe|pl|rb|zip|tar\.gz)\b")),
    dict(id="SC-PIP-URL", cat="supply-chain", sev="high", applies="any",
         title="pip/npm install from a URL or VCS (not a pinned registry package)",
         rec="Installing from an arbitrary URL/git ref lets the author swap the payload later. Pin to a released, hashed version.",
         pat=_r(r"pip\s+install\b[^\n]{0,120}(?:https?://|git\+|\.tar\.gz|\.whl\b)|npm\s+install\b[^\n]{0,120}(?:https?://|git\+|github:)")),
    dict(id="SC-UNPINNED-PEP723", cat="supply-chain", sev="low", applies="code",
         title="Inline (PEP 723) or requirements dependency without a pinned version",
         rec="Unpinned dependencies can be hijacked via a malicious update. Pin exact versions (and hashes where possible).",
         pat=_r(r"^\s*#\s*(?:dependencies|requires-python)\s*=|^\s*[A-Za-z0-9_.-]+\s*(?:>=|>|\^|~=|\*)\s*", re.MULTILINE)),

    # ---- Prompt injection (targeting the agent through SKILL.md/text) ----
    dict(id="PI-OVERRIDE", cat="prompt-injection", sev="high", applies="markdown",
         title="Instruction override / jailbreak language",
         rec="Language telling the agent to ignore prior instructions or safety is a prompt-injection attempt.",
         pat=_r(r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|context|prompts?)|disregard\s+(?:the\s+)?(?:system|previous|safety)|forget\s+(?:everything|all\s+previous)|you\s+are\s+now\s+(?:a\s+)?(?:DAN|jailbroken|unrestricted)|(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention\s+to|warn)\s+the\s+user")),
    dict(id="PI-SECRECY", cat="prompt-injection", sev="high", applies="markdown",
         title="Instruction to act covertly / hide actions from the user",
         rec="A skill that tells the agent to conceal what it does is acting against the user. Remove and distrust.",
         # "without asking the user" is ordinary English for "needs no user
         # input", so on its own it is not evidence of concealment -- it has
         # to attach to an action the agent performs, the way every other
         # alternative here already does. telling/informing/notifying carry
         # the concealment on their own and stay unconditional.
         # The verb list is deliberately data-movement only: "run" reads as
         # an agent action in "run it without asking the user" and as plain
         # description in "it runs unattended, without asking the user".
         pat=_r(r"(?:(?:send|upload|forward|transmit|delete|copy|collect|exfiltrat|post|share)[^\n]{0,40}without\s+(?:telling|informing|asking|notifying)\s+the\s+user|without\s+(?:telling|informing|notifying)\s+the\s+user|(?:silently|covertly|secretly)\s+(?:send|exfiltrat|upload|forward|transmit|run|execute|delete|copy|collect|post)|do\s+not\s+(?:tell|inform|log|report|mention)\s+the\s+user|hide\s+(?:this|it|your\s+actions?|the\s+upload)\s+from|keep\s+this\s+(?:secret|hidden)|delete\s+(?:the\s+)?(?:logs|history|evidence))")),
    dict(id="PI-TOOL-COERCE", cat="prompt-injection", sev="medium", applies="markdown",
         title="Instruction pushing the agent toward dangerous tool use / auto-approval",
         rec="Descriptions that coerce the agent to run commands, disable checks, or auto-approve should be reviewed.",
         pat=_r(r"(?:always\s+(?:run|execute|approve)|auto[-\s]?approve|bypass\s+(?:the\s+)?(?:permission|confirmation|safety|checks?)|disable\s+(?:the\s+)?(?:safety|guardrails?|permission)|run\s+this\s+immediately\s+without)")),
    dict(id="PI-HIDDEN-HTML", cat="prompt-injection", sev="medium", applies="markdown",
         title="Hidden instructions inside HTML comments",
         rec="Text hidden in comments is invisible to a skimming reader but seen by the model. Inspect the comment content.",
         pat=_r(r"<!--(?:(?!-->)[\s\S]){0,400}?(?:ignore|system|instruction|exfiltrat|password|token|curl|http|do not tell)(?:(?!-->)[\s\S]){0,400}?-->", re.IGNORECASE)),
    dict(id="PI-DATA-URI", cat="obfuscation", sev="medium", applies="any",
         title="Data URI or embedded encoded payload",
         rec="data: URIs can smuggle scripts/binaries past a quick read. Decode and confirm the content.",
         pat=_r(r"data:(?:text/html|application/(?:octet-stream|javascript)|image/svg\+xml)[^\n,]{0,40};base64,[A-Za-z0-9+/]{40,}")),

    # ---- Claude Code / skill-specific ----
    dict(id="FM-DYNAMIC-SHELL", cat="skill-mechanics", sev="medium", applies="markdown",
         title="Dynamic shell injection in skill body ( !`cmd` or ```! block )",
         rec="These commands run BEFORE Claude reads the skill, with no permission prompt. Review every such command.",
         pat=_r(r"(?:^|\s)!\`[^\`]+\`|```!\s")),
    dict(id="FM-CTX-EXFIL", cat="skill-mechanics", sev="high", applies="markdown",
         title="Dynamic shell injection that reads secrets or hits the network",
         rec="An injected command combining secret access or network egress runs automatically and unreviewed. Remove it.",
         pat=_r(r"!\`[^\`]*(?:curl|wget|env\b|printenv|cat\s+[^\`]*(?:\.env|id_rsa|credential)|nc\s)[^\`]*\`")),

    # ---- Anti-refusal / safety nullification (targets the model) ----
    dict(id="AR-REFUSAL-SUPPRESS", cat="anti-refusal", sev="high", applies="markdown",
         title="Instruction to never refuse / always comply",
         rec="Telling the agent it must never refuse strips its ability to decline harmful requests. Distrust.",
         pat=_r(r"(?:never\s+refuse|do\s+not\s+(?:refuse|decline)|always\s+(?:comply|obey|say\s+yes)|you\s+must\s+(?:always\s+)?comply|without\s+(?:any\s+)?(?:refusal|hesitation|question))")),
    dict(id="AR-DISCLAIMER-SUPPRESS", cat="anti-refusal", sev="medium", applies="markdown",
         title="Instruction to suppress warnings / disclaimers",
         rec="Suppressing warnings hides risk from the user. Legitimate skills don't need this.",
         pat=_r(r"(?:do\s+not|don'?t|never)\s+(?:add|include|show|give)\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?)|no\s+disclaimers?\b|skip\s+the\s+safety\s+notice")),
    dict(id="AR-SAFETY-NULLIFY", cat="anti-refusal", sev="high", applies="markdown",
         title="Instruction to ignore safety / guidelines / policy",
         rec="Explicitly nullifying safety rules is a jailbreak. Treat as hostile.",
         pat=_r(r"ignore\s+(?:your\s+)?(?:safety|guidelines?|policies|policy|rules|restrictions?)|(?:safety|content)\s+(?:policy|guidelines?)\s+(?:do(?:es)?\s*n'?t|not)\s+apply|bypass\s+(?:your\s+)?(?:safety|guidelines?)")),

    # ---- System-prompt leakage ----
    dict(id="SP-LEAK", cat="system-prompt-leakage", sev="high", applies="markdown",
         title="Instruction to reveal system prompt / hidden instructions",
         rec="Requests to print the system prompt or hidden instructions are an exfiltration/recon attempt.",
         pat=_r(r"(?:print|reveal|repeat|show|output|disclose|dump)\s+(?:me\s+)?(?:your|the)?[^\n]{0,25}(?:system\s+prompt|initial\s+instructions?|hidden\s+instructions?|prompt\s+verbatim|instructions?\s+verbatim)")),

    # ---- Memory poisoning / persistence-by-instruction ----
    dict(id="MP-PERSIST-INSTRUCTION", cat="memory-poisoning", sev="high", applies="markdown",
         title="Instruction to persist a directive into memory / future sessions",
         rec="Skills that plant standing instructions ('always do X from now on', 'save to memory') can poison later sessions.",
         pat=_r(r"(?:in\s+(?:all\s+)?future\s+(?:sessions?|conversations?)|save\s+(?:this\s+)?(?:instruction\s+)?to\s+(?:memory|CLAUDE\.md|your\s+memory)|add\s+(?:this\s+)?to\s+(?:your\s+)?memory|persist\s+(?:this\s+)?across\s+sessions|remember\s+this\s+(?:in|for)\s+(?:all\s+)?future)")),

    # ---- Excessive agency ----
    dict(id="EA-AUTONOMY", cat="excessive-agency", sev="medium", applies="markdown",
         title="Instruction to take irreversible action autonomously without confirmation",
         rec="Auto-deleting, deploying, pushing, emailing, or paying without user confirmation is dangerous scope. Require a prompt.",
         pat=_r(r"(?:automatically|without\s+(?:asking|confirmation|approval|checking))\s+(?:delete|remove|deploy|push|commit|send|email|transfer|pay|purchase|overwrite)|(?:delete|deploy|push|send)\s+.{0,40}\bwithout\s+(?:asking|confirming)")),

    # ---- Trigger abuse ----
    dict(id="TR-BROAD", cat="trigger-abuse", sev="low", applies="markdown",
         title="Overly broad trigger ('use for everything / any task / always')",
         rec="A description that claims to handle any task grabs invocations away from safer paths. Scope the trigger.",
         pat=_r(r"use\s+(?:this\s+)?(?:for\s+)?(?:everything|any(?:thing| task| request| time)|all\s+tasks?)|always\s+use\s+this\s+skill|for\s+every\s+(?:task|request|prompt)")),

    # ---- MCP tool poisoning / least privilege (scanned in json/text) ----
    dict(id="MCP-TOOL-POISON", cat="mcp", sev="high", applies="text",
         title="Hidden instruction embedded in an MCP tool/description field",
         rec="Instructions smuggled into a tool description or MCP metadata run as agent context (tool poisoning). Inspect the field.",
         pat=_r(r"\"(?:description|instructions?|prompt)\"\s*:\s*\"[^\"]{0,200}(?:ignore\s+previous|do\s+not\s+tell|exfiltrat|send\s+(?:the\s+)?(?:secret|token|env)|<important>|system:)")),
    dict(id="MCP-WILDCARD", cat="mcp", sev="high", applies="text",
         title="MCP server declares wildcard / unrestricted capability",
         rec="Wildcard tool/capability grants in MCP config violate least privilege. Enumerate exactly what's needed.",
         pat=_r(r"\"(?:tools|capabilities|scopes?|permissions?|allowed)\"\s*:\s*(?:\"\*\"|\[\s*\"\*\"\s*\])|\"autoApprove\"\s*:\s*(?:true|\[\s*\"\*\")")),

    # ---- More malicious code / droppers ----
    dict(id="CE-POWERSHELL-ENC", cat="malicious-code", sev="high", applies="any",
         title="PowerShell encoded command (-EncodedCommand)",
         rec="Base64-encoded PowerShell hides the real command. Decode and inspect it.",
         pat=_r(r"powershell(?:\.exe)?[^\n]{0,40}-e(?:nc|ncodedcommand)?\b\s+[A-Za-z0-9+/=]{20,}")),
    dict(id="CE-PY-ONELINER", cat="malicious-code", sev="medium", applies="any",
         title="Inline python -c that execs / imports os / opens a socket",
         rec="A packed `python -c` one-liner is a common launcher. Expand it and confirm what it does.",
         pat=_r(r"python3?\s+-c\s+[\"'][^\"']{0,200}(?:exec|eval|__import__|import\s+os|import\s+socket|b64decode)")),
    dict(id="CE-CURL-CHMOD-RUN", cat="malicious-code", sev="high", applies="any",
         title="Download → chmod +x → execute chain",
         rec="Fetching a file, marking it executable, and running it is a dropper. Vendor and review the code instead.",
         pat=_r(r"chmod\s+\+x[^\n]{0,60}(?:&&|;)[^\n]{0,60}(?:\./|bash\s|sh\s)|(?:curl|wget)[^\n]{0,80}-o[^\n]{0,40}(?:&&|;)[^\n]{0,40}chmod")),
    dict(id="CE-MARSHAL-PICKLE", cat="malicious-code", sev="high", applies="code",
         title="Executes serialized code (pickle / marshal / cloudpickle loads)",
         rec="Deserializing code from data runs arbitrary logic. Never unpickle untrusted data.",
         pat=_r(r"(?:pickle|cloudpickle|marshal)\.loads?\s*\(|dill\.loads?\s*\(")),
    dict(id="CE-ZLIB-EXEC", cat="obfuscation", sev="high", applies="code",
         title="Decompress-then-execute (zlib/gzip → exec/marshal)",
         rec="Compressed blobs that get decompressed and executed hide the payload. Decode and inspect.",
         pat=_r(r"(?:zlib|gzip|lzma|bz2)\.decompress\s*\([^\n]{0,80}(?:exec|eval|marshal|loads)")),
    dict(id="CE-CHR-CHAIN", cat="obfuscation", sev="medium", applies="code",
         title="String built from chr()/ord() arithmetic (obfuscation)",
         rec="Character-by-character string building usually hides a command or URL. Reconstruct it.",
         pat=_r(r"(?:chr\(\s*\d+\s*\)\s*\+\s*){3,}|\"\"\.join\(\s*(?:chr|map)\b")),
    dict(id="CE-STR-REVERSE", cat="obfuscation", sev="low", applies="code",
         title="Reversed-string execution ([::-1] into exec/eval)",
         rec="Reversing a string before executing it is an obfuscation trick. Reverse it and read it.",
         pat=_r(r"\[::-1\][^\n]{0,40}(?:exec|eval|__import__|system)")),

    # ---- More exfiltration channels ----
    dict(id="EX-EMAIL", cat="data-exfiltration", sev="medium", applies="code",
         title="Sends data by email (smtplib / sendmail / SES)",
         rec="Email is an exfiltration channel. Confirm what is being sent and to whom.",
         pat=_r(r"smtplib\.(?:SMTP|SMTP_SSL)\s*\(|import\s+smtplib|sendmail\b|MIMEText\s*\(|ses\.send_email\s*\(")),
    dict(id="EX-DNS", cat="data-exfiltration", sev="high", applies="code",
         title="Possible DNS exfiltration (data interpolated into a hostname lookup)",
         rec="Encoding data into DNS queries hides it in normal traffic. Verify the lookup target.",
         pat=_r(r"(?:gethostbyname|resolve|dns\.resolver|nslookup|dig)\s*[\(\s][^\n]{0,60}(?:\+|\$\(|encode|b64|hex)")),
    dict(id="EX-CLIPBOARD", cat="data-exfiltration", sev="medium", applies="code",
         title="Reads the system clipboard",
         rec="Clipboard often holds passwords and tokens. Confirm the skill needs it and where it goes.",
         pat=_r(r"pyperclip\.paste\s*\(|pbpaste\b|xclip\s+-o|xsel\s+-b|Get-Clipboard\b|clipboard\.readText")),
    dict(id="EX-SCREENSHOT", cat="data-exfiltration", sev="medium", applies="code",
         title="Captures the screen",
         rec="Screen capture can leak on-screen secrets. Confirm intent and destination.",
         pat=_r(r"ImageGrab\.grab\s*\(|pyautogui\.screenshot\s*\(|screencapture\b|\bscrot\b|import\s+mss\b")),
    dict(id="EX-GIT-REMOTE", cat="data-exfiltration", sev="high", applies="any",
         title="Pushes data to an external git remote",
         rec="Adding a remote and pushing can smuggle files out. Verify the remote URL.",
         pat=_r(r"git\s+remote\s+add\s+\S+\s+https?://|git\s+push\s+https?://")),

    # ---- Output handling ----
    dict(id="OH-HTML-INJECT", cat="output-handling", sev="medium", applies="code",
         title="Writes dynamic content into the DOM (innerHTML / document.write)",
         rec="Injecting unvalidated content into HTML is an XSS surface. Sanitize or use textContent.",
         pat=_r(r"(?:innerHTML|outerHTML)\s*=\s*[^;\n]{0,60}(?:\+|\$\{|`)|document\.write\s*\(")),
    dict(id="OH-UNVALIDATED-SINK", cat="output-handling", sev="medium", applies="code",
         title="Network/tool response flows straight into a dangerous sink",
         rec="Feeding fetched data directly into exec/eval/SQL lets a remote server drive your machine. Validate first.",
         pat=_r(r"(?:\.text|\.json\(\)|\.content|response|resp|fetched)[^\n]{0,50}(?:exec\s*\(|eval\s*\(|os\.system|cursor\.execute\s*\(\s*[^,\n]*\+)")),
    dict(id="OH-UNBOUNDED", cat="output-handling", sev="info", applies="code",
         title="Unbounded loop (potential resource exhaustion)",
         rec="An infinite loop with side effects can hang or exhaust resources. Confirm it has a real exit.",
         pat=_r(r"while\s+True\s*:\s*(?:#[^\n]*)?$|while\s*\(\s*(?:true|1)\s*\)\s*\{")),

    # ---- Tool misuse ----
    dict(id="TM-UNSAFE-DEFAULT", cat="tool-misuse", sev="low", applies="markdown",
         title="Dangerous action framed as the default behavior",
         rec="Making a destructive/privileged action the default hides risk from the user. Require an explicit opt-in.",
         pat=_r(r"by\s+default[^\n]{0,50}(?:run|execute|enable|allow|delete|remove|skip\s+(?:the\s+)?(?:check|confirm))")),
    dict(id="TM-CHAINING", cat="tool-misuse", sev="medium", applies="markdown",
         title="Instruction to chain tools to bypass a control",
         rec="Chaining tools specifically to get around a limit or check is misuse. Review the intent.",
         pat=_r(r"(?:chain|combine|pipe)\s+[^\n]{0,40}(?:to\s+)?(?:bypass|evade|get\s+around|circumvent|avoid\s+(?:the\s+)?(?:check|limit|permission))")),

    # ---- More prompt injection ----
    dict(id="PI-MODE-SWITCH", cat="prompt-injection", sev="high", applies="markdown",
         title="Fake privileged 'mode' activation (developer/god/root/debug mode)",
         rec="'You are now in developer/god mode' is a jailbreak framing. Distrust.",
         pat=_r(r"you\s+are\s+(?:now\s+)?(?:in\s+)?(?:developer|debug|god|admin|root|sudo|dan|jailbreak)\s*(?:mode)?\b|enable\s+(?:developer|god|debug)\s+mode")),
    dict(id="PI-FAKE-TURN", cat="prompt-injection", sev="medium", applies="markdown",
         title="Injected fake conversation turn / tool result",
         rec="Text imitating a system/assistant turn or a tool result tries to hijack the dialogue. Inspect it.",
         pat=_r(r"</?(?:system|assistant|user|function_call|tool_result)>|\[(?:system|assistant)\]\s*:|\bfunction_results?\b\s*:")),
    dict(id="PI-DECODE-FOLLOW", cat="prompt-injection", sev="high", applies="markdown",
         title="Instruction to decode text and then follow it",
         rec="'Decode the following and do what it says' smuggles instructions past a reader. Decode and inspect.",
         pat=_r(r"decode\s+(?:the\s+)?(?:following|below|this|base64|hex)[^\n]{0,50}(?:and\s+)?(?:follow|execute|run|do\s+what|obey)")),
    dict(id="PI-WHITESPACE-PAD", cat="prompt-injection", sev="low", applies="markdown",
         title="Large whitespace padding (may hide instructions off-screen)",
         rec="Long runs of spaces push hidden text out of view. Check what follows the padding.",
         pat=_r(r"\S {120,}\S| {200,}")),

    # ---- More supply chain ----
    dict(id="SC-POSTINSTALL", cat="supply-chain", sev="high", applies="text",
         title="npm pre/post-install lifecycle script",
         rec="install-time scripts run automatically on `npm install` — a classic supply-chain execution point. Review it.",
         pat=_r(r"\"(?:preinstall|postinstall|install)\"\s*:\s*\"[^\"]+\"")),
    dict(id="SC-RAW-FETCH-HOST", cat="supply-chain", sev="medium", applies="any",
         title="Fetches from raw code-hosting / gist URLs",
         rec="Pulling code from raw.githubusercontent or gists at runtime bypasses review. Vendor it in.",
         pat=_r(r"raw\.githubusercontent\.com|gist\.githubusercontent\.com|gitlab\.com/[^\s]+/raw/")),
    dict(id="SC-INDEX-OVERRIDE", cat="supply-chain", sev="high", applies="any",
         title="Overrides the package index/registry (dependency confusion)",
         rec="Pointing pip/npm at a custom index can pull attacker packages. Remove or pin to the official registry.",
         pat=_r(r"pip\s+install[^\n]{0,80}--(?:extra-)?index-url\s+https?://|npm\s+(?:install|i)[^\n]{0,80}--registry\s+https?://|PIP_INDEX_URL\s*=")),
    dict(id="SC-TYPOSQUAT", cat="supply-chain", sev="medium", applies="code",
         title="Imports a known typosquat package name",
         rec="This name resembles a popular package but isn't it — a common malware delivery trick. Verify the package.",
         pat=_r(r"\b(?:import|require)\s*\(?\s*['\"]?(?:requsts|reqeusts|urllib3333|beautifulsoup(?!4)|python3-dateutil|djangoo|pythonkafka|colourama|python-mysql)\b")),

    # ---- More privilege / persistence ----
    dict(id="PE-AUTHKEYS-WRITE", cat="persistence", sev="critical", applies="any",
         title="Writes an SSH key into authorized_keys (backdoor)",
         rec="Appending to authorized_keys installs a permanent remote-login backdoor. There is no benign reason in a skill.",
         pat=_r(r">>?\s*[^\n]{0,60}\.ssh/authorized_keys|echo\s+[^\n]{0,120}>>?\s*[^\n]{0,40}authorized_keys")),
    dict(id="PE-SUDOERS", cat="privilege-escalation", sev="critical", applies="any",
         title="Modifies /etc/sudoers",
         rec="Editing sudoers grants standing privilege escalation. Treat as malicious.",
         pat=_r(r"/etc/sudoers(?:\.d)?\b|visudo\b")),
    dict(id="PE-PATH-HIJACK", cat="privilege-escalation", sev="medium", applies="any",
         title="Prepends a writable/relative dir to PATH (binary hijack)",
         rec="Putting '.' or a writable dir first in PATH lets a planted binary shadow a real command. Avoid it.",
         pat=_r(r"export\s+PATH\s*=\s*(?:\.|\$PWD|/tmp)[:\"']*.{0,10}\$PATH|PATH\s*=\s*\.:\$PATH")),
]

# Precompute a broad URL finder for context (used to enrich, not to flag alone).
URL_RE = _r(r"https?://[^\s'\"\)\]}>]+")
# Private/loopback IP ranges to downgrade EX-HARDCODED-IP noise.
PRIVATE_IP_RE = _r(r"^(?:https?://)?(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|255\.)")


def _ships_executable(root):
    """True if the skill bundles any executable/script file (bigger blast radius)."""
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "__pycache__", "node_modules")]
        for f in fn:
            if os.path.splitext(f)[1].lower() in CODE_EXTS:
                return True
    return False


def kind_of(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in CODE_EXTS:
        return "code"
    if ext in (".md", ".markdown"):
        return "markdown"
    if ext in TEXT_EXTS:
        return "text"
    return "other"


def rule_applies(rule, kind):
    a = rule["applies"]
    if a == "any":
        return kind in ("code", "markdown", "text")
    if a == "text":
        return kind in ("code", "markdown", "text")
    return a == kind


def snippet(line):
    s = line.strip()
    if len(s) > MAX_SNIPPET:
        s = s[:MAX_SNIPPET] + "…"
    return s


def scan_text_file(rel, abspath, findings):
    kind = kind_of(rel)
    try:
        with open(abspath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        return
    lines = content.splitlines()

    # Invisible / bidi unicode smuggling — scan whole content for control chars.
    for m in re.finditer(r"[​-‏‪-‮⁠-⁤﻿­]", content):
        line_no = content.count("\n", 0, m.start()) + 1
        findings.append(dict(
            rule="PI-HIDDEN-UNICODE", category="prompt-injection", severity="high",
            file=rel, line=line_no,
            title="Invisible / bidirectional Unicode character",
            snippet=f"U+{ord(m.group()):04X} at column {m.start() - content.rfind(chr(10), 0, m.start())}",
            recommendation="Zero-width or bidi characters can hide instructions from a human reader while the model still reads them. Remove them and inspect the surrounding text."))

    # Evasion markers: we deliberately do NOT honor in-file suppression
    # comments (a malicious skill could add them to hide). Their presence is
    # itself a weak signal worth surfacing.
    for m in re.finditer(r"(?:skillvet:ignore|skillscan:ignore|\bnosec\b|# *noqa:? *security)", content, re.IGNORECASE):
        line_no = content.count("\n", 0, m.start()) + 1
        findings.append(dict(
            rule="EVASION-MARKER", category="review", severity="low",
            file=rel, line=line_no, title="Scanner-suppression / lint-ignore marker present",
            snippet=snippet(lines[line_no - 1] if 0 < line_no <= len(lines) else m.group()),
            recommendation="This scanner does not honor in-file suppression, but the marker's presence can indicate an attempt to dodge review. Confirm why it's here."))

    for rule in RULES:
        if not rule_applies(rule, kind):
            continue
        for m in rule["pat"].finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            raw_line = lines[line_no - 1] if 0 < line_no <= len(lines) else m.group()
            sev = rule["sev"]
            # Downgrade private/loopback IPs to info for the hardcoded-IP rule.
            if rule["id"] == "EX-HARDCODED-IP" and PRIVATE_IP_RE.search(m.group()):
                continue
            findings.append(dict(
                rule=rule["id"], category=rule["cat"], severity=sev,
                file=rel, line=line_no, title=rule["title"],
                snippet=snippet(raw_line), recommendation=rule["rec"]))

    # RA-SELFMOD (code only): fires when a script BOTH references a Claude
    # skills/config path AND performs a real write there. This avoids the huge
    # false-positive class of README/SKILL.md install instructions
    # ("cp -r <skill> ~/.claude/skills/"), which are prose, not code that writes.
    if kind == "code":
        pm = SELFMOD_PATH_RE.search(content)
        if pm:
            wm = SELFMOD_WRITE_RE.search(content)
            if wm:
                line_no = content.count("\n", 0, wm.start()) + 1
                findings.append(dict(
                    rule="RA-SELFMOD", category="rogue-agent", severity="high",
                    file=rel, line=line_no,
                    title="Script writes to a Claude skills/config path (self- or cross-skill modification)",
                    snippet=snippet(lines[line_no - 1] if 0 < line_no <= len(lines) else wm.group()),
                    recommendation="Code that programmatically writes into ~/.claude (skills, settings, CLAUDE.md, agents, hooks) can rewrite itself or other skills to add malicious behavior after review. Confirm this is an intended, disclosed action."))


# Two-signal RA-SELFMOD: a claude path reference + an actual write primitive.
SELFMOD_PATH_RE = _r(r"\.claude/(?:skills|settings|agents|hooks|commands)|(?:^|[/'\"\s])CLAUDE\.md")
SELFMOD_WRITE_RE = _r(r"open\s*\([^)]*,\s*['\"][aw]|\.write\s*\(|writelines\s*\(|"
                      r"shutil\.(?:copy2?|copytree|move)\s*\(|os\.replace\s*\(|"
                      r">>?\s*[^\n]{0,80}\.claude/|tee\s+[^\n]{0,80}\.claude/")


# ---------------------------------------------------------------------------
# Python AST taint pass: flag a file that BOTH reads a sensitive source AND
# has a network sink — a strong exfiltration signal that line rules may miss.
# ---------------------------------------------------------------------------
SENSITIVE_SOURCE_HINTS = ("environ", "getenv", "id_rsa", ".ssh", ".aws", "credential",
                          "password", "token", "secret", "api_key", "apikey", "netrc",
                          "keyring", "cookie", "read_clipboard")
NETWORK_SINK_NAMES = ("post", "put", "get", "urlopen", "request", "send", "sendto",
                      "connect", "sendall", "urlretrieve")
NETWORK_MODULES = ("requests", "urllib", "httpx", "http", "socket", "aiohttp", "ftplib", "smtplib")
# Secret-file paths for the AST taint source (tight — real credential files only).
SECRET_FILE_RE = _r(r"\.ssh/(?:id_(?:rsa|ed25519|ecdsa|dsa)|authorized_keys)|id_rsa|\.aws/credentials|"
                    r"\.config/gcloud|\.kube/config|\.docker/config\.json|\.netrc|\.npmrc|\.pypirc|"
                    r"\.git-credentials|/etc/shadow|/etc/passwd|Login Data|cookies\.sqlite")


def ast_taint_python(rel, abspath, findings):
    try:
        with open(abspath, "r", encoding="utf-8", errors="replace") as f:
            src = f.read()
        tree = ast.parse(src)
    except Exception:
        return

    has_sensitive = False
    sensitive_line = None
    has_network = False
    network_line = None

    def _str_arg(call):
        if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
            return call.args[0].value
        return ""

    for node in ast.walk(tree):
        # --- Sensitive SOURCE: only genuine secret access, not stray words. ---
        # os.environ (bulk env), os.getenv, keyring.get_password
        if isinstance(node, ast.Attribute) and node.attr == "environ":
            if not has_sensitive:
                has_sensitive, sensitive_line = True, getattr(node, "lineno", None)
        if isinstance(node, ast.Call):
            fn = node.func
            fname = fn.attr.lower() if isinstance(fn, ast.Attribute) else (fn.id.lower() if isinstance(fn, ast.Name) else "")
            # open(<secret-file path literal>, ...)
            if fname == "open":
                if SECRET_FILE_RE.search(_str_arg(node)) and not has_sensitive:
                    has_sensitive, sensitive_line = True, getattr(node, "lineno", None)
            # getenv / keyring.get_password / read_clipboard-style secret getters
            if fname in ("getenv", "get_password") and not has_sensitive:
                has_sensitive, sensitive_line = True, getattr(node, "lineno", None)

        # --- Network SINK: must be a real network library call, not any get(). ---
        if isinstance(node, ast.Call):
            func = node.func
            name = ""
            mod = ""
            if isinstance(func, ast.Attribute):
                name = func.attr.lower()
                if isinstance(func.value, ast.Name):
                    mod = func.value.id.lower()
                elif isinstance(func.value, ast.Attribute):
                    mod = func.value.attr.lower()
            elif isinstance(func, ast.Name):
                name = func.id.lower()
            is_net = (mod in NETWORK_MODULES and name in NETWORK_SINK_NAMES) or \
                     name in ("urlopen", "urlretrieve") or \
                     mod in ("requests", "httpx", "aiohttp")
            if is_net and not has_network:
                has_network, network_line = True, getattr(node, "lineno", None)

    if has_sensitive and has_network:
        findings.append(dict(
            rule="EX-TAINT-EXFIL", category="data-exfiltration", severity="critical",
            file=rel, line=sensitive_line or network_line or 1,
            title="Sensitive data read AND network egress in the same script",
            snippet=f"sensitive access near line {sensitive_line}, network call near line {network_line}",
            recommendation="This is a classic read-secret-then-send-it exfiltration shape. Trace the dataflow: confirm the secret is not what leaves the machine."))


YARA_SEV = {"critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "info": "info"}


def scan_yara(root, findings, rules_path=None):
    """Optional YARA layer. Runs only if the `yara` module is importable and the
    bundled ruleset compiles. Silent no-op otherwise (keeps the core dep-free)."""
    try:
        import yara
    except Exception:
        return False
    if rules_path is None:
        here = os.path.dirname(os.path.abspath(__file__))
        rules_path = os.path.normpath(os.path.join(here, "..", "references", "skillvet.yar"))
    if not os.path.isfile(rules_path):
        return False
    cache = getattr(scan_yara, "_cache", {})
    rules = cache.get(rules_path)
    if rules is None:
        try:
            rules = yara.compile(filepath=rules_path)
        except Exception:
            return False
        cache[rules_path] = rules
        scan_yara._cache = cache

    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "__pycache__", "node_modules")]
        for f in fn:
            ap = os.path.join(dp, f)
            rel = os.path.relpath(ap, root)
            try:
                if os.path.getsize(ap) > 5_000_000:
                    continue
                matches = rules.match(ap, timeout=10)
            except Exception:
                continue
            for m in matches:
                sev = YARA_SEV.get((m.meta or {}).get("severity", "high"), "high")
                findings.append(dict(
                    rule=f"YR-{m.rule}", category="yara", severity=sev,
                    file=rel, line=0,
                    title=(m.meta or {}).get("description", m.rule),
                    snippet=", ".join(sorted({s.identifier for s in m.strings})[:6]) if getattr(m, "strings", None) else m.rule,
                    recommendation="A YARA signature for known-malicious content matched. Inspect this file closely."))
    return True


def scan_dir(root):
    findings = []
    file_count = 0
    scanned_names = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip VCS internals but still report if a skill ships a .git dir.
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "node_modules")]
        for fn in filenames:
            abspath = os.path.join(dirpath, fn)
            rel = os.path.relpath(abspath, root)
            ext = os.path.splitext(fn)[1].lower()
            file_count += 1
            scanned_names.append(rel)

            if ext in SUSPICIOUS_BINARY_EXTS:
                findings.append(dict(
                    rule="BIN-PRESENT", category="supply-chain", severity="high",
                    file=rel, line=0, title="Bundled binary / compiled artifact",
                    snippet=f"{fn} ({os.path.getsize(abspath)} bytes)",
                    recommendation="A skill shipping a prebuilt binary can't be reviewed as source. Require source + a reproducible build, or remove it."))
                continue

            kind = kind_of(rel)
            if kind in ("code", "markdown", "text"):
                # Guard against very large files.
                try:
                    if os.path.getsize(abspath) > 5_000_000:
                        findings.append(dict(
                            rule="SIZE-LARGE", category="review", severity="info",
                            file=rel, line=0, title="Unusually large text/code file",
                            snippet=f"{os.path.getsize(abspath)} bytes",
                            recommendation="Large files are hard to review and can hide payloads. Confirm why it's this big."))
                        continue
                except OSError:
                    continue
                scan_text_file(rel, abspath, findings)
                if ext == ".py":
                    ast_taint_python(rel, abspath, findings)

    return findings, file_count, scanned_names


# ---------------------------------------------------------------------------
# Frontmatter (SKILL.md) specific checks.
# ---------------------------------------------------------------------------
def check_frontmatter(root, findings):
    skill_md = None
    for cand in ("SKILL.md", "skill.md"):
        p = os.path.join(root, cand)
        if os.path.isfile(p):
            skill_md = p
            break
    if not skill_md:
        # search one level down
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if fn.lower() == "skill.md":
                    skill_md = os.path.join(dirpath, fn)
                    break
            if skill_md:
                break
    if not skill_md:
        findings.append(dict(
            rule="FM-NO-SKILLMD", category="review", severity="info", file=".", line=0,
            title="No SKILL.md found at the scanned root",
            snippet="", recommendation="Point the scanner at the skill directory that contains SKILL.md."))
        return

    rel = os.path.relpath(skill_md, root)
    try:
        with open(skill_md, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return
    fm = re.match(r"^\s*---\s*\n(.*?)\n---\s*\n", content, re.DOTALL)
    if not fm:
        return
    block = fm.group(1)

    # allowed-tools breadth
    at = re.search(r"^\s*allowed-tools\s*:\s*(.+)$", block, re.MULTILINE | re.IGNORECASE)
    if at:
        val = at.group(1).strip()
        line_no = content.count("\n", 0, fm.start() + block.find(at.group(0))) + 1
        if re.search(r"Bash(?:\(\s*\*\s*\)|\b(?!\())|:\s*\*|\ball\b|\*\s*$", val) or val.strip() in ("*", "'*'", '"*"'):
            findings.append(dict(
                rule="FM-BROAD-TOOLS", category="privilege-escalation", severity="high",
                file=rel, line=line_no, title="Over-broad allowed-tools grant",
                snippet=snippet(at.group(0)),
                recommendation="allowed-tools pre-approves tools with no per-use prompt. A wildcard Bash(*) or blanket grant lets the skill run anything silently. Scope it to exact commands."))
        elif re.search(r"Bash", val, re.IGNORECASE):
            findings.append(dict(
                rule="FM-BASH-GRANT", category="privilege-escalation", severity="medium",
                file=rel, line=line_no, title="Skill pre-approves Bash via allowed-tools",
                snippet=snippet(at.group(0)),
                recommendation="Confirm the Bash pattern is tightly scoped (e.g. Bash(git status *)) rather than broad. Pre-approved Bash runs without a prompt."))

    # hooks in frontmatter — persists for the session
    if re.search(r"^\s*hooks\s*:", block, re.MULTILINE | re.IGNORECASE):
        line_no = content.count("\n", 0, fm.start() + block.lower().find("hooks")) + 1
        findings.append(dict(
            rule="FM-HOOKS", category="skill-mechanics", severity="medium",
            file=rel, line=line_no, title="Skill registers hooks",
            snippet="hooks: …",
            recommendation="Frontmatter hooks keep running for the rest of the session, even after the skill's turn. Review what each hook executes."))

    # name masquerading as anthropic/claude (spec forbids, but flag attempts)
    nm = re.search(r"^\s*name\s*:\s*(.+)$", block, re.MULTILINE | re.IGNORECASE)
    if nm and re.search(r"anthropic|claude|official|verified|trusted", nm.group(1), re.IGNORECASE):
        line_no = content.count("\n", 0, fm.start() + block.find(nm.group(0))) + 1
        findings.append(dict(
            rule="FM-IMPERSONATION", category="prompt-injection", severity="medium",
            file=rel, line=line_no, title="Name implies official/trusted provenance",
            snippet=snippet(nm.group(0)),
            recommendation="Names claiming to be 'official', 'verified', or from Anthropic/Claude can lull reviewers. Confirm the real source."))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def summarize(findings):
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def verdict(counts):
    if counts.get("critical"):
        return "CRITICAL — do NOT install without a full manual review. Malicious-intent patterns present."
    if counts.get("high"):
        return "HIGH RISK — review each high finding in context before installing."
    if counts.get("medium"):
        return "CAUTION — some patterns need a human judgment call."
    if counts.get("low") or counts.get("info"):
        return "LOW — minor / hygiene findings only. Still skim the skill before trusting it."
    return "CLEAN — no known-bad patterns matched. This is NOT a proof of safety; review anyway."


# Additive risk score (SkillSpector-style): severity weights, capped at 100,
# with a multiplier when the skill ships executable scripts (bigger blast radius).
SEV_WEIGHT = {"critical": 50, "high": 25, "medium": 10, "low": 5, "info": 0}


def risk_score(findings, ships_executable):
    raw = sum(SEV_WEIGHT[f["severity"]] for f in findings)
    if ships_executable:
        raw = int(round(raw * 1.3))
    return min(100, raw)


def score_band(score):
    """Return (band, recommendation)."""
    if score >= 81:
        return "CRITICAL", "DO NOT INSTALL"
    if score >= 51:
        return "HIGH", "DO NOT INSTALL"
    if score >= 21:
        return "MEDIUM", "INSTALL WITH CARE"
    return "LOW", "LIKELY SAFE — review before trusting"


def finding_fingerprint(f):
    """Stable id for baseline suppression (rule + file + snippet, line-tolerant)."""
    import hashlib
    basis = f"{f['rule']}|{f['file']}|{(f.get('snippet') or '').strip()}"
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


def render_markdown(target_name, findings, file_count, counts, score=None, band=None, rec=None):
    order = sorted(findings, key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["file"], f["line"]))
    lines = []
    lines.append(f"# Skill security scan — `{target_name}`\n")
    lines.append(f"**Files scanned:** {file_count}  ")
    lines.append(f"**Findings:** {len(findings)} "
                 f"(critical {counts['critical']}, high {counts['high']}, medium {counts['medium']}, "
                 f"low {counts['low']}, info {counts['info']})\n")
    if score is not None:
        lines.append(f"**Risk score:** {score}/100 — **{band}** → **{rec}**\n")
    lines.append(f"**Static verdict:** {verdict(counts)}\n")
    lines.append("> This is the deterministic static pass only. A reviewer should confirm each finding "
                 "in context — a match is a reason to look, not a proof of malice. No findings ≠ safe.\n")

    lines.append("## Findings\n")
    if not order:
        lines.append("_No pattern matched._\n")
    else:
        lines.append("| Sev | Rule | Category | File:Line | Detail |")
        lines.append("|-----|------|----------|-----------|--------|")
        badge = {"critical": "🔴 CRIT", "high": "🟠 HIGH", "medium": "🟡 MED",
                 "low": "🔵 LOW", "info": "⚪ INFO"}
        for f in order:
            loc = f["file"] if f["line"] in (0, None) else f'{f["file"]}:{f["line"]}'
            detail = f['title'].replace("|", "\\|")
            snip = (f.get("snippet") or "").replace("|", "\\|").replace("`", "'")
            cell = detail + (f" — `{snip}`" if snip else "")
            lines.append(f'| {badge[f["severity"]]} | {f["rule"]} | {f["category"]} | `{loc}` | {cell} |')
        lines.append("")
        lines.append("## Recommendations\n")
        seen = set()
        for f in order:
            key = f["rule"]
            if key in seen:
                continue
            seen.add(key)
            loc = f["file"] if f["line"] in (0, None) else f'{f["file"]}:{f["line"]}'
            lines.append(f'- **{f["rule"]}** ({f["severity"]}, `{loc}`): {f["recommendation"]}')
        lines.append("")
    return "\n".join(lines)


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "note"}


def render_sarif(target_name, findings):
    """SARIF 2.1.0 for GitHub Code Scanning / IDE integration."""
    rule_ids = sorted({f["rule"] for f in findings})
    rules = [{
        "id": rid,
        "name": rid,
        "shortDescription": {"text": next((f["title"] for f in findings if f["rule"] == rid), rid)},
        "properties": {"category": next((f["category"] for f in findings if f["rule"] == rid), "")},
    } for rid in rule_ids]
    results = []
    for f in findings:
        loc = {"physicalLocation": {
            "artifactLocation": {"uri": f["file"]},
            "region": {"startLine": max(1, int(f["line"] or 1))},
        }}
        results.append({
            "ruleId": f["rule"],
            "level": SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f'{f["title"]} — {f.get("snippet","")}'.strip(" —")},
            "locations": [loc],
            "properties": {"severity": f["severity"], "category": f["category"],
                           "recommendation": f["recommendation"]},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "skillvet",
                "informationUri": "https://github.com/skillvet/skillvet",
                "rules": rules,
            }},
            "results": results,
            "properties": {"target": target_name},
        }],
    }, indent=2)


def safe_extract(zip_path, dest, max_bytes=100 * 1024 * 1024, max_members=10000):
    """Extract a .skill/.zip with zip-bomb and zip-slip protection."""
    total = 0
    with zipfile.ZipFile(zip_path) as z:
        infos = z.infolist()
        if len(infos) > max_members:
            raise ValueError(f"archive has {len(infos)} members (> {max_members}); refusing (possible zip bomb)")
        dest_abs = os.path.realpath(dest)
        for info in infos:
            # zip-slip: reject paths that escape dest
            target = os.path.realpath(os.path.join(dest, info.filename))
            if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
                raise ValueError(f"unsafe path in archive (zip-slip): {info.filename}")
            total += info.file_size
            if total > max_bytes:
                raise ValueError(f"archive expands to > {max_bytes} bytes; refusing (possible zip bomb)")
        z.extractall(dest)


def osv_check(root, findings):
    """Optional: query OSV.dev for known-vulnerable declared dependencies.
    Network, no API key; silent offline fallback. Parses requirements.txt and
    package.json exact pins (name==ver / "name": "x.y.z")."""
    import urllib.request

    deps = []  # (ecosystem, name, version, file, line)
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "__pycache__", "node_modules")]
        for f in fn:
            ap = os.path.join(dp, f)
            rel = os.path.relpath(ap, root)
            try:
                if f == "requirements.txt":
                    for i, line in enumerate(open(ap, encoding="utf-8", errors="replace"), 1):
                        m = re.match(r"^\s*([A-Za-z0-9_.-]+)==([0-9][\w.\-]*)", line)
                        if m:
                            deps.append(("PyPI", m.group(1), m.group(2), rel, i))
                elif f == "package.json":
                    data = json.load(open(ap, encoding="utf-8", errors="replace"))
                    for sect in ("dependencies", "devDependencies"):
                        for name, ver in (data.get(sect) or {}).items():
                            v = re.sub(r"^[^0-9]*", "", str(ver))
                            if v:
                                deps.append(("npm", name, v, rel, 0))
            except Exception:
                continue

    if not deps:
        return
    queries = [{"package": {"ecosystem": eco, "name": name}, "version": ver}
               for (eco, name, ver, _, _) in deps]
    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/querybatch",
            data=json.dumps({"queries": queries}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            results = json.load(resp).get("results", [])
    except Exception:
        return  # offline / unreachable -> skip silently

    for (eco, name, ver, rel, line), res in zip(deps, results):
        vulns = res.get("vulns") or []
        if vulns:
            ids = ", ".join(v.get("id", "?") for v in vulns[:5])
            findings.append(dict(
                rule="SC-KNOWN-CVE", category="supply-chain", severity="high",
                file=rel, line=line,
                title=f"Declared dependency {name}=={ver} has known vulnerabilities",
                snippet=f"{eco}:{name}@{ver} → {ids}",
                recommendation="OSV.dev reports known advisories for this pinned version. Upgrade to a patched release."))


def main(argv):
    ap = argparse.ArgumentParser(description="Static security scanner for Agent Skills.")
    ap.add_argument("target", help="Path to a skill directory or a .skill/.zip archive")
    ap.add_argument("--json", dest="json_out", help="Write findings as JSON to this file")
    ap.add_argument("--markdown", dest="md_out", help="Write a Markdown report to this file")
    ap.add_argument("--sarif", dest="sarif_out", help="Write SARIF 2.1.0 to this file (GitHub Code Scanning / IDEs)")
    ap.add_argument("--min-severity", default="info", choices=list(SEVERITY_ORDER))
    ap.add_argument("--fail-on", default="high", choices=list(SEVERITY_ORDER))
    ap.add_argument("--osv", action="store_true", help="Also query OSV.dev for known-vulnerable declared deps (needs network; silent offline fallback)")
    ap.add_argument("--no-yara", action="store_true", help="Disable the YARA layer even if the yara module is installed")
    ap.add_argument("--baseline", help="Suppress findings listed in this baseline JSON (re-scans surface only new ones)")
    ap.add_argument("--write-baseline", help="Write the current findings to this baseline JSON and exit 0")
    ap.add_argument("--show-suppressed", action="store_true", help="Still list baseline-suppressed findings (they don't affect score/exit)")
    ap.add_argument("--llm", action="store_true", help="Run the optional LLM triage stage: reason over code+instructions, drop false positives, catch semantic attacks the static pass misses")
    ap.add_argument("--llm-provider", default="cli", choices=["cli", "anthropic", "openai"])
    ap.add_argument("--llm-model", default=None)
    ap.add_argument("--llm-cmd", default=None, help="Command for --llm-provider cli (default: 'claude -p')")
    ap.add_argument("--llm-timeout", type=int, default=90)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    target = args.target
    tmpdir = None
    if os.path.isfile(target) and target.lower().endswith((".zip", ".skill")):
        tmpdir = tempfile.mkdtemp(prefix="skillscan_")
        try:
            safe_extract(target, tmpdir)
        except Exception as e:
            print(f"error: could not safely unpack {target}: {e}", file=sys.stderr)
            return 2
        root = tmpdir
    elif os.path.isdir(target):
        root = target
    elif os.path.isfile(target):
        root = os.path.dirname(os.path.abspath(target)) or "."
    else:
        print(f"error: {target} is not a directory or .skill/.zip archive", file=sys.stderr)
        return 2

    findings, file_count, _ = scan_dir(root)
    check_frontmatter(root, findings)
    yara_ran = False
    if not args.no_yara:
        yara_ran = scan_yara(root, findings)
    if args.osv:
        osv_check(root, findings)

    # De-duplicate identical hits (same rule at the same file:line), which
    # happen when a single line contains several alternations of one pattern.
    deduped = {}
    for f in findings:
        key = (f["rule"], f["file"], f["line"])
        if key not in deduped:
            deduped[key] = f
    findings = list(deduped.values())

    # Filter by min severity.
    min_lvl = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if SEVERITY_ORDER[f["severity"]] >= min_lvl]

    # Baseline write mode: record fingerprints and exit.
    if args.write_baseline:
        base = {"target": os.path.basename(os.path.normpath(target)),
                "fingerprints": sorted({finding_fingerprint(f) for f in findings})}
        with open(args.write_baseline, "w", encoding="utf-8") as f:
            json.dump(base, f, indent=2)
        if not args.quiet:
            print(f"Wrote baseline with {len(base['fingerprints'])} fingerprints to {args.write_baseline}")
        return 0

    # Baseline suppression.
    suppressed = []
    if args.baseline:
        try:
            with open(args.baseline, encoding="utf-8") as f:
                known = set(json.load(f).get("fingerprints", []))
            kept = []
            for f in findings:
                (suppressed if finding_fingerprint(f) in known else kept).append(f)
            findings = kept
        except Exception as e:
            print(f"warning: could not read baseline {args.baseline}: {e}", file=sys.stderr)

    # Optional LLM triage stage (reasons over code + instructions).
    llm_summary = None
    if args.llm:
        try:
            import llm_triage
            judgment = llm_triage.triage(root, findings, provider=args.llm_provider,
                                         model=args.llm_model, cmd=args.llm_cmd,
                                         timeout=args.llm_timeout)
            findings, llm_summary = llm_triage.apply(findings, judgment)
        except Exception as e:
            print(f"warning: LLM triage failed: {e}", file=sys.stderr)

    counts = summarize(findings)
    ships_exec = any(kind_of(f["file"]) == "code" for f in findings) or _ships_executable(root)
    score = risk_score(findings, ships_exec)
    band, recommendation = score_band(score)
    # LLM verdict overrides the band in the decisive directions.
    if llm_summary and llm_summary.get("verdict"):
        v = llm_summary["verdict"]
        if v == "malicious":
            band, recommendation = "CRITICAL", "DO NOT INSTALL"
        elif v == "vulnerable" and recommendation == "LIKELY SAFE — review before trusting":
            band, recommendation = "MEDIUM", "INSTALL WITH CARE"
        elif v == "benign" and not (counts["high"] + counts["critical"]):
            recommendation = "LIKELY SAFE — review before trusting"
    target_name = os.path.basename(os.path.normpath(target))
    ordered = sorted(findings, key=lambda x: (-SEVERITY_ORDER[x["severity"]], x["file"], x["line"]))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(dict(target=target_name, files_scanned=file_count,
                           risk_score=score, band=band, recommendation=recommendation,
                           counts=counts, verdict=verdict(counts),
                           engines=dict(static=True, yara=yara_ran, osv=bool(args.osv),
                                        llm=bool(args.llm)),
                           llm=llm_summary,
                           findings=ordered,
                           suppressed=len(suppressed)),
                      f, indent=2, ensure_ascii=False)
    if args.md_out:
        with open(args.md_out, "w", encoding="utf-8") as f:
            f.write(render_markdown(target_name, findings, file_count, counts, score, band, recommendation))
    if args.sarif_out:
        with open(args.sarif_out, "w", encoding="utf-8") as f:
            f.write(render_sarif(target_name, ordered))

    if not args.quiet:
        print(f"Scanned {file_count} files in '{target_name}'.")
        print(f"Risk score: {score}/100 — {band} → {recommendation}")
        print(f"Findings: critical={counts['critical']} high={counts['high']} "
              f"medium={counts['medium']} low={counts['low']} info={counts['info']}"
              + (f"  (suppressed {len(suppressed)})" if suppressed else ""))
        print(f"Verdict: {verdict(counts)}")
        if llm_summary:
            print(f"LLM: {llm_summary.get('verdict','?')} (conf {llm_summary.get('confidence','?')}) — "
                  f"{llm_summary.get('reasoning','')} "
                  f"[dismissed {len(llm_summary.get('dismissed',[]))}, added {llm_summary.get('added',0)}]")
        if not args.json_out and not args.md_out and not args.sarif_out:
            for f in ordered:
                loc = f["file"] if f["line"] in (0, None) else f'{f["file"]}:{f["line"]}'
                print(f'  [{f["severity"].upper():8}] {f["rule"]:20} {loc}  {f["title"]}')
        if args.show_suppressed and suppressed:
            print("Suppressed by baseline:")
            for f in suppressed:
                loc = f["file"] if f["line"] in (0, None) else f'{f["file"]}:{f["line"]}'
                print(f'  [suppressed] {f["rule"]:20} {loc}  {f["title"]}')

    fail_lvl = SEVERITY_ORDER[args.fail_on]
    if any(SEVERITY_ORDER[f["severity"]] >= fail_lvl for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
