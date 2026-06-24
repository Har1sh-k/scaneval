# SB-SW-RW-003: macOS Swift exec allowlist parser missed combined POSIX inline-command flags

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-c226-q6fx-6j6c`
- CVE: `CVE-2026-53861`
- Vulnerable commit: `b1abf9d8ae4410c6a6e08f7dfd2d617f4550281c` (release v2026.5.5)
- Fix commit: `fc065b2693bfaeff795a88d080ff5cf30fe8addf` (release v2026.5.12)

## Vulnerability
The POSIX inline-command detection is an incomplete set of cases (CWE-184): POSIX shells accept clustered single-letter options (e.g. -ic, -lic) where the inline-command flag is combined with other flags, but the parser only recognized the exact whole-token forms in posixInlineFlags. A combined-flag form therefore yields no extracted payload, the wrapper is mis-classified as not-a-wrapper, and the shell content bypasses the allowlist evaluation that would otherwise require approval.

## Source / Carrier / Sink
- Source: model-/caller-controlled macOS exec command argv using a combined POSIX inline-command flag (e.g. sh -ic '<payload>')
- Carrier: extractPosixInlineCommand() only matches whole-token flags in posixInlineFlags, returns nil for combined flags, so ExecShellWrapperParser reports notWrapper and the inline payload is never surfaced to the allowlist
- Sink: macOS exec allowlist evaluation / command spawn that runs the shell content without the expected allowlist check or approval
- Missing guard: recognition of combined/clustered POSIX inline-command flags (and fail-closed treatment of unrecognized shell-startup forms) before the allowlist decision

## Fix
The fix introduces ExecInlineCommandParser and routes extractPosixInlineCommand() through ExecInlineCommandParser.extractInlineCommand(), which understands combined POSIX inline flags; it also adds fail-closed handling (extractForAllowlist / blockedWrapper, startupWrapperRequiresFullArgv) so startup/combined-flag forms are recognized as shell wrappers and forced through the allowlist instead of slipping past it.

## Scanner Expectation
Flag extractPosixInlineCommand() at lines 74-81 for matching only exact whole-token inline flags (posixInlineFlags) while ignoring combined POSIX flag forms, letting inline shell content bypass the exec allowlist.
