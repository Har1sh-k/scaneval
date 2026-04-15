# Codex Medium-Severity Security Fixes — Backlog

Cases to create later. All from `openai/codex` repo.
Source: git commit audit of https://github.com/openai/codex (April 2026).

| # | Commit | Vulnerability | CWE Category | Found In |
|---|--------|--------------|-------------|----------|
| 1 | `cb9024b8d9ffd1d9029ca5b85d1acecfd7666dea` | Prompt injection via tool name metadata in steering messages | Prompt Injection | `codex-rs/core/src/tools/handlers/dynamic.rs` |
| 2 | `cfbbbb1ddac35efdd5812196404d3582c2edb115` | js_repl emitImage() accepts arbitrary URLs — data exfiltration/SSRF | SSRF | `codex-rs/core/src/tools/js_repl/kernel.js` |
| 3 | `b62ef70d2af03b54bc4ec15e7fc7ebbd8580cbf8` | Suggest mode auto-executes "safe" commands without user consent | Auth Bypass | `codex-cli/src/approvals.ts` |
| 4 | `12ec57b330183480f27d43ef12f73f588298628b` | `find -exec/-delete` auto-approved as safe | Command Injection | `codex-cli/src/approvals.ts` |
| 5 | `f50c8b2f81d69e49d1f6eafaeebf0f6ba2bbba52` | Destructive git commands (`push --force`, `branch -D`) auto-approved | Auth Bypass | `codex-rs/core/src/command_safety/is_safe_command.rs` |
| 6 | `15fcc43cc677a056ca50ec704c0e9144fd1091a9` | deny_read bypass via exec escalation | Path Traversal | `codex-rs/core/src/tools/handlers/shell.rs` |
| 7 | `5ceff6588ef67aaac34f9461411b90f65e42b4f9` | apply_patch carveout bypass writes to blocked paths | Path Traversal | `codex-rs/core/src/apply_patch.rs` |
| 8 | `d36d295a1a8d047fa5d64cc4d67f92f113660f24` | Shell parsing confusion in user-defined safe commands | Command Injection | `codex-cli/src/approvals.ts` |
| 9 | `ab4cb9422753c2505bcd073d9de00f5d0972f873` | Path traversal via non-normalized `../` in resolvePathAgainstWorkdir | Path Traversal | `codex-cli/src/approvals.ts` |
| 10 | `b530ba3f464aa460a1ae8af1d7fa3b949bbf61b5` | deny_read bypass (broader second fix) | Path Traversal | `codex-rs/core/src/tools/sandboxing.rs` |
| 11 | `61805a832ddec35b811f511dd9863e1e0433a70b` | Container grants sudo to unprivileged node user | Privilege Escalation | `codex-cli/Dockerfile` |

## How to create a case

For each row:
1. `git show <commit>` to get the diff and parent
2. Checkout parent commit as the vulnerable snapshot
3. Create snapshot in `.repos/openai_codex__<prefix>/`
4. Create case dir `SB-RS-RW-XXX/case.json` following existing pattern
