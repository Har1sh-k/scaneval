# SB-TS-RW-078: Flowise replaceInputsWithConfig FILE-STORAGE:: bypass allows overrideConfig MCP env injection leading to RCE

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-cvrr-qhgw-2mm6`
- CVE: `CVE-2026-41268`
- Vulnerable commit: `f0c1294173a55f26e0b972c39c0c16917f5ca9e7` (release flowise@3.0.13)
- Fix commit: `c8282c97fb6854775d475f814c5d20312114b56f` (release flowise@3.1.0)

## Vulnerability
The intended guard, isParameterEnabled(label, config), is the only thing restricting which node parameters a client may override, but it is entirely skipped whenever overrideConfig[config] merely includes the substring 'FILE-STORAGE::' anywhere in its value. Because .includes() matches anywhere and there is no check that the parameter is actually a file input, an attacker embeds the marker in a comment and overrides a sensitive parameter like mcpServerConfig, which is then used to spawn a child process. The natural-language intent ('only files inputs') is not enforced, so attacker-controlled config reaches the MCP command/env spawn sink.

## Source / Carrier / Sink
- Source: Unauthenticated client-supplied overrideConfig sent to /api/v1/prediction/:id on a public chatflow with API Override enabled (overrideConfig[config], e.g. mcpServerConfig).
- Carrier: replaceInputsWithConfig() copies overrideConfig values into node inputsObj; the FILE-STORAGE:: substring check causes it to bypass isParameterEnabled() and apply the value to a non-file parameter such as mcpServerConfig.
- Sink: The overridden mcpServerConfig (command/args/env) is later used by the Custom MCP node to spawn a child process; an injected NODE_OPTIONS --experimental-loader value runs attacker JavaScript and OS commands.
- Missing guard: No enforcement that the overridden parameter is an enabled/authorized override; the FILE-STORAGE:: check uses .includes() instead of .startsWith() and does not validate the parameter type, so it unconditionally skips authorization.

## Fix
Fix commit c8282c9 (Fix Paramater Override Bypass #5667, shipped in flowise@3.1.0) deletes the FILE-STORAGE:: special case entirely so every overridden parameter must pass isParameterEnabled() before being applied; the same commit also hardens the MCP node's dangerousEnvVars list. After the fix the else branch is simply `if (!isParameterEnabled(flowNodeData.label, config)) { continue }`.

## Scanner Expectation
A scanner should flag that unauthenticated overrideConfig input reaches a process-spawn (MCP command/env) sink via replaceInputsWithConfig with an authorization check (isParameterEnabled) that is bypassable through a substring match, i.e. attacker-controlled config flowing to command execution (CWE-77/CWE-94) with an ineffective guard.
