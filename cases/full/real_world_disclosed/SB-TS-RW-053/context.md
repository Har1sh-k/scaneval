# SB-TS-RW-053: OpenClaw /focus command resolved and acted on target sessions without enforcing subagent controlScope

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-mpc8-jxjh-qpgh`
- CVE: `CVE-2026-53850`
- Vulnerable commit: `cbcfdf62c7297bda66009ea7476f053c3e9addab` (release v2026.4.24)
- Fix commit: `c1a42dce86cba23fb7ceb5994a83ddf82bdd754e` (release v2026.4.29)

## Vulnerability
The focus handler never resolved or checked the requesting subagent's controlScope before resolving the focus target and mutating focus state. Any caller able to reach the /focus command path could change focus on sessions it should not control, since leaf subagents were not blocked.

## Source / Carrier / Sink
- Source: Subagent/operator-issued /focus command token reaching handleSubagentsFocusAction via the command dispatch path.
- Carrier: ctx (SubagentsCommandContext) carrying params, runs, restTokens; the controlScope of the requesting subagent is available via params/requesterKey but is never consulted.
- Sink: resolveFocusTargetSession({ runs, token }) and the subsequent focus-state mutation that runs regardless of the caller's controlScope.
- Missing guard: A controlScope containment check (controller.controlScope === 'children') before resolving and acting on the focus target; leaf subagents must be rejected.

## Fix
Fix commit c1a42dce inserts a controlScope guard immediately after the usage check: it calls resolveCommandSubagentController(params, ctx.requesterKey) and returns 'Leaf subagents cannot control other sessions.' when controller.controlScope !== 'children'. It also threads requesterKey (controller.controllerSessionKey) into resolveFocusTargetSession so the target lookup is scoped to the authorized controller.

## Scanner Expectation
Flag the focus handler block that resolves/acts on a cross-session target without first checking the caller's subagent controlScope authority (CWE-862/863 missing authorization).
