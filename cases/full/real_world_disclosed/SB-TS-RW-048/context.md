# SB-TS-RW-048: OpenClaw inline skill-command dispatch executed tools without before-tool-call hook coverage

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-68xw-r643-9p5w`
- CVE: `CVE-2026-53845`
- Vulnerable commit: `b1abf9d8ae4410c6a6e08f7dfd2d617f4550281c` (release v2026.5.5)
- Fix commit: `d5eabbd36c874d6dfe44ce1b2e790bc664e19692` (release v2026.5.6)

## Vulnerability
The inline skill dispatch invokes the resolved tool's execute() directly without running the before_tool_call hook, and the tool construction did not wrap tools with that hook, so any policy/audit checks implemented as before-tool-call hooks are skipped for skill-command-dispatched tools.

## Source / Carrier / Sink
- Source: Skill command routed through auto-reply inline action dispatch (skillInvocation.command.dispatch.toolName)
- Carrier: Tool resolved from createOpenClawTools()/applyOwnerOnlyToolPolicy and invoked via tool.execute()
- Sink: Direct tool.execute(toolCallId, toolArgs) call running the dispatched tool
- Missing guard: No runBeforeToolCallHook / before_tool_call hook wrapping on the inline skill-command dispatch path (tools not hook-wrapped at construction, no hook invoked before execute)

## Fix
createOpenClawTools() was extended to wrap returned tools with wrapToolWithBeforeToolCallHook by default (new wrapBeforeToolCallHook/beforeToolCallHookContext options and a hook context built from session/channel ids), and the inline-actions path passes sessionId/currentChannelId and inspects the result for a 'blocked' status (extractBlockedToolReason), returning a blocked reply when the hook denies the call.

## Scanner Expectation
Flag that the inline skill-command dispatch calls tool.execute() directly without invoking the before-tool-call hook (no hook wrapping), bypassing hook-based policy/audit enforcement applied to other tool entry points.
