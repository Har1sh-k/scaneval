# SB-TS-RW-033: OpenClaw Slack thread context skipped the sender allowlist for thread starter and history

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-qm77-8qjp-4vcm`
- CVE: `CVE-2026-41358`
- Vulnerable commit: `da64a978e5814567f7797cc34fbe29b61b7eae7a` (release v2026.4.1)
- Fix commit: `ac5bc4fb37becc64a2ec314864cca1565e921f2d` (release v2026.4.2)

## Vulnerability
The thread-context builder trusts every message returned by the Slack thread-history API and the thread starter, with no per-sender authorization filter. Deployments configure a sender allowlist expecting that only approved users' content reaches the model, but thread history bypasses that control entirely: any message in a thread an allowlisted user touches is forwarded to the agent. This is a sender-access-control bypass that lets non-allowlisted content influence the agent.

## Source / Carrier / Sink
- Source: Slack thread starter text and thread-history messages returned by the Slack conversations API, authored by arbitrary (possibly non-allowlisted) users.
- Carrier: resolveSlackThreadContextData() copies starter.text into threadStarterBody and loops over the full threadHistory array, formatting each message into threadHistoryBody with no allowlist gating.
- Sink: threadStarterBody / threadHistoryBody are returned as thread context and injected into the agent/model conversation for the session.
- Missing guard: A per-message sender allowlist check (resolveSlackAllowListMatch) on the thread starter and each thread-history message before it is added to context; the vulnerable code applies no such filter.

## Fix
The fix adds isSlackThreadContextSenderAllowed(), which calls resolveSlackAllowListMatch against the effective allowlist (allowFromLower / allowNameMatching, now passed in as params). The thread starter is only used when starterAllowed is true, and threadHistory is filtered into allowedThreadHistory before the formatting loop, so non-allowlisted senders' messages are omitted (and logged) instead of entering the context.

## Scanner Expectation
A scanner should flag the unfiltered ingestion of Slack thread starter and thread-history content into agent context at lines 53-127 as an authorization bypass: externally-authored messages flow into the model context without being checked against the sender allowlist that gates direct messages.
