# SB-TS-RW-059: Chat sender allowlist matched mutable conversation identifiers (chatId/chatGuid/chatIdentifier) instead of a stable sender

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-8j37-5w68-wj2g`
- CVE: `CVE-2026-53860`
- Vulnerable commit: `c97b9f79ec43b531a3472c3219ca51efbf7695a3` (release v2026.5.6)
- Fix commit: `b7e0decf0cd3cef742c02b9e8ad58cefd3c8c3a9` (release v2026.5.18)

## Vulnerability
The matcher treats conversation-scoped identity fields (chat_id, chat_guid, chat_identifier) as equivalent to a stable per-sender handle for authorization, even on direct/non-group paths. Because BlueBubbles conversation identifiers are not a trustworthy sender identity (a participant can influence them), matching an allowlist entry against them is incorrect authorization (CWE-863): the allowlist intended to gate a specific sender is satisfied by mutable conversation metadata.

## Source / Carrier / Sink
- Source: inbound BlueBubbles/iMessage message whose conversation-level identifiers (chatId, chatGuid, chatIdentifier) a participant can influence
- Carrier: isAllowedParsedChatSender() lifts those conversation identifiers into match candidates and the allowlist loop returns true on a chat_id/chat_guid/chat_identifier match without requiring a stable sender
- Sink: sender-allowlist authorization decision that gates whether the agent replies to the message
- Missing guard: require a stable sender identity for allowlist matching (gate conversation-target matching behind explicit allowConversationTargets/group opt-in)

## Fix
The fix adds an allowConversationTargets opt-in to isAllowedParsedChatSender() (and createAllowedChatSenderMatcher) so chatId/chatGuid/chatIdentifier are only used as match candidates when conversation targets are explicitly enabled (group context); otherwise they are forced to undefined and only the normalized stable sender handle can match. iMessage ingress was updated to restrict conversation-identifier entries to group context.

## Scanner Expectation
Flag isAllowedParsedChatSender() at lines 50-70 for authorizing on mutable conversation identifiers (chat_id/chat_guid/chat_identifier) instead of a stable sender, an allowlist/authorization bypass on the BlueBubbles sender policy.
