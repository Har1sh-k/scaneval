# SB-PY-RW-015: SSRF in SendEmailBlock via user-controlled SMTP server/port bypassing the IP blocklist

## Advisory
- Repo: `Significant-Gravitas/AutoGPT`
- GHSA: `GHSA-4jwj-6mg5-wrwf`
- CVE: `CVE-2026-33234`
- Vulnerable commit: `c51dc7ad99265f68d9ea6c5b3a04a955dc06f575` (release autogpt-platform-beta-v0.6.51)
- Fix commit: `522f932e670851fc5e94ea80d03c2928c7040397` (release autogpt-platform-beta-v0.6.52)

## Vulnerability
smtp_server and smtp_port are attacker-controlled block inputs that flow straight into smtplib.SMTP() without resolving the host and checking the resulting IP against the platform's private/loopback/link-local/metadata blocklist, and without restricting the destination port. The unhandled SMTPConnectError carrying the service banner is re-raised and surfaced to the user, making the SSRF non-blind.

## Source / Carrier / Sink
- Source: Authenticated user setting config.smtp_server and config.smtp_port inputs on a SendEmailBlock node in a workflow.
- Carrier: config.smtp_server / config.smtp_port are read into smtp_server / smtp_port and passed unchanged into smtplib.SMTP(...).
- Sink: smtplib.SMTP(smtp_server, smtp_port, timeout=30) opens a raw TCP connection to the attacker-chosen host/port.
- Missing guard: DNS resolution + IP-blocklist validation (resolve_and_check_blocked / BLOCKED_IP_NETWORKS) and a destination-port allowlist before opening the connection.

## Fix
The fix commit (522f932e) imports resolve_and_check_blocked from backend.util.request and calls it on input_data.config.smtp_server before connecting, restricts smtp_port to an ALLOWED_SMTP_PORTS allowlist {25,465,587,2525}, and adds explicit handlers for SMTPConnectError/SMTPServerDisconnected/ValueError that return a generic message instead of leaking the target's TCP banner.

## Scanner Expectation
Detect SSRF: a user-controlled host/port flows into a raw network connection (smtplib.SMTP) without resolving and validating the destination against an internal-IP blocklist.
