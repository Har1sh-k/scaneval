# SB-PY-RW-016: SSRF in SendWebRequestBlock via IPv4-mapped IPv6 / CGNAT IP-validation bypass in _is_ip_blocked

## Advisory
- Repo: `Significant-Gravitas/AutoGPT`
- GHSA: `GHSA-8qc5-rhmg-r6r6`
- CVE: `CVE-2026-56663`
- Vulnerable commit: `c51dc7ad99265f68d9ea6c5b3a04a955dc06f575` (release autogpt-platform-beta-v0.6.51)
- Fix commit: `2479f3a1c466e1751ad286bef7ca8f1d47d3fb69` (release autogpt-platform-beta-v0.6.52)

## Vulnerability
The SSRF blocklist comparison relies on direct membership of the parsed ip_address in IPv4 networks, but an IPv4-mapped IPv6 address parses to an IPv6Address that is never matched by any IPv4Network in BLOCKED_IP_NETWORKS, so a private/link-local IPv4 encoded as ::ffff:a.b.c.d evades all IPv4 rules. The blocklist additionally lacked the 100.64.0.0/10 shared-address (CGNAT) range.

## Source / Carrier / Sink
- Source: Authenticated user supplying a URL/hostname to SendWebRequestBlock; the hostname resolves (via DNS AAAA) to an IPv4-mapped IPv6 address embedding an internal IPv4 target.
- Carrier: The resolved IP string is passed to _is_ip_blocked(ip), which parses it with ipaddress.ip_address and tests membership in BLOCKED_IP_NETWORKS.
- Sink: The outbound HTTP request proceeds to the resolved (internal) address because _is_ip_blocked returns False for the IPv4-mapped IPv6 form.
- Missing guard: Normalization of IPv4-mapped IPv6 addresses to IPv4 before the blocklist check (ipv4_mapped), and inclusion of CGNAT/special-use ranges in the blocklist.

## Fix
The fix commit (2479f3a1) normalizes IPv4-mapped IPv6 addresses to IPv4 before the range check (if isinstance(ip_addr, IPv6Address) and ip_addr.ipv4_mapped: ip_addr = ip_addr.ipv4_mapped) and adds 100.64.0.0/10 (CGNAT) plus 192.0.0.0/24 and 198.18.0.0/15 to BLOCKED_IP_NETWORKS.

## Scanner Expectation
Detect an SSRF IP-allow/deny-list bypass: the private/internal-IP validation can be evaded because an alternative (IPv4-mapped IPv6) encoding of a blocked address is not normalized before the blocklist comparison.
