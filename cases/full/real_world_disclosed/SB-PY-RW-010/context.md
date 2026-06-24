# SB-PY-RW-010: SSRF redirect bypass in HTMLHeaderTextSplitter.split_text_from_url

## Advisory
- Repo: `langchain-ai/langchain`
- GHSA: `GHSA-fv5p-p927-qmxr`
- CVE: `CVE-2026-41481`
- Vulnerable commit: `269947b11f3b78eb800dd3fe12f3c07151ac9feb` (release langchain-text-splitters==1.1.1)
- Fix commit: `c289bf10e940e960a132d7403482283114063063` (release langchain-text-splitters==1.1.2)

## Vulnerability
The SSRF check is applied only once to the initial URL, but requests.get follows redirects by default and does not re-run validate_safe_url on each redirect hop. An attacker-controlled public host that passes the initial check can redirect to an internal address, and the request is issued to that unvalidated target.

## Source / Carrier / Sink
- Source: The url argument supplied by the caller (potentially untrusted) to split_text_from_url().
- Carrier: The url variable passed through validate_safe_url() and then into requests.get(url, ...).
- Sink: requests.get(url, timeout=timeout, **kwargs) (line 213), which follows redirects to a target that is never revalidated.
- Missing guard: No per-request/per-redirect URL or resolved-IP validation; redirects are followed without re-checking each hop against the SSRF allowlist (and connections are not pinned to validated IPs).

## Fix
The fix replaces requests.get() with an SSRF-safe httpx client (ssrf_safe_client from langchain_core._security._transport / SSRFSafeSyncTransport) that validates DNS results and pins connections to validated IPs on every request including redirect targets. split_text_from_url() was also deprecated in favor of fetching HTML separately and calling split_text().

## Scanner Expectation
Flag requests.get on a network-reachable URL where the SSRF guard is applied once before the call but redirects are followed unvalidated, as an SSRF (CWE-918) sink.
