# SB-PY-RW-011: Path traversal / sandbox escape in file-search agent middleware glob_search

## Advisory
- Repo: `langchain-ai/langchain`
- GHSA: `GHSA-gr75-jv2w-4656`
- CVE: `CVE-2026-55443`
- Vulnerable commit: `f6d63bc9f344b2949e91a6904d301553376b4f10` (release langchain==1.3.8)
- Fix commit: `dcaf7795a3e6590af55c3ff7bda6add6355e9ea6` (release langchain==1.3.9)

## Vulnerability
Only the base path is validated; the search pattern is not normalized and is fed straight into Path.glob, which honors '..' traversal. The match loop guards only on is_file() and never canonicalizes the matched path (resolving symlinks) to verify it stays within root_path, so escaped and symlinked targets are enumerated and returned.

## Source / Carrier / Sink
- Source: The pattern (glob) and path arguments to the agent-exposed glob_search tool, influenced by an LLM acting on untrusted input or by untrusted workspace contents (symlinks).
- Carrier: The pattern string passed unmodified into base_full.glob(pattern), and matched Path objects returned by the glob iterator.
- Sink: for match in base_full.glob(pattern) followed by match.relative_to/match.stat() (lines 162-168), which enumerates and discloses files resolved outside root_path.
- Missing guard: No rejection of absolute or '..'-containing glob patterns before expansion, and no canonicalization (symlink-resolving real-path) containment check confirming each matched path is inside the configured root_path.

## Fix
The fix rejects glob patterns that start with '/' or contain any '..' segment before expansion, and adds a _is_within_root() helper (candidate.resolve().is_relative_to(root.resolve())) that re-checks every match after symlink resolution in glob_search, the ripgrep path, and the python search (which also switched to os.walk(..., followlinks=False)). The companion anthropic middleware tightened allowed_prefixes path-segment boundary checks.

## Scanner Expectation
Flag the use of a caller/attacker-influenced glob pattern in Path.glob (and the symlink-unaware is_file()-only filter) within a sandboxed root as a path-traversal/link-following (CWE-22/CWE-59) sink lacking resolved-path containment.
