# SB-TS-RW-100: Allowed-path enforcement bypass via lexical resolve() for non-existent paths enabling arbitrary file access

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-gfvg-qv54-r4pc`
- CVE: `CVE-2026-25052`
- Vulnerable commit: `911d3771ce23dda2eb00a9d2c446e37f8223a9e9` (release n8n@1.123.17)
- Fix commit: `46dd25439c4d6119e02f28b88e8feb7105f0d0b1` (release n8n@1.123.18)

## Vulnerability
On the ENOENT branch resolvePath uses resolve(path.toString()), a purely lexical resolution that does not canonicalize symlinks. The allowed-path containment check is therefore performed on a path that may differ from the real filesystem target that is ultimately opened, so a symlinked or otherwise non-canonical path bypasses the restriction and reads files outside the allowed directories.

## Source / Carrier / Sink
- Source: Authenticated user input: file path parameters supplied to file-reading nodes (Read/Write Files from Disk, Git).
- Carrier: The path string passed to resolvePath() and then to isFilePathBlocked() and the file open.
- Sink: createReadStream / file access on a path that escapes the allowed-paths restriction (arbitrary file read).
- Missing guard: Canonical (symlink-resolving) path resolution for non-existent paths; the lexical resolve() fallback lets the containment check be evaluated on a non-canonical path that differs from the opened target.

## Fix
The fix removes the lexical resolve() fallback: when the file does not exist it resolves the real parent directory with fsRealpath(dirname(path)) and rejoins the basename, so the path used for the containment check reflects the true (symlink-resolved) location and cannot escape the allowed paths.

## Scanner Expectation
Flag path containment/allow-list checks performed on a lexically-resolved (non-canonical) path that can diverge from the real opened file, enabling path traversal / restricted-file read (CWE-22/CWE-367).
