# SB-TS-RW-035: OpenClaw OpenShell FS bridge write was TOCTOU-racy, letting a symlink swap escape the sandbox mount root

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-wppj-c6mr-83jj`
- CVE: `CVE-2026-44112`
- Vulnerable commit: `f788c88b4c508c335336fb292afed8c900656d6d` (release v2026.4.21)
- Fix commit: `7be82d4fd1193bcb7e44ee38838f00bf924ffa76` (release v2026.4.22)

## Vulnerability
assertLocalPathSafety only lstat-walks the path once, up front, and the subsequent mkdir/writeFile/rename re-resolve hostPath/parentDir from scratch through the live filesystem. A symlink swap landing in that window makes the rename follow the swapped link and write outside the intended local mount root, so the path-containment guarantee is not atomic with the write.

## Source / Carrier / Sink
- Source: Agent/OpenShell-controlled write target path (filePath/cwd) for a sandbox filesystem write, where a parent directory or leaf can be replaced with a symlink concurrently.
- Carrier: writeFile() checks the path once via assertLocalPathSafety, then performs mkdir/writeFile/rename against the same path strings, re-resolving symlinks live at write time instead of operating on a pinned, root-scoped target.
- Sink: fsPromises.rename(tempPath, hostPath) (and the preceding mkdir/writeFile) commits bytes to a filesystem location resolved at use-time, which a swapped symlink can place outside target.mountHostRoot.
- Missing guard: Atomic, root-pinned write that re-validates the canonical target against the mount root and refuses symlink parents/leaves at write time (writeFileWithinRoot); the vulnerable code separates the check from the path-based write, leaving a TOCTOU window.

## Fix
The fix replaces the manual mkdir + temp-write + rename with writeFileWithinRoot({ rootDir: target.mountHostRoot, relativePath: path.relative(target.mountHostRoot, hostPath), data, mkdir }) from openclaw/plugin-sdk/infra-runtime, a root-scoped write helper that validates the canonical target against the mount root and rejects unsafe symlink parents and symlink leaves before writing, closing the TOCTOU window.

## Scanner Expectation
A scanner should flag the check-then-path-write sequence in writeFile (lines 61-92): a path-containment validation (assertLocalPathSafety) followed by non-atomic mkdir/writeFile/rename on the same path, which is a TOCTOU symlink-swap path traversal out of the sandbox mount root.
