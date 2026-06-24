# SB-TS-RW-036: OpenClaw OpenShell FS bridge read was TOCTOU-racy, letting a symlink swap read outside the sandbox mount root

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-5h3g-6xhh-rg6p`
- CVE: `CVE-2026-44113`
- Vulnerable commit: `f788c88b4c508c335336fb292afed8c900656d6d` (release v2026.4.21)
- Fix commit: `95119017c847c737bd113f0bff728c4666d79c45` (release v2026.4.22)

## Vulnerability
assertLocalPathSafety performs its lstat-based ancestor walk once, then readFile opens hostPath again by path. The two operations resolve symlinks independently at different times, so a symlink planted in the window after the check makes the read traverse outside the mount root, returning out-of-root file contents to the agent.

## Source / Carrier / Sink
- Source: Agent/OpenShell-controlled read target path (filePath/cwd) for a sandbox filesystem read, where a parent directory or leaf can be replaced with a symlink concurrently.
- Carrier: readFile() checks the path once via assertLocalPathSafety, then calls fsPromises.readFile(hostPath) which re-resolves the same path string through the live filesystem instead of reading from a pinned, in-root file descriptor.
- Sink: fsPromises.readFile(hostPath) opens and reads a file resolved at use-time, which a swapped symlink can point outside target.mountHostRoot, returning those bytes to the caller.
- Missing guard: Open-once-then-verify on a pinned fd (O_NOFOLLOW + fd-path/canonical-root validation, rejecting symlink/hardlink races) as in openPinnedReadableFile; the vulnerable code checks the path and then re-opens it by path, leaving a TOCTOU window.

## Fix
The fix introduces openPinnedReadableFile(), which opens the file once with O_NOFOLLOW (where available) so every later check runs against an already-pinned fd, validates the fd's kernel-resolved path against the canonical mount root (via /proc/self/fd or /dev/fd readlink), rejects multi-link/hardlink and symlink cases, and on platforms without fd-path readback walks the ancestor chain rejecting symlinks plus a single-syscall stat identity check. readFile then reads from the pinned handle instead of re-opening by path.

## Scanner Expectation
A scanner should flag the check-then-path-read sequence in readFile (lines 45-59): a path-containment validation (assertLocalPathSafety) immediately followed by fsPromises.readFile on the same path, which is a TOCTOU symlink-swap path traversal that reads outside the sandbox mount root.
