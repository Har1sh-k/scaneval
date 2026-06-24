# SB-TS-RW-034: OpenClaw marketplace plugin path containment check ignored symlinks, allowing repository-root escape

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-35mw-5vvr-vrxc`
- CVE: `CVE-2026-43570`
- Vulnerable commit: `d74a12264aa5fb0598605e8f04e1864b7239ddd5` (release v2026.4.2)
- Fix commit: `b1dd3ded3589f6fa60ab85b3930a82d538edaeae` (release v2026.4.5)

## Vulnerability
The containment guard reasons about the lexical path string only and trusts that a path which is textually under rootDir physically resolves under rootDir. Because symlinks are never resolved (no fs.realpath / canonical comparison), an attacker-controlled symlink inside a remote marketplace repo escapes the repository root: the check sees an in-root path while the install reads/copies the symlink's out-of-root target.

## Source / Carrier / Sink
- Source: Plugin source paths declared in a remote (attacker-supplied) marketplace manifest, including paths that traverse a symlink planted inside the cloned repository root.
- Carrier: ensureInsideMarketplaceRoot() returns ok:true for any candidate whose lexical path.relative against rootDir does not start with '..', without resolving symlinks, so an in-root symlink to an out-of-root target is accepted.
- Sink: resolveMarketplaceEntryInstallPath() / installPluginFromMarketplace() use the accepted path to read and install plugin files from a location outside the intended marketplace repository root.
- Missing guard: Canonical-path containment using fs.realpath of both root and resolved candidate (isPathInside on real paths) plus rejection of symlinked roots/leaves for remote origins; the vulnerable code performs only a lexical path.relative check.

## Fix
The fix makes ensureInsideMarketplaceRoot async and adds real canonicalization: it lstats the root (rejecting non-directories and, for remote origin via requireCanonicalRoot, symlinked roots), computes fs.realpath of the root and of the nearest existing ancestor of the candidate, and rejects when isPathInside(rootRealPath, existingRealPath) is false. resolveLocalMarketplaceSource and validateMarketplaceManifest were updated to canonicalize roots and run the check (origin-aware) so symlinked plugin paths can no longer escape the canonical repository root.

## Scanner Expectation
A scanner should flag the lexical-only containment check in ensureInsideMarketplaceRoot (lines 805-818) as a path/symlink traversal: a path.resolve + path.relative '..' check used as a security boundary without fs.realpath canonicalization, allowing a symlinked path under rootDir to resolve outside it.
