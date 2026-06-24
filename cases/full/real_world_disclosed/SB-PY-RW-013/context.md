# SB-PY-RW-013: AutoGPT Platform graph validation fails to enforce the block 'disabled' flag, allowing disabled-block (RCE) bypass

## Advisory
- Repo: `Significant-Gravitas/AutoGPT`
- GHSA: `GHSA-4crw-9p35-9x54`
- CVE: `CVE-2026-26020`
- Vulnerable commit: `4df5b7bde7ba548364b75ddce7a91ef6d5ecf5e4` (release autogpt-platform-beta-v0.6.47)
- Fix commit: `062fe1aa709217136b896c8b950e0f04435afb32` (release autogpt-platform-beta-v0.6.48)

## Vulnerability
The disabled flag is a safety/access control on which blocks may be invoked, but the single validation choke point (_validate_graph_get_errors) never consults block.disabled, so disabled blocks remain in the registry and pass all create/update/fork/execute checks when referenced as graph nodes. An authenticated user therefore reaches the dev-only BlockInstallationBlock (arbitrary Python write+import) through the graph path that was supposed to gate it, an authorization-control bypass leading to RCE.

## Source / Carrier / Sink
- Source: An authenticated user's graph create/update/fork/execute request that references a block marked disabled=True (e.g. BlockInstallationBlock) as one of its nodes.
- Carrier: The block object resolved from node.block_id flows through the _validate_graph_get_errors per-node loop, which accepts it for use in the graph without consulting block.disabled before the graph is persisted/executed.
- Sink: Execution of the disabled BlockInstallationBlock, which writes attacker-supplied Python to disk and dynamically imports it (arbitrary backend code execution) once the graph runs.
- Missing guard: A block.disabled check in graph validation (and at execution) to reject disabled blocks; only the direct block-execute endpoint enforced the flag, leaving the graph path unguarded.

## Fix
The fix (commit 062fe1aa7092, released as autogpt-platform-beta-v0.6.48, PR #12059 'enforce disabled flag on blocks in graph validation', GHSA-4crw-9p35-9x54) adds 'if block.disabled: raise ValueError(...)' in the _validate_graph_get_errors node loop so graphs containing disabled blocks are rejected, and adds a defense-in-depth 'if node_block.disabled: raise ValueError(...)' check in execute_node() in executor/manager.py.

## Scanner Expectation
Flag that the central graph-validation authorization gate (_validate_graph_get_errors) accepts blocks without checking the block.disabled access-control flag, allowing a restricted (disabled) capability to be invoked via the graph path: a missing-authorization / access-control bypass (CWE-862/CWE-285) on a privileged code-execution capability.
