# SB-TS-RW-095: Path traversal in ExecuteWorkflow localFile source bypassing file access restrictions

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-2vx9-7wpg-88jq`
- CVE: ``
- Vulnerable commit: `8630712455dd64bf76f0860d8fef1a92e308b7ad` (release n8n@2.19.2)
- Fix commit: `7277566c64c36f5e43c17a2e620da2408ab1dcb7` (release n8n@2.19.3)

## Vulnerability
workflowPath comes straight from a node parameter and is passed verbatim to fsReadFile() with no normalization or allowlist enforcement. The restriction enforced elsewhere (isFilePathBlocked / N8N_RESTRICT_FILE_ACCESS_TO) is entirely absent on this code path, so paths outside any intended directory are read freely.

## Source / Carrier / Sink
- Source: Authenticated workflow-editor input: the ExecuteWorkflow node 'workflowPath' parameter set via the REST API.
- Carrier: The workflowPath string returned by this.getNodeParameter('workflowPath', itemIndex).
- Sink: await fsReadFile(workflowPath, { encoding: 'utf8' }) reading an arbitrary filesystem path.
- Missing guard: No path resolution/normalization and no isFilePathBlocked / N8N_RESTRICT_FILE_ACCESS_TO enforcement before reading the file.

## Fix
The fix resolves the path via this.helpers.resolvePath(workflowPath) and then checks this.helpers.isFilePathBlocked(resolvedPath), throwing 'Access to the workflow file path is not allowed' before reading; only the validated resolved path is passed to fsReadFile, bringing this node in line with the file-access restrictions applied by other nodes.

## Scanner Expectation
Flag a user-controlled path flowing into a filesystem read (fsReadFile) without canonicalization or an allowlist/restriction check, enabling path traversal / arbitrary file access.
