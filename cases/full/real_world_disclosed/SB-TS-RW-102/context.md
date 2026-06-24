# SB-TS-RW-102: SSH node uploads files using unsanitized filename, enabling path traversal / arbitrary remote file write

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-m82q-59gv-mcr9`
- CVE: `CVE-2026-25055`
- Vulnerable commit: `747f5c24d8e2652fa413c1116447137f8c467045` (release n8n@2.3.2)
- Fix commit: `e0baf48c6a54808f6dbca8cb352bfa306092c223` (release n8n@2.3.3)

## Vulnerability
The remote destination is `${parameterPath}/${fileName || binaryData.fileName}` with no basename extraction, separator stripping, or null-byte removal, so directory-traversal sequences or absolute paths embedded in the filename are passed straight to ssh.putFile() and honoured by the remote server, overwriting files outside the configured directory.

## Source / Carrier / Sink
- Source: Attacker-controlled file metadata/name (binaryData.fileName, e.g. from an unauthenticated webhook file upload) or the node's fileName option flowing into the workflow.
- Carrier: The template literal `${parameterPath}/${fileName || binaryData.fileName}` that builds the remote destination path.
- Sink: ssh.putFile(binaryFile.path, <destination>) (lines 447-452), which writes the file to the attacker-influenced remote path.
- Missing guard: No sanitization of the filename (no path.basename/separator stripping/null-byte removal) before it is concatenated into the remote destination path (the fix's sanitizeFilename()).

## Fix
The fix adds a sanitizeFilename() utility (path.basename after normalising backslashes, with null-byte stripping and an 'untitled' fallback) in n8n-workflow and applies it in the SSH node: rawFileName = fileName || binaryData.fileName is passed through sanitizeFilename() and the sanitized result is used in the ssh.putFile() destination, so only a bare filename can be written into parameterPath.

## Scanner Expectation
Flag the data flow from the unsanitized filename (binaryData.fileName / options.fileName) into the ssh.putFile() destination path as a path-traversal / arbitrary file-write sink (CWE-22) lacking basename/normalisation sanitization.
