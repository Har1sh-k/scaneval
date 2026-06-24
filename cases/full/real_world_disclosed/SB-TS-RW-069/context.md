# SB-TS-RW-069: Flowise Faiss vector store writes to attacker-controlled basePath (path traversal)

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-w6v6-49gh-mc9w`
- CVE: ``
- Vulnerable commit: `f0c1294173a55f26e0b972c39c0c16917f5ca9e7` (release flowise@3.0.13)
- Fix commit: `0140ba4a3dbb3edade37b4f5de4346fb47a62a0d` (release flowise@3.1.0)

## Vulnerability
basePath flows directly from request input to a filesystem write (FaissStore.save) with no normalization, allowlist, or base-directory containment check, so '../../../tmp/x' or an absolute path escapes the intended storage directory. The process writes files wherever it has permission, enabling overwrite of existing files and potential code execution by targeting writable startup/web paths.

## Source / Carrier / Sink
- Source: User-supplied basePath in vectorStoreConfig of the authenticated POST /api/v1/document-store/vectorstore/insert request (nodeData.inputs?.basePath).
- Carrier: const basePath = nodeData.inputs?.basePath as string is taken verbatim inside upsert() (and init()).
- Sink: await vectorStore.save(basePath) (and FaissStore.load(basePath, embeddings)) performs the filesystem write/read at the attacker-chosen path.
- Missing guard: No path normalization or containment to an allowed base directory before the filesystem operation (the later-added validateVectorStorePath()).

## Fix
Fix commit 0140ba4a (shipped in flowise@3.1.0) imports validateVectorStorePath from ../../../src/validator and replaces vectorStore.save(basePath)/FaissStore.load(basePath) with calls using validateVectorStorePath(basePath), which normalizes and confines the path. The same guard was added to SimpleStore.ts.

## Scanner Expectation
A scanner should flag the dataflow from user-controlled basePath -> vectorStore.save(basePath) as path traversal (CWE-22): tainted path reaching a filesystem write sink with no canonicalization/base-dir check between source and sink.
