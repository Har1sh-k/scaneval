# SB-TS-RW-084: Flowise DocumentStore create endpoint mass-assignment / IDOR via client-supplied primary key (UPSERT)

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-3prp-9gf7-4rxx`
- CVE: `CVE-2026-41277`
- Vulnerable commit: `9d6a41677759699e886750683ce7753f026b8418` (release ?)
- Fix commit: `840d2ae14d25230579a58aa4305f8506672a0a45` (release flowise@3.1.0)

## Vulnerability
The create path persists a client-controlled entity (including id and workspaceId) via repo.create()/repo.save() with no field allowlist and no ownership check. Since the uuid primary key is globally unique and save() upserts on an existing id, a request carrying another tenant's DocumentStore id updates that record instead of creating a new one, and overwriting workspaceId can move the object into the attacker's workspace. Object-level authorization is therefore broken on the create endpoint.

## Source / Carrier / Sink
- Source: Authenticated user's HTTP request body to POST /api/v1/document-store, including an attacker-chosen `id` (and possibly `workspaceId`).
- Carrier: req.body -> DocumentStoreDTO.toEntity(body) (no allowlist) -> createDocumentStore(newDocumentStore) service function.
- Sink: appDataSource.getRepository(DocumentStore).create(newDocumentStore) then .save(documentStore), which UPDATEs an existing record when the client-supplied uuid id already exists.
- Missing guard: No DTO field allowlist (id/workspaceId must be server-controlled) and no ownership/workspace check that the targeted DocumentStore belongs to the caller before save().

## Fix
Fix commit 840d2ae ('Prevent IDOR Takeover of DocumentStores', #5914; shipped in flowise@3.1.0) forces the workspaceId to a trusted server-side value in both the controller (docStore.workspaceId = workspaceId) and the upsert helper, and replaces the wholesale `Object.assign(updateDocStore, body)` in updateDocumentStore with an explicit field allowlist (name/description/configs/loaders/whereUsed) so client-supplied id/workspaceId/timestamps can no longer be set, eliminating the mass-assignment/UPSERT takeover.

## Scanner Expectation
A scanner should flag that the full request body (including the primary key and workspaceId) is bound to a persisted entity and saved without an ownership/authorization check, enabling mass assignment and cross-tenant object takeover (broken object-level authorization).
