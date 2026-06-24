# SB-TS-RW-123: Missing credential-ownership guard in WorkflowService.update allows shared-workflow editors to reference others' credentials

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-pmqw-72cg-wx85`
- CVE: `CVE-2026-54307`
- Vulnerable commit: `a37ba249d46c98cd3369450c9624bf00497ef9db` (release n8n@2.25.6)
- Fix commit: `3f7246b41a768a331efd7681a103cf30a293f725` (release n8n@2.25.7)

## Vulnerability
The update method enforces workflow-edit permission and reconciles credential references but performs no per-user authorization check on the credentials referenced by the submitted nodes. With sharing enabled, an Editor of a shared workflow can therefore add or edit nodes pointing at credentials they have no access to, and the server saves and later executes them, bypassing credential ownership boundaries.

## Source / Carrier / Sink
- Source: Workflow update payload (nodes with credential references) supplied by an authenticated member-level user via UI or public API endpoints.
- Carrier: workflowUpdateData.nodes credential references passed into WorkflowService.update and persisted to the workflow.
- Sink: Workflow persistence and subsequent execution using the referenced credentials, granting access to credential secrets owned by other users.
- Missing guard: Per-user credential-access authorization (EnterpriseWorkflowService.preventTampering) on the credentials referenced by the updated workflow nodes.

## Fix
The fix adds a central credential guard in WorkflowService.update: after replaceInvalidCredentials resolves references to IDs, when sharing is licensed it lazily loads EnterpriseWorkflowService and calls preventTampering(workflowUpdateData, workflowId, user), which rejects new nodes referencing credentials the acting user cannot access and reverts edits to existing read-only credential nodes. The credential-format reconciliation was also moved earlier so the guard runs against fully resolved credential IDs.

## Scanner Expectation
Flag the workflow update path that persists user-supplied credential references without verifying the acting user is authorized to use those credentials (broken/ missing authorization check before a privileged write).
