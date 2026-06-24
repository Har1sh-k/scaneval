# SB-TS-RW-093: Public API execution retry authorizes with workflow:read instead of workflow:execute

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-h3jj-5f3v-3685`
- CVE: ``
- Vulnerable commit: `5826f22c0b67d1c9df4dffeb6757c1e3522df99d` (release n8n@2.26.1)
- Fix commit: `284b3f088988cabbaa1f250d56484b9b8b8f106c` (release n8n@2.26.2)

## Vulnerability
The handler uses the wrong permission scope for the operation: getSharedWorkflowIds is called with ['workflow:read'] even though retrying an execution causes the workflow to run, which requires workflow:execute. The set of permitted workflow IDs is therefore too broad, so a read-only sharee passes the check and ExecutionService.retry() runs on a workflow they may not execute.

## Source / Carrier / Sink
- Source: An authenticated Public API caller with only workflow:read (read-only sharing) access to a shared workflow invoking the retry-execution endpoint with an execution ID of that workflow.
- Carrier: sharedWorkflowsIds, the list of workflow IDs returned by getSharedWorkflowIds(req.user, ['workflow:read']) that gates which executions can be retried.
- Sink: Container.get(ExecutionService).retry(req, sharedWorkflowsIds), which re-executes the workflow for any execution belonging to a workflow in the under-scoped ID list.
- Missing guard: The authorization check requires the wrong (lower) permission scope: it uses workflow:read where workflow:execute is required for an execute-class retry operation.

## Fix
The fix changes the required scope from ['workflow:read'] to ['workflow:execute'] in the getSharedWorkflowIds call, so only users with execute permission on the shared workflow are returned an ID set and allowed to retry its executions; read-only sharees now receive an empty set and a Not Found response.

## Scanner Expectation
Flag that an execute-class action (ExecutionService.retry, which re-runs the workflow) is authorized using the workflow:read scope instead of workflow:execute, an authorization/permission-boundary bypass (CWE-285/CWE-863) on a Public API handler.
