"""Small, fabricated conformance bundle. Never presented as a scanner run."""

from .contracts import canonical_sha256, validate_document


SOURCE = '''def list_records(db, search, sort):
    query = "SELECT * FROM records WHERE name = ? ORDER BY " + sort
    return db.execute(query, (search,))

def delete_record(db, request):
    return db.delete(request.record_id)
'''


def demo_documents() -> dict:
    # This fixture hashes a declared path/content map, not a git export.
    input_hash = canonical_sha256({"app.py": SOURCE})
    request = {
        "schema_version": "2.0", "run_id": "diagnostic-example",
        "input": {"tree_hash": input_hash, "root": ".", "languages": ["python"],
                  "mode": "full", "profile": "standard"},
        "system": {"id": "scripted-fixture"},
        "limits": {"timeout_seconds": 60}, "trace_mode": "off",
    }
    plan = {
        "schema_version": "2.0", "input_hash": input_hash, "scope": "diagnostic",
        "targets": [
            {"target_id": "T1", "description": "Untrusted sort is interpolated into SQL structure.",
             "kind": "sql_injection", "validation_level": "fixture"},
            {"target_id": "T2", "description": "Delete lacks the required per-record authorization check.",
             "kind": "authz_bypass", "validation_level": "fixture"},
        ],
        "controls": [{"control_id": "C1", "description": "search is a bound SQL value, not query structure.",
                      "type": "capability_safe", "validation_level": "fixture"}],
        "review_budgets": [3, 5],
    }
    def claim(claim_id, rank, allegation, kind, line):
        return {"claim_id": claim_id, "rank": rank, "allegation": allegation, "kind": kind,
                "primary_location": {"path": "app.py", "start_line": line, "end_line": line}}

    first = claim("c1", 1, "sort changes SQL structure without an allowlist.", "sql_injection", 2)
    result = {
        "schema_version": "2.0", "run_id": request["run_id"], "system_id": "scripted-fixture",
        "input_hash": input_hash, "status": "success", "ranking": "native",
        "claims": [first, {**first, "claim_id": "c2", "rank": 2},
                   claim("c3", 3, "List access may cross a tenant boundary.", "authz_bypass", 1),
                   claim("c4", 4, "search is injectable as SQL syntax.", "sql_injection", 3),
                   claim("c5", 5, "Delete accepts a record ID without checking caller authority.", "authz_bypass", 6)],
        "bundles_resolved": True, "usage": {"wall_seconds": 0, "cost_usd": None},
    }
    decisions = {
        "schema_version": "2.0", "run_id": request["run_id"], "input_hash": input_hash,
        "result_sha256": canonical_sha256(result),
        "claim_matches": [
            {"claim_id": "c1", "target_id": "T1", "decision": "accepted", "reason": "Scripted fixture: identifies sort."},
            {"claim_id": "c5", "target_id": "T2", "decision": "accepted", "reason": "Scripted fixture: required ownership check missing."},
        ],
        "control_assessments": [{"control_id": "C1", "decision": "false_allegation", "claim_ids": ["c4"],
                                 "reason": "Scripted fixture: bound search is not SQL structure."}],
    }
    for kind, document in [("scan-request", request), ("evaluation-plan", plan),
                           ("scan-result", result), ("review-decisions", decisions)]:
        validate_document(kind, document)
    return {"request": request, "plan": plan, "result": result, "decisions": decisions}
