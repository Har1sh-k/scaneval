from scaneval import aggregate
from scaneval.contracts import validate_document
from test_v2_aggregate import planned, target, write_run


def test_aggregate_and_comparison_contracts_support_public_research_system_records(tmp_path):
    run = write_run(tmp_path, "fixture", [planned("source", targets=[target("target")])],
                    systems=("baseline", "candidate"))
    reports = [("aggregate-report", aggregate.aggregate([run])),
               ("comparison-report", aggregate.compare([run], baseline="baseline", candidate="candidate"))]
    for kind, report in reports:
        systems = report["systems"] if kind == "aggregate-report" else [report["baseline"], report["candidate"]]
        for system in systems:
            system["network_policy"] = "public_research"
            system["execution"] = {"backend": "oci", "enforced_expected": True,
                                   "image": "fixture@sha256:" + "a" * 64}
        assert validate_document(kind, report) is report
