"""Local runner fixtures through the public API and CLI; no scanner or network required."""
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from scaneval.contracts import canonical_sha256
from scaneval.investigation import build_investigation, export_investigation, InvestigationError
from scaneval.observer import Observer
from scaneval.review import review_record
from scaneval.runner import run_from_config
from scaneval.scoring import score
from test_v2_runner import upstream, write_pack, write_config, system_entry, FakeAdapter, CLOCK

MALICIOUS = '</script><script>alert("unsafe")</script><img src="https://example.invalid/x">'
PRIVATE_TEXT = 'Private source: /workspace/company/billing.py\napi_key="test-credential-value"\npassword="a secret with spaces"\n' + MALICIOUS


class ObservedAdapter(FakeAdapter):
    def __init__(self, status="success", malformed=False):
        super().__init__()
        self.status = status
        self.malformed = malformed

    def scan(self, **kwargs):
        outcome = super().scan(**kwargs)
        events = []
        for producer in ("producer-a", "producer-b"):
            observer = Observer(mode="content", sink=events.append,
                                run_id=kwargs["request"]["run_id"], producer_id=producer,
                                redactor=lambda key, value, path: value)
            observer.emit(type="tool.start", capture_status="complete", call_id="shared-call",
                          metadata={"source": "claude_code_transcript", "source_timestamp": "2025-01-02T00:00:00Z"})
            observer.emit(type="finding.candidate", capture_status="complete", call_id="shared-call",
                          candidate_id="same-candidate", metadata={"source": "claude_code_transcript"},
                          content={"text": PRIVATE_TEXT, "api_key": "structured-secret"})
            if producer == "producer-a":
                observer.emit(type="finding.submitted", capture_status="complete", call_id="shared-call",
                              claim_id="c1", candidate_id="same-candidate", metadata={"source": "harness_record"})
        path = kwargs["trace_dir"] / "events.jsonl"
        path.write_text("\n".join(map(json.dumps, events)) + ("\nnot JSON" if self.malformed else "") + "\n")
        outcome.trace_path = path
        outcome.capture = {"model_requests": "complete", "context_selection": "partial", "finding_submitted": "complete"}
        outcome.capture_state = {"capture_gap": False, "dropped_events": 0}
        outcome.status = self.status
        return outcome


def make_run(tmp_path, upstream, *, status="success", malformed=False, mode="content", repetitions=1, failed=False):
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    systems = [system_entry("fixture", "fake")]
    if failed:
        systems.append(system_entry("interrupted", "crash"))
    config = write_config(config_path, systems=systems, repetitions=repetitions)
    config["trace_mode"] = mode
    config_path.write_text(json.dumps(config))
    run = tmp_path / "saved-run"
    adapters = {"fake": ObservedAdapter(status, malformed),
                "crash": FakeAdapter(scan_exception=KeyboardInterrupt("fixture stopped"))}
    if failed:
        with pytest.raises(KeyboardInterrupt):
            run_from_config(config_path, run, adapters=adapters, clock=CLOCK)
    else:
        run_from_config(config_path, run, adapters=adapters, clock=CLOCK)
    for bundle in (run / "invocations").iterdir():
        if not (bundle / "result.json").exists():
            continue
        result = json.loads((bundle / "result.json").read_text())
        plan = json.loads((bundle / "evaluator/plan.json").read_text())
        decisions = json.loads((bundle / "evaluator/decisions.json").read_text())
        decisions["claim_matches"][0].update(decision="accepted", reason="Recorded fixture judgment: caller controls the shell argument.")
        # Also retain a target with no matching explanation.
        plan["targets"].append({**plan["targets"][0], "target_id": "unexplained-target", "description": MALICIOUS})
        (bundle / "evaluator/plan.json").write_text(json.dumps(plan))
        (bundle / "evaluator/decisions.json").write_text(json.dumps(decisions))
        record = review_record(plan, decisions, clock=CLOCK)
        (bundle / "evaluator/review-record.json").write_text(json.dumps(record))
        (bundle / "evaluation.json").write_text(json.dumps(score(plan, result, decisions)))
    return run


def fingerprints(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}



def test_scope_filters_and_original_hash_bindings(tmp_path, upstream):
    run = make_run(tmp_path, upstream, repetitions=2)
    complete = build_investigation(run)
    assert len(complete["invocations"]) == 2
    for inv in complete["invocations"]:
        by_ref = {r["ref"]: r for r in inv["events"]}
        for row in inv["events"]:
            for ref in row["links"]["call_id"]["refs"]:
                assert by_ref[ref]["scope"] == row["scope"]
        claim = inv["claims"][0]
        assert all(by_ref[ref]["event"]["producer_id"] == "producer-a" for ref in claim["event_refs"])
        assert inv["events"][0]["timestamp_label"] == "import emission time"
        assert inv["events"][0]["native_timestamp"] == "2025-01-02T00:00:00Z"
    filtered = build_investigation(run, filters={"producer_id": ["producer-b"], "call_id": ["shared-call"]})
    inv = filtered["invocations"][0]
    assert len(inv["events"]) == 2 and inv["claims"][0]["event_state"] == "filtered_out"
    assert inv["trace"]["sha256"] == complete["invocations"][0]["trace"]["sha256"]
    empty = build_investigation(run, filters={"type": ["not-recorded"]})["invocations"][0]
    assert empty["trace"]["state"] == "valid" and empty["trace"]["display_state"] == "filtered_out"
    assert empty["capture"] == complete["invocations"][0]["capture"]


@pytest.mark.parametrize("state", ["missing", "empty", "malformed", "unavailable"])
def test_trace_readability_states_and_no_fallback_reads(tmp_path, upstream, state):
    run = make_run(tmp_path, upstream)
    bundle = next((run / "invocations").iterdir())
    path = bundle / "trace/events.jsonl"
    if state == "missing": path.unlink()
    if state == "empty": path.write_text("\n")
    if state == "malformed": path.write_text('{}\nnot-json\n')
    if state == "unavailable":
        path.unlink()
        path.symlink_to(tmp_path / "private-outside")
        (tmp_path / "private-outside").write_text("outside secret")
    document = build_investigation(run)
    assert document["invocations"][0]["trace"]["state"] == state
    assert "outside secret" not in json.dumps(document)


def test_metadata_mode_omits_content_and_preserves_usage_missingness(tmp_path, upstream):
    run = make_run(tmp_path, upstream, mode="metadata")
    document = build_investigation(run)
    inv = document["invocations"][0]
    assert all("content" not in row["event"] for row in inv["events"])
    assert "Private source:" not in json.dumps(document)
    assert any("content excluded" in entry["reason"] for entry in document["export_policy"]["omissions"])
    assert inv["usage"]["recorded"].get("input_tokens") is None


def test_stale_and_missing_bindings_remain_visible(tmp_path, upstream):
    run = make_run(tmp_path, upstream)
    bundle = next((run / "invocations").iterdir())
    decisions_path = bundle / "evaluator/decisions.json"
    decisions = json.loads(decisions_path.read_text())
    decisions["result_sha256"] = "sha256:" + "0"*64
    decisions_path.write_text(json.dumps(decisions))
    (bundle / "raw/native.json").unlink()
    inv = build_investigation(run)["invocations"][0]
    assert inv["bindings"]["decisions"] == inv["review_state"] == "stale"
    assert inv["bindings"]["evaluation"] == "stale"
    assert inv["claims"][0]["decisions"][0]["reason"]
    assert inv["claims"][0]["artifact_bindings"][0]["state"] == "missing"
    (bundle / "evaluator/decisions.json").unlink()
    inv = build_investigation(run)["invocations"][0]
    assert inv["bindings"]["decisions"] == "missing"
    assert inv["review_state"] == "unavailable"


def test_no_output_in_runs_trials_existing_directories_or_symlink_aliases(tmp_path, upstream):
    run = make_run(tmp_path, upstream)
    trial = tmp_path / "trial"
    (trial / "source").mkdir(parents=True)
    (trial / "provenance.json").write_text('{}')
    alias = tmp_path / "alias"
    alias.symlink_to(run, target_is_directory=True)
    for output in [run / "view", trial / "source/view", alias / "view", tmp_path]:
        with pytest.raises(InvestigationError):
            export_investigation(run, output)
    assert not (run / "view").exists()


def test_nested_symlinks_and_traversal_are_refused(tmp_path, upstream):
    run = make_run(tmp_path, upstream)
    bundle = next((run / "invocations").iterdir())
    saved = tmp_path / "outside-evaluator"
    shutil.move(bundle / "evaluator", saved)
    (bundle / "evaluator").symlink_to(saved, target_is_directory=True)
    inv = build_investigation(run)["invocations"][0]
    assert inv["documents"]["plan"]["state"] == "unavailable"
    execution_path = bundle / "execution.json"
    execution = json.loads(execution_path.read_text())
    execution["trace"]["path"] = "../other/trace.jsonl"
    execution_path.write_text(json.dumps(execution))
    assert build_investigation(run)["invocations"][0]["trace"]["state"] == "unavailable"


def test_native_namespaces_and_duplicate_event_ids_do_not_fabricate_links(tmp_path, upstream):
    run = make_run(tmp_path, upstream)
    bundle = next((run / "invocations").iterdir())
    trace = bundle / "trace/events.jsonl"
    events = [json.loads(line) for line in trace.read_text().splitlines()]
    events[1]["event_id"] = events[0]["event_id"]
    events[2]["parent_event_id"] = events[0]["event_id"]
    for event in events:
        event["run_id"] = "separate-native-run"
    trace.write_text("\n".join(map(json.dumps, events)))
    inv = build_investigation(run)["invocations"][0]
    assert inv["events"][2]["links"]["parent_event_id"]["state"] == "ambiguous"
    assert inv["claims"][0]["event_state"] == "not_linked"
    assert all(row["scope"][2] == "separate-native-run" for row in inv["events"])



def test_document_ambiguity_is_not_a_current_binding(tmp_path, upstream):
    run = make_run(tmp_path, upstream)
    bundle = next((run / "invocations").iterdir())
    plan = bundle / "evaluator/plan.json"
    plan.write_text('{"scope":"draft",' + plan.read_text()[1:])
    inv = build_investigation(run)["invocations"][0]
    assert inv["documents"]["plan"]["state"] == "malformed"
    assert inv["bindings"]["decisions"] == "unavailable"
    assert inv["targets"] == []


def test_ui_navigation_filters_and_capture_with_a_dom_unit_harness(tmp_path, upstream):
    """Execute the real UI script against a small DOM test double; this is not browser QA."""
    import subprocess
    from scaneval.investigation_html import _SCRIPT
    if shutil.which("node") is None:
        pytest.skip("node is not installed")
    run = make_run(tmp_path, upstream, repetitions=2)
    document = build_investigation(run)
    source = r'''
const assert = require('node:assert/strict');
const vm = require('node:vm');
const nodes = new Map();
class Element {
  constructor(tag) { this.tag=tag;this.children=[];this.listeners={};this._text='';this.value=''; }
  set id(id){this._id=id;nodes.set(id,this);} get id(){return this._id;}
  set textContent(v){this._text=String(v);} get textContent(){return this._text+this.children.map(c=>c.textContent).join(' ');}
  appendChild(child){this.children.push(child);return child;}
  replaceChildren(){this.children=[];this._text='';}
  addEventListener(name,fn){this.listeners[name]=fn;}
  scrollIntoView(){}
}
const document={createElement:tag=>new Element(tag),getElementById:id=>nodes.get(id)};
for(const id of ['evidence','invocation','run','tabs','filters','summary','body']){const n=new Element('div');n.id=id;}
document.getElementById('evidence').textContent=JSON.stringify(DATA);
const ctx=vm.createContext({document,console});
vm.runInContext(SCRIPT,ctx);
const body=()=>document.getElementById('body').textContent;
const capture=document.getElementById('summary').textContent;
assert.match(body(),/Targets and supplied judgments/);
assert.match(body(),/unexplained/);
const buttons=parent=>parent.children.filter(n=>n.tag==='button');
const tab=name=>buttons(document.getElementById('tabs')).find(n=>n.textContent===name).listeners.click();
tab('Claims');assert.match(body(),/Recorded fixture judgment/);
const claimArticle=document.getElementById('body').children.find(n=>n.tag==='article');
buttons(claimArticle).find(n=>n.textContent.startsWith('Related lifecycle')).listeners.click();
assert.match(body(),/Captured activity/);assert.doesNotMatch(body(),/producer-b · complete/);
tab('Events');
const filter=document.getElementById('filter-producer_id');filter.value='not-recorded';filter.listeners.input();
assert.match(body(),/filtered_out/);assert.match(body(),/0 shown/);
assert.equal(document.getElementById('summary').textContent,capture);
buttons(document.getElementById('filters')).find(n=>n.textContent==='Clear view filters').listeners.click();
assert.match(body(),/5 shown/);assert.match(body(),/import emission time/);assert.match(body(),/Native timestamp: 2025/);
tab('Bindings and review');assert.match(body(),/Original canonical document hash/);
const picker=document.getElementById('invocation');picker.value='1';picker.listeners.change();
assert.match(document.getElementById('summary').textContent,/r2/);
console.log('DOM unit harness: navigation, scoped links, filters, capture and timestamp labels passed');
'''
    harness = tmp_path / "ui-test.cjs"
    harness.write_text("const DATA=" + json.dumps(document) + ";\nconst SCRIPT=" + json.dumps(_SCRIPT) + ";\n" + source)
    result = subprocess.run(["node", str(harness)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
