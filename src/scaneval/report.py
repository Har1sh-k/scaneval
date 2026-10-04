"""Offline HTML rendering of a freshly evaluated saved bundle."""

from html import escape


REVIEW_NOTICES = {
    "draft": "Decisions: machine-drafted, all unresolved; no human review recorded.",
    "stale": "Decisions or plan changed after the review record was written; "
             "the recorded review no longer applies.",
    "missing": "No review record accompanies these decisions.",
}


def _show(value):
    if value is None:
        return "N/A"
    if isinstance(value, float):
        return f"{value:.1%}"
    return escape(str(value))


def _review_notice(review_state) -> str:
    """One notice paragraph for a review state, or nothing at all when none was supplied.

    The state is reported, not checked: this says what a review record on disk claims about
    the decisions, never whether a human actually reviewed them, and an unrecognized state
    is shown as unreviewed rather than guessed at.
    """
    if review_state is None:
        return ""
    state = escape(str(review_state))
    if review_state == "human_approved":
        text = "Decisions: recorded human review (" + state + ")."
    else:
        text = REVIEW_NOTICES.get(
            review_state,
            "Review state " + state + " is not one this report recognizes; "
            "treat these decisions as unreviewed.",
        )
    return f'<p class="notice">{text}</p>'


def render_report(record: dict, result: dict, plan: dict, review_state=None) -> str:
    """Render data as escaped text. No scripts, CDN, source links or raw HTML.

    ``review_state`` adds one notice about the bundle's review record, as
    :func:`scaneval.review.review_status` reports it. Omitting it renders exactly the same
    page as before; supplying it adds a statement about the record, not a verification of
    it, and no value of it changes a metric on this page.
    """
    m = record["metrics"]
    disclaimer = {
        "diagnostic": "Diagnostic fixture only. No scanner or model was run. These are not real-world performance results.",
        "draft": "Draft labels. Targets and controls come from a draft plan and are not independently reviewed; "
                 "matching decisions may be unreviewed. Use for pipeline diagnostics only, not as benchmark evidence.",
        "reviewed": "Saved-output evaluation. Review decisions and validation levels are supplied by the evaluator, not certified by this report.",
    }[record["scope"]]
    warnings = "".join(f"<li>{escape(w)}</li>" for w in record["warnings"])
    budgets = "".join(f"<tr><td>{escape(b)}</td><td>{_show(r)}</td></tr>"
                      for b, r in m["recall_at_budget"].items())
    if m["random_order_expected_recall"] is not None:
        diagnostic = "<h3>Unranked random-order expectation</h3><p>Diagnostic only, not measured prioritization.</p><ul>" + "".join(
            f"<li>First {escape(b)}: {_show(r)}</li>" for b, r in m["random_order_expected_recall"].items()) + "</ul>"
    else:
        diagnostic = ""
    descriptions = {t["target_id"]: t["description"] for t in plan["targets"]}
    targets = "".join(
        f"<tr><td>{escape(t['target_id'])}</td><td>{escape(descriptions[t['target_id']])}</td>"
        f"<td>{'Detected' if t['detected'] else 'No confirmed hit'}</td><td>{_show(t['first_hit_rank'])}</td></tr>"
        for t in record["targets"]
    )
    controls = "".join(
        f"<tr><td>{escape(kind)}</td><td>{c['assigned']}</td><td>{c['completed']}</td>"
        f"<td>{c['resolved']}</td><td>{c['false_allegations']}</td><td>{c['observed_false_allegations']}</td>"
        f"<td>{_show(c['resolved_false_alarm_rate'])}</td><td>{_show(c['sensitivity_upper'])}</td></tr>"
        for kind, c in m["controls"].items()
    )
    claims = "".join(
        f"<tr><td>{_show(c.get('rank'))}</td><td>{escape(c['claim_id'])}</td>"
        f"<td>{escape(c['allegation'])}</td><td>{escape(c['kind'])}</td>"
        f"<td>{escape(c['primary_location']['path'])}"
        f"{':' + str(c['primary_location']['start_line']) if 'start_line' in c['primary_location'] else ' (file only)'}</td></tr>"
        for c in result["claims"]
    )
    review_notice = _review_notice(review_state)
    hashes = "".join(f"<dt>{escape(k)}</dt><dd><code>{escape(record[k])}</code></dd>"
                     for k in ("input_hash", "result_sha256", "plan_sha256", "decisions_sha256"))
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>ScanEval saved evaluation</title><style>
body{{font:16px/1.55 system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#15202b;background:#fafafa}}
h1,h2,h3{{line-height:1.2}} h2{{margin-top:2em}} .notice{{border-left:4px solid #a46700;background:#fff4da;padding:16px}}
table{{border-collapse:collapse;width:100%;margin:16px 0}} th,td{{padding:10px;border:1px solid #ccd3da;text-align:left;vertical-align:top}}
th{{background:#edf1f5}} .scroll{{overflow-x:auto}} code{{overflow-wrap:anywhere}} dd{{margin:0 0 12px}} .muted{{color:#526170}}
</style></head><body>
<h1>ScanEval: saved evaluation</h1><p class="notice">{disclaimer}</p>{review_notice}
<p>System: <strong>{escape(record['system_id'])}</strong> · Run: {escape(record['run_id'])} · Status: {escape(record['status'])}</p>
<h2>Detection and review burden</h2>
<p>Full-output recall: <strong>{_show(m['known_target_recall'])}</strong> ({m['targets_detected']}/{m['targets_assigned']} targets on this input).</p>
<p>Delivered atomic claims: {_show(m['claims_delivered'])}. Normalized records: {m['claim_records']}.
Exact duplicate copies: {m['duplicate_copies']}. Unmatched distinct claims: {m['unmatched_unique_claims']}.</p>
<p class="muted">Unmatched does not mean false positive. Duplicates consume review positions. Counts for unresolved bundles are incomplete.</p>
<table><thead><tr><th>Claims reviewed</th><th>Native recall</th></tr></thead><tbody>{budgets}</tbody></table>{diagnostic}
<div class="scroll"><table><thead><tr><th>Target</th><th>Mechanism</th><th>Result</th><th>First-hit rank</th></tr></thead><tbody>{targets}</tbody></table></div>
<h2>Property-specific controls</h2><p>Assessed against full output, not just the review budget. N/A is not zero.</p>
<div class="scroll"><table><thead><tr><th>Control view</th><th>Assigned</th><th>Completed</th><th>Resolved</th><th>Completed false allegations</th><th>All observed false allegations</th><th>Resolved rate</th><th>Completed upper bound</th></tr></thead><tbody>{controls}</tbody></table></div>
<p class="muted">The upper bound treats unresolved completed observations as false allegations. It is not a confidence interval and does not cover incomplete runs.</p>
<h2>Submitted claims</h2><div class="scroll"><table><thead><tr><th>Rank</th><th>ID</th><th>Allegation</th><th>Kind</th><th>Location</th></tr></thead><tbody>{claims}</tbody></table></div>
<h2>Limits and provenance</h2><ul>{warnings}</ul>
<p>Single-input metrics only. Corpus weighting and paired comparison (<code>scaneval aggregate</code>, <code>scaneval compare</code>), sampled precision estimates (<code>scaneval precision</code>), and gate decisions (<code>scaneval gate</code>) are separate commands over saved runs; a trace viewer is not implemented in this build.</p>
<p>Scorer: {escape(record['scorer_version'])}. Trace capture is optional and does not affect detection credit.</p><dl>{hashes}</dl>
</body></html>
'''
