"""Standalone local UI. All evidence reaches the DOM through textContent."""
import base64
import hashlib
import json

_SCRIPT = r'''
'use strict';
const data = JSON.parse(document.getElementById('evidence').textContent);
const el = (tag, text, parent, cls) => {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (cls) node.className = cls;
  if (parent) parent.appendChild(node);
  return node;
};
const json = value => JSON.stringify(value, null, 2);
const detail = (parent, title, value) => {
  const box = el('details', null, parent); el('summary', title, box); el('pre', json(value), box); return box;
};
const button = (parent, text, action) => {const b=el('button',text,parent); b.type='button'; b.addEventListener('click',action); return b;};
let current = 0, tab = 'Targets', focus = null;
const fields = ['type','producer_id','call_id','candidate_id','claim_id'];
const filters = {};
const picker = document.getElementById('invocation');
for (const [index, inv] of data.invocations.entries()) {
  const option = el('option', `${inv.invocation_id} · ${inv.status}`, picker); option.value = index;
}
picker.addEventListener('change', () => {current=Number(picker.value); focus=null; resetFilters(); render();});
el('p', `Run ${data.run.data.run_id} · ${data.run.data.status} · ${data.invocations.length} invocation(s)`, document.getElementById('run'));
if (data.run.data.failure) detail(document.getElementById('run'), 'Recorded run failure', data.run.data.failure);
el('p', `${data.export_policy.redactions.length} credential redaction(s); ${data.export_policy.omissions.length} recorded omission(s).`, document.getElementById('run'));
detail(document.getElementById('run'), 'Export policy, original bindings and filters', {policy:data.export_policy, manifest_sha256:data.run.sha256,filters:data.filters});
for (const name of ['Targets','Claims','Events','Bindings and review']) button(document.getElementById('tabs'),name,()=>{tab=name;render();});
const filterPanel=document.getElementById('filters');
for (const field of fields) {
  const label=el('label', field.replace('_id',''),filterPanel);
  const input=el('input',null,label);input.type='text';input.placeholder='Exact value';input.id='filter-'+field;
  input.addEventListener('input',()=>{filters[field]=input.value;focus=null;render();});
}
function resetFilters(){for(const field of fields){filters[field]='';document.getElementById('filter-'+field).value='';}}
button(filterPanel,'Clear view filters',()=>{resetFilters();focus=null;render();});
function showEvents(refs){resetFilters();focus=refs;tab='Events';render();}
function links(parent, refs, label){if(refs && refs.length) button(parent,`${label} (${refs.length})`,()=>showEvents(refs));else el('p','Events: not linked / not captured',parent,'muted');}
function render(){
  const inv=data.invocations[current];
  const summary=document.getElementById('summary'),body=document.getElementById('body');
  summary.replaceChildren();body.replaceChildren();filterPanel.hidden=tab!=='Events';
  if(!inv){el('p','No invocation bundle was recorded in this run.',body);return;}
  el('h2',`${inv.invocation_id} · ${inv.status}`,summary);
  el('p',`Capture record: ${inv.capture.state}; trace: ${inv.trace.state}; review: ${inv.review_state} (recorded attribution).`,summary,'notice');
  el('p','Saved capture declarations and effective capture after trace validation:',summary);
  el('pre',json(inv.capture),summary);
  el('p',`Usage: ${inv.usage.state}. Trace events: ${inv.trace.valid_events} valid; ${inv.trace.shown_events} exported; ${inv.trace.rejected_records ?? 'unavailable'} rejected.`,summary);
  detail(summary,'Recorded usage',inv.usage);
  if(inv.trace.diagnostics?.length)detail(summary,'Trace diagnostics',inv.trace.diagnostics);
  if(tab==='Targets'){
    el('h3','Targets and supplied judgments',body);
    if(!inv.targets.length)el('p','Targets: unavailable or empty; inspect document states under Bindings and review.',body);
    for(const target of inv.targets){
      const card=el('article',null,body);el('h4',target.target.target_id,card);el('p',target.target.description,card);
      el('p',`Explanation: ${target.explanation_state}; decisions: ${target.decision_binding}; saved outcome: ${target.outcome_binding}.`,card);
      if(target.explanation_state==='unexplained')el('p','No recorded explanation. A missing hit does not establish why the scanner missed it.',card,'muted');
      detail(card,'Existing decision reasons',target.decisions);detail(card,'Saved outcome (not recomputed)',target.recorded_outcomes);
      detail(card,'Planned target',target.target);links(card,target.event_refs,'Related lifecycle events');
      for(const id of target.claim_ids)button(card,`Claim ${id}`,()=>{tab='Claims';render();document.getElementById('claim-'+inv.claims.findIndex(c=>c.claim.claim_id===id))?.scrollIntoView();});
    }
  }else if(tab==='Claims'){
    el('h3','Claims, decisions and artifact bindings',body);
    if(!inv.claims.length)el('p',`Claims: ${inv.documents.result?.state === 'available' ? 'empty' : 'unavailable'}.`,body);
    for(const [index,claim] of inv.claims.entries()){
      const card=el('article',null,body);card.id='claim-'+index;el('h4',claim.claim.claim_id,card);el('p',claim.claim.allegation,card);
      el('p',`Decision: ${claim.decision_state}; binding: ${claim.decision_binding}; events: ${claim.event_state}; artifact: ${claim.artifact_state}.`,card);
      detail(card,'Claim and source location',claim.claim);detail(card,'Existing matching decisions and reasons',claim.decisions);
      detail(card,'Recorded control assessments',claim.control_assessments);detail(card,'Original artifact bindings',claim.artifact_bindings);links(card,claim.event_refs,'Related lifecycle events');
    }
  }else if(tab==='Events'){
    el('h3','Captured activity',body);
    const events=inv.events.filter(row=>(focus===null||focus.includes(row.ref))&&fields.every(field=>!filters[field]||row.event[field]===filters[field]));
    const state=events.length?'readable':inv.events.length?'filtered_out':inv.trace.display_state;
    el('p',`View: ${state}; ${events.length} shown of ${inv.events.length} exported events. Capture status above applies even when filters show zero events.`,body,'notice');
    el('p','Ordered by recorded observer/import emission time. Native timestamps are separate labels, not a latency calculation. Source delivery does not prove model attention.',body,'muted');
    if(focus!==null)button(body,'Show all exported events',()=>{focus=null;resetFilters();render();});
    for(const row of events){
      const event=row.event,card=el('article',null,body);card.id=row.ref;
      el('h4',`${event.type} · ${event.producer_id} · ${event.capture_status}`,card);
      el('p',`${row.timestamp_label}: ${event.timestamp}`,card);
      el('p',`Native timestamp: ${row.native_timestamp ?? 'unavailable'}${row.native_timestamp_of ? ' ('+row.native_timestamp_of+')' : ''}`,card);
      el('p',`Run / invocation / native run / producer: ${row.scope.join(' / ')}`,card,'muted');
      el('p',`Call: ${event.call_id ?? 'not linked'}; candidate: ${event.candidate_id ?? 'not linked'}; claim: ${event.claim_id ?? 'not linked'}`,card);
      for(const [field,link] of Object.entries(row.links)){
        el('span',`${field}: ${link.state} `,card);if(link.refs.length)links(card,link.refs,'Navigate');
      }
      detail(card,'Event metadata and recorded usage',event.metadata);
      if(event.content!==undefined){const content=detail(card,'Captured source / tool / prompt content',event.content);content.open=true;}
      else el('p','Content: not captured / excluded by trace mode.',card,'muted');
    }
  }else{
    el('h3','Bindings and recorded review attribution',body);
    el('p','Hashes bind original saved bytes/documents, before export redaction. Stale or unavailable bindings do not authenticate judgments. Reviewer names are recorded attribution, not verified identity.',body,'notice');
    detail(body,'Binding checks',inv.bindings ?? {});detail(body,'Manifest invocation',inv.manifest);
    for(const [name,doc] of Object.entries(inv.documents)){
      const card=el('article',null,body);el('h4',`${name}: ${doc.state}`,card);
      el('p',`Original file: ${doc.path}`,card);el('p',`Original byte hash: ${doc.sha256 ?? 'unavailable'}`,card);
      el('p',`Original canonical document hash: ${doc.canonical_sha256 ?? 'unavailable'}`,card);
      if(doc.diagnostics.length)detail(card,'Diagnostics',doc.diagnostics);
      if(doc.data)detail(card,'Recorded document (export redaction applied)',doc.data);
    }
    detail(body,'Raw artifact bindings (contents not copied)',inv.artifacts);
    detail(body,'Trace file binding and readability',inv.trace);
  }
}
render();
'''


def render_investigation(document: dict) -> str:
    payload = json.dumps(document, ensure_ascii=True, allow_nan=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    digest = base64.b64encode(hashlib.sha256(_SCRIPT.encode()).digest()).decode()
    return '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-''' + digest + ''''; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>ScanEval saved-run investigation</title><style>
body{font:16px/1.5 system-ui,sans-serif;max-width:1200px;margin:32px auto;padding:0 24px;background:#f7f8fa;color:#172638}
h1,h2,h3,h4{line-height:1.25}h4{margin-top:0}article{border:1px solid #c9d2dc;border-radius:8px;background:white;padding:20px;margin:16px 0}
button,select,input{font:inherit;padding:8px;margin:4px;border:1px solid #aebcc9;border-radius:4px;background:white;color:#172638}button{cursor:pointer}button:hover{background:#e9f2fc}
label{display:inline-flex;flex-direction:column}input{max-width:160px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#edf1f5;padding:12px;font:13px/1.5 ui-monospace,monospace}
.notice{background:#fff2d5;border-left:4px solid #b17c20;padding:12px}.muted{color:#526172}details{margin:12px 0}summary{cursor:pointer}a{color:#155ca2}#tabs{border-bottom:1px solid #bcc9d6;padding:12px 0}span{display:inline-block;margin:4px}
</style></head><body><h1>Saved-run investigation</h1>
<p>Local saved evidence and supplied judgments. No model calls, remote assets or uploads. Nothing is rescored.</p>
<p><a href="investigation.json" download>Download the same machine-readable export</a></p>
<div id="run"></div><label>Invocation <select id="invocation"></select></label>
<section id="summary" aria-live="polite"></section><nav id="tabs" aria-label="Investigation views"></nav>
<section id="filters" hidden aria-label="Event filters"></section><main id="body"></main>
<noscript>This local view needs JavaScript. The adjacent investigation.json contains the same export.</noscript>
<script id="evidence" type="application/json">''' + payload + '''</script><script>''' + _SCRIPT + '''</script></body></html>
'''
