# Diagnostics

A diagnostic reads a saved run and reports something about *how* the run happened. It scores
nothing, changes nothing in the bundle, and never reaches a metric. A target whose code was never
supplied to the model is still a target the scan did not detect: coverage attribution explains a
miss, it does not excuse one.

One diagnostic exists today.

## `context-coverage`: was the target's code delivered to the model?

### The question

When a scan misses a known vulnerability, two very different things look identical in the result:

- the model was never shown the code, or
- the model was shown the code and said nothing.

Only the second is a detection failure. The first is a context-selection failure, and it is fixed
somewhere else entirely — in the harness's file budget, its ranking, its chunking — by someone who
would otherwise be tuning a prompt. This diagnostic separates the two.

It answers: **for every labeled target of a case, was the target's code region delivered to the
model in some invocation, and if so in which?**

### Where the answer comes from

Two halves that never meet before this point:

- the **labels**: `accepted_locations` on the case pack's target — `path`, `start_line`,
  `end_line` — joined to the plan's targets by `target_id`.
- the **trace**: `context.selection` events, whose `metadata.spans` say what the harness placed in
  a prompt: `path`, `start_line`, `end_line`, `chars`, `sha256`, `truncated`, `role`
  (Contract 3 in the observer vocabulary).

Nothing in a trace names a target, a case, or a line the evaluator cares about, and nothing in a
pack reaches a scanner. The join happens here, in the evaluator, after the run. That ordering is
what makes the answer evidence rather than a hint the harness could have acted on.

Spans live in `metadata`, so this works in `metadata` trace mode as well as `content` mode. No
file content is read and none is needed.

### Classification

A **target** is classified per **invocation**. An invocation is a group of `context.selection`
events sharing a `call_id`; an event carrying no usable one — absent, or not a non-empty string,
which the schema forbids anyway — is its own group, keyed by its `event_id`, because two such
events say nothing about belonging together.

Within a group, the spans on one path are merged into a union of closed, 1-based line intervals.
Intervals that touch merge as well as ones that overlap: lines 10-14 and 15-20 are one contiguous
block of supplied text, not two. Paths are compared after normalizing backslashes to forward
slashes, dropping a leading `./`, and collapsing redundant separators — the same normalization
`scaneval.scoring` applies to a claim location, so two modules comparing evaluator paths cannot
disagree about spelling.

A span marked `location_known: false` is excluded from that union. It carries text the harness
reassembled out of fragments, so its line numbers run 1..N over what was placed in the prompt and
name nothing in the file; counting them as file lines would report a target as delivered because
some fragment happened to be the right number of lines long.

The flag is opt-in, so absence is the ordinary case: a span that does not carry `location_known`
at all, and one carrying `true`, are both read as file positions. An **explicit value other than
`true`** is read as *not known to be* a file position — `false` says so outright, and `null` is a
harness saying it does not know, which is never a harness saying it does. Such spans are counted
as `unlocated_spans`, and the path they name is still held: see `unlocated_span_on_target_path`
below.

A span's line range is the range of the text **actually supplied** (Contract 2), so a truncated
span is not discounted for being truncated. `truncated` is read only for the counts in `capture`,
where only a present `false` says untruncated: `true`, `null` and absent all land in
`truncation_unknown_spans`.

| Observation | `classification` |
|---|---|
| every accepted location of the target lies fully inside the union of that invocation's spans | `included` |
| some lines, or some locations, are covered — but not all | `partial` |
| no line overlaps, and every context event of that invocation is `capture_status: complete` | `absent` |
| otherwise | `unknown` |

Everything else can only weaken a verdict, never strengthen one — and the weakenings are not all
the same size. That split is the whole judgement of this diagnostic:

- **A record that holds nothing** makes every classification `unknown`. No trace file, no context
  event, or a capture record claiming the category was never observed: there is no span to
  discuss, so there is nothing to conclude.
- **A record that is incomplete rather than empty** blocks only `absent`, taking it to `unknown`.
  A reported capture gap, a dropped event, a trace line that would not parse. A span that is in
  the trace was delivered whatever else went missing, and a lost event cannot un-deliver one, so
  `included` and `partial` stand. Discarding that evidence would be its own dishonesty: the
  document would say "we do not know" about something the record plainly shows.
- **A context event that did not claim complete capture** blocks `absent` for its invocation. No
  overlap in an incompletely captured invocation means no overlap was *recorded*.
- **An unlocated span on the target's own path** blocks `absent` for that invocation. Text from
  that very file reached the prompt at lines nobody can place; it may have been the target's.
- **A label location with no line range** caps the target at `partial`: a pack may name a file
  whose exact region has not been reviewed yet, and nothing here invents a boundary the label did
  not draw. `included` would overclaim; `absent` would deny something never looked at.

Then, per target:

- `best` is the best classification any single invocation earned (`included` > `partial` >
  `absent` > `unknown`). It never counts the union, and it is weakened from `absent` to `unknown`
  when the run's own capture record is not `complete` — see the next section.
- `union` classifies the union of spans across every invocation. `scattered: true` means the union
  beats every single invocation — the region was delivered, but in pieces no one invocation held.
- `event_ids` maps each classification to the events it rests on.

### Reasons, and what each one costs

Every reason is listed in the top-level `reasons`. What each one costs is fixed by
`scaneval.diagnostics.REASON_EFFECTS`, and the document splits them for the reader into
`reasons_blocking_all_classification` and `reasons_blocking_absence`.

**Nothing was recorded — every target and every invocation is `unknown`:**

| code | what happened |
|---|---|
| `trace_file_missing` | no trace file in the bundle, or the declared path is a symlink or escapes the bundle |
| `no_context_selection_events` | a trace was read and holds no `context.selection` event |
| `capture_context_selection_not_observed` | the execution record's `capture.context_selection` claims no observation (`unavailable`, `not_applicable`) |

**The record is incomplete — `absent` becomes `unknown`, `included` and `partial` stand:**

| code | what happened |
|---|---|
| `trace_capture_gap` | the execution record's `trace.capture_gap` is true |
| `trace_dropped_events` | the execution record's `trace.dropped_events` is above zero |
| `trace_lines_unparsed` | a line of the trace would not parse as JSON |
| `trace_events_malformed` | a `context.selection` event lacked a field the schema requires |
| `run_capture_facts_unavailable` | no execution record, or no readable `capture.context_selection` in it |
| `execution_record_invalid` | the record parsed but breaks its contract |

A reason code this table does not name is treated the same way: it blocks the negative claim and
nothing else. That is the one default that cannot make the document say more than it knows.

**The run did not observe every context selection it made — a *target's* `absent` becomes
`unknown`:**

| code | what happened |
|---|---|
| `context_capture_partial_at_run_level` | `capture.context_selection` is `partial` or `redacted` rather than `complete` |

This one is deliberately narrower than the rest. A **per-invocation** `absent` answers only for
the events that invocation produced, and stays exactly as the table above says. A **target-level**
`best` or `union` would also have to answer for the invocations that produced no event at all —
which is precisely what a run-level `partial` admits to. So `best` can be weaker than the best
entry in `by_invocation`, and that is not a bug: the per-invocation row and the `overlap`
arithmetic are untouched, so the evidence stays visible under the weaker headline.

**Scoped to one target** (in that target's `reasons`, and for the last one in the per-invocation
`reasons` too):

| code | what happened |
|---|---|
| `target_locations_unavailable` | the plan names the target but no pack case locates it |
| `target_locations_without_line_range` | at least one accepted location names a file and no lines |
| `unlocated_span_on_target_path` | an invocation supplied text from a path this target names, at lines that are not file lines |

Even where a verdict is `unknown`, the arithmetic is still reported: `overlap`, `covered_lines`
and `needed_lines` say what the spans actually showed, so a reader can see that the lines *were*
there and that only the record is in doubt.

### What it does not claim

The document carries these as `notes`, verbatim, every time:

- `included` says the target's lines were **delivered** to the model in that invocation. It does
  not say the model attended to them, that what was delivered was sufficient to recognize the
  vulnerability, or that a miss is a model failure.
- **Partial capture weakens the negative claim, never the positive one.** An incomplete record
  turns `absent` into `unknown`; a record holding nothing turns everything into `unknown`. An
  absent event is never evidence of absent activity.
- A span marked `location_known: false` **covers nothing**, and one on a target's own path blocks
  `absent` for that invocation.
- A span's line range is the range of the text actually supplied, so a **truncated** span is not
  discounted; `truncated` feeds counts only, and `null` there is unknown, never untruncated.
- Whether a candidate the harness produced was later **filtered out** is a different question.
  `finding.candidate`, `finding.validation`, `finding.filtered` and `finding.submitted` answer that
  one; this diagnostic reads none of them.
- Only `context.selection` events are read. File content a model pulled in through **its own tool
  call** is reported on `tool.end` spans, which are not counted here. `absent` means no supplied
  context span covered the lines, not that the file was never read.
- Labels stay evaluator-side and never enter a trace.

The document also never lists a path the harness supplied. Per-invocation records carry counts of
spans and of distinct paths; the only paths in the document are the evaluator's own accepted
locations, which the evaluator already holds.

### Running it

```bash
scaneval diagnose context-coverage <run>/invocations/<name>/
scaneval diagnose context-coverage <run>/invocations/<name>/ --pack ~/corpus/pilot/pack.json
scaneval diagnose context-coverage <run>/invocations/<name>/ --out coverage.json
```

It reads, in the invocation directory:

- `execution.json` — required; supplies `capture.context_selection`, the `trace` record, and the
  run identity.
- the trace file named by `execution.json`'s `trace.path`, defaulting to `trace/events.jsonl` —
  optional, and a bundle without one produces a document that says so.
- `evaluator/plan.json` — the targets this invocation was actually scored against.
- the case pack — `--pack` when given, otherwise `<run>/evaluator/pack.json` beside the
  invocations. The plan's target contract carries no lines, so accepted locations come from the
  pack and are joined on `target_id`.

With no plan, the pack alone is used, narrowed to the snapshot the execution record says this
invocation scanned. With neither, the command refuses and names `--pack`.

The plan and the pack are read for their labels, not validated: a pack that no longer satisfies
its contract still names the regions a case is about, and withholding the answer over a defect in
a field this never reads would help nobody. `scaneval validate case-pack` is the command that
judges a pack.

Nothing is written into the bundle. `--out` is create-only and refuses to overwrite.

Exit codes: `0` when the document was produced, `1` when the diagnostic could not be computed
from what it was given — a directory that is not a bundle, an unreadable execution record, a
`--pack` that is not a file, a bundle with no way to learn its targets — and `2` for a usage error
or a refused overwrite. A capture gap is none of these: it produces a document, at `0`, saying so.

### Output

Sorted keys, two-space indent, one trailing newline. Targets sorted by `target_id`, invocations by
first sequence then group key, event IDs by sequence then ID, reason codes lexically. No clock, no
randomness, and no timestamp of its own: two runs over one bundle produce the same bytes.

The document is not a registered contract. It is derived from documents that have contracts, the
way a score record is, and nothing binds to its shape.

```
schema_version            "2.0"
diagnostic                "context_coverage"
diagnostic_version        integer; bumped when a field changes meaning
scaneval_version          the version that produced the document
run_id, invocation_id, input_id, system_id
                          from the execution record, or null

sources
  execution_record        "execution.json"
  trace                   the trace path read, relative to the bundle, or null
  plan                    "evaluator/plan.json", or null
  pack                    {namespace, pack_id, version} of the pack read, or null
  targets_from            "plan+pack" | "plan" | "pack"

capture                   the facts every classification here rests on
  context_selection       the execution record's capture value for this category
  trace_mode              "metadata" | "content" | null
  trace_events_recorded   the event count the execution record claims
  trace_capture_gap       the observer's own gap report
  trace_dropped_events    the observer's own dropped count
  trace_file_read         whether this diagnostic actually read a trace file
  trace_lines_unparsed    lines of the trace that would not parse
  events_read             events read from the trace, or null when none was read
  context_selection_events
  context_selection_events_malformed
  context_selection_events_by_capture_status   {status: count}
  context_selection_events_all_complete
  invocations_with_context
  spans                   usable located spans
  unusable_spans          spans missing a path, or - when located - missing a line range or
                          carrying impossible lines
  unlocated_spans         spans whose location_known is present and not true: a path, no
                          file position
  truncated_spans         located spans claiming truncated: true
  truncation_unknown_spans
                          located spans whose truncated is absent or null
  events_without_span_list  context events carrying no metadata.spans list at all

reasons                   every run-level reason code, sorted
reasons_blocking_all_classification
                          the subset that makes every classification unknown
reasons_blocking_absence  the subset that only turns absent into unknown

counts
  targets
  locations_declared
  locations_without_line_range
  best                    {included, partial, absent, unknown} over per-target best
  union                   the same over per-target union classifications
  scattered_targets

invocations               one per context.selection group; counts only, never a supplied path
  call_id                 null for an event that carried none
  group_key               the call_id, or the event_id for a group of one
  first_sequence
  events, event_ids
  capture_status          the distinct statuses in the group, sorted
  all_capture_complete
  spans, unusable_spans, unlocated_spans, paths

targets                   sorted by target_id
  target_id
  best                    the best single invocation
  union
    classification
    scattered             the union beats every single invocation
    event_ids             the events the union verdict rests on
    overlap               "full" | "partial" | "none" — arithmetic, no capture claim
    covered_lines, needed_lines, locations_covered, locations_total
    locations             per accepted location: path, start_line, end_line, lines,
                          covered_lines, coverage ("full" | "partial" | "none")
  by_invocation           sorted by first sequence then group key
    call_id, group_key, first_sequence
    classification
    event_ids             every event of the group
    contributing_event_ids
                          the events whose own spans covered a labeled line
    capture_status, all_capture_complete
    unlocated_spans         spans in this group that named no file position
    unlocated_target_paths  paths this target names that such a span landed on, sorted
    reasons                 unlocated_span_on_target_path, when it applies
    overlap, covered_lines, needed_lines, locations_covered, locations_total, locations
  event_ids               {classification: [event_id, ...]}
  locations               the judgeable accepted locations: path, start_line, end_line, lines
  locations_declared      including the ones with no line range
  locations_without_line_range
  reasons                 run-level reasons plus this target's own, sorted

notes                     what the document does not claim
```

### Using it as a library

```python
from pathlib import Path
from scaneval.diagnostics import context_coverage, context_coverage_for_invocation

document = context_coverage_for_invocation(Path("run/invocations/example"))
```

`context_coverage` is the pure half and reads no file:

```python
document = context_coverage(
    plan_targets=[{"target_id": "T-1", "accepted_locations": [...]}],
    events=[...],               # parsed trace events, or None to say no trace was read
    execution_record={...},     # or None: the run's capture facts are then unavailable
)
```

`events=None` and `events=[]` are different facts and are reported differently: no trace file
versus a trace holding no context event. `scaneval.diagnostics.DiagnosticsError` is raised only
for inputs the diagnostic cannot be computed from at all — a directory that is not a bundle, an
execution record that is not readable JSON, a bundle with no way to learn what its targets are.
A capture gap is not one of those: a diagnostic about capture gaps has to survive one.
