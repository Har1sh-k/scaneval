# Precision sampling and review

Recall asks about labeled targets. Precision asks about what a system delivered, and no label set answers that, because nobody labels every line of a repository. ScanEval answers it as [evaluation math section 3](EVALUATION_MATH.md#3-reviewed-precision-and-review-burden) states. You declare a population of claims, people review a seeded probability sample of it, and each reviewed claim is weighted by the inverse of its inclusion probability. No model or judge takes part.

Sampling and review never change a decision, plan, score, or detection credit. A claim reviewed true here is not a target hit, and recall is untouched. The commands read run directories and never write into one: an output path inside a run directory, or inside a trial, is refused.

The implementation is `src/scaneval/precision.py`. The documents are three contract kinds, all at protocol 2.1: `precision-sample`, `precision-reviews`, and `precision-estimate`.

## Populations

A **unit** is one exact-duplicate group of claims within one invocation. It uses the same `claim_fingerprint` identity scoring uses. It is named `<run_id>/<invocation_id>/<first claim id>` and records every copy's claim id. A claim delivered three times is judged once. Its extra copies are **duplicate delivery burden**, which is reported apart from precision. The same allegation from two invocations makes two units.

Declare one of two populations. They are different populations, and a figure from one says nothing about the other.

- **`first_b`** (`--budget B`): units with a copy at native rank at most B. This is the bounded list a reviewer would actually read. An invocation with unranked output or unresolved bundles has no measured position, so it is left out whole. The frame counts what it left out by reason: invocations, claim records, and units. Units of included invocations that lie past B are counted too.
- **`full`**: every unit a saved result delivered, whatever the invocation's status. Units from invocations with unresolved bundles are included and counted in a note, because such a unit may carry more than one allegation.

Assignments that delivered nothing (skipped, or never recorded by a failed run) add no claim to either population. They are listed with state `no_output`.

## The frame

`precision sample` reads each run directory's 2.1 `run-manifest.json`, the frozen `evaluator/schedule.json` it names, and the `result.json` of every bundle. It reads no plan, decision, or review record. The view is chosen by `--system` (repeatable; default every scheduled system), `--mode`, and `--profile`. Every assignment in the view becomes an invocation row, including one that delivered nothing.

The frame binds each run by the canonical digests of its manifest and schedule, and each result by its digest. Units are sorted by id and runs are read in run-id order. The order run directories are named in, or listed by a filesystem, changes nothing.

Refused:

- a 2.0 manifest, which predates frozen schedules;
- a run read twice;
- a manifest row its schedule never assigned;
- a bundle outside its run;
- a result that is unreadable or names another run, system, or input;
- an unknown system;
- a view no assignment falls in.

An unreadable result is never skipped, because dropping its claims would misstate the population.

## Design and inclusion probabilities

- **`srswor`** (default): simple random sampling without replacement of `--size` units from the whole population. Its one stratum is named `all`.
- **Stratified** (`--stratify-by system|input|kind`): each stratum is sampled without replacement. `--allocation` decides the stratum sizes:
  - **`proportional`** (the default) gives each stratum the whole part of `n·N_h/N`. Leftover units go one each to the largest fractional parts, ties broken by stratum name. A small stratum can end up with none.
  - **`equal`** shares n equally, the remainder one each to the first strata by name. A stratum no larger than its share is taken whole, and the rest is shared again, so the sample is always n units.

Stratum h draws from its own `scaneval.resampling.Stream(seed, label="precision/{frame_sha256}/{stratum}")` over its sorted unit ids (algorithm `sha256-counter-v1`). Every unit of stratum h is therefore drawn with probability **π_h = n_h/N_h**, recorded with N_h and n_h. A stratum that drew nothing is listed in `uncovered_strata`. No estimate from that sample represents it.

The same frame, size, seed, and design give the same sample, byte for byte. Every later step draws the sample again and refuses one that differs. A unit swapped after the draw, an edited claim, or a sample drawn by another algorithm is refused. This proves self-consistency only. Whoever holds the frame can draw with another seed, so state the seed before drawing.

## Review workflow

```bash
scaneval precision sample RUN_DIR... --population first_b --budget 10 \
    --size 60 --seed 20260929 --stratify-by system --output sample.json
scaneval precision queue sample.json --output queue.json
scaneval precision record reviews.json --sample sample.json --item item-0001 \
    --reviewer "Your Name" --role independent --outcome true --note "..."
scaneval precision estimate sample.json --reviews reviews.json --output estimate.json
```

- **Queue.** Reviewers get `queue.json`, not the sample. Each item carries:
  - an item id, from a seeded permutation, so the order reveals nothing;
  - the system's alias, such as `system-2`;
  - the input id, snapshot id, and input hash;
  - the allegation, kind, locations, and any evidence text.

  Run, invocation, unit, and claim ids and native rule ids are left out. The alias mapping stays in the sample. Blinding is only as good as the claim text: an allegation that names its tool still names it.
- **Outcomes.** One of four:
  - `true`: the allegation holds, whether or not it is a labeled target;
  - `false`: it does not hold;
  - `unresolved`: the review could not establish either;
  - `out_of_scope`: not a security allegation this review judges.
- **Record.** Each entry states `--reviewer`, `--role independent|adjudicator`, and `--outcome`. The tool never supplies a reviewer and refuses a blank one. Only a unit the sample drew can be reviewed: any other unit has no inclusion probability. The first review creates the reviews file, bound to the sample's digest. Later reviews append to it, and nothing is removed.
  - Entries form a chain (`chain_sha256`, head in `reviews_sha256`), so an edited, reordered, or truncated history is refused.
  - A reviewer who changes their mind records a new entry, and their earlier one stays in the history.
  - Appends are not locked, so record one at a time.
- **Resolution** of each sampled unit. "Latest" means latest in chain order, never by timestamp. Reviewers are distinguished by their names exactly as written.
  - The latest adjudication decides the unit's class. It is `adjudicated` evidence only when at least one independent reviewer other than the adjudicator also reviewed the unit. An adjudication with no independent review by another name rests on one person: the class is the adjudicator's and the basis is `single_review`, whatever role the entry states.
  - Otherwise each independent reviewer's latest entry counts once. One reviewer gives `single_review`; two or more who agree give `double_review`.
  - Any disagreement leaves the unit unresolved (`disagreement`) until an adjudicator records an outcome.
  - A unit with no review is unresolved (`nonresponse`).
- **Evidence grade.**
  - `incomplete`: any unit is in nonresponse or unadjudicated disagreement.
  - `single_review`: otherwise, any unit rests on one reviewer.
  - `double_review_or_adjudicated`: otherwise.

  The grade says how units were reviewed, not what the reviews found: a unit two reviewers agree is unresolved counts in U.

## Estimators

With π_h = n_h/N_h, the Horvitz-Thompson total of class c is N̂_c = Σ over sampled units of 1[class = c]/π_h. The classes are true (T), false (F), unresolved (U), and out of scope (O). U counts reviewed-unresolved, disagreement, and nonresponse together. O is reported apart and left out of every ratio. The estimate reports:

- resolved precision **T/(T+F)** and unresolved share **U/(T+F+U)**, each null when its denominator is zero;
- **sensitivity bounds [T/(T+F+U), (T+U)/(T+F+U)]**, which count every unresolved unit as false, then as true;
- an **approximate normal interval** for resolved precision, described below;
- **coverage**: the population units the sampled strata hold, and the strata left uncovered;
- per-stratum counts and figures. An uncovered stratum gets no totals: null, never zero;
- the raw sample counts by class and by resolution basis, and every unit's final class;
- the population's exclusions and the frame's **duplicate delivery burden** (copies per unit).

The interval uses the stratified linearized variance of the ratio R = T/X, where X = T+F. Each sampled unit scores z = (1[true] − R·1[true or false])/X, and V̂ = Σ_h N_h² (1 − n_h/N_h) s²_h / n_h, where s²_h is the sample variance of z in stratum h. The interval is R ± z_{(1+c)/2}·√V̂, clipped to [0, 1], with confidence `--confidence` (default 0.95). Its states:

- `ok`;
- `census`: every stratum was taken whole, none left uncovered, so there is no sampling variance;
- `degenerate`: zero variance from a sample that is not a census. The normal approximation has failed, so no bounds are given. A sample with an uncovered stratum is never a census, whatever its covered strata show: nothing was observed of the rest, and a zero-width interval would state certainty about it;
- `insufficient`: a stratum not taken whole drew one unit, so its variance cannot be estimated;
- `unavailable`: nothing resolved true or false.

Totals are exact fractions, converted to floats once at the end. The estimate carries no timestamp. It binds the digests of the sample, frame, and reviews, and the runs' manifest and schedule digests. Identical inputs give byte-identical documents.

## What the numbers do not mean

- Not a false-positive rate for a repository. They describe unique claims of the declared population, and nothing outside it.
- The sensitivity range is not a confidence interval.
- The interval covers sampling only. Reviewer error, disagreement, and unresolved units are outside it, and ratios need not be exactly unbiased.
- An uncovered stratum is not estimated at all. Read coverage before reading precision.
- A reviewed-true claim is an additional confirmed issue for precision. It earns no detection credit, and reaching the label set needs a separate reviewed label release.
- Hashes and the review chain bind documents; they are not signatures. Nothing verifies who a reviewer is, whether two reviewers are independent, or that anyone read the claim. A history wiped whole reads as a fresh one. The estimate records the digest of the history it used, which is where such a wipe shows.
