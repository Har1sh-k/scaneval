# SASTbench evaluation math

Companion to [the design decisions](DESIGN_DECISIONS.md). Updated 2026-09-18. Metric specification; implementation pending.

Sections 1 through 6 define core reporting and planning. Sections 7 and 8 cover annotation-dependent diagnostics and optional research. These formulas use reviewed labels and recorded outcomes, not an LLM judge. Zero denominators mean N/A unless a convention explicitly states otherwise.

## 1. Known-target recall within a review budget

Let $s$ identify a system configuration, $i$ a canonical target, $m$ a planned scan input/scope, and $r$ one of its $k_m$ assigned repetitions. A PR input is a base/head pair under its declared review scope, not two scanner runs.

Report `standard` and `metadata_blinded` scores separately. Cross-profile contrasts use a common validated case set with exclusions shown, not unequal denominators.

Apply the metrics separately to the [declared workflows](DESIGN_DECISIONS.md#workload-classification): conventional applications, conventional automation, AI-assisted applications, and agentic applications. Workflow and mechanism annotations describe the evaluated inputs, not repository-wide labels. Component role is a separate reporting dimension. Restrict eligibility and normalize the relevant weights within each slice. Preserve canonical-target identity across overlapping views; do not pool their counts as independent targets. Any cross-workload summary requires predeclared membership and weights. Sampling proportions, severity mix, and repository caps remain undecided; no allocation formula or fixed distribution is adopted here.

Use the claim, splitting, and duplicate rules in [design Section 4](DESIGN_DECISIONS.md#4-scoring-without-exhaustive-repository-labels). One claim can hit at most one canonical target. Freeze the native review order and tie-breaking before label matching; record any necessary human normalization decisions. Duplicates occupy review positions but cannot create additional target hits. Unresolved bundles leave budgeted scoring pending, not artificially cheap.

For ranked output, store the first accepted rank $q_{simr}$ per target observation, or `null` when there is no accepted hit. Record delivered claim count $M_{smr}$ and execution status separately; a miss does not receive rank $M_{smr}$. For unranked output, retain target-hit flags but mark native rank unavailable, and use the separately labeled diagnostic below.

Ranked-list cutoffs have a precedent in [TREC's evaluation measures](https://trec.nist.gov/pubs/trec15/appendices/CE.MEASURES06.pdf). Our target-based recall@B, claim-splitting policy, and choice of $B$ are benchmark-specific; TREC does not establish an appropriate SAST review budget or supply exhaustive labels.

For ranked output, define $Y^B_{simr}=1$ only if $q_{simr}$ is non-null and $q_{simr}\leq B$, with the accepted claim delivered within execution limits. Otherwise it is zero. An unresolved match earns no confirmed hit and remains pending, not a confirmed false allegation. A valid hit from partial output may count; missing/error/unsupported assignments remain in the denominator. For full-output recall, a confirmed hit counts whether or not output has native ranking.

Let $\mathcal V_i$ contain the validated, in-scope positive inputs for target $i$. Freeze nonnegative input weights $\rho_{im}$ summing to one within each target:

$$
\widehat p^B_{si}
=\sum_{m\in\mathcal V_i}\rho_{im}
  \left(\frac{1}{k_m}\sum_{r=1}^{k_m}Y^B_{simr}\right),
\qquad
\widehat D_s@B=\sum_{i=1}^{N}w_i\widehat p^B_{si},
\qquad
w_i\geq0,\quad\sum_iw_i=1.
$$

With one positive input per target, one repetition, and equal weights, this reduces to:

$$
\mathrm{Recall@}B
=\frac{\text{unique assigned targets detected within the first }B\text{ claims per scan}}
       {\text{assigned validated targets}}.
$$

$B=\infty$ denotes full submitted output, still subject to the execution budget; an undetected target never becomes a hit at infinity. Unranked full-output hits use the retained hit flags, not a fabricated rank. Report full-output recall and a curve over predeclared finite budgets, for example 5, 10, 20, and 50. Full and PR scans have separate budget grids. Report the distribution of assigned target counts per input beside the curve. First-hit ranks let us recompute every finite budget without rescanning; retain all claims for burden and control assessment.

Within a declared reporting slice, $N$ is its target count and default equal-target weights are $w_i=1/N$. A separately reported equal-project or equal-family view uses $w_i=1/(G n_{g(i)})$ for $G$ disjoint groups with $n_g$ targets. Group CVE aliases and genuine variants first. Multiple snapshots can contribute observations of one target without increasing its total weight. Weighting cannot establish coverage of absent workflows or mechanisms.

For systems $s$ and $t$ on the same frozen workload:

$$
\widehat\Delta_{s,t}@B
=\sum_iw_i\left(\widehat p^B_{si}-\widehat p^B_{ti}\right).
$$

Pair uncertainty calculations on those same inputs. Do not remove unsupported work from one system's denominator after observing its results. A separately declared supported-workload analysis must be labeled as such. Three targets scored from one scan remain three target outcomes, not three independent executions.

### Unranked output diagnostic

For a fixed unranked output, let $M$ be its delivered atomic claim count, $h_i$ the number of those claims accepted for target $i$, and $b=\min(B,M)$. Under a uniform random ordering of all delivered claims, including duplicates:

$$
\mathbb E_{\pi}[Y_i^B\mid\text{output}]
=1-\frac{\binom{M-h_i}{b}}{\binom{M}{b}}.
$$

Use $\binom ab=0$ when $a<b$, and zero expected recall for empty output. This is the complement of drawing no accepted claim in the first $b$ positions. Aggregate these expectations with the same planned-observation and target weights as above. No simulated permutations or scanner reruns are needed.

Label this random-order expected recall, not native recall@B or measured prioritization. Duplicate claims can change this expectation even though they add no distinct detection, so show duplicate volume and do not use this diagnostic for promotion. A missing native order is not silently replaced with a fabricated rank. Normalization and matching decisions must be resolved or their pending status retained before computing the diagnostic.

## 2. Fixed controls, safe capabilities, and pairs

### False-alarm rates

A control $j$ is a validated security property, not an entire safe repository. Let $\mathcal O_j$ be its preassigned input/repetition observations, with weights $\lambda_{jo}$ summing to one. For each separately reported control class $\mathcal C$, freeze weights $u_j\geq0$, $\sum_{j\in\mathcal C}u_j=1$, independently of how many snapshots contain that control.

For observation $o$, let $c_{sjo}=1$ when execution validly completes in the declared scope, and $b_{sjo}=1$ only when it also has a resolved control assessment, so $b_{sjo}\leq c_{sjo}$. On resolved observations, $z_{sjo}=1$ means a false allegation about that property and $z_{sjo}=0$ means no such allegation. An unrelated true issue is not $z=1$. Assess full output, not only the first $B$ claims.

$$
\widehat F_{\mathcal C,s}
=\frac{\displaystyle\sum_{j\in\mathcal C}u_j
                   \sum_{o\in\mathcal O_j}\lambda_{jo}b_{sjo}z_{sjo}}
       {\displaystyle\sum_{j\in\mathcal C}u_j
                   \sum_{o\in\mathcal O_j}\lambda_{jo}b_{sjo}},
\qquad
A_{\mathcal C,s}
=\sum_{j\in\mathcal C}u_j
 \sum_{o\in\mathcal O_j}\lambda_{jo}b_{sjo}.
$$

Terms with $b=0$ contribute zero without assigning them a benign label. Report this as the false-alarm rate on resolved, completed controls, alongside $A_{\mathcal C,s}$, raw assigned/completed counts, and unresolved assessments. Failures or unresolved reviews cannot improve a promotion decision by silently reducing the denominator.

Define completed control mass $C_{\mathcal C,s}$ and confirmed false-allegation mass $E_{\mathcal C,s}$ under the same frozen weights:

$$
C_{\mathcal C,s}=\sum_{j\in\mathcal C}u_j
 \sum_{o\in\mathcal O_j}\lambda_{jo}c_{sjo},
\qquad
E_{\mathcal C,s}=\sum_{j\in\mathcal C}u_j
 \sum_{o\in\mathcal O_j}\lambda_{jo}b_{sjo}z_{sjo}.
$$

For $C_{\mathcal C,s}>0$, treating unresolved completed assessments as all quiet or all false gives:

$$
F_{\mathrm{completed},\mathcal C,s}\in
\left[
\frac{E_{\mathcal C,s}}{C_{\mathcal C,s}},
\frac{E_{\mathcal C,s}+C_{\mathcal C,s}-A_{\mathcal C,s}}
     {C_{\mathcal C,s}}
\right].
$$

Call the upper endpoint $F^+_{\mathcal C,s}$. This is a missing-assessment sensitivity bound, not a confidence interval or a bound on failed/incomplete scans. With ten equally weighted completed observations, seven quiet and three unresolved, the resolved rate is 0 but $F^+=0.30$. With no resolved observations the resolved rate is N/A; with no completed observations the completed bound is also N/A.

Promotion requires $F^+_{\mathcal C,s}\leq\tau_F$, $C_{\mathcal C,s}\geq c_{\min}$, and $A_{\mathcal C,s}\geq a_{\min}$, plus the declared uncertainty and other quality constraints. Freeze tolerances and minimum masses before comparison, separately for each control class. Failed runs cannot be counted as quiet, and insufficient coverage leaves the gate unresolved rather than passed.

Compute capability-safe and fixed-target rates separately. A control meeting both definitions may appear in both labeled views; do not pool it twice into a combined score. Repeated fixed observations of an old CVE share that control's weight. Eligibility comes from the frozen scope, not which files the tool chose to read.

### Pair correctness and availability

Let $\mathcal P$ contain targets with an assigned validated vulnerable/fixed observation schedule. Observations may reuse already-planned scans. For target $i$, match $k_i^P$ observation pairs in advance, not the best vulnerable result and quietest fixed result.

Write $b^V,b^F$ for completed, resolved assessments, $y^V$ for full-output target detection, and $z^F$ for a false allegation of the same root cause in the fixed input. With pair weights $v_i\geq0$ summing to one:

$$
\widehat Q_s
=\sum_{i\in\mathcal P}\frac{v_i}{k_i^P}
 \sum_{t=1}^{k_i^P}
 b^V_{sit}b^F_{sit}y^V_{sit}(1-z^F_{sit}).
$$

Assigned failed/incomplete/unresolved pairs earn no confirmed pair credit. This is conservative confirmed-success credit, not an optimistic imputation of unresolved pairs. Require declared assessable-pair coverage before using it for promotion. Separately report coverage and the four resolved outcomes:

| Vulnerable hit | False allegation in fixed state | Outcome |
|---:|---:|---|
| 1 | 0 | Correct pair |
| 1 | 1 | Both flagged |
| 0 | 0 | Both silent |
| 0 | 1 | Reversed |

Targets without an eligible fixed observation are outside $\mathcal P$, not failed pairs or successful controls. Show target-level pair availability, $\sum_i w_i\mathbf1[i\in\mathcal P]$, and raw counts beside $Q_s$. Their detection results remain in Section 1.

This adapts [PrimeVul's pair evaluation](https://arxiv.org/abs/2403.18624) to repository targets. Rolling later snapshots support practical discrimination; unrelated changes prevent interpreting them as isolated patch effects. A dedicated fixed-only scan is not implied by the formula.

For mixed-intent correctness, require a valid completed scan, the target hit, and resolved absence of false allegations on every required safe control in that input. Keep this denominator restricted to assigned cases with those annotations; failed or unresolved assignments earn no confirmed success. Report assessable coverage. The upper-bound-on-errors rule does not become upper-bound-on-success credit for pairs or mixed intent.

## 3. Reviewed precision and review burden

Declare the review population: unique claims represented in the first $B$ positions, or unique claims across full output. They are different populations. Review the bounded list for immediate usefulness; use probability sampling across full output for broader estimates. Retain duplicate delivery counts separately.

For sampled claim $a$, record inclusion probability $\pi_a>0$ and adjudicated class $\ell_a\in\{T,F,U\}$: true, false, or unresolved. Estimate class totals with inverse inclusion-probability weighting, following [Horvitz and Thompson (1952)](https://doi.org/10.1080/01621459.1952.10483446):

$$
\widehat N_\ell
=\sum_{a\in S}\frac{\mathbf1[\ell_a=\ell]}{\pi_a}.
$$

Writing $T,F,U$ for those estimated totals, report:

$$
\widehat P_{\mathrm{resolved}}=\frac{T}{T+F},
\qquad
\widehat U=\frac{U}{T+F+U},
\qquad
P_{\mathrm{sensitivity}}\in
\left[\frac{T}{T+F+U},\frac{T+U}{T+F+U}\right].
$$

The sensitivity range treats unresolved claims as all false or all true. It is not a confidence interval. Sampling uncertainty and reviewer disagreement remain. Equal-probability weights cancel; oversampling suspicious claims requires their actual inclusion probabilities. Weighted totals have a design-based interpretation; ratios need not be exactly unbiased. No estimate covers strata with zero sampling probability.

Use independent reviewers and adjudication; retain unresolved and out-of-scope outcomes under a declared policy. An additional confirmed issue counts as a true claim even if it was absent from the original targets. It does not alter only that tool's recall denominator. [NIST SATE](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.500-326.pdf) supplies the production-warning review precedent, not these benchmark-specific sampling choices.

For stratum $h$ with $M_h$ delivered claims and an appropriately sampled mean handling time $\widehat t_h$:

$$
\widehat L=\sum_h M_h\widehat t_h.
$$

Include true, false, unresolved, and duplicate handling. Estimate mean time with sampling weights where needed and distinguish shared setup time from per-claim handling. Unknown count multiplied by estimated FP rate is not review time. None of these expressions estimates an exhaustive whole-repository FP rate.

## 4. Completion and cost

Let $a_{smr}=1$ for a valid completed invocation. With frozen input weights $\eta_m\geq0$ summing to one:

$$
\widehat{\mathrm{Completion}}_s
=\sum_m\frac{\eta_m}{k_m}\sum_r a_{smr}.
$$

Report completion by input and target/control coverage separately; their denominators are different. A valid empty result is not the same as parser failure, timeout, or unsupported work.

Sum worker time/usage/cost over unique executed invocations and setup events, not over attached CVEs. Report elapsed wall time separately from summed parallel worker time. Include retries, and state whether setup/indexing is fresh or amortized over a declared workload. Preserve measured versus estimated cost, pricing date, and separate license costs. Missing cost is unknown, not zero.

Use detection, precision, controls, completion, burden, and cost as separate promotion constraints. Freeze tolerances and uncertainty requirements before optimization. Do not introduce a composite reward that lets recall compensate for unlimited noise.

## 5. Repetitions and uncertainty

For the simplified case of $N$ independently sampled targets, equal weights, one positive input each, and $k$ conditionally independent Bernoulli runs with success probability $p_i$:

$$
\operatorname{Var}(\widehat D)
=\frac{\operatorname{Var}(p_i)}{N}
+\frac{\mathbb E[p_i(1-p_i)]}{Nk}.
$$

For a fixed corpus, conditional run noise alone is:

$$
\operatorname{Var}(\widehat D\mid p_1,\ldots,p_N)
=\frac{1}{N^2k}\sum_i p_i(1-p_i).
$$

More repetitions reduce run noise, not corpus-selection uncertainty. These are independent-target illustrations, not direct standard errors for shared repository scans.

A rough paired independent-target planning approximation is:

$$
N\approx
\frac{(z_{1-\alpha/2}+z_{1-\beta})^2\sigma_d^2}{\delta^2}.
$$

Here $d_i=\widehat p_{Ai}-\widehat p_{Bi}$ at the planned repetition count, $\sigma_d^2=\operatorname{Var}(d_i)$, $\delta$ is the minimum worthwhile difference, $\alpha$ the Type I error rate, $1-\beta$ power, and $z_q$ a standard-normal quantile. [Miller](https://arxiv.org/abs/2411.00640) discusses variance, paired comparisons, clustering, and power for model evaluations. This does not yield a universal repetition count.

Actual planning: pilot diverse inputs, then simulate candidate budgets using their paired, clustered outcomes. Preserve systems, shared scans, related targets, and repetitions when resampling dependency groups. With few repositories, show project results and leave-one-project-out sensitivity; neither a bootstrap nor many repeats makes the corpus representative of all software. Predeclare interval-width/effect goals and stopping rules. Five cases per class is a configurable workload size, not evidence of adequate power.

## 6. Freshness and knowledge probes

Let $\mathcal A_i$ be credible known public answer-bearing artifacts and $t_a^{\mathrm{public}}$ their evidenced publication dates:

$$
H_i=\min_{a\in\mathcal A_i}t_a^{\mathrm{public}}.
$$

With a defensible cutoff $C_s$ for the bound model/runtime:

$$
G_{si}=
\begin{cases}
\text{cutoff-eligible}, & H_i>C_s,\\
\text{cutoff-ineligible}, & H_i\leq C_s,\\
\text{cutoff-unknown}, & \text{insufficient date or runtime provenance}.
\end{cases}
$$

Use `not_applicable` when this model-cutoff concept does not apply, not to hide missing data. Uncertainty that prevents ordering dates means unknown. A commit timestamp alone is not evidence of first public availability. Ruleset dates do not substitute for training cutoffs; a multi-component system without a defensible exposure boundary remains unknown.

Keep full results and report a common eligible comparison slice with its coverage. Correct findings retain normal detection credit regardless of prior knowledge; freshness changes the reporting subset, not a finding's correctness. This rule does not establish that earlier artifacts were absent or later exposure impossible.

For identity-only probes, separately count valid repo/version advisory associations, recognition of the selected target, incorrect associations, `UNKNOWN`, and execution failures. Bound responses; another valid advisory is not an error just because it differs from the selected target. Probe only supported runtimes in fresh sessions. Positive temporal inconsistencies need investigation and controls; negative recall is not proof of no exposure. Neither these counts nor the date gate is a memorization percentage.

## 7. Evidence grounding and stability

### Grounding where annotations support it

On cases with reviewed evidence nodes and relationships:

$$
\mathrm{evidence\ coverage}
=\frac{\text{unique required evidence nodes supported by the report}}
       {\text{required evidence nodes}},
\qquad
\mathrm{citation\ precision}
=\frac{\text{checked citations supporting their associated claims}}
       {\text{checked citations}}.
$$

Complete-chain credit additionally requires every required relationship. Include the relevant security decision, not just taint nodes, for authorization and other non-injection mechanisms. Reports cite code and relationships; evaluator-only region IDs are mapped after submission.

Location overlap alone measures region coverage, not security support. Use validated matching rules or review for that support. Sampled citations require corresponding sampling weights. Missing annotations mean N/A. File access, content delivered to the model, report evidence, and target correctness are separate observations.

### Harmless-edit stability

Optional follow-on diagnostic under design Section 4, not a buyer metric or release gate.

For normalized alert-identity sets $A,A'$ before/after a validated harmless edit, remap paths/symbols and compute:

$$
\mathrm{churn}(A,A')=1-\frac{|A\cap A'|}{|A\cup A'|}.
$$

Both empty sets have churn zero only for valid completed scans. This Jaccard distance measures change, not correctness. Pair it with vulnerable/fixed correctness and unchanged-input repeat churn for stochastic systems; stable wrong answers can have zero churn.

## 8. Optional reliability and contamination research

### At least one success versus consistent success

For $n$ independent, identically distributed trials of an unchanged system on one target/input, with $c$ successes and $1\leq k\leq n$:

$$
\widehat{\mathrm{pass@}k}
=1-\frac{\binom{n-c}{k}}{\binom nk},
\qquad
\widehat{\mathrm{all@}k}
=\frac{\binom ck}{\binom nk}.
$$

Use $\binom ak=0$ when $a<k$. The first estimates at least one success, following [Chen et al.](https://arxiv.org/abs/2107.03374); the second estimates all runs succeeding, corresponding to [tau-bench's pass^k](https://arxiv.org/abs/2406.12045). Aggregate with frozen target weights.

Do not pool different snapshots as identical trials or treat feedback-driven retries as independent samples. State $n$, $k$, and whether success means recall@B or pair correctness. These metrics do not replace mean per-run performance or establish that a buyer can select the correct output.

### Future research: identity and temporal contrasts

These contrasts are outside the initial release and promotion gates. Estimating $I$ requires matched identity conditions, not a pre/post split. Estimating $R$ additionally requires both temporal strata and a defensible comparison between them. Sparse strata increase uncertainty and weaken inference; they do not by themselves make every contrast mathematically inestimable. Missing conditions make the corresponding contrast unavailable.

Let $\ell\in\{O,M\}$ select `standard` ($O$) or `metadata_blinded` ($M$). These are the only supported identity profiles; package/import and source-identifier renaming are excluded. On matched validated pairs, define:

$$
S_\ell
=P(\text{target hit}\mid V,\ell)
-P(\text{same root cause falsely alleged}\mid F,\ell),
\qquad
I=S_O-S_M,
\qquad
R=I_{\mathrm{pre}}-I_{\mathrm{post}}.
$$

Use the same hit definition, pair sets, weights, and predeclared missing/completion policy. Freeze the approved metadata transformation across paired inputs and systems; report unavailable variants and remaining identity cues. $I$ measures the effect of those metadata changes, not removal of all repository identity; $R$ is the temporal triple difference. Neither is a probability of recall. Causal interpretation needs comparable cases, stable transformation/context effects, and genuinely unexposed post-cutoff cases. Even metadata edits can alter useful context. [Test of Time](https://aclanthology.org/2026.acl-long.1693/) shows why temporal signals can depend on question construction.

Rolling fixed controls alone do not isolate a patch effect. A tightly matched experiment must be selected and validated separately.

### Exposure regression

An exploratory model, fitted separately for each system, is:

$$
\operatorname{logit}P(Y_{ir}=1)
=\alpha_{g(i)}+\beta_E E_i+\beta_T T_i
+\beta_{ET}E_iT_i+\gamma^\top X_i.
$$

$g(i)$ is repository; $E_i=\log(1+\mathrm{frequency}_i)$ is a frozen item-exposure proxy; $T_i$ indicates post-cutoff; $X_i$ contains predeclared difficulty/task covariates. Fix the input/hit definition and account for repeated/shared outcomes. Test the interaction directly; significant pre-cutoff and nonsignificant post-cutoff slopes do not establish that the slopes differ.

This is [Roberts-inspired](https://proceedings.iclr.cc/paper_files/paper/2024/file/2d04d97593c8c33d415337f408ed0e1b-Paper-Conference.pdf), not an exact replication: item frequency differs from repo stars. The main effect of repository-constant stars is absorbed by repository fixed effects. Sparse overlap and collinearity may prevent identification. Separate source-code familiarity from advisory/patch exposure; present-day frequency is not historical training exposure. Keep this analysis outside release/promotion gates.
