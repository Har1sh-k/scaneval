# External benchmark datasets

ScanEval keeps these datasets separate from `corpus/diverse`, its 50-CVE corpus.
The source locks under `src/scaneval/datasets/locks/` identify the exact upstream
revision, source-file hashes, licenses, and supplemental commit-resolution evidence.
Source locks contain annotations and provenance references, not scanner results.

| Dataset | Evaluation mode | Pinned upstream revision |
| --- | --- | --- |
| [AACR-Bench](https://github.com/alibaba/aacr-bench) | PR review | `ee9d7fef70ef31acea2ff7ae316ce0a9575fe4df` |
| [ReviewBench](https://github.com/review-bench/ReviewBench) | PR review | `9fd1c9bb1f3a2e1e6dbbd2a226a47c82b6c90e87` |
| [Martian Code Review Bench](https://github.com/withmartian/code-review-benchmark) | PR review | `e616e849755441da38f18bf3adba2c9583b03803` |
| [OpenSSF CVE Benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark) | CVE detection and fixed controls | `91c59fd54b2b768c0f310bb0027d2ac59cdf74d4` |

Upstream correctness labels are attributed to their publishers; importing them
does not independently validate a vulnerability or manufacture a human review.
Rejected PR comments do not establish that an entire PR is safe. An OpenSSF fixed
control concerns the named CVE, not every possible vulnerability in that checkout.

AACR-Bench's GitHub revision contains 1,506 positive and 639 negative comments.
Its separately published Hugging Face revision has a different label on one
DBeaver comment; these releases must not be silently mixed. One upstream AACR
line range is reversed and must remain flagged rather than silently repaired.

Martian supplies PR URLs but no commit IDs in its golden comments. Supplemental
pins come from GitHub's PR API on 2026-10-22, including redirects from `calcom/cal.com`
to `calcom/cal.diy`. OpenSSF has two abbreviated post-patch commit IDs; supplemental
pins expand those exact prefixes using GitHub's commit API. Original values and
response hashes are retained in the locks.

Downloaded source datasets retain their upstream licenses. This directory is an
integration inventory, not a copy of any publisher's leaderboard results.
