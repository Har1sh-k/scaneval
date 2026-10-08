# Running the draft pilot

The [pilot pack](../corpus/pilot/pack.json) contains three pinned source snapshots:
oauth2-proxy, FastMCP, and Fastify. Its cases have mechanical L1 checks only. No label or
finding match has human approval, and no fixed/safe controls are defined. Use this pack to
exercise the pipeline, not to rank scanners.

## Prerequisites

Install ScanEval using the [setup guide](INITIAL_BUILD.md#try-it), then configure the scanner:

| Configuration | Required setup |
|---|---|
| [`run-semgrep.json`](../corpus/pilot/run-semgrep.json) | Install Semgrep. The adapter fetches the pinned ruleset rather than loading registry rules at scan time. |
| [`run-harness.json`](../corpus/pilot/run-harness.json) | Haiku through securevibes-agent. Set `config.root` to your checkout with its dependencies installed. Build the [TypeScript Observer](OBSERVER_SDK.md) and authenticate the requested model route. |
| [`run-harness-codex-sol.json`](../corpus/pilot/run-harness-codex-sol.json) | GPT-5.6 Sol through securevibes-agent and pi's OpenAI Codex provider. The checked-in path expands to `~/Documents/GitHub/securevibes-agent`; update it if your checkout lives elsewhere. |
| [`run-deepsec.json`](../corpus/pilot/run-deepsec.json) | Set `config.deepsec_root` to an installed DeepSec workspace and configure CLI authentication. |

Review model, budget, input, and tracing settings before running. The harness and DeepSec
configurations make live model calls and can incur charges. Source preparation fetches pinned
commits. Network policies are recorded but not enforced by ScanEval; use an appropriate
disposable environment for untrusted scanners or source. See the [threat model](THREAT_MODEL.md).

## Run locally

Run from the repository root. Each output directory must be new.

```sh
# Conventional scanner, all configured inputs.
scaneval run corpus/pilot/run-semgrep.json --output results/semgrep-pilot

# Own harness, one input. Makes live model calls.
scaneval run corpus/pilot/run-harness.json --output results/harness-pilot \
  --only-input fastify-v5.12.1

# Own harness with GPT-5.6 Sol, all three pilot inputs. Makes live model calls.
scaneval run corpus/pilot/run-harness-codex-sol.json \
  --output "results/harness-codex-sol-$(date +%Y%m%d-%H%M%S)"

# Third-party scanner, one input. Makes live model calls.
scaneval run corpus/pilot/run-deepsec.json --output results/deepsec-pilot \
  --only-input fastify-v5.12.1
```

These configurations are starting points, not performance claims. File-limited or incomplete
scans cannot establish silence on unexamined targets or controls. The supplied DeepSec file
limit can leave incomplete coverage; retain the reported status.

`scaneval run` prints preparation, invocation start, periodic heartbeat, completion, and final
manifest messages to stderr. It does not print prompts or raw scanner output. Use `--quiet` only
when a calling script needs progress suppressed.

## Inspect and replay

Choose an invocation directory from the generated `run-manifest.json`:

```sh
BUNDLE='results/harness-pilot/invocations/<invocation-id>'
scaneval review status "$BUNDLE"
scaneval replay "$BUNDLE"
scaneval diagnose context-coverage "$BUNDLE"
```

Replace `<invocation-id>` with the actual directory name before running the commands. Replay
and diagnostics are offline. Unreviewed labels and unresolved matches remain draft; do not
interpret missing approval as measured zero detection. Follow the [review workflow](INITIAL_BUILD.md#review-workflow)
and [case authoring guide](BRING_YOUR_OWN_CORPUS.md) before publishing comparisons.

Keep scanner output and content traces local. They can contain source code, credentials not
recognized by redaction, or previously unknown findings. Publishing artifacts or contacting
maintainers requires a separate review and authorization.
