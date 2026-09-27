# Adapter Validation

Run the smallest set of commands that proves the adapter actually works.

## Unit tests

If you added a dedicated adapter test file:

```bash
python -m pytest tests/test_<scanner>_adapter.py -q
```

If the adapter touches shared behavior, also run:

```bash
python -m pytest tests/test_adapters.py tests/test_<scanner>_adapter.py -q
```

## Core smoke test

Use the canonical Python SSRF case:

```bash
python scripts/run.py --scanner <name> --track core --case-id SB-PY-SV-001
```

Expected outcome:

- the adapter runs without crashing
- the result shows a target hit if the scanner can detect SSRF in Python

## Full Core Track

If the smoke test works and the scanner is stable:

```bash
python scripts/run.py --scanner <name> --track core
```

## PR-mode smoke test

Only if the adapter implements native PR support or you changed PR-related behavior:

```bash
python scripts/run.py --scanner <name> --mode pr --track core --case-id SB-PY-SV-001
```

Expected outcome:

- no harness crash
- PR summary is produced
- native PR adapters return review findings
- non-PR-native adapters still work via fallback synthesis

## Guardrails

- Do not commit `results/`
- Do not commit scanner state directories
- Do not claim PR support if the adapter only works in benchmark mode
