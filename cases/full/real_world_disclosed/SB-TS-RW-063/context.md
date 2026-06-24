# SB-TS-RW-063: Flowise AirtableAgent executes unvalidated LLM-generated Python in Pyodide, enabling prompt-injection RCE

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-f228-chmx-v6j6`
- CVE: `CVE-2026-41138`
- Vulnerable commit: `f0c1294173a55f26e0b972c39c0c16917f5ca9e7` (release flowise@3.0.13)
- Fix commit: `a24acac5d8b71aa69caa71650a026d5ceaa9efbc` (release flowise@3.1.0)

## Vulnerability
The attacker controls the chat `question`, which is reflected unsanitized into the LLM prompt, so the LLM can be coerced via prompt injection into returning arbitrary Python rather than a constrained pandas DataFrame expression. That returned code is passed straight to pyodide.runPythonAsync with no allow-listing or AST validation, so any Python construct the model emits executes. The intended constraint ("output only pandas code") is purely a natural-language instruction and provides no real security boundary.

## Source / Carrier / Sink
- Source: The user-controlled `input` (chat `question`) argument of AirtableAgent.run(), at most passed through optional input moderation.
- Carrier: `input` is interpolated as the `{question}` field of the LLMChain prompt; the LLM's text output is captured into `pythonCode` and only stripped of markdown code fences.
- Sink: pyodide.runPythonAsync(`import pandas as pd\n${pythonCode}`) executes the LLM-generated Python in the Pyodide runtime.
- Missing guard: No validation/allow-listing of the generated Python before execution; the prompt's natural-language "only output pandas code" instruction is not an enforceable boundary against prompt injection.

## Fix
The fix (commit a24acac, shipped in flowise@3.1.0) introduces packages/components/src/pythonCodeValidator.ts and calls validatePythonCodeForDataFrame(pythonCode) before execution. If validation fails (unsafe construct detected), the agent throws and refuses to run the code instead of passing it to pyodide.runPythonAsync. Later commits (cf36fb71) further harden the validator to reject any additional imports in the generated code.

## Scanner Expectation
A scanner should flag the data flow from the user-controlled run() `input` -> LLMChain prompt -> `pythonCode` -> pyodide.runPythonAsync as code/command injection (CWE-94): attacker-influenced text reaching a dynamic Python execution sink with no validating guard between source and sink.
