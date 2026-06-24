# SB-TS-RW-076: Flowise CSV Agent RCE via bypassable Python import allow-regex before Pyodide execution

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-3hjv-c53m-58jj`
- CVE: `CVE-2026-41264`
- Vulnerable commit: `84758d794d2a3678c1c49cc5d6e20010c84d8ded` (release ?)
- Fix commit: `cf36fb71fbd33437166f8a94de8534a4d9b6180c` (release flowise@3.1.0)

## Vulnerability
The import allow-list is enforced with a regex that only checks the first module name after `import` via a negative lookahead, so multi-target import statements such as `import pandas as np, os as pandas` slip through and bring in os/subprocess under an allowed alias. The LLM-generated text is then executed by pyodide.runPythonAsync() without any real sandbox, so any code that evades the regex runs with the server process's privileges. This is a bypass of the validation added for CVE-2026-41137.

## Source / Carrier / Sink
- Source: Attacker-supplied chat prompt (the `question`) sent to a chatflow using the CSV Agent node, or an attacker-controlled model server returning crafted code.
- Carrier: The prompt is embedded into systemPrompt, sent to the LLM, and the returned text is stored as pythonCode in CSVAgent.run(); it is then passed to validatePythonCodeForDataFrame() and on to pyodide.runPythonAsync().
- Sink: pyodide.runPythonAsync(`import pandas as pd\n${pythonCode}`) executing LLM-generated Python in a non-sandboxed Pyodide runtime that can reach os/subprocess.
- Missing guard: An import filter that actually blocks all non-allowed imports; the negative-lookahead regex only validates the first import target and is trivially bypassed by `import pandas as np, os as pandas`.

## Fix
Fix commit cf36fb71 (shipped in flowise@3.1.0) replaces the permissive `/\bimport\s+(?!pandas|numpy\b)/g` pattern with `/\bimport\b/g`, forbidding every import in LLM-generated code (pandas/numpy are pre-imported by the executor), and adds further reflection guards (vars(), dir(), __dict__, __module__). The advisory confirms the maintainers 'addressed this advisory by disallowing all imports in the CSV Agent.'

## Scanner Expectation
A scanner should flag that LLM/attacker-influenced text reaches a code-execution sink (pyodide.runPythonAsync) guarded only by a denylist/allow-regex that does not robustly prevent dangerous imports, enabling command/code execution.
