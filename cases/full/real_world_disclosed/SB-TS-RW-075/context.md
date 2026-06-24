# SB-TS-RW-075: Code injection in CSVAgent: user-controlled customReadCSV interpolated into Python executed by Pyodide

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-9wc7-mj3f-74xv`
- CVE: `CVE-2026-41137`
- Vulnerable commit: `f0c1294173a55f26e0b972c39c0c16917f5ca9e7` (release flowise@3.0.13)
- Fix commit: `0c8236ac9a9720725e135603f4a54f7d7d6646ac` (release flowise@3.1.0)

## Vulnerability
customReadCSV is taken from node inputs and concatenated into a Python source string that is run by Pyodide with no allow-listing or syntactic restriction, so attacker Python statements (including os.system) execute. This is Improper Control of Generation of Code (CWE-94) enabling authenticated RCE.

## Source / Carrier / Sink
- Source: User-controlled CSVAgent customReadCSV input (_customReadCSV from node inputs) supplied when creating/configuring a chatflow.
- Carrier: customReadCSVFunc string interpolated into the multiline `code` template variable.
- Sink: pyodide.runPythonAsync(code) executing the constructed Python program containing 'df = pd.${customReadCSVFunc}'.
- Missing guard: No sanitization/validation/allow-listing of customReadCSVFunc before interpolation; arbitrary Python statements are accepted and executed.

## Fix
Commit 0c8236ac (#5836, 'Sanitize Code Ran in Pyodide in CSVAgent') added a validatePythonCodeForDataFrame(customReadCSVFunc) call before building the code and throws an error rejecting the input when validation fails; later commits tightened the validator to permit only a single read_csv(...) call. The hardening shipped in flowise@3.1.0.

## Scanner Expectation
Flag user-controlled input concatenated/interpolated into a code string that is then executed by an interpreter (runPythonAsync/eval-style sink) without validation (code injection).
