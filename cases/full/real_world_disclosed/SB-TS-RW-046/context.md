# SB-TS-RW-046: OpenClaw Gmail setup let a workspace .env CLOUDSDK_PYTHON select the Python interpreter for gcloud execution

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-fq9j-vw4w-fr6v`
- CVE: `CVE-2026-53842`
- Vulnerable commit: `a448042c2edd94a4e8ee86d5ed90a5ed9fe8e4cd` (release v2026.4.29)
- Fix commit: `86251f43916d8210d38d8f69c9fb0b0070a88fdf` (release v2026.5.2)

## Vulnerability
gcloudEnv() treats an existing CLOUDSDK_PYTHON as authoritative and declines to override it, so a value injected through the workspace dotenv flows unchanged into the gcloud child process environment. CLOUDSDK_PYTHON controls the Python binary gcloud runs, turning a workspace config value into control over which interpreter executes during Gmail setup.

## Source / Carrier / Sink
- Source: Workspace .env CLOUDSDK_PYTHON entry loaded into process.env
- Carrier: process.env.CLOUDSDK_PYTHON passed through gcloudEnv() into runGcloudCommand()'s child-process env
- Sink: gcloud child process execution (runCommandWithTimeout(["gcloud", ...])) selecting the Python interpreter
- Missing guard: No override/blocking of inherited CLOUDSDK_PYTHON; workspace dotenv key was not in the blocklist and gcloudEnv deferred to ambient env

## Fix
gcloudEnv() was changed to always resolve a trusted interpreter and return { CLOUDSDK_PYTHON: pythonPath }, never deferring to the inherited value, and CLOUDSDK_PYTHON was added to BLOCKED_WORKSPACE_DOTENV_KEYS in src/infra/dotenv.ts so workspace .env files can no longer set it.

## Scanner Expectation
Flag that gcloudEnv() returns undefined when CLOUDSDK_PYTHON is present, letting a workspace-controlled CLOUDSDK_PYTHON reach gcloud execution and select the interpreter, instead of forcing a trusted interpreter.
