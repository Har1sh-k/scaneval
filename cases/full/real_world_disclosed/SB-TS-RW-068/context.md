# SB-TS-RW-068: Flowise Custom MCP server command blocklist incomplete, allowing docker build / npx --yes / node // path RCE

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-m99r-2hxc-cp3q`
- CVE: ``
- Vulnerable commit: `34cf28546b700998e88a8f14d6f6d0754f572da4` (release flowise@3.1.1)
- Fix commit: `7176dcb409b197ee1eeec0ebec389b6db36340f8` (release flowise@3.1.2)

## Vulnerability
The security control is an allow-everything-except-blocklist over command flags/subcommands, and the blocklist omits multiple equally dangerous forms (docker build/compose, npx --yes, node --require/--loader/--import). It is a classic incomplete-denylist (CWE-184) over an attacker-controlled command spec, so configurations that are functionally equivalent to the blocked ones (docker build instead of docker run, --yes instead of -y) sail through and reach the MCP transport's child-process spawn. The companion path check additionally has a regex flaw (/^\/[^/]/) that fails to match // -prefixed absolute paths.

## Source / Carrier / Sink
- Source: Attacker-controlled Custom MCP Server configuration (command + args) supplied via the MCP tool node UI or chatflow create/update API by any authenticated user (any role) or an API key with chatflow view+update.
- Carrier: command and args are passed to validateCommandFlags()/validateArgsForLocalFileAccess(); the incomplete dangerousFlagsByCommand denylist (and the /^\/[^/]/ path regex) lets equivalent dangerous forms (docker build, npx --yes, node //path) pass validation.
- Sink: The validated command + args are spawned as a child process by the MCP stdio transport, executing docker build of a remote Dockerfile, npx auto-installing/running a remote package, or node executing a local attacker-written script.
- Missing guard: The denylist does not cover docker build/compose/--mount/--device/--entrypoint or the npx --yes long alias, and the absolute-path regex /^\/[^/]/ does not match // -prefixed paths, so dangerous-equivalent argv shapes reach process spawn.

## Fix
Fix commit 7176dcb (shipped in 3.1.2) hardens both checks in MCP/core.ts: it adds build/compose/--mount/--volumes-from/--device/--entrypoint/--env-file to the docker blocklist, adds --yes and --node-options to npx, adds -r/--require/--loader/--experimental-loader/--import/--env-file to node, and changes the path regex from /^\/[^/]/ to /^\// so // -prefixed absolute paths are also rejected. Tests in core.test.ts cover the docker build and npx --yes cases.

## Scanner Expectation
A scanner should flag that an attacker-controlled command specification is validated only by an incomplete flag/subcommand denylist before being spawned as a child process, allowing equivalent dangerous forms (docker build, npx --yes, node //file) to execute arbitrary code (command/argument injection, CWE-78/CWE-184).
