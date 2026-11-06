#!/usr/bin/env node
// Run the upstream unbundled program so its imports use this image's patched dependencies.
// Pi's prebuilt CLI embeds dependency copies that npm overrides cannot replace.
import { fileURLToPath } from "node:url";

const entrypoint = new URL("./node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url);
process.argv[1] = fileURLToPath(entrypoint);
await import(entrypoint.href);
