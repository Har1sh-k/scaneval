// Pi extension for the SV-Agent open-context route: recorded public research and read-only
// repository history, loaded in the Pi process by explicit path (`--no-extensions -e`).
//
// It registers only the tools defined in pi_open_context_tools.mjs and does nothing else: no
// event handlers, no provider, no command. The runner then names exactly these tools in
// `--tools`, so no built-in tool (read, bash, edit, write, grep, find, ls) is declared to the
// model. The built-in file tools are left out on purpose: they read any absolute path the
// process can, which includes Pi's private agent directory and the run's raw output.

import { Type } from "@earendil-works/pi-ai";
import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createOpenContextTools } from "./pi_open_context_tools.mjs";

export default function scanevalOpenContext(pi: ExtensionAPI): void {
  const { tools } = createOpenContextTools({ Type, env: process.env });
  for (const tool of tools) {
    pi.registerTool(defineTool(tool as Parameters<typeof defineTool>[0]));
  }
}
