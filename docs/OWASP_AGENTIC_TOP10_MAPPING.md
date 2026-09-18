# OWASP Agentic Top 10 -- SASTbench Mapping

> This page describes the legacy mapping and scoring implementation. Its case lists are historical, non-exhaustive examples, not the next release manifest. See the proposed [scoring contract](DESIGN_DECISIONS.md#4-scoring-without-exhaustive-repository-labels); the composite Agentic Score is legacy only.

SASTbench aligns with the [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) as a **reporting crosswalk**, not a replacement for the benchmark's own scoring taxonomy.

The mapping enables users and report consumers to filter or aggregate results by OWASP ASI category. The six-kind canonical taxonomy is `command_injection`, `path_traversal`, `ssrf`, `auth_bypass`, `authz_bypass`, and `sql_injection`. The legacy scorer uses kind and region overlap; the design adds claim/property validation. OWASP mappings remain reporting metadata and do not establish ground truth or change scoring.

## Mapping Table

| ASI ID | OWASP Category | SASTbench Focus | Coverage | SAST Suitability |
|--------|----------------|-----------------|----------|------------------|
| ASI01 | Agent Goal Hijack | `command_injection` | Targeted coverage | Medium -- SAST can often trace goal-carrying prompt/context data into powerful sinks, but it cannot fully reason about agent intent. |
| ASI02 | Tool Misuse & Exploitation | `ssrf`, `path_traversal`, selected `command_injection` secondaries | Strong coverage | High -- this is the benchmark's best static-analysis fit because it reduces cleanly to taint and guard validation at tool boundaries. |
| ASI03 | Identity & Privilege Abuse | `auth_bypass`, `authz_bypass`, approval/scope binding flaws | Strong coverage | Medium-High -- missing auth, scope binding, and privilege inheritance checks usually leave static evidence. |
| ASI04 | Agentic Supply Chain Vulnerabilities | plugin and package install/load surfaces | Targeted coverage | Medium-High -- SAST can often spot untrusted plugin installation, discovery, or execution paths, especially when integrity checks are absent. |
| ASI05 | Unexpected Code Execution | `command_injection` | Strong coverage | High -- direct shell execution, eval, and RCE-style sinks are highly benchmarkable with region-level scoring. |
| ASI06 | Memory & Context Poisoning | `command_injection` via poisoned memory/context | Targeted coverage | Medium -- static analysis can detect the final sink path, but persistent memory poisoning is broader than code alone. |
| ASI07 | Insecure Inter-Agent Communication | `auth_bypass`, cross-agent sandbox inheritance | Targeted coverage | Medium -- SAST can catch missing authentication and broken trust-boundary checks between agents, but not all protocol-level guarantees. |
| ASI08 | Cascading Failures | Not in scope | Not covered | Low -- system-wide propagation and blast radius are emergent runtime properties, not stable file-local findings. |
| ASI09 | Human-Agent Trust Exploitation | Not in scope | Not covered | Very low -- this category depends on human approval behavior, misleading UX, and social proof, not just source code structure. |
| ASI10 | Rogue Agents | Not in scope | Not covered | Very low -- long-horizon misalignment, concealment, and self-directed behavior require runtime evaluation rather than region-scored SAST. |

## Per-ASI Case Lists

### ASI01 -- Agent Goal Hijack

Cases where attacker-controlled prompt or context data changes the agent's objective or tool plan.

| Case ID | Kind | Track | Role |
|---------|------|-------|------|
| SB-PY-SV-003 | `command_injection` | Core | Primary |
| SB-PY-SV-001 | `ssrf` | Core | Secondary |
| SB-TS-SV-002 | `ssrf` | Core | Secondary |

### ASI02 -- Tool Misuse & Exploitation

Cases where an agent misuses a legitimate tool boundary such as HTTP, filesystem, or shell execution wrappers.

| Case ID | Kind | Track | Role |
|---------|------|-------|------|
| SB-PY-MI-001 | `ssrf` | Core | Primary |
| SB-PY-RW-001 | `ssrf` | Full | Primary |
| SB-PY-RW-002 | `ssrf` | Full | Primary |
| SB-PY-RW-003 | `ssrf` | Full | Primary |
| SB-PY-RW-004 | `ssrf` | Full | Primary |
| SB-PY-RW-005 | `ssrf` | Full | Primary |
| SB-PY-RW-006 | `path_traversal` | Full | Primary |
| SB-PY-SV-001 | `ssrf` | Core | Primary |
| SB-PY-SV-002 | `path_traversal` | Core | Primary |
| SB-RS-CS-001 | `path_traversal` | Core | Primary |
| SB-RS-SV-001 | `path_traversal` | Core | Primary |
| SB-RS-SV-003 | `path_traversal` | Core | Primary |
| SB-TS-CS-001 | `ssrf` | Core | Primary |
| SB-TS-MI-001 | `ssrf` | Core | Primary |
| SB-TS-RW-008 | `path_traversal` | Full | Primary |
| SB-TS-RW-014 | `ssrf` | Full | Primary |
| SB-TS-SV-002 | `ssrf` | Core | Primary |
| SB-PY-RW-007 | `command_injection` | Full | Secondary |
| SB-RS-MI-001 | `command_injection` | Core | Secondary |
| SB-RS-RW-001 | `path_traversal` | Full | Secondary |
| SB-RS-SV-002 | `command_injection` | Core | Secondary |
| SB-TS-RW-002 | `command_injection` | Full | Secondary |
| SB-TS-RW-005 | `command_injection` | Full | Secondary |
| SB-TS-RW-012 | `path_traversal` | Full | Secondary |
| SB-TS-SV-001 | `command_injection` | Core | Secondary |

### ASI03 -- Identity & Privilege Abuse

Cases where authentication, authorization, approval binding, or sandbox scope checks are missing or bypassable.

| Case ID | Kind | Track | Role |
|---------|------|-------|------|
| SB-RS-RW-001 | `path_traversal` | Full | Primary |
| SB-TS-RW-003 | `auth_bypass` | Full | Primary |
| SB-TS-RW-004 | `auth_bypass` | Full | Primary |
| SB-TS-RW-007 | `command_injection` | Full | Primary |
| SB-TS-RW-009 | `authz_bypass` | Full | Primary |
| SB-TS-RW-010 | `authz_bypass` | Full | Primary |
| SB-TS-RW-011 | `command_injection` | Full | Primary |
| SB-TS-RW-013 | `auth_bypass` | Full | Primary |
| SB-TS-RW-015 | `auth_bypass` | Full | Primary |
| SB-TS-RW-016 | `authz_bypass` | Full | Primary |
| SB-TS-RW-017 | `authz_bypass` | Full | Primary |
| SB-TS-RW-019 | `authz_bypass` | Full | Primary |
| SB-RS-SV-004 | `auth_bypass` | Core | Secondary |
| SB-TS-RW-001 | `command_injection` | Full | Secondary |
| SB-TS-RW-006 | `path_traversal` | Full | Secondary |

### ASI04 -- Agentic Supply Chain Vulnerabilities

Cases where agents load or install code, plugins, or packages from untrusted registries, repositories, or workspace roots.

| Case ID | Kind | Track | Role |
|---------|------|-------|------|
| SB-TS-RW-012 | `path_traversal` | Full | Primary |
| SB-TS-RW-018 | `command_injection` | Full | Primary |
| SB-TS-SV-003 | `command_injection` | Core | Primary |

### ASI05 -- Unexpected Code Execution

Cases where attacker-controlled data reaches a shell, eval, or equivalent code-execution sink.

| Case ID | Kind | Track | Role |
|---------|------|-------|------|
| SB-PY-CS-001 | `command_injection` | Core | Primary |
| SB-PY-RW-007 | `command_injection` | Full | Primary |
| SB-RS-MI-001 | `command_injection` | Core | Primary |
| SB-RS-SV-002 | `command_injection` | Core | Primary |
| SB-TS-RW-001 | `command_injection` | Full | Primary |
| SB-TS-RW-002 | `command_injection` | Full | Primary |
| SB-TS-RW-005 | `command_injection` | Full | Primary |
| SB-TS-SV-001 | `command_injection` | Core | Primary |
| SB-PY-SV-003 | `command_injection` | Core | Secondary |
| SB-PY-SV-004 | `command_injection` | Core | Secondary |
| SB-TS-RW-007 | `command_injection` | Full | Secondary |
| SB-TS-RW-011 | `command_injection` | Full | Secondary |
| SB-TS-RW-018 | `command_injection` | Full | Secondary |
| SB-TS-SV-003 | `command_injection` | Core | Secondary |

### ASI06 -- Memory & Context Poisoning

Cases where poisoned memory, retrieval, or context state later drives unsafe execution.

| Case ID | Kind | Track | Role |
|---------|------|-------|------|
| SB-PY-SV-004 | `command_injection` | Core | Primary |

### ASI07 -- Insecure Inter-Agent Communication

Cases where agent-to-agent channels or subagent hops are trusted without sufficient authentication or confinement.

| Case ID | Kind | Track | Role |
|---------|------|-------|------|
| SB-RS-SV-004 | `auth_bypass` | Core | Primary |
| SB-TS-RW-006 | `path_traversal` | Full | Primary |

### ASI08 -- Cascading Failures

System-level failure amplification across chained agents, services, or automations.

No cases are currently mapped to this category.

### ASI09 -- Human-Agent Trust Exploitation

Cases where agents exploit human trust, approvals, or operator expectations.

No cases are currently mapped to this category.

### ASI10 -- Rogue Agents

Cases where agents act beyond intended goals or controls over time.

No cases are currently mapped to this category.

## Why ASI08-ASI10 Are Out of Scope

SASTbench is a static analysis benchmark. Its scoring is built around region-level matching of concrete source-code findings. Three OWASP categories remain intentionally out of scope for that model:

- **ASI08 (Cascading Failures)**: This category is about system-wide propagation, chained automation effects, and blast radius across components. Those effects are emergent runtime behaviors rather than stable file-local vulnerabilities.

- **ASI09 (Human-Agent Trust Exploitation)**: This category depends on human approvals, misleading interfaces, confidence cues, and operator behavior. It is important, but it is not something a SAST benchmark can score reliably from annotated code regions alone.

- **ASI10 (Rogue Agents)**: This category is about long-horizon autonomy, concealment, and behavior that drifts beyond intended goals. That requires runtime evaluation, adversarial simulation, or longitudinal testing rather than static code scanning.

These categories are valuable for agentic security programs, but they belong in runtime exercises, red teaming, behavioral evaluation, or operational governance rather than in SASTbench's current scoring model.

## Relationship Between SASTbench Scoring and the OWASP Mapping

SASTbench uses its own six-kind canonical taxonomy:

- `command_injection`
- `path_traversal`
- `ssrf`
- `auth_bypass`
- `authz_bypass`
- `sql_injection`

Legacy metrics (Recall, Capability FP Rate, Mixed-Intent Accuracy, Agentic Score) use kind/region matching. They are not the proposed claim-based scorecard, and Agentic Score is scheduled for retirement. Capability FP results currently cover six synthetic safe regions, not validated real-world controls.

The OWASP mapping is **metadata** stored in each case's `standards.owaspAgenticTop10` field. It enables:

- Filtering results by ASI category in reports
- Aggregating coverage statistics by OWASP category for compliance narratives
- Mapping SASTbench findings to organizational risk frameworks that reference the OWASP Agentic Top 10

The OWASP mapping does **not**:

- Change how true positives, false positives, or false negatives are determined
- Replace the canonical kind as the matching key
- Affect the legacy Agentic Score computation or introduce a new composite score
- Require adapters to emit ASI category labels

In short, the OWASP mapping is a reporting crosswalk that sits alongside the scoring system without replacing it.
