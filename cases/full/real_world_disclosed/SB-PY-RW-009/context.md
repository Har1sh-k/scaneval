# SB-PY-RW-009: Path traversal in legacy load_prompt config loaders in langchain-core

## Advisory
- Repo: `langchain-ai/langchain`
- GHSA: `GHSA-qh6h-p6c9-ff54`
- CVE: `CVE-2026-34070`
- Vulnerable commit: `19f81cf6f1d73f7adf156491ba0617497a526b8c` (release langchain-core==1.2.21)
- Fix commit: `27add913474e01e33bededf4096151130ba0d47c` (release langchain-core==1.2.22)

## Vulnerability
The path string comes from the untrusted config dict and flows unchecked into Path(config.pop(...)).read_text(), so absolute paths and ../ sequences are honored. The only filter is the file-extension check, which limits the file type but does not confine the path to any trusted base directory.

## Source / Carrier / Sink
- Source: Path strings inside the prompt config dict passed to load_prompt_from_config()/load_prompt() (config['template_path'], config['suffix_path'], config['prefix_path']).
- Carrier: config.pop(f"{var_name}_path") wrapped in pathlib.Path(...) and held in template_path.
- Sink: template_path.read_text(encoding="utf-8") (line 56) reading file contents from the attacker-influenced path.
- Missing guard: No validation that the resolved path is absolute or contains '..' traversal components, and no confinement to a trusted base directory before reading.

## Fix
The fix adds a _validate_path() helper that rejects absolute paths and any path part equal to '..', and calls it before reading each config-supplied path (template_path, examples, example_prompt_path) unless the caller explicitly passes allow_dangerous_paths=True. The legacy load_prompt / load_prompt_from_config APIs were also deprecated.

## Scanner Expectation
Flag the data flow from the untrusted config-derived path into Path(...).read_text() as a path-traversal (CWE-22) sink lacking absolute-path/'..' validation.
