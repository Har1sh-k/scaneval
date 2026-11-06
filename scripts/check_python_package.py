#!/usr/bin/env python3
"""Install one built wheel or sdist in a fresh environment and verify its public surface."""

from __future__ import annotations

import argparse
from email import message_from_bytes
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile


OBSERVER_SMOKE = r'''
import json
import sys
from importlib.metadata import version
from importlib.resources import files
from scaneval.observer import Observer, TraceSink, create_jsonl_sink

assert version("scaneval") == sys.argv[1]
assert not any(name in sys.modules for name in (
    "scaneval.contracts", "scaneval.scoring", "scaneval.runner", "scaneval.execution",
)), "the standalone Observer imported evaluator modules"
lines = []
observer = Observer(mode="metadata", sink=create_jsonl_sink(lines.append),
                    run_id="package-smoke", producer_id="installed-observer")
observer.emit(type="model.request", capture_status="complete", call_id="call-1",
              metadata={"model": "synthetic-no-call"})
observer.flush()
assert observer.get_state().dropped_events == 0
observer.close()
assert len(lines) == 1
assert json.loads(lines[0])["type"] == "model.request"
for resource in (
    "schemas/run-config-2.1.schema.json", "mappings/kinds.json",
    "datasets/locks/aacr-bench.json", "data/model-cutoffs.json",
    "adapters/llm_harness_driver.mts", "adapters/pi_open_context_tools.mjs",
):
    assert files("scaneval").joinpath(resource).is_file(), resource
'''


def artifact_version(path: Path) -> str:
    """Read distribution metadata without extracting or executing the archive."""
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            candidates = [name for name in archive.namelist()
                          if name.count("/") == 1 and name.endswith(".dist-info/METADATA")]
            if len(candidates) != 1:
                raise ValueError("wheel must contain exactly one distribution metadata file")
            payload = archive.read(candidates[0])
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            candidates = [item for item in archive.getmembers()
                          if item.isfile() and item.name.count("/") == 1
                          and item.name.endswith("/PKG-INFO")]
            if len(candidates) != 1:
                raise ValueError("sdist must contain exactly one top-level PKG-INFO")
            with archive.extractfile(candidates[0]) as stream:
                payload = stream.read()
    else:
        raise ValueError("expected a .whl or .tar.gz distribution")
    metadata = message_from_bytes(payload)
    if metadata["Name"] != "scaneval" or not metadata["Version"]:
        raise ValueError("artifact metadata must identify scaneval and its version")
    return metadata["Version"]


def run(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 180) -> None:
    completed = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    if completed.returncode:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise subprocess.CalledProcessError(completed.returncode, command)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="one built scaneval wheel or source archive")
    args = parser.parse_args()
    artifact = args.artifact.expanduser().resolve(strict=True)
    version = artifact_version(artifact)
    with tempfile.TemporaryDirectory(prefix="scaneval-package-smoke-") as directory:
        scratch = Path(directory)
        environment = scratch / "venv"
        work = scratch / "work"
        work.mkdir()
        venv.EnvBuilder(with_pip=True).create(environment)
        binaries = environment / ("Scripts" if os.name == "nt" else "bin")
        python = binaries / ("python.exe" if os.name == "nt" else "python")
        cli = binaries / ("scaneval.exe" if os.name == "nt" else "scaneval")
        env = dict(os.environ)
        for name in ("PYTHONPATH", "PYTHONHOME"):
            env.pop(name, None)
        env["PYTHONNOUSERSITE"] = "1"
        # Isolated pip ignores ambient install destinations, indexes and user configuration.
        run([str(python), "-I", "-m", "pip", "--isolated", "--disable-pip-version-check",
             "--no-input", "install", "--no-cache-dir", str(artifact)], cwd=work, env=env)
        run([str(python), "-I", "-c", OBSERVER_SMOKE, version], cwd=work, env=env, timeout=30)
        run([str(cli), "demo", "demo"], cwd=work, env=env, timeout=30)
        run([str(cli), "replay", "demo", "--output", "replay.json"], cwd=work, env=env, timeout=30)
        if (work / "demo" / "evaluation.json").read_bytes() != (work / "replay.json").read_bytes():
            raise AssertionError("installed CLI demo/replay produced different evaluation bytes")
    print(f"scaneval {version}: {artifact.name} passed isolated Observer, resources, and CLI demo/replay checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
