"""Execution backends: where a scanner's processes run, and what bounds them while they do.

Two backends exist. ``local`` runs every scanner process on the host as the operator, which is
what :func:`scaneval.execution.run_invocation` does when it is handed no backend at all; nothing is
enforced and the record says so. ``oci`` runs every scanner process in a fresh Docker container
created for that one process and removed after it (:mod:`scaneval.isolation.oci`), and records
the engine, the image, every setting, every mount, the network, and each container's outcome.
What that does and does not guarantee is stated in ``docs/THREAT_MODEL.md``.

The interface :func:`~scaneval.execution.run_invocation` relies on, which a backend provides:

- ``activate()``, a context manager in force while the adapter scans. Entering it runs the
  preflight and sets up whatever the scan needs, and it routes every
  :func:`~scaneval.adapters.base.run_command` of the scan through the backend
  (:func:`~scaneval.adapters.base.routed_through`). Leaving it tears down what entering created.
  A preflight that fails raises :class:`IsolationError` out of the ``with``, so the invocation is a
  recorded error carrying the refusal, never an empty scan and never a local fallback.
- ``run_command(...)``, with the signature of :func:`~scaneval.adapters.base.run_command`.
- ``isolation_record()``, the 2.1 isolation block, read after the scan so it can carry each
  container's outcome; ``backend``, ``enforced`` and ``note`` are always present.
- ``network_enforced``, true only when the declared network policy was actually enforced.
- ``close()``, which removes anything left behind and returns what it could not remove as
  messages; it never raises.

Selection is three steps, all here. :func:`resolve_execution` reads one system's ``execution``
block from a 2.1 run configuration into :class:`ExecutionSettings`, adding the checks the
contract cannot express. :func:`refusal_for` names why an adapter cannot run under the selected
backend: under ``oci`` that is every adapter not declaring ``oci_compatible``, which today is
``llm-harness`` and ``deepsec``, whose tools exist only as host installs and whose processes have
not been audited to go through the backend. :func:`backend_for` builds the backend for one
invocation, or returns ``None`` for ``local``. Nothing here ever turns a system configured for
``oci`` into a local run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any

from ..adapters.base import AdapterError


BACKENDS = ("local", "oci")
NETWORK_POLICIES = ("none", "model_provider_only", "unrestricted")
# The unprivileged user a scanner runs as unless the configuration names another: nobody:nogroup
# on Debian and Alpine alike, owning nothing on the host or in the image.
DEFAULT_USER = "65534:65534"
# One image reference pinned by content: name@sha256:<digest>, or a local image id. The same
# shape the run-config contract requires; repeated here for callers that build settings directly.
PINNED_IMAGE = re.compile(r"^(?:[^@\s]+@sha256:[0-9a-f]{64}|sha256:[0-9a-f]{64})$")
_USER = re.compile(r"^([0-9]+):([0-9]+)$")
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")
# A host name or an IPv4 literal as the egress proxy compares it; an IPv6 literal is bracketed.
_EGRESS_HOST = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*|\[[0-9A-Fa-f:.]+\])$")


class IsolationError(AdapterError):
    """An execution backend refused to run, or could not run, a scanner process.

    It is an :class:`~scaneval.adapters.base.AdapterError` so an adapter that reports its own
    setup failures reports this one the same way, and the invocation is recorded as a failure
    carrying the message. The message names the refusal; it never carries a credential value.
    """


@dataclass(frozen=True)
class Limits:
    """Resource limits for every container of one system. Memory includes the ``/tmp`` tmpfs."""

    memory_mb: int = 2048
    cpus: float = 2.0
    pids: int = 256
    tmpfs_mb: int = 256
    nofile: int = 4096


@dataclass(frozen=True)
class ExecutionSettings:
    """How one system's scanner processes run: the backend and everything it needs to hold them.

    ``egress`` is the exact ``(host, port)`` pairs the egress proxy forwards under
    ``model_provider_only``, and ``credentials`` the ``(environment variable, provider)`` pairs
    passed into the container by name. Nothing here holds a credential value.
    """

    backend: str
    network_policy: str
    image: str | None = None
    proxy_image: str | None = None
    egress: tuple[tuple[str, int], ...] = ()
    credentials: tuple[tuple[str, str], ...] = ()
    limits: Limits = field(default_factory=Limits)
    user: str = DEFAULT_USER

    @property
    def enforcing(self) -> bool:
        """Whether a backend other than the unenforced local one runs this system."""
        return self.backend != "local"


def resolve_execution(execution: dict[str, Any] | None, network_policy: str) -> ExecutionSettings:
    """Read one system's ``execution`` block into :class:`ExecutionSettings`, or refuse it.

    An absent block, and ``{"backend": "local"}``, is the local backend. Everything else must be
    ``oci`` with an image pinned by digest; ``model_provider_only`` also needs its egress and a
    pinned proxy image, and no other policy may carry either. Those are the contract's own rules,
    checked again because a caller can build settings without loading a document. Added here,
    because a schema cannot say them: the ``/tmp`` tmpfs counts against the memory limit, so it
    must be smaller than that limit; the user must not be root; an egress host must be a plain
    host name, an IPv4 literal, or a bracketed IPv6 literal; and a credential is named once.
    Every refusal is an :class:`IsolationError` naming the field.
    """
    if network_policy not in NETWORK_POLICIES:
        raise IsolationError(f"unknown network policy {network_policy!r}")
    if not execution:
        return ExecutionSettings("local", network_policy)
    backend = execution.get("backend")
    if backend not in BACKENDS:
        raise IsolationError(f"execution.backend must be one of {', '.join(BACKENDS)}, not {backend!r}")
    if backend == "local":
        extra = sorted(set(execution) - {"backend"})
        if extra:
            raise IsolationError(f"the local backend enforces nothing, so it takes no {', '.join(extra)}")
        return ExecutionSettings("local", network_policy)
    image = execution.get("image")
    if not isinstance(image, str) or not PINNED_IMAGE.match(image):
        raise IsolationError(f"execution.image must be an image pinned by digest, not {image!r}")
    proxy_image = execution.get("proxy_image")
    raw_egress = execution.get("egress") or []
    if network_policy == "model_provider_only":
        if not raw_egress:
            raise IsolationError("model_provider_only needs the egress it allows declared in execution.egress")
        if not isinstance(proxy_image, str) or not PINNED_IMAGE.match(proxy_image):
            raise IsolationError(
                f"model_provider_only needs execution.proxy_image pinned by digest, not {proxy_image!r}")
    elif raw_egress or proxy_image:
        raise IsolationError("execution.egress and execution.proxy_image apply only to model_provider_only")
    egress: list[tuple[str, int]] = []
    for index, entry in enumerate(raw_egress):
        host, port = (entry or {}).get("host"), (entry or {}).get("port")
        if not isinstance(host, str) or not _EGRESS_HOST.match(host) or len(host) > 253:
            raise IsolationError(f"execution.egress[{index}].host must be a host name or an IP literal, "
                                 f"not {host!r}")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise IsolationError(f"execution.egress[{index}].port must be an integer from 1 to 65535, "
                                 f"not {port!r}")
        pair = (host.lower(), port)
        if pair not in egress:
            egress.append(pair)
    credentials: list[tuple[str, str]] = []
    for index, entry in enumerate(execution.get("credentials") or []):
        name, provider = (entry or {}).get("env"), (entry or {}).get("provider")
        if not isinstance(name, str) or not _ENV_NAME.match(name):
            raise IsolationError(f"execution.credentials[{index}].env must name an environment "
                                 f"variable, not {name!r}")
        if not isinstance(provider, str) or not provider.strip():
            raise IsolationError(f"execution.credentials[{index}].provider must be stated")
        if any(name == seen for seen, _ in credentials):
            raise IsolationError(f"execution.credentials names {name} twice")
        credentials.append((name, provider))
    limits = _limits(execution.get("limits") or {})
    user = execution.get("user", DEFAULT_USER)
    match = _USER.match(user) if isinstance(user, str) else None
    if match is None:
        raise IsolationError(f"execution.user must be numeric uid:gid, not {user!r}")
    if int(match.group(1)) == 0:
        raise IsolationError("execution.user names uid 0; the oci backend runs a scanner as a "
                             "non-root user only")
    return ExecutionSettings("oci", network_policy, image=image,
                             proxy_image=proxy_image if network_policy == "model_provider_only" else None,
                             egress=tuple(egress), credentials=tuple(credentials), limits=limits, user=user)


def _limits(values: dict[str, Any]) -> Limits:
    """The configured limits over the defaults, each checked against the floor the engine needs."""
    defaults = Limits()
    unknown = sorted(set(values) - {"memory_mb", "cpus", "pids", "tmpfs_mb", "nofile"})
    if unknown:
        raise IsolationError(f"execution.limits has unknown field(s): {', '.join(unknown)}")
    chosen: dict[str, Any] = {}
    for name, floor in (("memory_mb", 64), ("pids", 16), ("tmpfs_mb", 1), ("nofile", 64)):
        value = values.get(name, getattr(defaults, name))
        if isinstance(value, bool) or not isinstance(value, int) or value < floor:
            raise IsolationError(f"execution.limits.{name} must be an integer of at least {floor}, not {value!r}")
        chosen[name] = value
    cpus = values.get("cpus", defaults.cpus)
    if isinstance(cpus, bool) or not isinstance(cpus, (int, float)) or not cpus > 0:
        raise IsolationError(f"execution.limits.cpus must be a positive number, not {cpus!r}")
    chosen["cpus"] = float(cpus)
    if chosen["tmpfs_mb"] >= chosen["memory_mb"]:
        raise IsolationError(
            f"execution.limits.tmpfs_mb ({chosen['tmpfs_mb']}) must be smaller than memory_mb "
            f"({chosen['memory_mb']}): what a scanner writes to /tmp is memory the same limit counts")
    return Limits(**chosen)


def refusal_for(adapter: Any, settings: ExecutionSettings) -> str | None:
    """Why *adapter* cannot run under *settings*' backend, or ``None`` when it can.

    The local backend runs anything. ``oci`` runs only an adapter declaring ``oci_compatible``,
    because anything else starts processes the backend would not hold or needs host installs no
    image carries. The refusal is decided before the adapter's preparation runs, so a refused
    system fetches nothing and touches nothing.
    """
    if settings.backend == "local" or getattr(adapter, "oci_compatible", False) is True:
        return None
    name = getattr(adapter, "name", type(adapter).__name__)
    return (f"the oci execution backend refuses adapter {name!r}: it is not oci_compatible, which "
            "means no audited Linux image runs its scanner and not every process it starts is known "
            "to go through the backend; the system was not invoked rather than run outside the "
            "boundary or on the host")


def backend_for(settings: ExecutionSettings, *, adapter: Any, spec: Any, preparation: dict,
                run_id: str, invocation_id: str, scratch_root: Path | None,
                protected: tuple[Path, ...] = (), runtime_roots: tuple[Path, ...] = ()) -> Any:
    """The backend for one invocation of a system, or ``None`` when the system runs locally.

    An ``oci`` backend owns a private scratch directory created here under *scratch_root* (the
    system temporary directory when that is ``None``); the invocation's workspace must be created
    inside its ``workspace_root``, and its ``close()`` must run after the invocation whatever
    happened. The adapter's declared state directories are read here; its runtime paths are asked
    for during the preflight, so a preparation they cannot be read from is a recorded refusal of
    the invocation rather than a failure of the run. *protected* directories (the run's output)
    may never overlap a mount, and a runtime path must sit strictly inside one of the
    *runtime_roots* (the source cache), so the cache itself is never mounted whole.
    """
    if settings.backend == "local":
        return None
    refusal = refusal_for(adapter, settings)
    if refusal is not None:
        raise IsolationError(refusal)
    from .oci import OciBackend

    return OciBackend(settings, run_id=run_id, invocation_id=invocation_id, scratch_root=scratch_root,
                      state_dirs=tuple(getattr(adapter, "state_dirs", ())),
                      runtime_mounts=lambda: adapter.runtime_mounts(spec, preparation),
                      protected=protected, runtime_roots=runtime_roots)


__all__ = ["BACKENDS", "DEFAULT_USER", "ExecutionSettings", "IsolationError", "Limits", "backend_for",
           "refusal_for", "resolve_execution"]
