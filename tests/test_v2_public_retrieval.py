import base64
import hashlib
import json
import http.client
import io
import socket
import threading
import types

import pytest

from scaneval.isolation import IsolationError, resolve_execution
from scaneval.isolation import public_retrieval as retrieval
from scaneval.isolation.oci import OciBackend
from scaneval.open_context_evidence import classify_condition


POLICY = {"policy": "recorded_public_v1", "allowed_origins": ["https://research.example"],
          "capture": "content", "retention": "bundle"}
IMAGE = "python@sha256:" + "a" * 64


def addresses(*ips):
    return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM,
             socket.IPPROTO_TCP, "", (ip, 443, 0, 0) if ":" in ip else (ip, 443)) for ip in ips]


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.169.254",
                                   "0.0.0.0", "100.100.100.200", "::1", "fe80::1", "fd00::1",
                                   "::ffff:8.8.8.8", "64:ff9b::a00:1"])
def test_private_local_metadata_and_translation_addresses_are_denied(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: addresses(ip))
    with pytest.raises(retrieval.RetrievalDenied):
        retrieval.public_addresses("research.example")


def test_mixed_answers_are_denied_and_validated_ip_is_pinned(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: addresses("8.8.8.8", "127.0.0.1"))
    with pytest.raises(retrieval.RetrievalDenied):
        retrieval.connect_public("research.example")
    resolutions = []
    def resolve(*_args, **_kwargs):
        resolutions.append(True)
        return addresses("8.8.8.8") if len(resolutions) == 1 else addresses("127.0.0.1")
    connected = []
    class Connection:
        def settimeout(self, _timeout): pass
        def connect(self, address): connected.append(address)
        def close(self): pass
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", lambda *_args: Connection())
    connection, checked, chosen = retrieval.connect_public("research.example")
    assert checked == ["8.8.8.8"] and chosen == "8.8.8.8"
    assert connected == [("8.8.8.8", 443)] and len(resolutions) == 1


def test_explicit_zero_port_is_denied_and_ipv6_literals_keep_port_443():
    with pytest.raises(retrieval.RetrievalDenied):
        retrieval.parse_url("https://research.example:0/")
    connection = retrieval.PublicHTTPS("2606:4700::1111", port=443)
    assert connection.host == "2606:4700::1111" and connection.port == 443


class Response:
    def __init__(self, status=200, body=b"public evidence", location=None):
        self.status, self.body, self.location = status, body, location
        self.closes = 0
    def getheader(self, _key): return self.location
    def read(self, limit): return self.body[:limit]
    def close(self): self.closes += 1


def transport(monkeypatch, responses, closed=None):
    requests = []
    class HTTPS:
        def __init__(self, host, **_kwargs):
            self.host = host
        def request(self, method, path, headers):
            checked = retrieval.public_addresses(self.host)
            self.validated_addresses = [item[3][0] for item in checked]
            self.connected_address = self.validated_addresses[0]
            requests.append((method, self.host, path, headers))
        def getresponse(self):
            result = responses.pop(0)
            if isinstance(result, BaseException): raise result
            return result
        def close(self):
            if closed is not None:
                closed.append(self.host)
    monkeypatch.setattr(retrieval, "PublicHTTPS", HTTPS)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *_args, **_kwargs:
                        addresses("127.0.0.1" if host == "private.example" else "8.8.8.8"))
    return requests


def test_preserved_fetch_and_real_search_url_have_complete_attempt_provenance(tmp_path, monkeypatch):
    requests = transport(monkeypatch, [Response(), Response()])
    recorder = retrieval.Recorder(str(tmp_path), {**POLICY, "search_endpoint": "https://research.example/search"})
    result = recorder.retrieve({"url": "https://research.example/advisory", "source": "browser_tool"})
    search = recorder.retrieve({"query": "repository vulnerable function"}, "search")
    assert result["outcome"] == "ok" and result["content_entered_model"] is None
    assert result["model_use_assurance"] == "unverifiable" and result["source"] == "browser_tool"
    assert result["source_assurance"] == "self_reported"
    assert base64.b64decode(result["content_base64"]) == b"public evidence"
    assert (tmp_path / result["content_path"]).read_bytes() == b"public evidence"
    assert (tmp_path / result["content_path"]).stat().st_mode & 0o777 == 0o644
    assert result["content_sha256"] == "sha256:" + hashlib.sha256(b"public evidence").hexdigest()
    assert result["started_at"] <= result["finished_at"]
    assert search["query"] == "repository vulnerable function" and "q=repository+vulnerable+function" in search["url"]
    assert len((tmp_path / "retrieval.jsonl").read_text().splitlines()) == 2
    assert all(set(headers) == {"User-Agent", "Accept-Encoding"} for *_, headers in requests)


def test_redirects_revalidate_private_dns_and_keep_denied_attempt(tmp_path, monkeypatch):
    requests = transport(monkeypatch, [Response(302, location="https://private.example/metadata")])
    recorder = retrieval.Recorder(str(tmp_path), {**POLICY,
        "allowed_origins": ["https://research.example", "https://private.example"]})
    result = recorder.retrieve({"url": "https://research.example/start"})
    assert result["outcome"] == "denied" and result["capture_status"] == "unavailable"
    assert len(result["redirect_chain"]) == 2 and result["redirect_chain"][0]["status"] == 302
    assert len(requests) == 1
    assert json.loads((tmp_path / "retrieval.jsonl").read_text())["outcome"] == "denied"
    assert result["redirect_chain"][-1]["resolved_addresses"] == ["127.0.0.1"]


def test_undeclared_and_credential_redirects_are_denied(tmp_path, monkeypatch):
    transport(monkeypatch, [Response(302, location="https://secret:token@research.example/next")])
    recorder = retrieval.Recorder(str(tmp_path), POLICY)
    denied = recorder.retrieve({"url": "https://undeclared.example/"})
    redirect = recorder.retrieve({"url": "https://research.example/start"})
    assert denied["outcome"] == "denied" and redirect["outcome"] == "denied"
    assert len(denied["redirect_chain"]) == 0
    assert "secret:token" not in (tmp_path / "retrieval.jsonl").read_text()
    assert redirect["redirect_chain"][0]["location"] == "https://[redacted]@research.example/next"


@pytest.mark.parametrize("url", ["https://user:credential-value@research.example/",
                                 "https://user:credential-\nvalue@research.example/",
                                 "https://user%3Acredential-value@research.example/",
                                 "https://user:credential-value@bad@research.example/"])
def test_denied_url_userinfo_never_enters_capture_or_returned_provenance(tmp_path, url):
    recorder = retrieval.Recorder(str(tmp_path), POLICY)
    result = recorder.retrieve({"url": url})
    assert result["outcome"] == "denied" and result["capture_status"] == "unavailable"
    assert "credential-value" not in json.dumps(result) and "credential-\\nvalue" not in json.dumps(result)
    assert "credential-value" not in (tmp_path / "retrieval.jsonl").read_text()
    assert "credential-\\nvalue" not in (tmp_path / "retrieval.jsonl").read_text()


def test_failures_http_errors_and_hash_only_capture_are_not_empty_success(tmp_path, monkeypatch):
    transport(monkeypatch, [TimeoutError("fixture"), Response(503, b"retry"), Response()])
    recorder = retrieval.Recorder(str(tmp_path), {**POLICY, "capture": "hashes", "retention": "hashes_only"})
    failed = recorder.retrieve({"url": "https://research.example/timeout"})
    error = recorder.retrieve({"url": "https://research.example/unavailable"})
    hashed = recorder.retrieve({"url": "https://research.example/ok"})
    assert failed["outcome"] == "failed" and failed["capture_status"] == "unavailable"
    assert error["outcome"] == "http_error" and error["content_sha256"]
    assert hashed["capture_status"] == "hash_only" and hashed["content_path"] is None
    assert not (tmp_path / "content").exists()


def test_real_http_response_truncated_content_length_is_not_preserved_as_success(tmp_path, monkeypatch):
    class Wire:
        def makefile(self, *_args, **_kwargs):
            return io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nfragment")
    response = http.client.HTTPResponse(Wire())
    response.begin()
    transport(monkeypatch, [response])
    recorder = retrieval.Recorder(str(tmp_path), POLICY)
    event = recorder.retrieve({"url": "https://research.example/truncated"})
    assert event["outcome"] == "failed" and event["error"] == "IncompleteRead"
    assert event["capture_status"] == "unavailable" and event["content_base64"] is None
    assert event["content_sha256"] is None and not (tmp_path / "content").exists()


def test_partial_capture_write_leaves_no_fragment_and_returns_no_content(tmp_path, monkeypatch):
    transport(monkeypatch, [Response()])
    recorder = retrieval.Recorder(str(tmp_path), POLICY)
    original = retrieval.os.fdopen
    class FullDisk:
        def __init__(self, stream): self.stream = stream
        def __enter__(self): return self
        def __exit__(self, *_args): self.stream.close()
        def write(self, data):
            self.stream.write(data[:3])
            raise OSError("fixture full disk")
    monkeypatch.setattr(retrieval.os, "fdopen", lambda *args: FullDisk(original(*args)))
    event = recorder.retrieve({"url": "https://research.example/"})
    assert event["outcome"] == "failed" and event["capture_status"] == "unavailable"
    assert event["capture_error"] == "OSError" and event["content_base64"] is None
    assert event["content_path"] is None
    assert list((tmp_path / "content").iterdir()) == []


def test_existing_corrupt_digest_file_is_replaced_only_by_complete_content(tmp_path, monkeypatch):
    transport(monkeypatch, [Response()])
    recorder = retrieval.Recorder(str(tmp_path), POLICY)
    content = tmp_path / "content"
    content.mkdir()
    path = content / (hashlib.sha256(b"public evidence").hexdigest() + ".bin")
    path.write_bytes(b"old truncated fragment")
    event = recorder.retrieve({"url": "https://research.example/"})
    assert event["capture_status"] == "preserved" and path.read_bytes() == b"public evidence"


def test_failed_tls_keeps_checked_and_connected_address_provenance(tmp_path, monkeypatch):
    transport(monkeypatch, [retrieval.ssl.SSLCertVerificationError("fixture")])
    recorder = retrieval.Recorder(str(tmp_path), POLICY)
    event = recorder.retrieve({"url": "https://research.example/"})
    assert event["outcome"] == "failed"
    assert event["redirect_chain"][0]["resolved_addresses"] == ["8.8.8.8"]
    assert event["redirect_chain"][0]["connected_address"] == "8.8.8.8"


def test_failed_connect_keeps_checked_addresses_without_claiming_connected_peer(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: addresses("8.8.8.8"))
    class Offline:
        def settimeout(self, _timeout): pass
        def connect(self, _address): raise TimeoutError("fixture")
        def close(self): pass
    monkeypatch.setattr(socket, "socket", lambda *_args: Offline())
    connection = retrieval.PublicHTTPS("research.example", port=443)
    with pytest.raises(TimeoutError):
        connection.connect()
    assert connection.resolved_addresses == ["8.8.8.8"]
    assert connection.attempted_addresses == ["8.8.8.8"] and connection.connected_address is None


def test_real_https_connect_preserves_peer_when_tls_verification_fails(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: addresses("8.8.8.8"))
    class Connected:
        def settimeout(self, _timeout): pass
        def connect(self, _address): pass
        def close(self): pass
    class RejectCertificate:
        def wrap_socket(self, *_args, **_kwargs):
            raise retrieval.ssl.SSLCertVerificationError("fixture")
    monkeypatch.setattr(socket, "socket", lambda *_args: Connected())
    connection = retrieval.PublicHTTPS("research.example", port=443)
    connection._context = RejectCertificate()
    with pytest.raises(retrieval.ssl.SSLCertVerificationError):
        connection.connect()
    assert connection.resolved_addresses == ["8.8.8.8"] and connection.connected_address == "8.8.8.8"


def test_incomplete_request_headers_have_a_timeout_before_do_post(monkeypatch):
    monkeypatch.setattr(retrieval.Handler, "timeout", 0.05)
    client, server = socket.socketpair()
    with client, server:
        client.sendall(b"POST /fetch HTTP/1.1\r\nHost: incomplete")
        thread = threading.Thread(target=lambda: retrieval.Handler(server, ("127.0.0.1", 0), object()), daemon=True)
        thread.start()
        thread.join(1)
        assert not thread.is_alive(), "incomplete headers held a retrieval thread after its deadline"


def test_public_research_configuration_requires_enforcement_and_safe_explicit_policy():
    with pytest.raises(IsolationError, match="oci"):
        resolve_execution(None, "public_research")
    settings = {"backend": "oci", "image": IMAGE, "proxy_image": IMAGE,
                "egress": [{"host": "api.example", "port": 443}], "retrieval": POLICY}
    assert resolve_execution(settings, "public_research").retrieval["policy"] == "recorded_public_v1"
    with pytest.raises(IsolationError, match="stale"):
        resolve_execution({**settings, "retrieval": {**POLICY, "policy": "old"}}, "public_research")
    with pytest.raises(IsolationError, match="HTTPS port 443"):
        resolve_execution({**settings, "egress": [{"host": "api.example", "port": 8080}]}, "public_research")
    with pytest.raises(IsolationError, match="cannot override"):
        resolve_execution({**settings, "credentials": [{"env": "GIT_CONFIG_GLOBAL", "provider": "fixture"}]}, "public_research")


def test_idna_evaluator_denials_apply_to_fetch_and_search_configuration(tmp_path):
    settings = {**POLICY, "allowed_origins": ["https://bücher.example"],
                "denied_hosts": ["BÜCHER.EXAMPLE."]}
    normalized = retrieval.validate_settings(settings)
    assert normalized["denied_hosts"] == ["xn--bcher-kva.example"]
    recorder = retrieval.Recorder(str(tmp_path), settings)
    assert recorder.retrieve({"url": "https://xn--bcher-kva.example/"})["outcome"] == "denied"
    with pytest.raises(retrieval.RetrievalDenied, match="declared, allowed"):
        retrieval.validate_settings({**settings, "search_endpoint": "https://bücher.example/search"})


def test_attempt_journal_is_flushed_before_dns_or_transport(tmp_path, monkeypatch):
    transport(monkeypatch, [Response()])
    recorder = retrieval.Recorder(str(tmp_path), POLICY)
    seen = []
    def resolve(*_args, **_kwargs):
        starts = [json.loads(line) for line in (tmp_path / "retrieval-started.jsonl").read_text().splitlines()]
        assert len(starts) == 1 and starts[0]["url"] == "https://research.example/"
        seen.append(starts[0]["id"])
        return addresses("8.8.8.8")
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    event = recorder.retrieve({"url": "https://research.example/"})
    assert seen == [event["id"]]


@pytest.mark.parametrize("value,expected", [
    ("https://research.example/a?next=//x@y", None),
    ("https://research.example/p/https://u@host/x", None),
    ("https://research.example/a#//x@y", None),
    ("/login?next=//a@b", None),
    ("login?next=https://a@b", None),
    ("https://research.example", None),
    ("https://user:pw@research.example/x?next=//a@b", "https://[redacted]@research.example/x?next=//a@b"),
    ("https://user:a@b@research.example/", "https://[redacted]@research.example/"),
    ("https://user:pw@research.example#f@x", "https://[redacted]@research.example#f@x"),
    ("https://user:pw@research.example", "https://[redacted]@research.example"),
    ("https://user\\pw@research.example/", "https://[redacted]@research.example/"),
    ("//user:pw@research.example/next?u=//a@b", "//[redacted]@research.example/next?u=//a@b"),
    (" https://user:pw@research.example/", " https://[redacted]@research.example/"),
    ("\x01\t//user:pw@research.example/", "\x01\t//[redacted]@research.example/"),
    ("ht tps://user:pw@research.example/", "ht tps://[redacted]@research.example/"),
    ("https://user:p\nw@research.example/", "https://[redacted]@research.example/"),
    ("https:\t//user:pw@research.example/", "https:\t//[redacted]@research.example/"),
    ("https:/\x7f/user:pw@research.example/", "https:/\x7f/[redacted]@research.example/"),
    ("ht\x01tps://user:pw@research.example/", "ht\x01tps://[redacted]@research.example/"),
    ("https\x0b://user:pw@research.example/", "https\x0b://[redacted]@research.example/"),
    ("https:// user:pw@research.example/", "https://[redacted]@research.example/"),
    ("https://user:pw@\x00research.example/", "https://[redacted]@\x00research.example/"),
    ("/\t/user:pw@research.example/", "/\t/[redacted]@research.example/"),
    ("1https:\t//user:pw@research.example/", "1https:\t//[redacted]@research.example/"),
    ("https://@research.example/", "https://[redacted]@research.example/"),
    ("https://[redacted]@research.example/", "https://[redacted]@research.example/"),
    ("https:\t/\t/research.example/a?next=https://x@y", None),
    ("/a\t/b?next=//x@y", None),
])
def test_only_outer_authority_userinfo_is_redacted(value, expected):
    assert retrieval.recorded_url(value) == (value if expected is None else expected)
    assert retrieval.recorded_url(None) is None


@pytest.mark.parametrize("value,span", [
    ("https://@research.example/", (8, 9)),
    ("https://[redacted]@research.example/", (8, 19)),
    ("https:\t//user:pw@research.example/", (9, 17)),
    ("\x01//u@research.example/", (3, 5)),
    ("https://research.example/a?next=//x@y", None),
    ("/login?next=//a@b", None),
    (None, None),
])
def test_outer_userinfo_presence_is_an_original_span_even_when_empty_or_placeholder(value, span):
    assert retrieval._outer_userinfo(value) == span


class WireFile(io.RawIOBase):
    """Unbuffered socket-file double that releases its socket reference exactly once."""
    def __init__(self, wire):
        self.wire = wire
        wire.io_refs += 1
    def readable(self): return True
    def readinto(self, buffer):
        """Deliver the next scripted (delay, bytes) item, honoring the socket timeout in force."""
        self.wire.reads += 1
        if not self.wire.script:
            return 0
        delay, data = self.wire.script.pop(0)
        timeout = self.wire.timeouts[-1] if self.wire.timeouts else retrieval.TIMEOUT
        if delay > timeout:
            self.wire.clock[0] += timeout
            self.wire.script.insert(0, (delay - timeout, data))
            raise TimeoutError("timed out")
        self.wire.clock[0] += delay
        size = min(len(buffer), len(data))
        buffer[:size] = data[:size]
        if data[size:]:
            self.wire.script.insert(0, (0, data[size:]))
        return size
    def close(self):
        if not self.closed:
            self.wire.io_refs -= 1
            self.wire.file_closes += 1
        super().close()


class Wire:
    """The connected TLS socket double: scripted response bytes behind the real HTTP parser."""
    def __init__(self, script, clock=None):
        self.script = [item if isinstance(item, tuple) else (0, item) for item in script]
        self.sent, self.timeouts, self.clock = b"", [], clock if clock is not None else [0.0]
        self.io_refs = self.closed = self.file_closes = self.reads = 0
    def settimeout(self, value): self.timeouts.append(value)
    def sendall(self, data): self.sent += data
    def makefile(self, mode, buffering=None):
        assert mode == "rb"
        raw = WireFile(self)
        return raw if buffering == 0 else io.BufferedReader(raw)
    def close(self): self.closed += 1


def open_files(wire):
    return wire.io_refs if isinstance(wire, Wire) else wire._io_refs


def real_transport(monkeypatch, *scripts, clock=None, connect_delay=0):
    """Run the actual PublicHTTPS, address validation, and HTTPResponse over scripted TLS sockets.

    A script is response bytes, a list of bytes or (virtual delay, bytes) reads, or an already
    connected real socket. With *clock*, monotonic time is virtual and advances only by delays.
    """
    class Transported(list):
        """Connected sockets in order, plus the socket timeout each TLS handshake started with."""
    wires = Transported()
    wires.handshakes = handshakes = []
    wires.prior_open_files = []
    pending = [script if isinstance(script, socket.socket) else
               Wire(script if isinstance(script, list) else [script], clock) for script in scripts]
    class TCP:
        def __init__(self):
            self.timeouts = []
        def settimeout(self, value): self.timeouts.append(value)
        def connect(self, _address):
            if clock is not None:
                clock[0] += connect_delay
        def close(self): pass
    original = retrieval.ssl.create_default_context
    def context():
        verified = original()
        def wrap_socket(sock, server_hostname):
            assert server_hostname and verified.verify_mode == retrieval.ssl.CERT_REQUIRED
            handshakes.append(sock.timeouts[-1])
            # Earlier hops must already have released their socket files before the next starts.
            wires.prior_open_files.append(sum(open_files(wire) for wire in wires))
            wires.append(pending.pop(0))
            return wires[-1]
        verified.wrap_socket = wrap_socket
        return verified
    if clock is not None:
        # Only the retrieval module's clock is virtual; other code keeps real monotonic time.
        monkeypatch.setattr(retrieval, "time", types.SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(retrieval.ssl, "create_default_context", context)
    monkeypatch.setattr(socket, "socket", lambda *_args: TCP())
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *_args, **_kwargs:
                        addresses("127.0.0.1" if host == "private.example" else "8.8.8.8"))
    return wires


def http_bytes(status, body=b"", **headers):
    lines = [f"HTTP/1.1 {status} Fixture"] + [f"{key.replace('_', '-')}: {value}" for key, value in headers.items()]
    return ("\r\n".join(lines + [f"Content-Length: {len(body)}", "", ""])).encode() + body


OPEN_POLICY = {"history": "ancestor_history_v1", "retrieval": "recorded_public_v1", "web_mode": "live",
               "capture": "content", "retention": "bundle"}


def capture_and_classify(tmp_path, logs):
    """Collect the proxy journals with the real OCI capture and recompute the condition from them."""
    settings = resolve_execution({"backend": "oci", "image": IMAGE, "proxy_image": IMAGE,
                                  "egress": [{"host": "api.example", "port": 443}], "retrieval": POLICY},
                                 "public_research")
    backend = OciBackend(settings, run_id="fixture", invocation_id="retrieval", scratch_root=tmp_path)
    workspace = backend.workspace_root / "scaneval-trial-retrieval"
    (workspace / "source").mkdir(parents=True)
    (workspace / "raw").mkdir()
    backend._proxy = {"log_dir": logs}
    try:
        summary = backend._capture_retrieval()
        assert summary["events_path"] and summary["attempts_path"], summary["gaps"]
        execution = {"provenance": {"mode": "full", "profile": "standard", "tree_hash": "sha256:" + "a" * 64},
                     "network_policy": {"declared": "public_research", "enforced": False},
                     "isolation": {"backend": "oci", "enforced": False, "containers": [], "retrieval": summary}}
        condition = classify_condition(workspace, execution, OPEN_POLICY, {})
        saved = b"".join((workspace / summary[key]).read_bytes() for key in ("events_path", "attempts_path"))
    finally:
        backend._proxy = None
        assert backend.close() == []
    return summary, condition, saved


def test_nested_urls_and_relative_redirects_keep_recorded_hops_classifiable(tmp_path, monkeypatch):
    wires = real_transport(monkeypatch, http_bytes(200, b"query"), http_bytes(200, b"path"),
                           http_bytes(302, Location="/login?next=//a@b"), http_bytes(200, b"login"),
                           http_bytes(301, Location="//research.example/final?u=https://c@d"),
                           http_bytes(200, b"final"))
    logs = tmp_path / "proxy-log"
    logs.mkdir()
    recorder = retrieval.Recorder(str(logs), POLICY)
    urls = ["https://research.example/a?next=//x@y", "https://research.example/p/https://u@host/x",
            "https://research.example/start", "https://research.example/hop"]
    results = [recorder.retrieve({"url": url}) for url in urls]
    assert [result["outcome"] for result in results] == ["ok"] * 4
    assert [result["url"] for result in results] == urls
    assert results[2]["redirect_chain"][0]["location"] == "/login?next=//a@b"
    assert results[2]["redirect_chain"][1]["url"] == "https://research.example/login?next=//a@b"
    assert results[3]["redirect_chain"][1]["url"] == "https://research.example/final?u=https://c@d"
    assert b"GET /p/https://u@host/x HTTP/1.1" in wires[1].sent
    summary, condition, _saved = capture_and_classify(tmp_path, logs)
    assert summary["capture_status"] == "recorded" and summary["preserved"] == 4
    assert condition["retrieval"] == "recorded", condition["reasons"]
    assert not any(reason["code"] == "retrieval_artifact_mismatch" for reason in condition["reasons"])


def test_outer_credentials_stay_redacted_and_denied_through_capture_and_classification(tmp_path, monkeypatch):
    real_transport(monkeypatch, http_bytes(302, Location="//user:outer-secret@research.example/next"),
                   http_bytes(302, Location="https://user:outer-secret@research.example/next?u=//a@b"))
    logs = tmp_path / "proxy-log"
    logs.mkdir()
    recorder = retrieval.Recorder(str(logs), POLICY)
    attempts = ["https://user:outer-secret@research.example/", " https://user:outer-secret@research.example/",
                "\x01https://user:outer-secret@research.example/", "ht tps://user:outer-secret@research.example/",
                "//user:outer-secret@research.example/", "https://user:outer\nsecret@research.example/"]
    results = [recorder.retrieve({"url": url}) for url in attempts]
    redirects = [recorder.retrieve({"url": "https://research.example/" + name}) for name in ("relative", "absolute")]
    assert all(result["outcome"] == "denied" for result in results + redirects)
    assert all("[redacted]@research.example/" in result["url"] for result in results)
    assert redirects[0]["redirect_chain"][0]["location"] == "//[redacted]@research.example/next"
    assert redirects[1]["redirect_chain"][0]["location"] == "https://[redacted]@research.example/next?u=//a@b"
    returned = json.dumps(results + redirects)
    summary, condition, saved = capture_and_classify(tmp_path, logs)
    for evidence in (returned, (logs / retrieval.EVENTS).read_text(), (logs / retrieval.STARTED).read_text(),
                     saved.decode()):
        assert "outer-secret" not in evidence and "outer\\nsecret" not in evidence
    assert summary["capture_status"] == "recorded" and summary["denied"] == len(attempts) + 2
    assert condition["retrieval"] == "recorded", condition["reasons"]
    assert not any(reason["code"] == "retrieval_artifact_mismatch" for reason in condition["reasons"])


@pytest.mark.parametrize("control", ["\t", " ", "\x00", "\x01", "\x0b", "\x1f", "\x7f"])
def test_controls_anywhere_in_the_outer_prefix_cannot_expose_credentials(tmp_path, monkeypatch, control):
    secret = "synthetic-secret"
    prefixes = [control + "https://", "ht" + control + "tps://", "https" + control + "://",
                "https:" + control + "//", "https:/" + control + "/", "https://" + control,
                "1https:" + control + "//", control + "//", "/" + control + "/"]
    attempts = [prefix + "user:" + secret + "@research.example/" for prefix in prefixes]
    logs = tmp_path / "proxy-log"
    logs.mkdir()
    recorder = retrieval.Recorder(str(logs), POLICY)
    observed = recording(monkeypatch, recorder)
    results = [recorder.retrieve({"url": url}) for url in attempts]
    assert [result["outcome"] for result in results] == ["denied"] * len(attempts)
    assert all(result["redirect_chain"] == [] for result in results)
    for prefix, result in zip(prefixes, results):
        # Only the userinfo is replaced: the malformed prefix and the rest stay as attempted.
        assert result["url"] == prefix[:prefix.rindex("/") + 1] + "[redacted]@research.example/"
    starts = [json.loads(line) for line in (logs / retrieval.STARTED).read_text().splitlines()]
    assert [start["url"] for start in starts] == [result["url"] for result in results]
    assert [event["url"] for event in observed] == [result["url"] for result in results]
    summary, condition, saved = capture_and_classify(tmp_path, logs)
    for evidence in (json.dumps(results), (logs / retrieval.EVENTS).read_text(),
                     (logs / retrieval.STARTED).read_text(), saved.decode()):
        assert secret not in evidence
    assert summary["capture_status"] == "recorded" and summary["denied"] == len(attempts)
    assert condition["retrieval"] == "recorded", condition["reasons"]


def test_trickling_body_cannot_reset_the_retrieval_budget(tmp_path, monkeypatch):
    clock = [0.0]
    class Trickle(Response):
        length = None
        def read1(self, _limit):
            clock[0] = 61.0
            return b"fragment"
    transport(monkeypatch, [Trickle()])
    monkeypatch.setattr(retrieval.time, "monotonic", lambda: clock[0])
    event = retrieval.Recorder(str(tmp_path), POLICY).retrieve({"url": "https://research.example/"})
    assert event["outcome"] == "failed" and event["error"] == "TimeoutError"
    assert event["content_base64"] is None and event["capture_status"] == "unavailable"


def recording(monkeypatch, recorder):
    """Observe how many socket files remain open at the moment the terminal event is journaled."""
    observed = []
    original = recorder.write
    def write(event):
        observed.append(event)
        original(event)
    monkeypatch.setattr(recorder, "write", write)
    return observed


@pytest.mark.parametrize("phase", ["status_and_headers", "interim_continue"])
def test_slow_response_head_cannot_outlast_the_total_deadline(tmp_path, monkeypatch, phase):
    clock = [0.0]
    if phase == "status_and_headers":
        script = [(19, b"HTTP/1.1 200 OK\r\n"), (19, b"X-One: 1\r\n"), (19, b"X-Two: 2\r\n"),
                  (19, b"X-Three: 3\r\n"), (0, b"Content-Length: 2\r\n\r\nok")]
    else:
        script = [(19, b"HTTP/1.1 100 Continue\r\n\r\n")] * 4 + [(0, http_bytes(200, b"ok"))]
    # Every read is inside the 20-second per-read timeout; only the total budget can stop this.
    wires = real_transport(monkeypatch, script, clock=clock)
    logs = tmp_path / "proxy-log"
    logs.mkdir()
    recorder = retrieval.Recorder(str(logs), POLICY)
    journaled = recording(monkeypatch, recorder)
    event = recorder.retrieve({"url": "https://research.example/slow"})
    assert event["outcome"] == "failed" and event["error"] == "TimeoutError"
    assert clock[0] == 60.0 and wires[0].timeouts[-1] == pytest.approx(3.0)
    assert wires[0].script, "bytes after the deadline must never reach the parser"
    assert event["redirect_chain"][0]["status"] is None
    assert event["redirect_chain"][0]["connected_address"] == "8.8.8.8"
    assert wires[0].io_refs == 0 and wires[0].file_closes == 1 and wires[0].closed
    assert [item["id"] for item in journaled] == [event["id"]]
    summary, condition, _saved = capture_and_classify(tmp_path, logs)
    assert summary["capture_status"] == "recorded" and summary["incomplete_attempts"] == 0
    assert summary["failed"] == 1 and condition["retrieval"] == "recorded", condition["reasons"]
    assert not any(reason["code"] == "retrieval_artifact_mismatch" for reason in condition["reasons"])


def test_already_buffered_interim_responses_observe_the_same_deadline(monkeypatch):
    queued = b"HTTP/1.1 100 Continue\r\n\r\n" * 20 + http_bytes(200, b"ok")
    clock = [0.0]
    monkeypatch.setattr(retrieval, "time", types.SimpleNamespace(monotonic=lambda: clock[0]))
    connection = retrieval.PublicHTTPS("research.example", port=443)
    connection.deadline = 60.0
    control = Wire([queued])
    response = connection.response_class(control, method="GET")
    response.begin()
    assert response.status == 200 and response.read() == b"ok"
    response.close()
    assert control.io_refs == 0 and control.file_closes == 1
    def ticking():
        clock[0] += 4.0  # Parsing queued bytes takes time but performs no further socket read.
        return clock[0]
    monkeypatch.setattr(retrieval, "time", types.SimpleNamespace(monotonic=ticking))
    clock[0] = 0.0
    wire = Wire([queued])
    response = connection.response_class(wire, method="GET")
    with pytest.raises(TimeoutError):
        response.begin()
    assert wire.reads == 1, "the deadline must stop parsing of already buffered responses"
    response.close()
    assert wire.io_refs == 0 and wire.file_closes == 1


@pytest.mark.parametrize("operation,args", [("read", (2,)), ("read1", (2,)), ("readinto", (bytearray(2),)),
                                            ("readinto1", (bytearray(2),)), ("readline", ()), ("peek", (1,))])
def test_every_buffered_read_operation_checks_the_deadline(monkeypatch, operation, args):
    clock = [0.0]
    monkeypatch.setattr(retrieval, "time", types.SimpleNamespace(monotonic=lambda: clock[0]))
    connection = retrieval.PublicHTTPS("research.example", port=443)
    connection.deadline = 60.0
    wire = Wire([b"ab\ncd\nef\n"])
    response = connection.response_class(wire, method="GET")
    stream = response.fp
    assert getattr(stream, operation)(*args)
    clock[0] = 60.0
    with pytest.raises(TimeoutError):
        getattr(stream, operation)(*args)
    assert wire.reads == 1
    response.close()
    response.close()
    assert stream.closed and wire.io_refs == 0 and wire.file_closes == 1


def test_fast_real_responses_keep_framing_size_limits_and_read_timeouts(tmp_path, monkeypatch):
    clock = [0.0]
    chunked = [b"HTTP/1.1 100 Continue\r\n\r\n", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
               b"lo\r\n6\r\n world\r\n0\r\n\r\n"]
    wires = real_transport(monkeypatch, chunked, http_bytes(200, b"x" * (retrieval.MAX_RESPONSE + 1)),
                           b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nfragment", clock=clock)
    recorder = retrieval.Recorder(str(tmp_path), POLICY)
    ok, large, truncated = (recorder.retrieve({"url": "https://research.example/" + name})
                            for name in ("chunked", "large", "truncated"))
    assert ok["outcome"] == "ok" and base64.b64decode(ok["content_base64"]) == b"hello world"
    assert ok["capture_status"] == "preserved"
    assert large["outcome"] == "denied" and "retained-content limit" in large["error"]
    assert truncated["outcome"] == "failed" and truncated["error"] == "IncompleteRead"
    assert wires.handshakes == [20, 20, 20]
    for wire in wires:
        assert wire.timeouts and set(wire.timeouts) == {20}
        assert wire.io_refs == 0 and wire.file_closes == 1 and wire.closed


@pytest.mark.parametrize("connect_delay", [50, 60])
def test_tls_handshake_gets_only_the_remaining_budget(tmp_path, monkeypatch, connect_delay):
    clock = [0.0]
    wires = real_transport(monkeypatch, http_bytes(200, b"ok"), clock=clock, connect_delay=connect_delay)
    event = retrieval.Recorder(str(tmp_path), POLICY).retrieve({"url": "https://research.example/"})
    hop = event["redirect_chain"][0]
    assert hop["connected_address"] == "8.8.8.8" and hop["attempted_addresses"] == ["8.8.8.8"]
    if connect_delay == 50:
        assert event["outcome"] == "ok" and wires.handshakes == [10]
        assert set(wires[0].timeouts) == {10}
    else:
        assert event["outcome"] == "failed" and event["error"] == "TimeoutError"
        assert len(wires) == 0, "an exhausted budget must refuse before the TLS handshake"
        assert json.loads((tmp_path / retrieval.EVENTS).read_text())["outcome"] == "failed"


def test_detached_and_persistent_responses_release_socket_files_every_hop(tmp_path, monkeypatch):
    detached = b"HTTP/1.1 302 Found\r\nLocation: /next\r\nConnection: close\r\nContent-Length: 20\r\n\r\nunread"
    persistent = b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 20\r\n\r\nunread"
    wires = real_transport(monkeypatch, detached, persistent, http_bytes(200, b"done"))
    recorder = retrieval.Recorder(str(tmp_path), POLICY)
    journaled = recording(monkeypatch, recorder)
    event = recorder.retrieve({"url": "https://research.example/start"})
    assert event["outcome"] == "ok" and [hop["status"] for hop in event["redirect_chain"]] == [302, 302, 200]
    assert wires.prior_open_files == [0, 0, 0]
    assert len(journaled) == 1
    for wire in wires:
        assert wire.io_refs == 0 and wire.file_closes == 1 and wire.closed


def test_detached_body_timeout_releases_its_file_before_the_failure_is_journaled(tmp_path, monkeypatch):
    clock = [0.0]
    head = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 10\r\n\r\n"
    wires = real_transport(monkeypatch, [head, (70, b"0123456789")], clock=clock)
    recorder = retrieval.Recorder(str(tmp_path), POLICY)
    open_at_completion = []
    original = recorder.write
    def write(event):
        open_at_completion.append(open_files(wires[0]))
        original(event)
    monkeypatch.setattr(recorder, "write", write)
    event = recorder.retrieve({"url": "https://research.example/"})
    assert event["outcome"] == "failed" and event["error"] == "TimeoutError"
    assert event["content_base64"] is None and event["capture_status"] == "unavailable"
    assert open_at_completion == [0] and wires[0].file_closes == 1 and wires[0].closed


def test_real_socket_file_of_a_detached_unread_redirect_is_really_closed(tmp_path, monkeypatch):
    first, first_peer = socket.socketpair()
    second, second_peer = socket.socketpair()
    with first_peer, second_peer:
        first_peer.sendall(b"HTTP/1.1 302 Found\r\nLocation: /next\r\nConnection: close\r\n"
                           b"Content-Length: 64\r\n\r\npartial")
        second_peer.sendall(http_bytes(200, b"done"))
        wires = real_transport(monkeypatch, first, second)
        recorder = retrieval.Recorder(str(tmp_path), POLICY)
        released = []
        original = recorder.write
        def write(event):
            released.append([(sock._io_refs, sock.fileno()) for sock in (first, second)])
            original(event)
        monkeypatch.setattr(recorder, "write", write)
        event = recorder.retrieve({"url": "https://research.example/start"})
    assert event["outcome"] == "ok" and base64.b64decode(event["content_base64"]) == b"done"
    assert wires.prior_open_files == [0, 0]
    assert released == [[(0, -1), (0, -1)]], "socket files must be closed, not left to garbage collection"


def test_response_close_failure_still_closes_the_connection_and_records_failure(tmp_path, monkeypatch):
    class Unclosable(Response):
        def close(self):
            super().close()
            raise OSError("fixture close failure")
    closed = []
    normal, failing = Response(), Unclosable(302, location="/next")
    transport(monkeypatch, [normal, failing], closed)
    recorder = retrieval.Recorder(str(tmp_path), POLICY)
    assert recorder.retrieve({"url": "https://research.example/"})["outcome"] == "ok"
    assert normal.closes == 1 and closed == ["research.example"]
    event = recorder.retrieve({"url": "https://research.example/redirect"})
    assert failing.closes == 1 and closed == ["research.example"] * 2
    assert event["outcome"] == "failed" and event["error"] == "OSError"
    assert json.loads((tmp_path / retrieval.EVENTS).read_text().splitlines()[-1])["id"] == event["id"]
