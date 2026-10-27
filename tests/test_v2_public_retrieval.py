import base64
import hashlib
import json
import http.client
import io
import socket
import threading

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
    def getheader(self, _key): return self.location
    def read(self, limit): return self.body[:limit]


def transport(monkeypatch, responses):
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
        def close(self): pass
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
])
def test_only_outer_authority_userinfo_is_redacted(value, expected):
    assert retrieval.recorded_url(value) == (value if expected is None else expected)
    assert retrieval.recorded_url(None) is None


class WireFile(io.RawIOBase):
    """Unbuffered socket-file double that releases its socket reference exactly once."""
    def __init__(self, wire):
        self.wire = wire
        wire.io_refs += 1
    def readable(self): return True
    def readinto(self, buffer):
        if not self.wire.script:
            return 0
        data = self.wire.script.pop(0)
        size = min(len(buffer), len(data))
        buffer[:size] = data[:size]
        if data[size:]:
            self.wire.script.insert(0, data[size:])
        return size
    def close(self):
        if not self.closed:
            self.wire.io_refs -= 1
        super().close()


class Wire:
    """The connected TLS socket double: scripted response bytes behind the real HTTP parser."""
    def __init__(self, script):
        self.script, self.sent, self.timeouts = list(script), b"", []
        self.io_refs = self.closed = 0
    def settimeout(self, value): self.timeouts.append(value)
    def sendall(self, data): self.sent += data
    def makefile(self, mode, buffering=None):
        assert mode == "rb"
        raw = WireFile(self)
        return raw if buffering == 0 else io.BufferedReader(raw)
    def close(self): self.closed += 1


def real_transport(monkeypatch, *scripts):
    """Run the actual PublicHTTPS, address validation, and HTTPResponse over scripted TLS sockets."""
    wires = []
    pending = [Wire(script if isinstance(script, list) else [script]) for script in scripts]
    class TCP:
        def settimeout(self, _value): pass
        def connect(self, _address): pass
        def close(self): pass
    original = retrieval.ssl.create_default_context
    def context():
        verified = original()
        def wrap_socket(_sock, server_hostname):
            assert server_hostname and verified.verify_mode == retrieval.ssl.CERT_REQUIRED
            wires.append(pending.pop(0))
            return wires[-1]
        verified.wrap_socket = wrap_socket
        return verified
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
