import base64
import hashlib
import json
import socket

import pytest

from scaneval.isolation import IsolationError, resolve_execution
from scaneval.isolation import public_retrieval as retrieval


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
    assert base64.b64decode(result["content_base64"]) == b"public evidence"
    assert (tmp_path / result["content_path"]).read_bytes() == b"public evidence"
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


def test_undeclared_and_credential_redirects_are_denied(tmp_path, monkeypatch):
    transport(monkeypatch, [Response(302, location="https://secret:token@research.example/next")])
    recorder = retrieval.Recorder(str(tmp_path), POLICY)
    denied = recorder.retrieve({"url": "https://undeclared.example/"})
    redirect = recorder.retrieve({"url": "https://research.example/start"})
    assert denied["outcome"] == "denied" and redirect["outcome"] == "denied"
    assert len(denied["redirect_chain"]) == 0


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
