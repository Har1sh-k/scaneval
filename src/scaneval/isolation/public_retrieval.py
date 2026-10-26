"""Standalone recorded public retrieval service used by the OCI proxy.

Only HTTPS GET to declared origins is supported. DNS answers are all validated, and a validated
address is connected directly while TLS still verifies the original host. Every redirect gets
the same checks. This file deliberately imports only the standard library: the proxy image does
not need an installed copy of ScanEval.
"""

import base64
import datetime
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.parse
import uuid


POLICY = "recorded_public_v1"
EVENTS = "retrieval.jsonl"
MAX_REQUEST = 16384
MAX_RESPONSE = 1024 * 1024
MAX_REDIRECTS = 5
TIMEOUT = 20
_TRANSLATORS = tuple(ipaddress.ip_network(value) for value in (
    "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32",
))
SOURCES = ("scanner_native", "browser_tool")


class RetrievalDenied(ValueError):
    pass


def recorded_url(value):
    """Keep the attempted destination while excluding explicit URL userinfo from evidence.

    This also handles malformed credentialed URLs before parse_url rejects them. A query is
    untrusted research data, not a secret-injection channel; callers must not put secrets in it.
    """
    if not isinstance(value, str):
        return None
    return re.sub(r"(//)[^/?#]*@", r"\1[redacted]@", value, count=1)


def parse_url(value):
    if not isinstance(value, str) or len(value) > 8192 or any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        raise RetrievalDenied("URL is missing, too long, or contains whitespace/control characters")
    try:
        parts = urllib.parse.urlsplit(value)
        port = parts.port or 443
        host = (parts.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
    except (ValueError, UnicodeError) as exc:
        raise RetrievalDenied("URL authority is invalid") from exc
    if parts.scheme != "https" or port != 443 or not host or parts.username is not None or parts.password is not None:
        raise RetrievalDenied("only credential-free HTTPS on port 443 is allowed")
    if "\\" in parts.netloc or "%" in host:
        raise RetrievalDenied("URL authority is ambiguous")
    authority = "[" + host + "]" if ":" in host else host
    origin = "https://" + authority
    url = urllib.parse.urlunsplit(("https", authority, parts.path or "/", parts.query, ""))
    return url, origin, host


def validate_settings(settings):
    if not isinstance(settings, dict) or settings.get("policy") != POLICY:
        raise RetrievalDenied("retrieval policy is unknown or stale")
    allowed_keys = {"policy", "allowed_origins", "denied_hosts", "search_endpoint", "capture", "retention"}
    if set(settings) - allowed_keys:
        raise RetrievalDenied("retrieval settings contain unknown fields")
    origins = settings.get("allowed_origins")
    if not isinstance(origins, list) or not origins:
        raise RetrievalDenied("at least one public retrieval origin must be explicitly declared")
    normalized = []
    for value in origins:
        url, origin, host = parse_url(value)
        if url != origin + "/":
            raise RetrievalDenied("allowed_origins must contain origins without paths or queries")
        if origin not in normalized:
            normalized.append(origin)
    capture, retention = settings.get("capture"), settings.get("retention")
    if (capture, retention) not in (("content", "bundle"), ("hashes", "hashes_only")):
        raise RetrievalDenied("retrieval capture/retention must be content/bundle or hashes/hashes_only")
    denied = settings.get("denied_hosts", [])
    if not isinstance(denied, list) or any(not isinstance(host, str) or not host for host in denied):
        raise RetrievalDenied("denied_hosts must list evaluator infrastructure host names")
    search = settings.get("search_endpoint")
    if search:
        url, origin, host = parse_url(search)
        if origin not in normalized or host in denied:
            raise RetrievalDenied("search_endpoint must use a declared, allowed retrieval origin")
        search = url
    return {"policy": POLICY, "allowed_origins": sorted(normalized),
            "denied_hosts": sorted(set(host.lower().rstrip(".") for host in denied)),
            "capture": capture, "retention": retention,
            **({"search_endpoint": search} if search else {})}


def public_addresses(host, port=443):
    """Reject mixed public/private answers and return the exact addresses callers may connect."""
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    if not answers:
        raise RetrievalDenied("destination has no public address")
    safe = []
    for family, kind, protocol, _canon, address in answers:
        raw = address[0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise RetrievalDenied("destination resolved to an invalid address") from exc
        if ("%" in raw or not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified
                or (isinstance(ip, ipaddress.IPv6Address) and
                    (ip.ipv4_mapped is not None or any(ip in network for network in _TRANSLATORS)))):
            raise RetrievalDenied("destination has a private, local, reserved, or translated address")
        item = (family, kind, protocol, address)
        if item not in safe:
            safe.append(item)
    return safe


def connect_public(host, port=443, timeout=TIMEOUT):
    """Connect without resolving the host a second time, preventing DNS rebinding between checks."""
    addresses = public_addresses(host, port)
    last = None
    for family, kind, protocol, address in addresses:
        connection = socket.socket(family, kind, protocol)
        connection.settimeout(timeout)
        try:
            connection.connect(address)
            return connection, [item[3][0] for item in addresses], address[0]
        except OSError as exc:
            last = exc
            connection.close()
    raise last or OSError("no validated public address could be connected")


class PublicHTTPS(http.client.HTTPSConnection):
    def connect(self):
        connection, self.validated_addresses, self.connected_address = connect_public(self.host, self.port, self.timeout)
        try:
            self.sock = self._context.wrap_socket(connection, server_hostname=self.host)
        except BaseException:
            connection.close()
            raise


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


class Recorder:
    def __init__(self, directory, settings):
        self.directory = directory
        self.settings = validate_settings(settings)
        self.lock = threading.Lock()
        self.stream = open(os.path.join(directory, EVENTS), "a", encoding="utf-8")

    def write(self, event):
        line = json.dumps(event, sort_keys=True, ensure_ascii=True)
        with self.lock:
            self.stream.write(line + "\n")
            self.stream.flush()

    def retrieve(self, request, operation="fetch"):
        event = {"id": uuid.uuid4().hex, "operation": operation, "source": "scanner_native",
                 "query": None, "url": None, "started_at": now(), "finished_at": None,
                 "outcome": "failed", "redirect_chain": [], "content_sha256": None, "byte_count": 0,
                 "capture_status": "unavailable", "content_path": None,
                 "content_entered_model": None, "model_use_assurance": "unverifiable"}
        body = None
        try:
            if not isinstance(request, dict) or set(request) - {"url", "query", "source"}:
                raise RetrievalDenied("retrieval request must contain only url, query, and source")
            source = request.get("source", "scanner_native")
            if source not in SOURCES:
                raise RetrievalDenied("retrieval source must be scanner_native or browser_tool")
            event["source"] = source
            query = request.get("query")
            if query is not None and (not isinstance(query, str) or len(query) > 4096):
                raise RetrievalDenied("query must be text of at most 4096 characters")
            event["query"] = query
            if operation == "search":
                endpoint = self.settings.get("search_endpoint")
                if not endpoint or not query:
                    raise RetrievalDenied("search requires a declared search_endpoint and a nonempty query")
                separator = "&" if urllib.parse.urlsplit(endpoint).query else "?"
                target = endpoint + separator + urllib.parse.urlencode({"q": query})
            else:
                target = request.get("url")
            event["url"] = recorded_url(target)
            deadline = time.monotonic() + 60
            for redirect in range(MAX_REDIRECTS + 1):
                url, origin, host = parse_url(target)
                if origin not in self.settings["allowed_origins"] or host in self.settings["denied_hosts"]:
                    raise RetrievalDenied("destination is not a declared public retrieval origin")
                if time.monotonic() >= deadline:
                    raise TimeoutError("retrieval exceeded its total time limit")
                parts = urllib.parse.urlsplit(url)
                path = parts.path + (("?" + parts.query) if parts.query else "")
                connection = PublicHTTPS(host, timeout=min(TIMEOUT, max(1, deadline - time.monotonic())),
                                         context=ssl.create_default_context())
                hop = {"url": url, "status": None, "location": None}
                event["redirect_chain"].append(hop)
                try:
                    # No caller headers, cookies, authorization, or proxy environment can reach this request.
                    connection.request("GET", path, headers={"User-Agent": "ScanEval-recorded-public/1",
                                                               "Accept-Encoding": "identity"})
                    response = connection.getresponse()
                    hop.update(status=response.status, resolved_addresses=connection.validated_addresses,
                               connected_address=connection.connected_address)
                    if response.status in (301, 302, 303, 307, 308):
                        location = response.getheader("Location")
                        hop["location"] = recorded_url(location)
                        if not location or redirect == MAX_REDIRECTS:
                            raise RetrievalDenied("redirect is missing a target or exceeds the redirect limit")
                        target = urllib.parse.urljoin(url, location)
                        continue
                    body = response.read(MAX_RESPONSE + 1)
                    if len(body) > MAX_RESPONSE:
                        body = None
                        raise RetrievalDenied("response exceeds the retained-content limit")
                    digest = hashlib.sha256(body).hexdigest()
                    event.update(outcome="ok" if 200 <= response.status < 300 else "http_error",
                                 content_sha256="sha256:" + digest, byte_count=len(body),
                                 capture_status="hash_only")
                    if self.settings["capture"] == "content":
                        evidence = os.path.join(self.directory, "content")
                        os.makedirs(evidence, exist_ok=True)
                        path = os.path.join(evidence, digest + ".bin")
                        with self.lock:
                            if not os.path.exists(path):
                                with open(path, "xb") as stream:
                                    stream.write(body)
                        event.update(capture_status="preserved", content_path="content/" + digest + ".bin")
                    break
                finally:
                    connection.close()
        except RetrievalDenied as exc:
            event.update(outcome="denied", error=str(exc))
        except (OSError, ValueError, http.client.HTTPException) as exc:
            event.update(outcome="failed", error=type(exc).__name__)
        finally:
            event["finished_at"] = now()
            self.write(event)
        return {**event, "content_base64": base64.b64encode(body).decode("ascii") if body is not None else None}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *_args):
        pass

    def do_POST(self):
        try:
            self.connection.settimeout(TIMEOUT)
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 0 or length > MAX_REQUEST or self.headers.get("Transfer-Encoding"):
                raise RetrievalDenied("request length is missing, too large, or chunked")
            request = json.loads(self.rfile.read(length))
        except (OSError, ValueError) as exc:
            request = {"invalid_request": type(exc).__name__}
        operation = "search" if self.path == "/search" else "fetch"
        if self.path not in ("/fetch", "/search"):
            request = {"invalid_route": self.path[:100]}
        result = self.server.recorder.retrieve(request, operation)
        data = json.dumps(result, sort_keys=True).encode("utf-8")
        self.send_response(200 if result["outcome"] == "ok" else 403 if result["outcome"] == "denied" else 502)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start(directory, settings, port, bind="0.0.0.0"):
    server = Server((bind, port), Handler)
    server.recorder = Recorder(directory, settings)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
