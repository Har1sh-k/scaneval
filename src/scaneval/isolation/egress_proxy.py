"""A CONNECT-only egress proxy that forwards exactly the declared host:port pairs, and logs each decision.

This file is the proxy the ``oci`` backend runs in its own container under the
``model_provider_only`` network policy. The scanner's container sits on an internal network with
no gateway, so the only thing it can reach is this proxy; this proxy sits on that network and on
one ordinary bridge, and decides what crosses. The backend copies this file into its private
scratch directory and mounts it read-only into the proxy container, so it runs as a standalone
script: it imports nothing outside the Python standard library, never imports ``scaneval``, and
runs under any Python 3.8 or later.

What it does, all of it:

- listens on one TCP port, on every interface of its own container, and on nothing else;
- reads one request head per connection, at most 16 KiB and within 30 seconds;
- accepts only ``CONNECT host:port``, and only when that exact pair was declared with ``--allow``
  (the host compared without regard to case, an IPv6 literal written in brackets); anything else
  gets ``400``, ``403``, or ``405`` and the connection is closed;
- for an allowed pair, resolves and connects to it itself, answers ``200``, and relays bytes both
  ways until both sides have finished or the tunnel has been idle for ten minutes;
- appends one JSON object per line to ``egress.jsonl`` in ``--log-dir`` for every decision, and
  writes ``ready`` there once it is listening, which is how the backend knows it may start the
  scanner.

What it does not do: it does not terminate TLS or look inside a tunnel, so an allowed endpoint
receives whatever the client sends it and the log records destinations and byte counts only; it
does not forward plain HTTP requests or resolve names for the client; it does not authenticate
the client, because only the scanner's container can reach it; and it holds at most 64
connections at once, refusing the rest with ``503``. A declared host that resolves to a private
address is reached like any other, because the declaration is the operator's.
"""

import argparse
import datetime
import json
import os
import select
import socket
import socketserver
import sys
import threading
import time


HEAD_LIMIT = 16 * 1024
HEAD_TIMEOUT = 30.0
CONNECT_TIMEOUT = 30.0
IDLE_TIMEOUT = 600.0
MAX_CONNECTIONS = 64
LOG_NAME = "egress.jsonl"
READY_NAME = "ready"
# A logged request target is what the client sent, so it is capped before it is written.
TARGET_LIMIT = 300


def split_authority(text):
    """``(host, port)`` from ``host:port`` or ``[v6]:port``, or ``None`` when it is not one.

    The host comes back lowercased and without brackets. A port must be decimal digits naming
    1 to 65535; a host must be non-empty and hold no whitespace, slash, or at sign.
    """
    if text.startswith("["):
        close = text.find("]")
        if close < 0 or not text[close + 1:].startswith(":"):
            return None
        host, port_text = text[1:close], text[close + 2:]
    else:
        host, sep, port_text = text.rpartition(":")
        if not sep or ":" in host:
            return None
    if not host or any(ch.isspace() or ch in "/@" for ch in host):
        return None
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        return None
    return host.lower(), int(port_text)


class EgressLog:
    """One JSON object per line, flushed as it is written, so a killed proxy loses no decision."""

    def __init__(self, directory):
        self._lock = threading.Lock()
        self._stream = open(os.path.join(directory, LOG_NAME), "a", encoding="utf-8")

    def write(self, **entry):
        entry["at"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
        line = json.dumps(entry, sort_keys=True, ensure_ascii=True)
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()


def read_head(connection):
    """The request head up to the blank line, and whatever followed it, or ``None``.

    ``None`` when the head is larger than :data:`HEAD_LIMIT`, when the client closes first, and
    when the whole head has not arrived within :data:`HEAD_TIMEOUT` seconds of the first read. The
    limit is on the whole head, not on each read, so a client trickling one byte at a time cannot
    hold a connection slot for longer than that.
    """
    deadline = time.monotonic() + HEAD_TIMEOUT
    data = b""
    while b"\r\n\r\n" not in data:
        remaining = deadline - time.monotonic()
        if len(data) > HEAD_LIMIT or remaining <= 0:
            return None
        try:
            connection.settimeout(remaining)
            chunk = connection.recv(4096)
        except OSError:
            return None
        if not chunk:
            return None
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    if len(head) > HEAD_LIMIT:
        return None
    return head, rest


def reply(connection, status, reason):
    try:
        connection.sendall(f"HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                           .encode("ascii"))
    except OSError:
        pass


def relay(client, upstream):
    """Copy bytes both ways until both directions have ended; ``(sent upstream, received back)``."""
    peers = {client: upstream, upstream: client}
    counts = {client: 0, upstream: 0}
    reading = {client, upstream}
    while reading:
        try:
            ready, _, _ = select.select(list(reading), [], [], IDLE_TIMEOUT)
        except (OSError, ValueError):
            break
        if not ready:
            break
        for sock in ready:
            try:
                data = sock.recv(65536)
            except OSError:
                data = b""
            peer = peers[sock]
            if not data:
                reading.discard(sock)
                try:
                    peer.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                continue
            try:
                peer.sendall(data)
            except OSError:
                reading.clear()
                break
            counts[sock] += len(data)
    return counts[client], counts[upstream]


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        if not server.slots.acquire(blocking=False):
            server.log.write(event="deny", reason="too many connections")
            reply(self.request, 503, "Service Unavailable")
            return
        try:
            self.decide(server)
        finally:
            server.slots.release()

    def decide(self, server):
        client = self.request
        received = read_head(client)
        # The head read leaves whatever was left of its own deadline on the socket; a reply gets a
        # fresh one, so a refusal is never cut short by how long the client took to send its head.
        client.settimeout(HEAD_TIMEOUT)
        if received is None:
            server.log.write(event="deny", reason="no complete request head within the size and time limits")
            reply(client, 400, "Bad Request")
            return
        head, rest = received
        parts = head.split(b"\r\n", 1)[0].decode("latin-1").split()
        if len(parts) != 3 or not parts[2].startswith("HTTP/"):
            server.log.write(event="deny", reason="not an HTTP request line")
            reply(client, 400, "Bad Request")
            return
        method, target = parts[0], parts[1]
        if method.upper() != "CONNECT":
            server.log.write(event="deny", reason="only CONNECT is forwarded", method=method[:20],
                             target=target[:TARGET_LIMIT])
            reply(client, 405, "Method Not Allowed")
            return
        authority = split_authority(target)
        if authority is None:
            server.log.write(event="deny", reason="the CONNECT target is not host:port",
                             target=target[:TARGET_LIMIT])
            reply(client, 400, "Bad Request")
            return
        host, port = authority
        if authority not in server.allow:
            server.log.write(event="deny", reason="not a declared destination", host=host[:TARGET_LIMIT],
                             port=port)
            reply(client, 403, "Forbidden")
            return
        try:
            upstream = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        except OSError as exc:
            server.log.write(event="allow", host=host, port=port, outcome="connect_failed",
                             error=type(exc).__name__)
            reply(client, 502, "Bad Gateway")
            return
        with upstream:
            server.log.write(event="allow", host=host, port=port, outcome="connected")
            client.settimeout(IDLE_TIMEOUT)
            upstream.settimeout(IDLE_TIMEOUT)
            try:
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    upstream.sendall(rest)
            except OSError:
                return
            sent, received_back = relay(client, upstream)
            server.log.write(event="closed", host=host, port=port, sent=sent + len(rest),
                             received=received_back)


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = MAX_CONNECTIONS


def main(argv=None):
    parser = argparse.ArgumentParser(description="CONNECT-only egress proxy for exactly the declared pairs.")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--allow", action="append", default=[], help="host:port, repeatable")
    parser.add_argument("--bind", default="0.0.0.0", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    allow = set()
    for value in args.allow:
        pair = split_authority(value)
        if pair is None:
            parser.error(f"--allow {value!r} is not host:port")
        allow.add(pair)
    if not allow:
        parser.error("at least one --allow host:port is required; a proxy that forwards nothing is not needed")
    log = EgressLog(args.log_dir)
    server = Server((args.bind, args.port), Handler)
    server.allow = frozenset(allow)
    server.log = log
    server.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
    declared = sorted(f"{host}:{port}" for host, port in allow)
    log.write(event="listening", port=server.server_address[1], allow=declared)
    ready = os.path.join(args.log_dir, READY_NAME)
    with open(ready + ".part", "w", encoding="utf-8") as stream:
        stream.write(json.dumps({"port": server.server_address[1], "allow": declared}) + "\n")
    os.replace(ready + ".part", ready)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
