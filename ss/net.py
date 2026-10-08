# Framed JSON over a socket, because a dataset crossing a border is larger than
# one read, and a message boundary is not something TCP hands you.
#
# Each frame is a 4-byte big-endian length followed by canonical JSON, sealed with
# AES-GCM under a session key derived from a shared secret. The framing is small
# enough to re-implement against, which matters when the peer is a machine nobody
# has shell access to; ss/gatewayctl.py is the client this project ships.
from __future__ import annotations

import json
import socket
import struct
import threading

from .crypto import canonical, decrypt, encrypt, hkdf

HEADER = struct.Struct("!I")
MAX_FRAME = 16 * 1024 * 1024


def send_frame(sock, obj) -> int:
    body = canonical(obj)
    sock.sendall(HEADER.pack(len(body)) + body)
    return len(body)


def recv_exactly(sock, n: int) -> bytes:
    chunks = []
    got = 0
    while got < n:
        chunk = sock.recv(min(65536, n - got))
        if not chunk:
            raise ConnectionError("peer closed after %d of %d bytes" % (got, n))
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def is_sealed(frame) -> bool:
    return isinstance(frame, dict) and "n" in frame and "blob" in frame


def recv_frame(sock) -> dict:
    (size,) = HEADER.unpack(recv_exactly(sock, HEADER.size))
    if size > MAX_FRAME:
        raise ConnectionError("frame of %d bytes over the %d-byte cap" % (size, MAX_FRAME))
    return json.loads(recv_exactly(sock, size).decode("utf-8"))


class SecureSession:
    """Authenticated frames in one direction.

    Two keys are derived from the shared secret, one per direction, and the
    counter in the associated data makes each frame unique. The directional split
    is what stops a reflection: a frame this side sent cannot be replayed back to
    it as if it came from the peer, because it will not decrypt under the other
    direction's key. The counter is what stops a repeat within a direction.
    """

    def __init__(self, send_key: bytes, recv_key: bytes, aad: bytes = b"ss-v1/frame"):
        self.send_key = send_key
        self.recv_key = recv_key
        self.aad = aad
        self.sent = 0
        self.received = 0

    @classmethod
    def pair(cls, shared: bytes, aad: bytes = b"ss-v1/frame"):
        """The two sides of one session, keys swapped, from one shared secret."""
        c2s = hkdf(shared, aad + b"/client-to-server")
        s2c = hkdf(shared, aad + b"/server-to-client")
        return cls(c2s, s2c, aad), cls(s2c, c2s, aad)

    def seal(self, obj) -> dict:
        self.sent += 1
        aad = self.aad + b"|n|%d" % self.sent
        return {"n": self.sent, "blob": encrypt(self.send_key, canonical(obj), aad).hex()}

    def open(self, frame: dict) -> dict:
        if "n" not in frame or "blob" not in frame:
            raise ConnectionError("frame is not a sealed frame")
        n = int(frame["n"])
        if n <= self.received:
            raise ConnectionError("frame %d arrives after %d: replay" % (n, self.received))
        aad = self.aad + b"|n|%d" % n
        try:
            plain = decrypt(self.recv_key, bytes.fromhex(frame["blob"]), aad)
        except Exception as exc:
            # Not a ConnectionError from the transport: the frame authenticated
            # under nothing this side holds, which is what a reflection or a
            # forgery looks like from here.
            raise ConnectionError("frame %d does not authenticate: %s"
                                  % (n, type(exc).__name__)) from exc
        self.received = n
        return json.loads(plain.decode("utf-8"))


class TcpServer:
    """One node, listening. handler(message) -> reply, on its own thread."""

    def __init__(self, handler, host: str = "127.0.0.1", port: int = 0,
                 session_factory=None):
        self.handler = handler
        # When a session factory is given, every frame on the wire must be sealed
        # with it. A node that accepts unsealed frames is a dev convenience and
        # not a deployment, so the two modes are separate constructors' worth of
        # difference and the refusal is counted.
        self.session_factory = session_factory
        self.unsealed_refused = 0
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(8)
        self.host, self.port = self.sock.getsockname()
        self._stop = threading.Event()
        self._thread = None
        self.connections = 0
        self.requests = 0

    def start(self):
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            self.connections += 1
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn) -> None:
        session = self.session_factory() if self.session_factory else None
        with conn:
            conn.settimeout(30)
            while True:
                try:
                    frame = recv_frame(conn)
                except (ConnectionError, OSError, ValueError):
                    return
                if session is not None:
                    if not is_sealed(frame):
                        self.unsealed_refused += 1
                        try:
                            send_frame(conn, {"error": "unsealed-frame-refused",
                                              "detail": "this node only accepts sealed frames"})
                        except OSError:
                            return
                        continue
                    try:
                        message = session.open(frame)
                    except ConnectionError as exc:
                        self.unsealed_refused += 0
                        try:
                            send_frame(conn, {"error": "frame-rejected", "detail": str(exc)})
                        except OSError:
                            pass
                        return
                else:
                    message = frame
                self.requests += 1
                try:
                    reply = self.handler(message)
                except Exception as exc:
                    # A handler that raises must not kill the listener, and the
                    # caller must be able to tell a refusal from a dropped link.
                    reply = {"error": type(exc).__name__, "detail": str(exc)[:200]}
                try:
                    send_frame(conn, session.seal(reply) if session else reply)
                except OSError:
                    return

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


def call(host: str, port: int, message: dict, timeout: float = 30.0,
         session_factory=None, session=None) -> dict:
    """One request, one reply, one connection.

    The session is built per call, from a factory rather than handed in, because
    the frame counter lives in the session: reusing one across two connections
    would make the second reply look exactly like a replay, which is a mistake
    this function made until the deployment acceptance test caught it.
    """
    if session is None and session_factory is not None:
        session = session_factory()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        send_frame(sock, session.seal(message) if session else message)
        reply = recv_frame(sock)
        return session.open(reply) if session else reply
