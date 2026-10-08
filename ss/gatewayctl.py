# The client. Five verbs, no state of its own beyond a store file, and every call
# is one connection that either authenticates or is refused at the framing layer.
from __future__ import annotations

import argparse
import json
import os
import sys

from . import net, ops
from .crypto import hkdf
from .exchange import Request



def session_for(secret: str, peer_did: str):
    """A factory, not a session.

    Two reasons. The frame counter lives in the session, so one session per
    connection is what keeps a second reply from looking like a replay. And the
    key is bound to the peer's DID, which is how the node derives its own -- a
    client that does not know which node it is talking to cannot open the reply,
    which is the intended failure.
    """
    def make():
        client, _ = net.SecureSession.pair(
            hkdf(secret.encode(), b"ss-v1/session|%s" % peer_did.encode()))
        return client
    return make


def health(host: str, port: int, secret: str | None = None, peer_did: str = "") -> dict:
    session_factory = session_for(secret, peer_did) if secret else None
    return net.call(host, port, {"verb": "health"}, session_factory=session_factory)


def inspect(host: str, port: int, n: int = 5, secret: str | None = None,
            peer_did: str = "") -> dict:
    session_factory = session_for(secret, peer_did) if secret else None
    reply = net.call(host, port, {"verb": "inspect", "n": n}, session_factory=session_factory)
    if "chain_ok" in reply:
        reply["verified"] = bool(reply["chain_ok"]) and all(
            type(entry) is dict and "head" in entry for entry in reply["entries"])
    return reply


def pull(host: str, port: int, store: ops.Store, secret: str | None = None,
         peer_did: str = "", limit: int = 500) -> dict:
    session_factory = session_for(secret, peer_did) if secret else None
    have = sorted(store.digest_map())
    applied = 0
    rounds = 0
    while True:
        reply = net.call(host, port, {"verb": "ops.pull", "have": have, "limit": limit},
                         session_factory=session_factory)
        if "ops" not in reply:
            return {"error": reply.get("error", "unexpected reply"), "applied": applied}
        incoming = [ops.Op(**raw) for raw in reply["ops"]]
        applied += store.merge(incoming)
        rounds += 1
        if not incoming or reply.get("remaining", 0) <= 0:
            break
        have = sorted(store.digest_map())
    return {"pulled": applied, "rounds": rounds, "state_digest": store.state_digest(),
            "ops": store.size()}


def push(host: str, port: int, store: ops.Store, secret: str | None = None,
         outbox: ops.Outbox | None = None, peer_did: str = "", limit: int = 500) -> dict:
    session_factory = session_for(secret, peer_did) if secret else None
    sent = acked = 0
    while True:
        batch = (outbox.batch(limit) if outbox is not None
                 else store.ops[sent:sent + limit])
        if not batch:
            break
        reply = net.call(host, port,
                         {"verb": "ops.push", "ops": [op.body() for op in batch]},
                         session_factory=session_factory)
        if "acked" not in reply:
            return {"error": reply.get("error", "unexpected reply"), "sent": sent}
        sent += len(batch)
        acked += len(reply["acked"])
        if outbox is not None:
            outbox.ack(reply["acked"])
        if len(batch) < limit:
            break
    return {"sent": sent, "acked": acked, "state_digest": store.state_digest()}


def sync(host: str, port: int, store: ops.Store, secret: str | None = None,
         peer_did: str = "") -> dict:
    """Pull then push. Afterwards both sides hold the same set of operations."""
    p = pull(host, port, store, secret, peer_did)
    q = push(host, port, store, secret, peer_did)
    remote = health(host, port, secret, peer_did)
    return {"pull": p, "push": q, "local": store.state_digest(),
            "remote_head": remote.get("chain_head"),
            "ok": p.get("state_digest") == store.state_digest()
                  and q.get("state_digest") == store.state_digest()}


def ask(host: str, port: int, request: Request, chain: list, secret: str | None = None,
        peer_did: str = "") -> dict:
    session_factory = session_for(secret, peer_did) if secret else None
    message = {"verb": "exchange", "request": request.body(),
               "chain": [g.encode() for g in chain]}
    return net.call(host, port, message, session_factory=session_factory)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sgw-ctl", description="talk to a sovereign-stack node")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--secret", default=None, help="shared secret for sealed frames")
    parser.add_argument("--peer-did", default="",
                        help="the DID of the node being called; part of the session key")
    parser.add_argument("--store", default=None, help="store file for pull/push/sync")
    sub = parser.add_subparsers(dest="verb", required=True)
    sub.add_parser("health")
    p_inspect = sub.add_parser("inspect")
    p_inspect.add_argument("-n", type=int, default=5)
    sub.add_parser("pull")
    sub.add_parser("push")
    sub.add_parser("sync")
    args = parser.parse_args(argv)
    secret = args.secret
    did = args.peer_did

    if args.verb == "health":
        print(json.dumps(health(args.host, args.port, secret, did), indent=1))
    elif args.verb == "inspect":
        print(json.dumps(inspect(args.host, args.port, args.n, secret, did), indent=1))
    else:
        path = args.store or ".sgw-store.json"
        store = ops.Store("cli")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                for raw in json.load(fh)["ops"]:
                    store.apply(ops.Op(**raw))
        if args.verb == "pull":
            out = pull(args.host, args.port, store, secret, did)
        elif args.verb == "push":
            out = push(args.host, args.port, store, secret, did)
        else:
            out = sync(args.host, args.port, store, secret, did)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"ops": [op.body() for op in store.ops]}, fh)
        print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
