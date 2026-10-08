# One node, running: the gateway protocol, the replicated store and the audit
# chain behind a socket, with a CLI an operator can actually type.
#
# The node is deliberately two things at once, because in the field it is:
# a party to the exchange (it answers queries about data it holds) and a replica
# of the operational state (it keeps working while the link is down and merges
# when the link returns).
#
# Durability is plain files in a directory -- chain.json, store.json, identity.json
# -- so that a node can be stopped, copied onto a USB stick and restarted
# somewhere else with its history intact and verifiable.
from __future__ import annotations

import argparse
import json
import os
import time

from . import net, ops
from .crypto import HashChain, KeyPair
from .exchange import Gateway, Node, Request, Refused


class NodeService:
    """The message loop. Every verb is one method; nothing is implicit."""

    def __init__(self, name: str, did: str, data_dir: str, keys: KeyPair | None = None,
                 threshold: int = 10):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.node = Node(name, did, keys or self.load_keys(did), threshold)
        self.store = ops.Store(did)
        self.outbox = ops.Outbox(self.store)
        self.gateway = Gateway(self.node, None)
        self.started_at = time.time()
        self.counters = {"exchange": 0, "refused": 0, "ops.push": 0, "ops.pull": 0,
                         "health": 0, "offline_writes": 0}

    def load_keys(self, did: str) -> KeyPair:
        """A node's key is its identity, so it has to survive a restart."""
        path = os.path.join(self.data_dir, "identity.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                saved = json.load(fh)
            return KeyPair.from_seed(bytes.fromhex(saved["seed"]))
        keys = KeyPair.generate()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"did": did, "seed": keys.seed.hex(),
                       "public": keys.public.hex()}, fh)
        return keys

    # -- persistence -------------------------------------------------------
    def save(self) -> dict:
        chain_path = os.path.join(self.data_dir, "chain.json")
        store_path = os.path.join(self.data_dir, "store.json")
        with open(chain_path, "w", encoding="utf-8") as fh:
            json.dump({"did": self.node.did, "entries": self.node.chain.entries,
                       "heads": self.node.chain.snapshot_heads(),
                       "head": self.node.chain.head}, fh)
        with open(store_path, "w", encoding="utf-8") as fh:
            json.dump({"node": self.store.node, "lamport": self.store.lamport,
                       "ops": [op.body() for op in self.store.ops],
                       "pending": [op.op_id for op in self.outbox.pending.values()]}, fh)
        return {"chain_entries": len(self.node.chain), "ops": self.store.size(),
                "chain_head": self.node.chain.head,
                "state_digest": self.store.state_digest()}

    def load(self) -> dict:
        chain_path = os.path.join(self.data_dir, "chain.json")
        store_path = os.path.join(self.data_dir, "store.json")
        out = {}
        if os.path.exists(chain_path):
            with open(chain_path, encoding="utf-8") as fh:
                data = json.load(fh)
            reborn = HashChain(data["entries"])
            ok, idx = reborn.verify()
            out["chain_ok"] = ok
            out["first_bad_index"] = None if ok else idx
            out["heads_match"] = reborn.snapshot_heads() == data["heads"]
            self.node.chain = reborn
        if os.path.exists(store_path):
            with open(store_path, encoding="utf-8") as fh:
                data = json.load(fh)
            for raw in data["ops"]:
                self.store.apply(ops.Op(**raw))
            out["ops"] = self.store.size()
            out["state_digest"] = self.store.state_digest()
        return out



# ---------------------------------------------------------------- the verbs
#
#   health        what this node is, and what it can see
#   exchange      a query against data this node holds
#   ops.push      hand over operations this node has written
#   ops.pull      ask for the operations this node is missing
#   inspect       the last N audit entries, each with its own inclusion proof


def handle_health(service: "NodeService", message: dict) -> dict:
    service.counters["health"] += 1
    return {"node": service.node.did, "name": service.node.name,
            "scopes": sorted(service.node.known_keys),
            "series": {name: {"unit": s.unit, "cells": len(s.values)}
                       for name, s in sorted(service.node.series.items())},
            "ops": service.store.size(), "lamport": service.store.lamport,
            "outbox": service.outbox.depth(),
            "chain_entries": len(service.node.chain),
            "chain_head": service.node.chain.head,
            "uptime_seconds": round(time.time() - service.started_at, 3),
            "counters": dict(service.counters)}


def handle_exchange(service: "NodeService", message: dict) -> dict:
    from .identity import Delegation
    request = Request(**message["request"])
    chain = [Delegation(**{k: v for k, v in d.items() if k != "digest"})
             for d in message.get("chain", [])]
    service.counters["exchange"] += 1
    reply = service.node.receive(request.requester, {"request": request.body(),
                                                     "chain": [g.encode() for g in chain]})
    if reply["receipt"]["status"] == "refused":
        service.counters["refused"] += 1
    return reply


def handle_ops_push(service: "NodeService", message: dict) -> dict:
    incoming = [ops.Op(**raw) for raw in message.get("ops", [])]
    applied = service.store.merge(incoming)
    service.counters["ops.push"] += 1
    acked = [op.op_id for op in incoming]
    return {"received": len(incoming), "applied": applied,
            "state_digest": service.store.state_digest(),
            "acked": acked}


def handle_ops_pull(service: "NodeService", message: dict) -> dict:
    have = set(message.get("have", []))
    missing = [op.body() for op in service.store.ops if op.op_id not in have]
    limit = int(message.get("limit", 500))
    service.counters["ops.pull"] += 1
    return {"ops": missing[:limit], "remaining": max(0, len(missing) - limit),
            "state_digest": service.store.state_digest()}


def handle_inspect(service: "NodeService", message: dict) -> dict:
    n = int(message.get("n", 5))
    total = len(service.node.chain)
    idxs = range(max(0, total - n), total)
    return {"entries": [service.node.chain.inclusion_proof(i) for i in idxs],
            "length": total, "head": service.node.chain.head,
            "chain_ok": service.node.chain.verify()[0]}


VERBS = {"health": handle_health, "exchange": handle_exchange,
         "ops.push": handle_ops_push, "ops.pull": handle_ops_pull,
         "inspect": handle_inspect}


def dispatch(service: "NodeService", message: dict) -> dict:
    verb = message.get("verb")
    fn = VERBS.get(verb)
    if fn is None:
        return {"error": "unknown-verb", "detail": str(verb)}
    try:
        return fn(service, message)
    except Refused as exc:
        service.counters["refused"] += 1
        return {"error": "refused", "code": exc.code, "detail": exc.detail}
    except Exception as exc:  # pragma: no cover - defensive
        return {"error": type(exc).__name__, "detail": str(exc)[:300]}


def serve(data_dir: str, name: str, did: str, host: str = "127.0.0.1",
          port: int = 0, shared_secret: bytes | None = None):
    """Start a node on a socket. Returns (server, service) with the port set."""
    service = NodeService(name, did, data_dir)
    loaded = service.load()
    factory = None
    if shared_secret:
        from .crypto import hkdf
        def factory():
            _, srv_session = net.SecureSession.pair(
                hkdf(shared_secret, b"ss-v1/session|%s" % did.encode()))
            return srv_session
    server = net.TcpServer(lambda m: dispatch(service, m), host, port,
                           session_factory=factory)
    server.loaded = loaded
    return server.start(), service


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sgw-node",
                                     description="run one sovereign-stack node")
    parser.add_argument("--data", required=True, help="directory for chain.json etc")
    parser.add_argument("--name", default="node")
    parser.add_argument("--did", default="did:sgw:local")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--secret", default=None,
                        help="shared secret; frames are sealed with it")
    parser.add_argument("--once", action="store_true",
                        help="print the health reply and exit (for a smoke test)")
    args = parser.parse_args(argv)
    secret = args.secret.encode() if args.secret else None
    server, service = serve(args.data, args.name, args.did, args.host, args.port, secret)
    info = {"port": server.port, "host": server.host, "did": service.node.did,
            "loaded": server.loaded}
    if args.once:
        from .crypto import hkdf
        from .net import SecureSession, call as net_call
        factory = None
        if secret:
            def factory():
                client, _ = SecureSession.pair(
                    hkdf(secret, b"ss-v1/session|%s" % service.node.did.encode()))
                return client
        reply = net_call(server.host, server.port, {"verb": "health"},
                         session_factory=factory)
        print(json.dumps(reply, indent=1))
        server.stop()
        return 0
    print(json.dumps(info, indent=1))
    print("listening; ctrl-c to stop")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        print(json.dumps(service.save(), indent=1))
        server.stop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
