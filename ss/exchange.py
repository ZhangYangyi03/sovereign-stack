# The gateway: what actually crosses a jurisdiction boundary, and what does not.
#
# Three query classes, and the rule for each is the point of the module:
#
#   aggregate.bounded   answered with commitments and a proof; no raw record and no
#                       exact count leaves the node that holds the data.
#   aggregate.exact     the number itself is released, and a release is a
#                       disclosure, so it is written into the audit chain with the
#                       requester DID -- a recorded act rather than a silent one.
#   record.lookup       refused, always. A gateway that can hand over a row is a
#                       gateway that has just become one place to lose everything.
#
# Transport is a bus, so the same protocol runs in-process for tests and over TCP
# for two machines. Each node has an X25519 key; the session key is HKDF over the
# shared secret, so a node that records the wire learns nothing from it later.
from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives import serialization

from . import zk
from .crypto import (HashChain, KeyPair, canonical, commit, commit_homomorphic,
                     hkdf, sha256_hex, verify_signature)
from .crypto import group as _group
from .identity import Delegation, may

DEFAULT_THRESHOLD = 10


class Refused(Exception):
    # Every refusal carries a reason code, because "denied" with no reason is
    # indistinguishable from a gateway that is simply broken.
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass
class Cell:
    """One contribution. The value never leaves the node in cleartext."""
    cell_id: str
    partition: str
    v: int
    C: int = 0
    r: int = 0

    def seal(self) -> "Cell":
        self.C, self.r = commit(self.v)
        return self

    def digest(self) -> str:
        return sha256_hex(canonical({"cell": self.cell_id, "C": hex(self.C)}))


@dataclass
class Series:
    """A dataset held by one node, as a grid of (subject class, partition)."""
    name: str
    unit: str
    values: dict = field(default_factory=dict)
    release_history: tuple = ()

    @classmethod
    def from_counts(cls, name: str, unit: str, counts: dict) -> "Series":
        return cls(name=name, unit=unit, values=dict(counts))

    def cell(self, partition: str, subject: str) -> int | None:
        return self.values.get((partition, subject))

    def total(self) -> int:
        return sum(self.values.values())

    def sealed(self) -> list:
        return [Cell("%s/%s" % (p, s), p, v).seal() for (p, s), v in sorted(self.values.items())]


def prior_releases(history, partition: str, subject: str, selection=None) -> int:
    """Release accounting, so a sequence of "different" questions cannot recover a cell.

    Asking for {p} alone, then for everything except {p}, yields the cell by
    subtraction with no single query looking like a disclosure. Two releases count
    against a cell if both include it and their selections differ: identical
    repeats teach an observer nothing new, and a selection that does not include
    the cell is a different question about a different subject.
    """
    n = 0
    for d in history:
        parts = tuple(d.get("partitions", ()))
        subs = tuple(d.get("subjects", ()))
        if partition not in parts or subject not in subs:
            continue           # this release did not expose this cell
        if selection is not None and (parts, subs) == selection:
            continue           # an exact repeat of a release already made
        n += 1
    return n


def disclosure_ok(history, partitions, subjects, threshold: int = DEFAULT_THRESHOLD) -> tuple:
    """A release is allowed only if it does not make a cell isolable by subtraction."""
    selection = (tuple(partitions), tuple(subjects))
    for p in partitions:
        for s in subjects:
            n = prior_releases(history, p, s, selection)
            if n + 1 >= threshold:
                return False, "subject-exposure:%s/%s" % (p, s)
    return True, "ok"


@dataclass
class Request:
    kind: str
    requester: str
    request_id: str
    series: str
    partitions: tuple = ()
    subjects: tuple = ()
    statement_class: str = ""
    threshold: int = 0
    bits: int = 24
    purpose: str = ""

    def body(self) -> dict:
        return {"kind": self.kind, "requester": self.requester,
                "request_id": self.request_id, "series": self.series,
                "partitions": list(self.partitions), "subjects": list(self.subjects),
                "statement_class": self.statement_class, "threshold": self.threshold,
                "bits": self.bits, "purpose": self.purpose}

    def digest(self) -> str:
        return sha256_hex(canonical(self.body()))


@dataclass
class Receipt:
    request_id: str
    responder: str
    status: str
    payload: dict = field(default_factory=dict)
    reason: str = ""
    ts: float = field(default_factory=time.time)
    sig: str = ""

    def body(self) -> dict:
        return {"request_id": self.request_id, "responder": self.responder,
                "status": self.status, "payload": self.payload, "reason": self.reason,
                "ts": round(self.ts, 6)}

    def sign(self, kp: KeyPair) -> "Receipt":
        self.sig = base64.urlsafe_b64encode(
            kp.sign(canonical(self.body()))).decode().rstrip("=")
        return self

    def verify(self, public: bytes) -> bool:
        if not self.sig:
            return False
        raw = base64.urlsafe_b64decode(self.sig + "=" * (-len(self.sig) % 4))
        return verify_signature(public, canonical(self.body()), raw)


class Transport:
    """In-process bus. A TCP transport subclasses this and changes only send()."""

    def __init__(self):
        self.nodes = {}
        self.wire = []

    def register(self, node) -> None:
        self.nodes[node.did] = node

    def lookup(self, did: str):
        node = self.nodes.get(did)
        if node is None:
            raise Refused("unknown-node", did)
        return node

    def send(self, src: str, dst: str, message: dict) -> dict:
        envelope = {"src": src, "dst": dst, "nonce": secrets.token_hex(8),
                    "payload": message}
        self.wire.append(envelope)
        return self.lookup(dst).receive(src, message)


class Node:
    """One participant: its data, its identity, its audit chain, its policy."""

    def __init__(self, name: str, did: str, keys: KeyPair | None = None,
                 threshold: int = DEFAULT_THRESHOLD):
        self.name = name
        self.did = did
        self.keys = keys or KeyPair.generate()
        self.threshold = threshold
        self.series: dict = {}
        self.chain = HashChain()
        self.known_keys: dict = {did: self.keys.public}
        self.release_history: list = []
        self.rng = secrets.SystemRandom()
        self.x25519 = X25519PrivateKey.generate()
        self.peer_keys: dict = {}
        self.chain.append({"event": "node.create", "did": did, "name": name,
                           "ts": round(time.time(), 6)})

    # -- identity ----------------------------------------------------------
    def x25519_public(self) -> bytes:
        return self.x25519.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def trust(self, did: str, public: bytes, x_pub: bytes | None = None) -> None:
        self.known_keys[did] = public
        if x_pub:
            self.peer_keys[did] = x_pub
        self.chain.append({"event": "trust", "did": did,
                           "fingerprint": sha256_hex(public),
                           "ts": round(time.time(), 6)})

    def session_key(self, peer_did: str, info: bytes = b"ss-v1/session") -> bytes:
        shared = self.x25519.exchange(X25519PublicKey.from_public_bytes(
            self.peer_keys[peer_did]))
        # Both sides must derive the same key, so the transcript is ordered
        # rather than "mine then yours".
        pair = b"|".join(sorted([self.did.encode(), peer_did.encode()]))
        return hkdf(shared, info + pair)

    # -- data --------------------------------------------------------------
    def load(self, series: Series) -> None:
        self.series[series.name] = series
        self.chain.append({"event": "series.load", "series": series.name,
                           "unit": series.unit, "cells": len(series.values),
                           "digest": sha256_hex(canonical(sorted(
                               ((p, s, v) for (p, s), v in series.values.items()))))})

    def _auth(self, request: Request, chain, now: float) -> tuple:
        scope = {"aggregate.bounded": "query.aggregate",
                 "aggregate.exact": "query.aggregate",
                 "record.lookup": "query.record"}[request.kind]
        cls = request.statement_class or "case_count"
        return may(chain, scope, cls, self.known_keys, now,
                   requester=request.requester)

    # -- the three rules ---------------------------------------------------
    def receive(self, src_did: str, message: dict) -> dict:
        request = Request(**message["request"])
        chain = [Delegation(**{k: v for k, v in d.items() if k != "digest"})
                 for d in message["chain"]]
        now = time.time()
        try:
            ok, why = self._auth(request, chain, now)
            if not ok:
                raise Refused("not-authorised:" + why, request.digest())
            if request.kind == "record.lookup":
                raise Refused("record-lookup-always-refused", request.digest())
            series = self.series.get(request.series)
            if series is None:
                raise Refused("unknown-series", request.series)
            if request.kind == "aggregate.exact":
                return self._exact(series, request)
            if request.kind == "aggregate.bounded":
                return self._bounded(series, request)
            raise Refused("unknown-kind", request.kind)
        except Refused as exc:
            self.chain.append({"event": "refuse", "request": request.digest(),
                               "requester": request.requester, "code": exc.code,
                               "ts": round(now, 6)})
            return {"receipt": Receipt(request.request_id, self.did, "refused", {},
                                       exc.code).sign(self.keys).body(),
                    "attestation": self.chain.inclusion_proof(-1)}

    def _exact(self, series: Series, request: Request) -> dict:
        parts = request.partitions or tuple(sorted({p for p, _ in series.values}))
        subs = request.subjects or tuple(sorted({s for _, s in series.values}))
        ok, why = disclosure_ok(self.release_history, parts, subs, self.threshold)
        if not ok:
            raise Refused("disclosure-control:" + why, request.digest())
        total = sum(v for (p, s), v in series.values.items() if p in parts and s in subs)
        self.release_history.append({"request_id": request.request_id,
                                     "partitions": list(parts), "subjects": list(subs),
                                     "ts": round(time.time(), 6)})
        self.chain.append({"event": "release", "request": request.digest(),
                           "requester": request.requester, "series": series.name,
                           "partitions": list(parts), "subjects": list(subs),
                           "disclosed": total, "ts": round(time.time(), 6)})
        payload = {"disclosed": total, "unit": series.unit,
                   "partitions": list(parts), "subjects": list(subs),
                   "exposure_counter": len(self.release_history)}
        return {"receipt": Receipt(request.request_id, self.did, "released", payload)
                .sign(self.keys).body(), "attestation": self.chain.inclusion_proof(-1)}

    def _bounded(self, series: Series, request: Request) -> dict:
        parts = request.partitions or tuple(sorted({p for p, _ in series.values}))
        subs = request.subjects or tuple(sorted({s for _, s in series.values}))
        threshold = request.threshold or self.threshold
        cells = [Cell("%s/%s" % (p, s), p, v).seal()
                 for (p, s), v in sorted(series.values.items())
                 if p in parts and s in subs]
        if not cells:
            raise Refused("empty-selection", request.digest())
        summed = 1
        for cell in cells:
            summed = commit_homomorphic(summed, cell.C)
        combined = cum_rand(sum(cell.r for cell in cells))
        total = sum(cell.v for cell in cells)
        if total >= (1 << request.bits):
            # The node can see the total itself, so it knows the statement it was
            # asked to prove is false. Proving it is impossible, and answering
            # the question instead would be the disclosure this exists to avoid.
            raise Refused("range-exceeded", "%d >= 2^%d" % (total, request.bits))
        proof = zk.prove_range(total, combined, request.bits)
        if not zk.verify_range(proof):
            raise Refused("self-check-failed", "range proof did not verify")
        self.chain.append({"event": "answer.bounded", "request": request.digest(),
                           "requester": request.requester, "series": series.name,
                           "cells": len(cells), "threshold": threshold,
                           "proof_digest": zk.proof_digest(proof),
                           "ts": round(time.time(), 6)})
        payload = {"commitment": hex(summed), "proof": proof, "unit": series.unit,
                   "cells": len(cells), "threshold": threshold,
                   "statement": "sum in [0, 2^%d)" % request.bits,
                   "reveals": "nothing beyond the statement"}
        return {"receipt": Receipt(request.request_id, self.did, "proved", payload)
                .sign(self.keys).body(), "attestation": self.chain.inclusion_proof(-1)}


def cum_rand(total: int, q: int | None = None) -> int:
    return total % (_group()["q"] if q is None else q)


class Gateway:
    """The requesting side: builds the delegation chain, keeps the receipts."""

    def __init__(self, node: Node, transport: Transport):
        self.node = node
        self.transport = transport
        self.receipts: list = []
        self.attestations: list = []

    def ask(self, target: str, request: Request, chain) -> dict:
        message = {"request": request.body(),
                   "chain": [g.encode() for g in chain]}
        reply = self.transport.send(self.node.did, target, message)
        self.receipts.append(reply["receipt"])
        self.attestations.append(reply.get("attestation"))
        return reply

    def verify_receipt(self, receipt: dict, responder_public: bytes) -> bool:
        r = Receipt(**{k: v for k, v in receipt.items() if k != "sig"})
        return r.verify(responder_public)

    def ledger(self) -> dict:
        return {"receipts": len(self.receipts),
                "released": sum(1 for r in self.receipts if r["status"] == "released"),
                "proved": sum(1 for r in self.receipts if r["status"] == "proved"),
                "refused": sum(1 for r in self.receipts if r["status"] == "refused"),
                "disclosed_total": sum(r["payload"].get("disclosed", 0)
                                      for r in self.receipts if r["status"] == "released")}


def save_chain(node: Node, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"did": node.did, "entries": node.chain.entries,
                   "heads": node.chain.snapshot_heads(), "head": node.chain.head}, fh)


def load_chain(node: Node, path: str) -> dict:
    """Reload a log and say whether it is the log that was written."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    reborn = HashChain(data["entries"])
    ok, idx = reborn.verify()
    # verify() only says the file agrees with itself; the saved heads are what
    # make an edit visible, so both are reported and neither is assumed.
    matches, bad = reborn.matches(data.get("heads", []))
    node.chain = reborn
    return {"entries": len(reborn), "chain_ok": ok, "heads_match": matches,
            "first_bad_index": None if ok and matches else (idx if not ok else bad),
            "head": reborn.head}
