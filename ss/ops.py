# Offline-first replication, for the site where the link is intermittent and the
# power is not guaranteed.
#
# The design rule is that there is no "primary": every node accepts writes
# whether or not it can see any other node, and merging is a function of the
# operations, never of the order they arrive in. Two data types carry the whole
# state:
#
#   Counter   one register per writer, merged by max. Concurrent increments from
#             two nodes both survive, which is what a case count needs.
#   Register  last-writer-wins on (lamport, node id). The node id breaks the tie
#             so the merge is total and the result is identical on both sides.
#
# On top of that: an outbox that holds operations until the peer acknowledges
# them, a sync that ships only what the peer does not have, and a policy cache
# that keeps decisions available -- and visibly stale -- while the gateway is
# unreachable.
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable

from .crypto import canonical, sha256_hex


@dataclass(frozen=True, order=True)
class Stamp:
    """Lamport clock plus writer id: a total order that needs no wall clock."""
    lamport: int
    node: str

    def next(self, node: str) -> "Stamp":
        return Stamp(self.lamport + 1, node)


@dataclass
class Op:
    op_id: str
    node: str
    lamport: int
    target: str          # "collection/key"
    kind: str            # "inc" | "set" | "add_member"
    arg: object = None
    ts: float = field(default_factory=time.time)

    def body(self) -> dict:
        return {"op_id": self.op_id, "node": self.node, "lamport": self.lamport,
                "target": self.target, "kind": self.kind, "arg": self.arg,
                "ts": round(self.ts, 6)}

    def digest(self) -> str:
        return sha256_hex(canonical(self.body()))

    @property
    def stamp(self) -> Stamp:
        return Stamp(self.lamport, self.node)


class Store:
    """Replicated state. merge() is commutative, associative and idempotent."""

    def __init__(self, node: str):
        self.node = node
        self.lamport = 0
        self.applied: dict = {}        # op_id -> Op, so a replay costs nothing
        self.ops: list = []            # in application order, for sync
        self.counters: dict = {}       # target -> {writer: value}
        self.registers: dict = {}      # target -> (Stamp, value)
        self.sets: dict = {}           # target -> {member: Stamp}
        self.clock = 0.0

    # -- writing -----------------------------------------------------------
    def _stamp(self) -> int:
        self.lamport += 1
        return self.lamport

    def _record(self, target: str, kind: str, arg) -> Op:
        lamport = self._stamp()
        op = Op(op_id=sha256_hex(canonical({"n": self.node, "t": target, "k": kind,
                                           "a": arg, "l": lamport, "c": self.clock}))[:32],
                node=self.node, lamport=lamport, target=target, kind=kind, arg=arg)
        self.apply(op)
        return op

    def inc(self, target: str, by: int = 1) -> Op:
        return self._record(target, "inc", by)

    def set(self, target: str, value) -> Op:
        return self._record(target, "set", value)

    def add_member(self, target: str, member: str, weight: int = 1) -> Op:
        return self._record(target, "add_member", {"member": member, "weight": weight})

    # -- merging -----------------------------------------------------------
    def apply(self, op: Op) -> bool:
        """True if the operation changed anything. A repeat returns False."""
        key = op.op_id
        if key in self.applied:
            self.lamport = max(self.lamport, op.lamport)
            return False
        self.applied[key] = op
        self.ops.append(op)
        self.lamport = max(self.lamport, op.lamport)
        self.clock = max(self.clock, op.ts)
        if op.kind == "inc":
            per_writer = self.counters.setdefault(op.target, {})
            per_writer[op.node] = per_writer.get(op.node, 0) + int(op.arg or 0)
        elif op.kind == "set":
            current = self.registers.get(op.target)
            if current is None or current[0] < op.stamp:
                self.registers[op.target] = (op.stamp, op.arg)
        elif op.kind == "add_member":
            members = self.sets.setdefault(op.target, {})
            member = op.arg["member"]
            weight = int(op.arg.get("weight", 1))
            if weight <= 0:
                members.pop(member, None)
            else:
                members[member] = op.stamp
        else:
            raise ValueError("unknown op kind %r" % op.kind)
        return True

    def merge(self, ops: Iterable[Op]) -> int:
        return sum(1 for op in ops if self.apply(op))

    # -- reading -----------------------------------------------------------
    def value(self, target: str):
        if target in self.counters:
            return sum(self.counters[target].values())
        if target in self.registers:
            return self.registers[target][1]
        if target in self.sets:
            return sorted(self.sets[target])
        return None

    def counters_view(self, target: str) -> dict:
        return dict(self.counters.get(target, {}))

    def snapshot(self) -> dict:
        return {"counters": {t: dict(w) for t, w in sorted(self.counters.items())},
                "registers": {t: [st.lamport, st.node, v]
                              for t, (st, v) in sorted(self.registers.items())},
                "sets": {t: sorted(m) for t, m in sorted(self.sets.items())}}

    def state_digest(self) -> str:
        return sha256_hex(canonical(self.snapshot()))

    def digest_map(self) -> dict:
        """What a peer needs to work out which operations to send."""
        return {op.op_id: 1 for op in self.ops}

    def missing(self, peer_ids: dict) -> list:
        return [op for op in self.ops if op.op_id not in peer_ids]

    def size(self) -> int:
        return len(self.ops)


class Outbox:
    """Operations written while the link was down, held until acknowledged.

    The retry budget is bounded on purpose: an outbox that grows without limit
    is a disk filling up in the field, which is how offline systems actually
    fail.
    """

    def __init__(self, store: Store, max_pending: int = 10000, max_attempts: int = 8):
        self.store = store
        self.pending: dict = {}
        self.max_pending = max_pending
        self.max_attempts = max_attempts
        self.attempts: dict = {}
        self.acked = 0
        self.dropped = 0

    def queue(self, op: Op) -> str:
        if len(self.pending) >= self.max_pending:
            raise RuntimeError("outbox full: %d pending" % len(self.pending))
        self.pending[op.op_id] = op
        self.attempts[op.op_id] = 0
        return op.op_id

    def batch(self, limit: int = 500) -> list:
        return list(self.pending.values())[:limit]

    def attempt(self, op_ids: list) -> None:
        for ident in op_ids:
            self.attempts[ident] = self.attempts.get(ident, 0) + 1

    def ack(self, op_ids: list) -> int:
        done = 0
        for ident in op_ids:
            if ident in self.pending:
                del self.pending[ident]
                self.attempts.pop(ident, None)
                done += 1
                self.acked += 1
        return done

    def give_up(self) -> list:
        dead = [ident for ident, n in self.attempts.items() if n >= self.max_attempts]
        for ident in dead:
            self.pending.pop(ident, None)
            self.attempts.pop(ident, None)
            self.dropped += 1
        return dead

    def depth(self) -> int:
        return len(self.pending)


def sync(a: Store, b: Store, limit: int | None = None) -> dict:
    """Two-way sync. Both sides end with the same state, whatever they started with."""
    a_ids, b_ids = a.digest_map(), b.digest_map()
    to_b = a.missing(b_ids)
    to_a = b.missing(a_ids)
    if limit is not None:
        to_b, to_a = to_b[:limit], to_a[:limit]
    applied_b = b.merge(to_b)
    applied_a = a.merge(to_a)
    return {"sent_to_b": len(to_b), "sent_to_a": len(to_a),
            "applied_b": applied_b, "applied_a": applied_a,
            "converged": a.state_digest() == b.state_digest(),
            "a_digest": a.state_digest(), "b_digest": b.state_digest()}


def replica_run(nodes: list, rounds: int = 6, rng=None, actions: int = 40) -> dict:
    """A partition and heal, played out, with the write count measured on each side.

    The cut is real in the only sense that matters here: during a round, a node
    only syncs with the nodes on its own side. At the end every pair syncs, and
    the report says whether the replicas agree and whether the counter equals the
    number of increments that were applied -- a write that was applied and then
    lost in a merge is the failure this function exists to catch.
    """
    import random
    rng = rng or random.Random(20261008)
    stores = {n: Store(n) for n in nodes}
    increments = 0
    for round_index in range(rounds):
        order = list(nodes)
        rng.shuffle(order)
        cut = max(1, len(order) // 2)
        for group in (order[:cut], order[cut:]):
            for _ in range(actions):
                writer = rng.choice(group)
                store = stores[writer]
                if rng.random() < 0.7:
                    store.inc("cases/total", 1)
                    increments += 1
                else:
                    store.set("policy/%s" % rng.choice(["storage", "retention"]),
                              "v%d-%s" % (round_index, writer))
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    sync(stores[group[i]], stores[group[j]])
    # heal: every pair, so no node is left holding only what it heard first-hand
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            sync(stores[nodes[i]], stores[nodes[j]])
    digests = {n: stores[n].state_digest() for n in nodes}
    total = stores[nodes[0]].value("cases/total")
    applied = stores[nodes[0]].size()
    return {"nodes": len(nodes), "rounds": rounds, "increments": increments,
            "operations": applied, "total": total, "lost": increments - total,
            "converged": len(set(digests.values())) == 1, "digests": digests}


@dataclass
class PolicyCache:
    """A decision that stays available, and visibly stale, when the link is gone."""
    policy: dict
    cached_at: float
    ttl_seconds: float = 3600.0

    def fresh(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return (now - self.cached_at) <= self.ttl_seconds

    def decide(self, question: str, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        fresh = self.fresh(now)
        return {"question": question, "answer": self.policy.get(question),
                "freshness": "current" if fresh else "stale",
                "age_seconds": round(now - self.cached_at, 3),
                "served_offline": not fresh,
                "requires_review": not fresh}
