# Participant identity, and the delegation rule that decides what a node may
# be asked for.
#
# A DID here is self-certifying: the identifier is derived from the public key,
# so a document cannot claim an identity its key does not hold. Delegation is a
# signed grant of scope, and a chain of grants resolves only if every hop
# narrows what the hop before it held. That narrowing rule is the whole point:
# a gateway that accepts a chain it cannot walk is a gateway that will answer a
# query the identity was never entitled to make.
from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import KeyPair, canonical, sha256_hex, verify_signature


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw)


def did_for(public: bytes) -> str:
    return "did:sgw:" + sha256_hex(public)[:32]


# The vocabulary. query.record exists so that it can be granted and still
# refused: record.lookup is not a permission question in this design.
SCOPES = ("query.aggregate", "query.distinct", "query.record", "audit.read",
          "audit.attest", "node.admin", "evidence.submit")

STATEMENT_CLASSES = ("case_count", "case_ratio", "facility_count",
                     "record_digest", "control_status", "operational_metric")


@dataclass
class DidDocument:
    name: str
    public: bytes
    endpoint: str
    scopes: frozenset
    issued_at: float = field(default_factory=time.time)
    expires_at: float | None = None

    def __post_init__(self):
        self.scopes = frozenset(self.scopes)

    @property
    def did(self) -> str:
        return did_for(self.public)

    @property
    def created(self) -> float:
        return self.issued_at

    def body(self) -> dict:
        return {"did": self.did, "name": self.name, "endpoint": self.endpoint,
                "scopes": sorted(self.scopes),
                "issued_at": round(self.issued_at, 6),
                "expires_at": None if self.expires_at is None else round(self.expires_at, 6)}

    def sign(self, kp: KeyPair) -> dict:
        body = self.body()
        if kp.public != self.public:
            raise ValueError("signing key does not match the DID in this document")
        return {**body, "sig": b64(kp.sign(canonical(body)))}

    def encode(self, kp: KeyPair) -> dict:
        """A self-contained document: the key travels with it, so it resolves offline."""
        doc = self.sign(kp)
        doc["public"] = b64(self.public)
        return doc


def resolve(document: dict, now: float | None = None) -> tuple[bool, str]:
    """Two checks, in the order a verifier must make them.

    The identifier is recomputed from the key in the document (self-certification),
    and only then is the signature checked. Doing it the other way round would
    verify a document against a key the document itself chose.
    """
    now = time.time() if now is None else now
    if "public" not in document or "sig" not in document:
        return False, "malformed"
    try:
        public = unb64(document["public"])
        Ed25519PublicKey.from_public_bytes(public)
    except Exception:
        return False, "bad-key"
    body = {k: v for k, v in document.items() if k not in ("sig", "public")}
    if body.get("did") != did_for(public):
        return False, "id-not-derived-from-key"
    if not verify_signature(public, canonical(body), unb64(document["sig"])):
        return False, "bad-signature"
    exp = body.get("expires_at")
    if exp is not None and now > exp:
        return False, "expired"
    return True, "ok"


@dataclass
class Delegation:
    grantor: str
    grantee: str
    scopes: frozenset
    statement_classes: frozenset
    issued_at: float
    expires_at: float
    purpose: str = ""
    sig: str = ""

    def __post_init__(self):
        # Grants travel as JSON, where a set is a list. Coercing here means a
        # deserialised grant is compared as a set, not compared lexicographically
        # as a list -- which would silently answer "widened" for every chain.
        self.scopes = frozenset(self.scopes)
        self.statement_classes = frozenset(self.statement_classes)

    def body(self) -> dict:
        return {"grantor": self.grantor, "grantee": self.grantee,
                "scopes": sorted(self.scopes),
                "statement_classes": sorted(self.statement_classes),
                "issued_at": round(self.issued_at, 6),
                "expires_at": round(self.expires_at, 6),
                "purpose": self.purpose}

    def digest(self) -> str:
        return sha256_hex(canonical(self.body()))

    def sign(self, kp: KeyPair) -> "Delegation":
        self.sig = b64(kp.sign(canonical(self.body())))
        return self

    def encode(self) -> dict:
        return {**self.body(), "sig": self.sig, "digest": self.digest()}


def chain_ok(chain: list[Delegation], keys: dict, now: float,
             revoked: set | None = None) -> tuple[bool, str]:
    """Walk root-first. Signed, live, unrevoked, and never widening the parent."""
    revoked = revoked or set()
    if not chain:
        return False, "empty-chain"
    carried = None
    for i, grant in enumerate(chain):
        public = keys.get(grant.grantor)
        if public is None:
            return False, "unknown-grantor@%d" % i
        if grant.digest() in revoked:
            return False, "revoked@%d" % i
        if not verify_signature(public, canonical(grant.body()), unb64(grant.sig)):
            return False, "bad-signature@%d" % i
        if now > grant.expires_at:
            return False, "expired@%d" % i
        if grant.issued_at > now + 60:
            return False, "not-yet-valid@%d" % i
        if carried is not None:
            if not grant.scopes <= carried[0]:
                return False, "scope-widened@%d" % i
            if not grant.statement_classes <= carried[1]:
                return False, "class-widened@%d" % i
        carried = (grant.scopes, grant.statement_classes)
    return True, "ok"


def entitlements(chain: list[Delegation]) -> tuple[frozenset, frozenset]:
    """Effective rights = the leaf grant, since every hop was verified to narrow."""
    return chain[-1].scopes, chain[-1].statement_classes


def may(chain: list[Delegation], scope: str, statement_class: str, keys: dict,
        now: float, revoked: set | None = None,
        requester: str | None = None) -> tuple[bool, str]:
    """The gate. Rights belong to the grantee of the leaf grant, and to nobody else."""
    ok, why = chain_ok(chain, keys, now, revoked)
    if not ok:
        return False, why
    if requester is not None and chain[-1].grantee != requester:
        return False, "not-the-grantee"
    scopes, classes = entitlements(chain)
    if scope not in scopes:
        return False, "scope-not-held"
    if statement_class not in classes:
        return False, "class-not-held"
    return True, "ok"


def revoke(chain: list[Delegation], index: int) -> set:
    """Cutting a link in the middle kills everything under it, not just that hop."""
    return {g.digest() for g in chain[index:]}


def scope_report(chain: list[Delegation]) -> dict:
    scopes, classes = entitlements(chain)
    return {"hops": len(chain), "scopes": sorted(scopes),
            "statement_classes": sorted(classes),
            "leaf": chain[-1].grantee, "root": chain[0].grantor,
            "narrows": all(chain[i].scopes >= chain[i + 1].scopes
                           for i in range(len(chain) - 1))}
