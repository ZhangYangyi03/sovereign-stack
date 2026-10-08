# Primitives, all standard, each checked against a second implementation.
#
# Ed25519 signatures, HMAC-SHA256 for the audit chain, HKDF-SHA256 for key
# separation, AES-GCM for the encrypted channel, and one Schnorr group from
# RFC 3526 for the commitment work -- a published group rather than a bespoke
# modulus, because a bespoke modulus is indistinguishable from a trapdoor.
#
# The group is re-verified at import: p and q=(p-1)/2 are tested for primality,
# the generator is confirmed to have order q, and the Pedersen base h is derived
# so that nobody, including this file, knows log_g h.
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from functools import lru_cache

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


# Modular exponentiation is the whole cost of the commitment work, so it is the
# one place worth an optional accelerator. gmpy2 is used when it is installed and
# the builtin is used when it is not -- the same group, the same results, one
# number in the benchmark that says which was in play.
try:  # pragma: no cover - environment dependent
    import gmpy2
    _BACKEND = "gmpy2"

    def powmod(base: int, exp: int, mod: int) -> int:
        return int(gmpy2.powmod(int(base), int(exp), int(mod)))
except Exception:  # pragma: no cover
    _BACKEND = "native"

    def powmod(base: int, exp: int, mod: int) -> int:
        return pow(base, exp, mod)


def pow_backend() -> str:
    return _BACKEND


def mod_inverse(x: int, mod: int) -> int:
    return powmod(x, mod - 2, mod)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> bytes:
    # Deterministic JSON: sorted keys, fixed separators, floats at 12dp.
    def norm(x):
        if isinstance(x, float):
            return round(x, 12)
        if isinstance(x, dict):
            return {k: norm(v) for k, v in sorted(x.items())}
        if isinstance(x, (list, tuple)):
            return [norm(v) for v in x]
        return x
    return json.dumps(norm(obj), separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def hkdf(ikm: bytes, info: bytes, length: int = 32, salt: bytes = b"ss-v1") -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=info).derive(ikm)


@dataclass(frozen=True)
class KeyPair:
    private: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "KeyPair":
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def at(cls, index: int) -> "KeyPair":
        # Reproducible keys, for tests and for the benchmark harness.
        return cls.from_seed(hashlib.sha256(b"ss-v1-key/%d" % index).digest())

    @property
    def public(self) -> bytes:
        return self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @property
    def seed(self) -> bytes:
        return self.private.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())

    def sign(self, msg: bytes) -> bytes:
        return self.private.sign(msg)


def verify_signature(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except Exception:
        return False


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    # AES-GCM with the associated data bound in, so a payload cannot be replayed
    # into a different request than the one it was sealed for.
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


# ---------------------------------------------------------------- Schnorr group

def miller_rabin(n: int, rounds: int = 20) -> bool:
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


@lru_cache(maxsize=1)
def group() -> dict:
    # Fails loudly rather than silently if the group file is not what it claims.
    with open(os.path.join(_DATA, "modp14.json"), encoding="utf-8") as fh:
        spec = json.load(fh)
    p = int(spec["p_hex"], 16)
    q = (p - 1) // 2
    assert p.bit_length() == 2048, "not the 2048-bit MODP group"
    assert sha256_hex(spec["p_hex"].encode()) == spec["sha256_p_hex"], "group file edited"
    assert miller_rabin(p, 16) and miller_rabin(q, 16), "modulus fails primality"
    g = 2
    assert pow(g, q, p) == 1 and pow(g, 2, p) != 1, "generator has the wrong order"
    h = powmod(int(hashlib.sha256(b"ss/v1/pedersen/h").hexdigest(), 16) % p, 2, p)
    assert h not in (1, g) and pow(h, q, p) == 1, "Pedersen base is degenerate"
    return {"p": p, "q": q, "g": g, "h": h, "source": spec["source"]}


def commit(value: int, blind: int | None = None) -> tuple[int, int]:
    # Pedersen: C = g^value * h^blind. Perfectly hiding; binding on dlog.
    G = group()
    if blind is None:
        blind = secrets.randbelow(G["q"] - 1) + 1
    c = powmod(G["g"], value % G["q"], G["p"]) * powmod(G["h"], blind, G["p"]) % G["p"]
    return c, blind


def commit_open(c: int, value: int, blind: int) -> bool:
    G = group()
    return c == (powmod(G["g"], value % G["q"], G["p"])
                 * powmod(G["h"], blind, G["p"]) % G["p"])


def commit_homomorphic(c1: int, c2: int) -> int:
    # C(v1) * C(v2) commits to v1+v2 with nobody revealing either value.
    return c1 * c2 % group()["p"]


def fiat_shamir(challenge_input: bytes) -> int:
    return int.from_bytes(hashlib.sha256(challenge_input).digest(), "big") % group()["q"]


# ---------------------------------------------------------------- audit chain

class HashChain:
    # Append-only log: each entry commits to the digest before it. The seam it
    # exists for is that an evidence pack is worthless if entries can be dropped
    # or reordered, so the log says which entry it is and what the whole prefix
    # hashes to. verify() recomputes from genesis; verify_inclusion() lets a
    # third party check a single entry without holding the rest.

    GENESIS = "0" * 64

    def __init__(self, entries=None):
        self.entries: list[dict] = []
        self.heads: list[str] = []
        for e in entries or []:
            self.append(e)

    @staticmethod
    def _digest(prev: str, entry: dict) -> str:
        return hmac.new(prev.encode(), canonical(entry), hashlib.sha256).hexdigest()

    def append(self, entry: dict) -> str:
        # The position is part of the entry, not of the container, so a log that
        # has had an entry dropped or moved cannot be made to verify by rebuilding
        # it: the surviving entries would sit at the wrong index and say so.
        stamped = json.loads(json.dumps(entry))
        if "seq" not in stamped:
            stamped["seq"] = len(self.entries)
        prev = self.heads[-1] if self.heads else self.GENESIS
        d = self._digest(prev, stamped)
        self.entries.append(stamped)
        self.heads.append(d)
        return d

    @property
    def head(self) -> str:
        return self.heads[-1] if self.heads else self.GENESIS

    def __len__(self) -> int:
        return len(self.entries)

    def inclusion_proof(self, index: int) -> dict:
        n = len(self.entries)
        idx = index if index >= 0 else n + index
        if not 0 <= idx < n:
            raise IndexError(index)
        return {"index": idx, "length": idx + 1, "entry": self.entries[idx],
                "prev_head": self.heads[idx - 1] if idx else self.GENESIS,
                "head": self.heads[idx]}

    @staticmethod
    def verify_inclusion(proof: dict) -> bool:
        return hmac.compare_digest(HashChain._digest(proof["prev_head"],
                                                   proof["entry"]),
                                   proof["head"])

    def verify(self) -> tuple[bool, int]:
        """Recompute from genesis. Reports the first index that does not hold.

        Two things are checked at each index: that the entry sits where it says
        it does, and that the digest recomputes over the entry as written.
        """
        prev = self.GENESIS
        for i, e in enumerate(self.entries):
            if e.get("seq") != i:
                return False, i
            prev = self._digest(prev, e)
            if not hmac.compare_digest(prev, self.heads[i]):
                return False, i
        return True, len(self.entries)

    def snapshot_heads(self) -> list[str]:
        return list(self.heads)

    def matches(self, saved_heads: list[str]) -> tuple[bool, int]:
        """Compare against heads recorded elsewhere.

        This is the check that actually catches an edit, and the reason it has to
        be separate from verify() is worth stating: rebuilding a chain from its
        entries recomputes its own heads, so verify() on a *loaded* log can only
        ever say that the file is internally consistent. A rewrite that is
        internally consistent is exactly what an attacker produces. The heads
        have to come from somewhere the attacker did not write.
        """
        if len(saved_heads) != len(self.heads):
            return False, min(len(saved_heads), len(self.heads))
        for i, (a, b) in enumerate(zip(saved_heads, self.heads)):
            if not hmac.compare_digest(a, b):
                return False, i
        return True, len(self.heads)

    def detect_rewrite(self, old_heads: list[str]) -> dict:
        # What a retained copy of the heads alone can say about a log shown later.
        common = 0
        for a, b in zip(old_heads, self.heads):
            if a != b:
                break
            common += 1
        return {"common_prefix": common, "appended": len(self.heads) - common,
                "rewritten": len(old_heads) > common,
                "intact": common == len(old_heads)}


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return sha256_hex(b"")
    level = list(leaves)
    while len(level) > 1:
        level = [sha256_hex((level[i] + (level[i + 1] if i + 1 < len(level)
                             else level[i])).encode())
                 for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaves: list[str], index: int) -> list[tuple[str, str]]:
    # (sibling, side) path from a leaf to the root.
    path: list[tuple[str, str]] = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        sib = idx ^ 1
        if sib >= len(level):
            path.append((level[idx], "dup"))
        else:
            path.append((level[sib], "left" if sib < idx else "right"))
        level = [sha256_hex((level[i] + (level[i + 1] if i + 1 < len(level)
                             else level[i])).encode())
                 for i in range(0, len(level), 2)]
        idx //= 2
    return path


def merkle_verify(leaf: str, path, root: str) -> bool:
    cur = leaf
    for sib, side in path:
        if side == "left":
            cur = sha256_hex((sib + cur).encode())
        elif side == "right":
            cur = sha256_hex((cur + sib).encode())
        else:
            cur = sha256_hex((cur + cur).encode())
    return hmac.compare_digest(cur, root)
