# Proofs over committed values. Not a zk-SNARK and not a circuit language: four
# named relations, each one chosen because a public-sector data exchange needs
# exactly it, and each one cheap enough to run in a laptop test.
#
#   dlog        knowledge of an opening       "this contribution is mine"
#   bit         an OR proof on a commitment   "my contribution is 0 or 1"
#   range       bit decomposition             "the total is under a threshold"
#   equality    Chaum-Pedersen                "both offices counted one person once"
#
# Soundness is in the random-oracle model: challenges come from SHA-256 over a
# canonical encoding of the statement and the first message (Fiat-Shamir). The
# group is the published RFC 3526 modulus in ss.crypto -- no trusted setup and
# no bespoke modulus, so nothing here can be back-doored by its own author.
from __future__ import annotations

import secrets

from .crypto import (canonical, commit, fiat_shamir, group, mod_inverse,
                     powmod, sha256_hex)


def _rand_scalar() -> int:
    q = group()["q"]
    return secrets.randbelow(q - 1) + 1


def _challenge(statement: dict, first: dict) -> int:
    return fiat_shamir(canonical({"d": "ss/v1/zk", "statement": statement,
                                  "first": first}))


# ---------------------------------------------------------------- dlog

def prove_dlog(base_name: str, base: int, public: int, witness: int,
               statement_extra: dict | None = None) -> dict:
    """Schnorr: knowledge of x with base^x = public (mod p)."""
    p, q = group()["p"], group()["q"]
    k = _rand_scalar()
    a = powmod(base, k, p)
    statement = {"kind": "dlog", "base": base_name, "public": hex(public),
                 **(statement_extra or {})}
    c = _challenge(statement, {"a": hex(a)})
    z = (k + c * (witness % q)) % q
    return {"kind": "dlog", "statement": statement, "a": hex(a), "z": z}


def verify_dlog(proof: dict) -> bool:
    p, q = group()["p"], group()["q"]
    base = group()[proof["statement"]["base"]]
    public = int(proof["statement"]["public"], 16)
    c = _challenge(proof["statement"], {"a": proof["a"]})
    lhs = powmod(base, proof["z"], p)
    rhs = int(proof["a"], 16) * powmod(public, c, p) % p
    return lhs == rhs and 0 <= proof["z"] < q


# ---------------------------------------------------------------- bit (OR proof)

def prove_bit(c: int, value: int, blind: int) -> dict:
    """C commits to 0 or to 1; the proof says so without saying which.

    Y0 = C is h^r exactly when value = 0, and Y1 = C/g is h^r exactly when
    value = 1. Each side is a dlog proof on base h, and the two challenges are
    forced to sum to the Fiat-Shamir challenge -- so one side can be answered
    honestly and the other must be simulated, and the verifier cannot tell which
    side is which. That is the whole of the OR.
    """
    if value not in (0, 1):
        raise ValueError("bit proof needs a value in {0, 1}")
    p, q, g, h = group()["p"], group()["q"], group()["g"], group()["h"]
    Y = [c % p, (c * mod_inverse(g, p)) % p]
    # value 0 of the committed number sits in Y0 = C, value 1 in Y1 = C/g;
    # in both cases the honest witness is the same blind r (see the docstring).
    witnesses = [blind % q, blind % q]

    k = _rand_scalar()
    a_real = powmod(h, k, p)
    c_fake = _rand_scalar()
    z_fake = _rand_scalar()
    a_fake = powmod(h, z_fake, p) * powmod(Y[1 - value], (q - c_fake) % q, p) % p

    a = [None, None]
    a[value] = hex(a_real)
    a[1 - value] = hex(a_fake)
    statement = {"kind": "bit", "commitment": hex(c)}
    ch = _challenge(statement, {"a0": a[0], "a1": a[1]})

    c_real = (ch - c_fake) % q
    z_real = (k + c_real * witnesses[value]) % q

    cs = [0, 0]
    zs = [0, 0]
    cs[value], zs[value] = c_real, z_real
    cs[1 - value], zs[1 - value] = c_fake, z_fake
    return {"kind": "bit", "statement": statement, "a": a, "c": cs, "z": zs}


def verify_bit(proof: dict) -> bool:
    p, q, g, h = group()["p"], group()["q"], group()["g"], group()["h"]
    c = int(proof["statement"]["commitment"], 16)
    Y = [c % p, (c * mod_inverse(g, p)) % p]
    ch = _challenge(proof["statement"], {"a0": proof["a"][0], "a1": proof["a"][1]})
    if (proof["c"][0] + proof["c"][1]) % q != ch:
        return False
    for i in (0, 1):
        lhs = powmod(h, proof["z"][i], p)
        rhs = int(proof["a"][i], 16) * powmod(Y[i], proof["c"][i], p) % p
        if lhs != rhs:
            return False
    return True


# ---------------------------------------------------------------- range

def prove_range(total: int, blind: int, bits: int = 16) -> dict:
    """Total is in [0, 2^bits), shown from bit commitments of the total itself.

    The committed value is decomposed, each bit is proved to be a bit, and the
    folded commitments are proved to reconstruct the original -- so the range
    is a statement about the same number the total commits to, not about a
    second number that happens to be small.
    """
    if total < 0 or total >= (1 << bits):
        raise ValueError("value outside the declared range")
    p, q, g, h = group()["p"], group()["q"], group()["g"], group()["h"]
    bit_commits, bit_proofs, blinds = [], [], []
    for i in range(bits):
        b = (total >> i) & 1
        cb, rb = commit(b)
        bit_commits.append(cb)
        blinds.append(rb)
        bit_proofs.append(prove_bit(cb, b, rb))
    acc = 1
    for i, cb in enumerate(bit_commits):
        acc = acc * powmod(cb, 1 << i, p) % p
    # acc = g^total * h^R with R = sum r_i 2^i, so C/acc = h^(blind - R):
    # a dlog statement on base h whose witness is the difference of blinds.
    C = powmod(g, total % q, p) * powmod(h, blind % q, p) % p
    residual = C * mod_inverse(acc, p) % p
    fold = prove_dlog("h", h, residual, (blind - sum(blinds[i] * (1 << i) for i in range(bits))) % q,
                      {"role": "fold", "bits": bits})
    return {"kind": "range", "bits": bits, "commitment": hex(C),
            "bit_commitments": [hex(x) for x in bit_commits],
            "bit_proofs": bit_proofs, "fold": fold}


def verify_range(proof: dict) -> bool:
    p, q, g, h = group()["p"], group()["q"], group()["g"], group()["h"]
    bits = proof["bits"]
    if len(proof["bit_commitments"]) != bits or len(proof["bit_proofs"]) != bits:
        return False
    acc = 1
    for i, cb in enumerate(proof["bit_commitments"]):
        if not verify_bit(proof["bit_proofs"][i]):
            return False
        if int(proof["bit_proofs"][i]["statement"]["commitment"], 16) != int(cb, 16):
            return False   # a bit proof for a different commitment proves nothing
        acc = acc * powmod(int(cb, 16), 1 << i, p) % p
    residual = int(proof["commitment"], 16) * mod_inverse(acc, p) % p
    fold = proof["fold"]
    if int(fold["statement"]["public"], 16) != residual:
        return False
    return verify_dlog(fold)


# ---------------------------------------------------------------- equality

def prove_equality(pairs: list[tuple[int, int]], witness: int, context: dict) -> dict:
    """Chaum-Pedersen across several (Y = X^x) pairs at once.

    Used for the case an exchange actually exists to serve: two jurisdictions
    each publish a pseudonymous commitment to the same person, and the proof
    says both commitments hide the same identifier without revealing it.
    """
    p, q = group()["p"], group()["q"]
    k = _rand_scalar()
    first = [hex(powmod(X, k, p)) for X, _ in pairs]
    statement = {"kind": "equality", "pairs": [[hex(X), hex(Y)] for X, Y in pairs],
                 "context": context}
    c = _challenge(statement, {"t": first})
    z = (k + c * (witness % q)) % q
    return {"kind": "equality", "statement": statement, "t": first, "z": z}


def verify_equality(proof: dict) -> bool:
    p, q = group()["p"], group()["q"]
    c = _challenge(proof["statement"], {"t": proof["t"]})
    for (Xh, Yh), t in zip(proof["statement"]["pairs"], proof["t"]):
        X, Y = int(Xh, 16), int(Yh, 16)
        if powmod(X, proof["z"], p) != int(t, 16) * powmod(Y, c, p) % p:
            return False
    return 0 <= proof["z"] < q


VERIFIERS = {"dlog": verify_dlog, "bit": verify_bit, "range": verify_range,
             "equality": verify_equality}


def verify(proof: dict) -> bool:
    fn = VERIFIERS.get(proof.get("kind"))
    return bool(fn and fn(proof))


def proof_digest(proof: dict) -> str:
    return sha256_hex(canonical(proof))
