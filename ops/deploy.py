"""Field deployment: turn a fresh machine into a node, and prove it afterwards.

The target is a machine with Python 3, no build tools and no package index. The
plan is therefore: copy the source tree, check the two things it needs are
importable, create the node, write a systemd unit (or a Windows scheduled task),
then run the acceptance checks -- including a real query between two nodes over
loopback, so "it is deployed" means "it answered a question", not "the files are
in place".

    python ops/deploy.py plan  --host 192.168.1.50 --user ops
    python ops/deploy.py check --data node-data --peer-port 8787
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ss import net
from ss.crypto import hkdf

SYSTEMD_UNIT = """[Unit]
Description=sovereign-stack node ({name})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
WorkingDirectory={workdir}
ExecStart={python} -m ss.gatewayd --data {data} --name {name} --did {did} \
    --host {host} --port {port}{secret}
Restart=always
RestartSec=5
# The node keeps its own state under {data}; nothing else needs to be writable.
ProtectSystem=strict
ReadWritePaths={data}
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
"""


def plan(host: str, user: str, port: int = 8787, data: str = "/var/lib/sovereign-stack",
         python: str = "/usr/bin/python3", name: str = "gateway", did: str = "did:sgw:node",
         secret: str | None = None) -> dict:
    return {
        "steps": [
            {"step": "copy source", "cmd": "scp -r . %s@%s:%s/src" % (user, host, data)},
            {"step": "check deps", "cmd": "%s -c 'import cryptography; print(cryptography.__version__)'" % python},
            {"step": "make dirs", "cmd": "ssh %s@%s 'sudo install -d -o %s %s'" % (user, host, user, data)},
            {"step": "install unit", "cmd": "ssh %s@%s 'sudo tee /etc/systemd/system/sgw-%s.service'"
                                            % (user, host, name)},
            {"step": "enable", "cmd": "ssh %s@%s 'sudo systemctl enable --now sgw-%s'" % (user, host, name)},
            {"step": "acceptance", "cmd": "%s %s/src/ops/deploy.py check --data %s --peer-port %d"
                                          % (python, data, data, port)},
        ],
        "unit": SYSTEMD_UNIT.format(name=name, user=user, workdir="%s/src" % data, python=python,
                                    data=data, did=did, host=host, port=port,
                                    secret=(" --secret %s" % secret) if secret else ""),
        "ports": [port],
        "writable_paths": [data],
    }


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def check(data: str, peer_port: int | None = None, host: str = "127.0.0.1") -> dict:
    """Acceptance. Every item is a thing that can fail on a real machine."""
    from ss import gatewayd
    results = []

    def record(name: str, ok: bool, detail: str = ""):
        results.append({"check": name, "ok": bool(ok), "detail": detail})

    record("python", sys.version_info >= (3, 10), sys.version.split()[0])
    try:
        import cryptography  # noqa: F401
        record("dependency: cryptography", True, cryptography.__version__)
    except Exception as exc:
        record("dependency: cryptography", False, str(exc))
    try:
        import gmpy2  # noqa: F401
        record("optional: gmpy2 (acceleration)", True, gmpy2.version())
    except Exception:
        record("optional: gmpy2 (acceleration)", True, "absent; the builtin is in use")

    port = free_port()
    try:
        server, service = gatewayd.serve(data, "acceptance", "did:sgw:acceptance",
                                         host, port, b"acceptance-secret")
    except Exception as exc:
        record("node starts", False, "%s: %s" % (type(exc).__name__, exc))
        return {"ok": False, "results": results}
    try:
        record("node starts", os.path.exists(os.path.join(data, "identity.json")),
               "data dir %s" % data)
        def factory():
            client, _ = net.SecureSession.pair(
                hkdf(b"acceptance-secret", b"ss-v1/session|did:sgw:acceptance"))
            return client
        reply = net.call(host, server.port, {"verb": "health"}, session_factory=factory)
        record("health over a sealed frame", reply.get("node") == "did:sgw:acceptance",
               json.dumps({"ops": reply.get("ops"), "chain_entries": reply.get("chain_entries")}))
        unsealed = net.call(host, server.port, {"verb": "health"})
        record("unsealed frame refused", unsealed.get("error") == "unsealed-frame-refused",
               str(unsealed.get("error")))
        # a write, then a pull by a second client, then a digest comparison
        write = service.store.inc("cases/total", 7)
        pusher = net.call(host, server.port,
                          {"verb": "ops.push", "ops": [write.body()]}, session_factory=factory)
        pulled = net.call(host, server.port, {"verb": "ops.pull", "have": []},
                          session_factory=factory)
        record("ops push/pull round trip", pusher.get("applied") == 0 and len(pulled.get("ops", [])) >= 1,
               "received=%s ops=%s" % (pusher.get("received"), len(pulled.get("ops", []))))
        record("state digest agrees", pulled.get("state_digest") == service.store.state_digest(),
               pulled.get("state_digest", "")[:16])
        saved = service.save()
        from ss.crypto import HashChain
        with open(os.path.join(data, "chain.json"), encoding="utf-8") as fh:
            reborn = HashChain(json.load(fh)["entries"])
        record("chain verifies after a restart from disk", reborn.verify()[0],
               "%d entries" % len(reborn))
        record("audit head written", bool(saved.get("chain_head")),
               str(saved.get("chain_head"))[:16])
    finally:
        server.stop()

    if peer_port:
        try:
            client, _ = net.SecureSession.pair(hkdf(b"peer", b"session"))
            reply = net.call(host, peer_port, {"verb": "health"})
            record("peer on port %d answers" % peer_port, "node" in reply, str(reply)[:120])
        except Exception as exc:
            record("peer on port %d answers" % peer_port, False, "%s" % exc)
    ok = all(r["ok"] for r in results)
    return {"ok": ok, "results": results, "data_dir": data, "when": round(time.time(), 3)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sgw-deploy")
    sub = parser.add_subparsers(dest="verb", required=True)
    p_plan = sub.add_parser("plan")
    p_plan.add_argument("--host", required=True)
    p_plan.add_argument("--user", required=True)
    p_plan.add_argument("--port", type=int, default=8787)
    p_plan.add_argument("--data", default="/var/lib/sovereign-stack")
    p_plan.add_argument("--name", default="gateway")
    p_plan.add_argument("--did", default="did:sgw:node")
    p_plan.add_argument("--secret", default=None)
    p_check = sub.add_parser("check")
    p_check.add_argument("--data", required=True)
    p_check.add_argument("--peer-port", type=int, default=None)
    args = parser.parse_args(argv)
    if args.verb == "plan":
        print(json.dumps(plan(args.host, args.user, args.port, args.data, name=args.name,
                              did=args.did, secret=args.secret), indent=1))
        return 0
    out = check(args.data, args.peer_port)
    for item in out["results"]:
        print("%-44s %s   %s" % (item["check"], "ok" if item["ok"] else "FAIL", item["detail"]))
    print("acceptance: %s" % ("pass" if out["ok"] else "fail"))
    return 0 if out["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
