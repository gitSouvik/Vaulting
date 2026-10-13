"""Command line interface:  python -m vaulting <command>"""
import argparse
import json
import os
import sys
import threading
import time

from .agent import GuardAgent
from .crypto import CryptoError, Keyring
from .providers import HashiCorpKVProvider
from .ratelimit import RateLimiter
from .rotation import RotationManager, http_dependent
from .sentinel import Sentinel
from .server import make_server
from .vault import Vault, VaultError
from .watcher import Watcher

DEFAULT_DB = os.environ.get("VAULTING_DB", "vaulting.db")


def _ts(t) -> str:
    return time.strftime("%H:%M:%S", time.localtime(t)) if t else "-"


def _providers_from_env() -> dict:
    addr = os.environ.get("VAULTING_HCV_ADDR")
    if not addr:
        return {}
    return {"hcv": HashiCorpKVProvider(
        addr, token=os.environ.get("VAULTING_HCV_TOKEN"),
        role_id=os.environ.get("VAULTING_HCV_ROLE_ID"),
        secret_id=os.environ.get("VAULTING_HCV_SECRET_ID"),
        mount=os.environ.get("VAULTING_HCV_MOUNT", "secret"),
        ca_file=os.environ.get("VAULTING_HCV_CA_FILE"))}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vaulting", description="Encrypted secrets service with a guard agent")
    p.add_argument("--db", default=DEFAULT_DB, help="SQLite path (env VAULTING_DB)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="generate a master key (does not touch the database)")
    s.add_argument("--id", default="k1")
    s.add_argument("--out", help="write to this file with 0600 permissions instead of printing")

    s = sub.add_parser("put", help="create a secret")
    s.add_argument("name")
    s.add_argument("--value", help="omit to generate a random one")

    s = sub.add_parser("register-app", help="create an app identity and print its token once")
    s.add_argument("app_id")
    s.add_argument("--grant", nargs="*", default=[], help="secret names (or provider paths) it may read")
    s.add_argument("--ttl-days", type=float, help="token lifetime; omit for no expiry")

    s = sub.add_parser("revoke-app", help="disable an app's token immediately")
    s.add_argument("app_id")

    s = sub.add_parser("rotate", help="rotate a secret now")
    s.add_argument("name")

    s = sub.add_parser("set-rotation", help="rotate a secret automatically every N hours (0 disables)")
    s.add_argument("name")
    s.add_argument("hours", type=float)

    sub.add_parser("rewrap", help="re-wrap all data keys under the active master key")

    s = sub.add_parser("serve", help="run the HTTP API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8200)
    s.add_argument("--ttl", type=int, default=30)
    s.add_argument("--tls-cert")
    s.add_argument("--tls-key")
    s.add_argument("--rate", type=float, default=20.0, help="requests/second per client IP")
    s.add_argument("--burst", type=int, default=40)

    s = sub.add_parser("scan", help="scan paths for leaked secrets")
    s.add_argument("paths", nargs="+")

    s = sub.add_parser("agent", help="let the guard agent handle pending findings")
    s.add_argument("--dependent", action="append", default=[], metavar="SECRET=URL")

    s = sub.add_parser("watch", help="loop: scheduled rotation, grace expiry, scanning, agent")
    s.add_argument("--paths", nargs="*", default=[], help="paths to scan each tick")
    s.add_argument("--interval", type=float, default=30.0)
    s.add_argument("--grace-seconds", type=float, default=300.0)
    s.add_argument("--dependent", action="append", default=[], metavar="SECRET=URL")

    s = sub.add_parser("audit", help="show recent access, findings and agent decisions")
    s.add_argument("--verify", action="store_true", help="verify the tamper-evident hash chain")

    sub.add_parser("status", help="print monitoring metrics as JSON")
    return p


def _manager(vault, specs) -> RotationManager:
    mgr = RotationManager(vault)
    for spec in specs:
        secret, url = spec.split("=", 1)
        mgr.register(secret, http_dependent(url, url))
    return mgr


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)

    if a.cmd == "keygen":
        entry = f"{a.id}:{Keyring.new_key_b64()}"
        if a.out:
            fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(entry + "\n")
            print(f"key written to {a.out} (0600). Use: export VAULTING_KEY_FILE={a.out}")
        else:
            print(f"export VAULTING_KEYS='{entry}'")
            print("# Store this in a secrets manager. Losing it means losing every secret.", file=sys.stderr)
        return 0

    try:
        vault = Vault(a.db, Keyring.from_env())
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    try:
        return _run(a, vault)
    except (VaultError, CryptoError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def _run(a, vault: Vault) -> int:
    if a.cmd == "put":
        r = vault.put_secret(a.name, a.value)
        print(f"created '{r['name']}' v{r['version']} (encrypted)")
    elif a.cmd == "register-app":
        ttl = a.ttl_days * 86400 if a.ttl_days else None
        token = vault.register_app(a.app_id, ttl)
        for name in a.grant:
            vault.grant(a.app_id, name)
        print(f"app '{a.app_id}' registered. Token (shown once): {token}")
    elif a.cmd == "revoke-app":
        vault.revoke_app(a.app_id)
        print(f"app '{a.app_id}' revoked")
    elif a.cmd == "rotate":
        r = vault.rotate(a.name, reason="manual")
        print(f"'{a.name}' v{r['old_version']} -> v{r['version']} (old version in grace)")
    elif a.cmd == "set-rotation":
        vault.set_rotation_policy(a.name, a.hours * 3600 if a.hours > 0 else None)
        print(f"'{a.name}' rotation: " + (f"every {a.hours}h" if a.hours > 0 else "disabled"))
    elif a.cmd == "rewrap":
        print(f"re-wrapped {vault.rewrap_all()} data key(s) under '{vault.keyring.active_id}'")
    elif a.cmd == "serve":
        admin = os.environ.get("VAULTING_ADMIN_TOKEN")
        srv = make_server(vault, a.host, a.port, a.ttl, providers=_providers_from_env(),
                          admin_token=admin, limiter=RateLimiter(a.rate, a.burst),
                          tls_cert=a.tls_cert, tls_key=a.tls_key)
        scheme = "https" if a.tls_cert else "http"
        print(f"vaulting listening on {scheme}://{a.host}:{srv.server_address[1]}")
        if not a.tls_cert and a.host not in ("127.0.0.1", "localhost"):
            print("WARNING: serving plain HTTP on a non-local address. Use --tls-cert/--tls-key.", file=sys.stderr)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nbye")
    elif a.cmd == "scan":
        found = Sentinel(vault).scan(a.paths)
        for f in found:
            print(f"[{f['severity']:<8}] {f['kind']:<22} {f['source']}  {f['detail']}")
        print(f"{len(found)} new finding(s)")
    elif a.cmd == "agent":
        for o in GuardAgent(vault, _manager(vault, a.dependent)).run_once():
            print(f"#{o['finding_id']} [{o['severity']}] {o['kind']} -> {o['action']} => {o['outcome']}")
            print(f"    thought: {o['thought']}")
            print(f"    result:  {o['result']}")
    elif a.cmd == "watch":
        mgr = _manager(vault, a.dependent)
        w = Watcher(vault, mgr, Sentinel(vault), GuardAgent(vault, mgr), a.paths, a.grace_seconds)
        stop = threading.Event()
        print(f"watching every {a.interval}s (Ctrl-C to stop)")
        try:
            w.run(a.interval, stop, on_tick=lambda r: print(_ts(time.time()), json.dumps(r)))
        except KeyboardInterrupt:
            stop.set()
            print("\nbye")
    elif a.cmd == "audit":
        if a.verify:
            r = vault.verify_audit_chain()
            print(f"audit chain: {'OK' if r['ok'] else 'TAMPERED at entry #' + str(r['bad_id'])} "
                  f"({r['entries']} entries verified)\nhead hash: {r['head']}")
            return 0 if r["ok"] else 3
        print("== recent access ==")
        for r in vault.recent_access(10):
            print(f"{_ts(r['ts'])} app={r['app_id']} secret={r['secret_name']} v={r['version']} {r['outcome']}")
        with vault.tx() as c:
            print("== findings ==")
            for r in c.execute("SELECT id, severity, kind, source, handled, outcome FROM findings ORDER BY id"):
                print(f"#{r['id']} [{r['severity']}] {r['kind']} {r['source']} handled={r['handled']} {r['outcome'] or ''}")
            print("== agent trace ==")
            for r in c.execute("SELECT run_id, step, action, result FROM agent_trace ORDER BY id"):
                print(f"run {r['run_id']} step {r['step']}: {r['action']} -> {r['result']}")
    elif a.cmd == "status":
        print(json.dumps(vault.metrics(), indent=2))
    return 0
