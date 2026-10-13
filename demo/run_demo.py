"""End-to-end demo: a secret leaks into a log file and the system fixes itself.

Run from the repo root:  python -m demo.run_demo
"""
import json
import os
import tempfile
import urllib.request

from demo.toy_app import ToyApp
from vaulting.agent import GuardAgent
from vaulting.client import VaultingClient
from vaulting.crypto import Keyring
from vaulting.rotation import RotationManager, http_dependent
from vaulting.sentinel import Sentinel
from vaulting.server import make_server, serve_in_thread
from vaulting.vault import Vault

SECRET = "orders_db_password"


def step(n, title):
    print(f"\n\033[1m[{n}] {title}\033[0m")


def whoami(app):
    with urllib.request.urlopen(app.url + "/whoami") as r:
        return json.loads(r.read())["secret_version"]


def main():
    work = tempfile.mkdtemp(prefix="vaulting-demo-")
    vault = Vault(os.path.join(work, "demo.db"), Keyring.generate())

    step(1, "Boot the vault, register an app, start a service that uses the secret")
    vault.put_secret(SECRET)
    token = vault.register_app("orders-api")
    vault.grant("orders-api", SECRET)
    server = make_server(vault, ttl=300)  # long TTL: the app WON'T notice rotation by itself
    serve_in_thread(server)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    app = ToyApp(VaultingClient(base, token), SECRET).start()
    print(f"   vault  {base}\n   app    {app.url}  using secret v{whoami(app)}")

    step(2, "A developer accidentally logs the live password")
    leaked = vault.get_active(SECRET)["value"]
    logdir = os.path.join(work, "logs")
    os.makedirs(logdir)
    with open(os.path.join(logdir, "app.log"), "w") as fh:
        fh.write("INFO  server started on :8080\n")
        fh.write(f"DEBUG connecting to db with password={leaked}\n")
        fh.write("DEBUG aws key AKIAIOSFODNN7EXAMPLE found in env dump\n")
    print(f"   wrote {logdir}/app.log")

    step(3, "Sentinel scans the logs")
    for f in Sentinel(vault).scan([logdir]):
        print(f"   [{f['severity']:<8}] {f['kind']:<20} {f['detail']}")

    step(4, "Guard agent decides what to do")
    mgr = RotationManager(vault)
    mgr.register(SECRET, http_dependent("orders-api", app.url))
    for o in GuardAgent(vault, mgr).run_once():
        print(f"   #{o['finding_id']} {o['kind']} -> {o['action']} => {o['outcome']}")
        print(f"      why:    {o['thought']}")
        print(f"      result: {o['result']}")

    step(5, "Verify")
    print(f"   service now on secret v{whoami(app)}, still healthy: "
          f"{urllib.request.urlopen(app.url + '/health').status == 200}")
    print(f"   leaked value still valid in vault? {vault.validate(SECRET, leaked)}")
    print("   version history:", [(v['version'], v['status']) for v in vault.versions(SECRET)])

    server.shutdown()
    server.server_close()
    app.stop()


if __name__ == "__main__":
    main()
