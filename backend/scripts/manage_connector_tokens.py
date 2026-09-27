"""OpenDRP Connector Credential CLI.

Every connector authenticates with its **own** token, so a leaked credential can
be revoked for one connector without re-keying the others, and a token cannot be
replayed as a different connector. There is no platform-wide connector secret.

The plaintext token exists only in the output of this command: the core stores a
SHA-256 digest, so a lost token is rotated, never recovered.

Run INSIDE the backend container (so DB env and venv are wired correctly):

    # Bootstrap a connector for the first time (creates its registry row):
    docker compose exec backend python -m scripts.manage_connector_tokens issue connector-hibp --type breaches --env CONNECTOR_TOKEN_HIBP

    # Rotate a leaked credential (the previous token stops working immediately):
    docker compose exec backend python -m scripts.manage_connector_tokens rotate connector-hibp --env CONNECTOR_TOKEN_HIBP

    # Cut a connector off without deleting its history:
    docker compose exec backend python -m scripts.manage_connector_tokens revoke connector-hibp

    # See which connectors have credentials (prefixes only, never the secret):
    docker compose exec backend python -m scripts.manage_connector_tokens list
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.models import Connector
from app.services.connector_credentials import ConnectorCredentials
from app.services.connector_service import ConnectorService, normalize_connector_name
from app.services.module_registry import load_modules


def _print_token(name: str, token: str, env_var: str | None) -> None:
    print()
    print("[OK] Credential issued. This value is shown once and cannot be recovered.")
    if env_var:
        print(f"     {env_var}={token}")
    else:
        print(f"     {token}")
    print()
    print(f"     Set it in the environment of the '{name}' connector container,")
    print("     then recreate that container (`docker compose up -d <service>`).")
    print("     A plain `docker compose restart` is not enough: a container keeps")
    print("     the environment it was created with.")
    print("     Never commit it or paste it into a ticket.")
    print()


async def cmd_issue(name: str, connector_type: str, env_var: str | None) -> None:
    clean = normalize_connector_name(name)
    async with AsyncSessionLocal() as db:
        svc = ConnectorService(db)
        # Modules are data: the operator is told which ones exist rather than
        # guessing from a list baked into this CLI.
        specs = await load_modules(db)
        module = specs.get(str(connector_type or "").strip().lower())
        if module is None:
            print(
                f"[ERROR] unknown module '{connector_type}'. "
                f"Registered modules: {sorted(specs)}"
            )
            sys.exit(2)
        if not module.enabled:
            print(
                f"[ERROR] module '{module.id}' is disabled. Enable it in the UI "
                "(or via PATCH /modules/{id}) before provisioning a connector for it."
            )
            sys.exit(2)
        existing = await svc.get_by_name(clean)
        if existing is None:
            # Provisioning creates the row: the connector cannot register
            # itself before a credential exists.
            existing = await svc.register(name=clean, connector_type=connector_type)
            print(f"[INFO] Registered connector '{clean}' (type={connector_type}).")
        elif existing.connector_type != connector_type:
            print(
                f"[ERROR] Connector '{clean}' is already registered as type "
                f"'{existing.connector_type}'. Use 'rotate' to re-key it, or pick "
                f"another name."
            )
            sys.exit(2)
        elif existing.has_token:
            print(
                f"[ERROR] Connector '{clean}' already has a credential. Use "
                f"'rotate' to replace it (the old token stops working), or "
                f"'revoke' to drop it."
            )
            sys.exit(2)
        token, _ = await ConnectorCredentials(db).issue(existing)

    _print_token(clean, token, env_var)


async def cmd_rotate(name: str, env_var: str | None) -> None:
    clean = normalize_connector_name(name)
    async with AsyncSessionLocal() as db:
        connector = await ConnectorService(db).get_by_name(clean)
        if connector is None:
            print(f"[ERROR] Connector '{clean}' is not registered. Use 'issue' first.")
            sys.exit(2)
        token, _ = await ConnectorCredentials(db).issue(connector)

    print("[INFO] Previous credential revoked; the old token is rejected from now on.")
    _print_token(clean, token, env_var)


async def cmd_revoke(name: str) -> None:
    clean = normalize_connector_name(name)
    async with AsyncSessionLocal() as db:
        connector = await ConnectorService(db).get_by_name(clean)
        if connector is None:
            print(f"[ERROR] Connector '{clean}' is not registered.")
            sys.exit(2)
        if not connector.has_token:
            print(f"[SKIP] Connector '{clean}' has no credential to revoke.")
            return
        await ConnectorCredentials(db).revoke(connector)
    print(f"[OK] Credential for '{clean}' revoked. Its registry row and history remain.")


async def cmd_list() -> None:
    async with AsyncSessionLocal() as db:
        rows = list((await db.execute(select(Connector).order_by(Connector.name))).scalars().all())
        if not rows:
            print("[INFO] No connectors registered yet. Use 'issue' to bootstrap one.")
            return
        print(f"[INFO] Connectors: {len(rows)}\n")
        print(f"{'NAME':<28} {'TYPE':<10} {'TOKEN':<10} {'PREFIX':<18} {'LAST USED'}")
        print("-" * 100)
        for conn in rows:
            state = "issued" if conn.has_token else "none"
            print(
                f"{conn.name:<28} {conn.connector_type:<10} {state:<10} "
                f"{conn.token_prefix or '-':<18} "
                f"{conn.token_last_used_at.isoformat() if conn.token_last_used_at else '-'}"
            )
        missing = [conn.name for conn in rows if not conn.has_token]
        if missing:
            print(
                "\n[WARN] Without a credential these connectors cannot poll for "
                "work: " + ", ".join(missing)
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="manage_connector_tokens",
        description="Issue, rotate and revoke per-connector credentials.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m scripts.manage_connector_tokens issue connector-hibp "
            "--type breaches --env CONNECTOR_TOKEN_HIBP\n"
            "  python -m scripts.manage_connector_tokens rotate connector-hibp\n"
            "  python -m scripts.manage_connector_tokens revoke connector-hibp\n"
            "  python -m scripts.manage_connector_tokens list\n"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_issue = sub.add_parser("issue", help="Provision a connector and issue its token")
    p_issue.add_argument("name", help="Connector name (as CONNECTOR_NAME in its container)")
    p_issue.add_argument(
        "-t",
        "--type",
        required=True,
        help="Module the connector feeds (must be registered on the core)",
    )
    p_issue.add_argument(
        "-e",
        "--env",
        default=None,
        help="Print the token as '<ENV_VAR>=<token>' for pasting into .env",
    )

    p_rotate = sub.add_parser("rotate", help="Replace a connector's token")
    p_rotate.add_argument("name", help="Connector name")
    p_rotate.add_argument("-e", "--env", default=None, help="Print as '<ENV_VAR>=<token>'")

    p_revoke = sub.add_parser("revoke", help="Drop a connector's token")
    p_revoke.add_argument("name", help="Connector name")

    sub.add_parser("list", help="List connectors and their credential state")

    args = parser.parse_args()

    if args.command == "issue":
        asyncio.run(cmd_issue(args.name, args.type, args.env))
    elif args.command == "rotate":
        asyncio.run(cmd_rotate(args.name, args.env))
    elif args.command == "revoke":
        asyncio.run(cmd_revoke(args.name))
    elif args.command == "list":
        asyncio.run(cmd_list())
    else:  # pragma: no cover
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
