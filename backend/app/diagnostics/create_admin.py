"""Create the first platform administrator.

Sign-in credentials are managed through the API, but the very first
administrator has to come from somewhere: there is nobody to authorise creating
them. This command fills that gap and nothing else.

    python -m app.diagnostics.create_admin --email ops@example.com --name "Ops"

The password is read from the terminal without echoing it, or from the
``NETSHIELD_ADMIN_PASSWORD`` environment variable for unattended provisioning.
It is never passed as an argument, which would put it in the shell history and
in the process list.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import func, select

from app.core.logging import configure_logging, get_logger
from app.core.passwords import MIN_PASSWORD_LENGTH, PasswordTooWeakError, hash_password
from app.db.session import session_scope
from app.models import User, UserRole

logger = get_logger(__name__)

#: Name of the environment variable consulted when no terminal is available.
#: This is the variable's name, not a credential; the linter flags the
#: identifier rather than the value.
PASSWORD_ENV_VAR = "NETSHIELD_ADMIN_PASSWORD"  # noqa: S105  # nosec B105


def _build_parser() -> argparse.ArgumentParser:
    """Define the command line."""
    parser = argparse.ArgumentParser(description="Create a NetShield-ISP platform administrator.")
    parser.add_argument("--email", required=True, help="Sign-in address.")
    parser.add_argument("--name", required=True, help="Display name.")
    parser.add_argument(
        "--allow-additional",
        action="store_true",
        help="Create the account even when an administrator already exists.",
    )
    return parser


def _read_password() -> str:
    """Obtain the password without putting it in the shell history."""
    from_env = os.environ.get(PASSWORD_ENV_VAR)
    if from_env:
        return from_env

    if not sys.stdin.isatty():
        msg = (
            f"No terminal available. Set {PASSWORD_ENV_VAR} to provision "
            "an administrator without one."
        )
        raise SystemExit(msg)

    first = getpass.getpass(f"Password (at least {MIN_PASSWORD_LENGTH} characters): ")
    second = getpass.getpass("Repeat password: ")
    if first != second:
        msg = "The passwords did not match."
        raise SystemExit(msg)
    return first


def main(argv: list[str] | None = None) -> int:
    """Create the administrator. Returns a process exit code."""
    configure_logging()
    args = _build_parser().parse_args(argv)

    with session_scope() as session:
        existing = session.scalar(
            select(func.count()).select_from(User).where(User.role == UserRole.PLATFORM_ADMIN)
        )
        if existing and not args.allow_additional:
            print(
                f"{existing} administrator account(s) already exist. "
                "Create further ones through the console, or pass --allow-additional.",
                file=sys.stderr,
            )
            return 1

        if session.scalar(select(User).where(User.email == args.email.strip().lower())):
            print(f"An account already exists for {args.email}.", file=sys.stderr)
            return 1

    password = _read_password()
    try:
        password_hash = hash_password(password)
    except PasswordTooWeakError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    with session_scope() as session:
        user = User(
            email=args.email,
            full_name=args.name,
            password_hash=password_hash,
            role=UserRole.PLATFORM_ADMIN,
            tenant_id=None,
        )
        session.add(user)
        session.flush()
        created_id = str(user.id)

    logger.info("admin.created", user_id=created_id, email=args.email.strip().lower())
    print(f"Created platform administrator {args.email} ({created_id}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
