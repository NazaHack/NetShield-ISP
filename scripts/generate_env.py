#!/usr/bin/env python3
"""Create a `.env` file from `.env.example` with freshly generated secrets.

Run once per checkout:

    python3 scripts/generate_env.py

The script refuses to overwrite an existing `.env`, because doing so would
rotate the database password out from under a running stack and leave the
persisted volume unreachable.
"""

from __future__ import annotations

import re
import secrets
import sys
from pathlib import Path

#: Variables replaced with generated values, mapped to their byte length.
GENERATED_SECRETS: dict[str, int] = {
    "SECRET_KEY": 64,
    "POSTGRES_PASSWORD": 32,
    "REDIS_PASSWORD": 32,
}

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = PROJECT_ROOT / ".env.example"
TARGET_PATH = PROJECT_ROOT / ".env"


def main() -> int:
    """Generate `.env`. Returns a process exit code."""
    if TARGET_PATH.exists():
        print(f"refusing to overwrite the existing {TARGET_PATH.name}", file=sys.stderr)
        return 1

    if not TEMPLATE_PATH.exists():
        print(f"missing template: {TEMPLATE_PATH}", file=sys.stderr)
        return 1

    content = TEMPLATE_PATH.read_text(encoding="utf-8")

    for variable, length in GENERATED_SECRETS.items():
        pattern = rf"^{re.escape(variable)}=.*$"
        if not re.search(pattern, content, flags=re.MULTILINE):
            print(f"template does not define {variable}", file=sys.stderr)
            return 1
        content = re.sub(
            pattern,
            f"{variable}={secrets.token_urlsafe(length)}",
            content,
            count=1,
            flags=re.MULTILINE,
        )

    TARGET_PATH.write_text(content, encoding="utf-8")
    # Secrets on disk are readable by the owner only.
    TARGET_PATH.chmod(0o600)

    print(f"created {TARGET_PATH.name} with generated {', '.join(GENERATED_SECRETS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
