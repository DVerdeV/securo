"""Signing secrets that are safe out of the box.

SECRET_KEY and AGENTS_MCP_JWT_SECRET sign session, reset/verification and
MCP tokens. Older compose files, the Helm chart and the env examples shipped
fixed placeholder values for them, so an install that never set its own
secret signed tokens with a key anyone could read in this repository.

``resolve_signing_secret`` keeps any secret the operator chose. When the
value is missing, or is one of those published placeholders, it uses a
random secret generated once and stored on disk instead, so every process
sharing that directory (API, Celery worker and beat, MCP server) signs and
verifies with the same key and sessions survive restarts.
"""

from __future__ import annotations

import logging
import os
import secrets
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Every value this repository has shipped as a default for a signing secret.
KNOWN_DEFAULT_SECRETS: frozenset[str] = frozenset(
    {
        "change-me-in-production",
        "dev-secret-change-in-production",
        "dev-mcp-secret-change-in-production",
    }
)

# How long a reader waits for a concurrent writer to finish, on filesystems
# where the file cannot be published atomically (see _publish).
_READ_TIMEOUT_SECONDS = 5.0


def resolve_signing_secret(value: str, *, env_var: str, directory: Path, filename: str) -> str:
    """Return the secret to sign with for ``env_var``.

    A value the operator set is returned untouched unless it is a published
    placeholder. Otherwise the secret stored in ``directory/filename`` is
    returned, generating it first if no process has done so yet.
    """
    value = value.strip()
    if value and value not in KNOWN_DEFAULT_SECRETS:
        return value

    path = directory / filename
    secret, created = _load_or_create(path)
    if value:
        logger.warning(
            "%s is set to %r, a default published in the Securo repository: anyone "
            "could sign tokens with it. It is ignored, and a random secret stored "
            "in %s is used instead. Set %s to your own random value (for example "
            "`openssl rand -hex 32`) or remove it to silence this warning.",
            env_var,
            value,
            path,
            env_var,
        )
    elif created:
        logger.warning(
            "%s is not set; generated a random one and stored it in %s. Keep that "
            "file (it lives in the data volume) or set %s explicitly.",
            env_var,
            path,
            env_var,
        )
    return secret


def _load_or_create(path: Path) -> tuple[str, bool]:
    """Read the secret at ``path``, creating it if missing.

    Returns ``(secret, created)``. Safe when several processes start at once:
    exactly one of them creates the file and the rest read its content.
    """
    existing = _read(path)
    if existing:
        return existing, False

    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(_unwritable_message(path, exc)) from exc

    candidate = secrets.token_urlsafe(48)
    try:
        created = _publish(path, candidate)
    except OSError as exc:
        raise RuntimeError(_unwritable_message(path, exc)) from exc
    if created:
        return candidate, True

    # Another process won the race; use what it wrote.
    deadline = time.monotonic() + _READ_TIMEOUT_SECONDS
    while True:
        existing = _read(path)
        if existing:
            return existing, False
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"{path} exists but is empty. Delete it to have a new secret "
                "generated, or set the secret explicitly."
            )
        time.sleep(0.05)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except (FileNotFoundError, NotADirectoryError):
        return ""
    except OSError as exc:
        raise RuntimeError(f"Cannot read the generated signing secret in {path} ({exc}).") from exc


def _publish(path: Path, secret: str) -> bool:
    """Create ``path`` holding ``secret`` unless it already exists.

    Returns True when this call created the file. The secret is written to a
    private temporary file first and hard-linked into place, which fails if
    the target exists, so a reader never sees a half-written file. Where hard
    links are unsupported, fall back to an exclusive create; readers then wait
    for the content in _load_or_create.
    """
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    _write_new(tmp, secret)
    try:
        os.link(tmp, path)
        return True
    except FileExistsError:
        return False
    except OSError:
        try:
            _write_new(path, secret)
            return True
        except FileExistsError:
            return False
    finally:
        tmp.unlink(missing_ok=True)


def _write_new(path: Path, secret: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(secret + "\n")
        f.flush()
        os.fsync(f.fileno())


def _unwritable_message(path: Path, exc: OSError) -> str:
    return (
        f"Cannot store a generated signing secret in {path} ({exc}). Make that "
        "directory writable, point GENERATED_SECRETS_PATH at a writable "
        "persistent directory, or set SECRET_KEY / AGENTS_MCP_JWT_SECRET explicitly."
    )
