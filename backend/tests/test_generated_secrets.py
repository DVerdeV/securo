"""Signing secrets are never a value published in this repository (#1173, #1174)."""

import logging
import multiprocessing
from pathlib import Path

import pytest

from app.agents.config import AgentSettings
from app.core import generated_secrets
from app.core.config import Settings
from app.core.generated_secrets import KNOWN_DEFAULT_SECRETS, resolve_signing_secret


def _resolve(value: str, directory: Path) -> str:
    return resolve_signing_secret(value, env_var="SECRET_KEY", directory=directory, filename="secret_key")


def test_unset_secret_is_generated_and_persisted(tmp_path: Path, caplog):
    caplog.set_level(logging.WARNING, logger=generated_secrets.__name__)

    secret = _resolve("", tmp_path)

    stored = tmp_path / "secret_key"
    assert stored.read_text().strip() == secret
    assert len(secret) >= 32
    assert secret not in KNOWN_DEFAULT_SECRETS
    assert stored.stat().st_mode & 0o777 == 0o600
    assert "SECRET_KEY is not set" in caplog.text


def test_generated_secret_is_reused_on_later_starts(tmp_path: Path, caplog):
    first = _resolve("", tmp_path)
    caplog.clear()
    caplog.set_level(logging.WARNING, logger=generated_secrets.__name__)

    assert _resolve("", tmp_path) == first
    assert _resolve("   ", tmp_path) == first
    # Reusing the stored secret is the normal case: nothing to warn about.
    assert caplog.text == ""


def test_generated_secrets_differ_between_installs(tmp_path: Path):
    assert _resolve("", tmp_path / "a") != _resolve("", tmp_path / "b")


@pytest.mark.parametrize("default", sorted(KNOWN_DEFAULT_SECRETS))
def test_published_default_is_replaced_and_warned_about(tmp_path: Path, caplog, default: str):
    caplog.set_level(logging.WARNING, logger=generated_secrets.__name__)

    secret = _resolve(default, tmp_path)

    assert secret != default
    assert secret == (tmp_path / "secret_key").read_text().strip()
    assert "default published in the Securo repository" in caplog.text
    # Warned on every start while the placeholder is still configured.
    caplog.clear()
    assert _resolve(default, tmp_path) == secret
    assert "default published in the Securo repository" in caplog.text


def test_custom_secret_is_used_untouched(tmp_path: Path, caplog):
    caplog.set_level(logging.WARNING, logger=generated_secrets.__name__)

    assert _resolve("my-own-long-random-secret", tmp_path) == "my-own-long-random-secret"
    assert not (tmp_path / "secret_key").exists()
    assert caplog.text == ""


def test_custom_secret_wins_over_a_stored_one(tmp_path: Path):
    _resolve("", tmp_path)
    assert _resolve("my-own-long-random-secret", tmp_path) == "my-own-long-random-secret"


def test_unwritable_directory_fails_with_a_clear_error(tmp_path: Path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    with pytest.raises(RuntimeError, match="SECRET_KEY / AGENTS_MCP_JWT_SECRET"):
        _resolve("", blocker / "secrets")


def test_loser_of_a_race_reads_the_winners_secret(tmp_path: Path, monkeypatch):
    """A process that finds the file missing, then loses the create, must use
    the secret the other process wrote, not its own candidate."""
    target = tmp_path / "secret_key"
    real_publish = generated_secrets._publish

    def publish_after_rival(path: Path, secret: str) -> bool:
        assert real_publish(path, "rival-secret")
        return real_publish(path, secret)

    monkeypatch.setattr(generated_secrets, "_publish", publish_after_rival)

    assert _resolve("", tmp_path) == "rival-secret"
    assert target.read_text().strip() == "rival-secret"


def test_exclusive_create_fallback_when_hard_links_are_unsupported(tmp_path: Path, monkeypatch):
    def no_links(*_args, **_kwargs):
        raise PermissionError("hard links not supported")

    monkeypatch.setattr(generated_secrets.os, "link", no_links)

    secret = _resolve("", tmp_path)

    assert (tmp_path / "secret_key").read_text().strip() == secret
    assert _resolve("", tmp_path) == secret
    assert [p.name for p in tmp_path.iterdir()] == ["secret_key"]


def _resolve_in_child(directory: str, queue) -> None:
    queue.put(_resolve("", Path(directory)))


def test_concurrent_starts_agree_on_one_secret(tmp_path: Path):
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    procs = [ctx.Process(target=_resolve_in_child, args=(str(tmp_path), queue)) for _ in range(6)]
    for p in procs:
        p.start()
    results = {queue.get(timeout=60) for _ in procs}
    for p in procs:
        p.join(timeout=60)

    assert len(results) == 1
    assert results == {(tmp_path / "secret_key").read_text().strip()}
    assert [p.name for p in tmp_path.iterdir()] == ["secret_key"]


def test_settings_generate_secret_key_when_unset(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("SECRET_KEY")
    store = tmp_path / "store"

    settings = Settings(_env_file=None, generated_secrets_path=str(store))

    secret = settings.secret_key.get_secret_value()
    assert secret == (store / "secret_key").read_text().strip()
    assert Settings(_env_file=None, generated_secrets_path=str(store)).secret_key.get_secret_value() == secret


def test_settings_default_store_is_inside_local_storage(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("SECRET_KEY")

    settings = Settings(_env_file=None, storage_local_path=str(tmp_path))

    assert settings.generated_secrets_dir == tmp_path / ".secrets"
    assert (tmp_path / ".secrets" / "secret_key").read_text().strip() == settings.secret_key.get_secret_value()


def test_settings_replace_published_secret_key(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "dev-secret-change-in-production")

    settings = Settings(_env_file=None, generated_secrets_path=str(tmp_path))

    assert settings.secret_key.get_secret_value() != "dev-secret-change-in-production"


def test_settings_keep_custom_secret_key(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "operator-chosen-secret")

    settings = Settings(_env_file=None, generated_secrets_path=str(tmp_path))

    assert settings.secret_key.get_secret_value() == "operator-chosen-secret"
    assert not any(tmp_path.iterdir())


def test_mcp_secret_is_generated_next_to_secret_key(tmp_path: Path, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setenv("GENERATED_SECRETS_PATH", str(tmp_path))
    monkeypatch.delenv("AGENTS_MCP_JWT_SECRET", raising=False)
    get_settings.cache_clear()
    try:
        first = AgentSettings(_env_file=None).mcp_jwt_secret
        second = AgentSettings(_env_file=None).mcp_jwt_secret
        main_secret = get_settings().secret_key.get_secret_value()
    finally:
        get_settings.cache_clear()

    assert first == second == (tmp_path / "agents_mcp_jwt_secret").read_text().strip()
    # Distinct from the app secret, so the two can be rotated independently.
    assert first != main_secret


@pytest.mark.parametrize(
    "value, kept",
    [("dev-mcp-secret-change-in-production", False), ("change-me-in-production", False), ("my-mcp-secret", True)],
)
def test_mcp_secret_published_defaults_are_replaced(tmp_path: Path, monkeypatch, value: str, kept: bool):
    from app.core.config import get_settings

    monkeypatch.setenv("GENERATED_SECRETS_PATH", str(tmp_path))
    monkeypatch.setenv("AGENTS_MCP_JWT_SECRET", value)
    get_settings.cache_clear()
    try:
        secret = AgentSettings(_env_file=None).mcp_jwt_secret
    finally:
        get_settings.cache_clear()

    assert (secret == value) is kept
