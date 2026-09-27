"""Operator CLI for per-connector credentials.

The CLI is the documented way to bootstrap a connector (row + token together),
so its contract matters: the plaintext is printed once, a second ``issue`` must
not silently re-key a live connector, and ``rotate``/``revoke`` must take effect
immediately.
"""

import pytest

from app.services.connector_credentials import ConnectorCredentials, hash_token
from app.services.connector_service import ConnectorService
from scripts import manage_connector_tokens as cli


@pytest.fixture
def cli_db(db_session, monkeypatch):
    """Point the CLI at the test session (the CLI opens its own in production)."""

    class _Session:
        async def __aenter__(self):
            return db_session

        async def __aexit__(self, *exc_info):
            return False

    monkeypatch.setattr(cli, "AsyncSessionLocal", lambda: _Session())
    return db_session


class TestIssue:
    @pytest.mark.asyncio
    async def test_issue_provisions_a_connector_and_prints_its_env_line(self, cli_db, capsys):
        await cli.cmd_issue("connector-hibp", "breaches", "CONNECTOR_TOKEN_HIBP")
        out = capsys.readouterr().out

        assert "CONNECTOR_TOKEN_HIBP=opendrp_connector-hibp_" in out
        assert "shown once" in out
        connector = await ConnectorService(cli_db).get_by_name("connector-hibp")
        assert connector.connector_type == "breaches"
        assert connector.has_token is True
        # Only the digest is stored: the printed value is the operator's copy.
        printed = out.split("CONNECTOR_TOKEN_HIBP=", 1)[1].splitlines()[0].strip()
        assert connector.token_hash == hash_token(printed)
        assert (await ConnectorCredentials(cli_db).resolve(printed)).id == connector.id

    @pytest.mark.asyncio
    async def test_issue_refuses_to_silently_rekey_a_live_connector(self, cli_db, capsys):
        await cli.cmd_issue("connector-hibp", "breaches", None)
        with pytest.raises(SystemExit) as exit_info:
            await cli.cmd_issue("connector-hibp", "breaches", None)
        assert exit_info.value.code == 2
        assert "rotate" in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_issue_requires_a_registered_module(self, cli_db, capsys):
        """Modules are data, so the CLI validates against the registry."""
        with pytest.raises(SystemExit) as exit_info:
            await cli.cmd_issue("voipwatch", "voip", None)
        assert exit_info.value.code == 2
        out = capsys.readouterr().out
        assert "unknown module 'voip'" in out and "phishing" in out

    @pytest.mark.asyncio
    async def test_issue_refuses_a_disabled_module(self, cli_db, capsys):
        from app.services.module_registry import set_module_enabled

        await set_module_enabled(cli_db, "breaches", enabled=False)
        with pytest.raises(SystemExit) as exit_info:
            await cli.cmd_issue("connector-hibp", "breaches", None)
        assert exit_info.value.code == 2
        assert "is disabled" in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_issue_rejects_a_type_change(self, cli_db, capsys):
        await cli.cmd_issue("connector-hibp", "breaches", None)
        with pytest.raises(SystemExit) as exit_info:
            await cli.cmd_issue("connector-hibp", "phishing", None)
        assert exit_info.value.code == 2
        assert "already registered as type 'breaches'" in capsys.readouterr().out


class TestRotateAndRevoke:
    @pytest.mark.asyncio
    async def test_rotate_replaces_the_credential_immediately(self, cli_db, capsys):
        await cli.cmd_issue("dnstwist", "phishing", None)
        first = capsys.readouterr().out.split("\n")[2].strip()

        await cli.cmd_rotate("dnstwist", "CONNECTOR_TOKEN_DNSTWIST")
        out = capsys.readouterr().out
        assert "Previous credential revoked" in out
        second = out.split("CONNECTOR_TOKEN_DNSTWIST=", 1)[1].splitlines()[0].strip()

        assert second != first
        credentials = ConnectorCredentials(cli_db)
        assert await credentials.resolve(first) is None
        assert await credentials.resolve(second) is not None

    @pytest.mark.asyncio
    async def test_rotate_requires_the_connector_to_exist(self, cli_db):
        with pytest.raises(SystemExit) as exit_info:
            await cli.cmd_rotate("ghost", None)
        assert exit_info.value.code == 2

    @pytest.mark.asyncio
    async def test_revoke_drops_the_credential_but_keeps_the_connector(self, cli_db, capsys):
        await cli.cmd_issue("dnstwist", "phishing", None)
        token = capsys.readouterr().out.split("\n")[2].strip()

        await cli.cmd_revoke("dnstwist")
        out = capsys.readouterr().out
        assert "history remain" in out
        assert await ConnectorCredentials(cli_db).resolve(token) is None

        connector = await ConnectorService(cli_db).get_by_name("dnstwist")
        assert connector is not None and connector.has_token is False


class TestList:
    @pytest.mark.asyncio
    async def test_list_warns_about_connectors_without_credentials(self, cli_db, capsys):
        await ConnectorService(cli_db).register(name="dnstwist", connector_type="phishing")
        await cli.cmd_issue("connector-hibp", "breaches", None)
        capsys.readouterr()

        await cli.cmd_list()
        out = capsys.readouterr().out
        assert "connector-hibp" in out and "issued" in out
        assert "dnstwist" in out and "none" in out
        assert "cannot poll for work" in out

    @pytest.mark.asyncio
    async def test_list_on_an_empty_registry_says_so(self, cli_db, capsys):
        await cli.cmd_list()
        assert "No connectors registered yet" in capsys.readouterr().out
