"""Request correlation: one identifier through HTTP, logs and the audit trail.

The value of a correlation id is entirely in the links between the three sinks.
A header that is returned but never logged, or logged but never written to the
audit row, gives an operator three identifiers for one event — so each test here
asserts a *link*, not the existence of an id.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.core import request_context
from app.core.audit import AuditLog
from app.core.logging_config import AUDIT_FIELDS, configure_logging, get_logger
from app.core.request_context import (
    GENERATED_PREFIX,
    REQUEST_ID_HEADER,
    current_request_id,
    new_request_id,
    sanitize_request_id,
)


class TestSanitizeRequestId:
    """The header is client input written to two sinks, so it is allowlisted."""

    @pytest.mark.parametrize(
        "value",
        [
            "abc",
            "web-9f8c1d2e3b4a",
            "conn-dnstwist-0f1e2d3c",
            "a.b_c-9",
            "x" * 64,
        ],
    )
    def test_accepts_reasonable_identifiers(self, value):
        assert sanitize_request_id(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            None,
            "",
            "   ",
            "x" * 65,
            "with space",
            "new\nline",  # would forge a log record in a non-JSON sink
            "carriage\rreturn",
            "tab\tchar",
            "semi;colon",
            "quote\"char",
            "<script>alert(1)</script>",
            "юникод",
        ],
    )
    def test_rejects_anything_outside_the_allowlist(self, value):
        assert sanitize_request_id(value) is None

    def test_generated_ids_are_prefixed_and_distinct(self):
        first = new_request_id()
        second = new_request_id()
        assert first.startswith(GENERATED_PREFIX)
        assert first != second
        # A generated id must itself pass validation: an id the platform issues
        # and then refuses to accept back would be an absurd bug.
        assert sanitize_request_id(first) == first


class TestMiddleware:
    @pytest.mark.asyncio
    async def test_missing_id_is_generated_and_returned(self, client):
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        returned = response.headers[REQUEST_ID_HEADER.lower()]
        assert returned.startswith(GENERATED_PREFIX)

    @pytest.mark.asyncio
    async def test_client_supplied_id_is_echoed(self, client):
        response = await client.get(
            "/api/v1/health", headers={REQUEST_ID_HEADER: "web-client-supplied"}
        )
        assert response.headers[REQUEST_ID_HEADER.lower()] == "web-client-supplied"

    @pytest.mark.asyncio
    async def test_invalid_id_is_replaced_not_propagated(self, client):
        response = await client.get(
            "/api/v1/health", headers={REQUEST_ID_HEADER: "not a valid id"}
        )
        returned = response.headers[REQUEST_ID_HEADER.lower()]
        assert returned != "not a valid id"
        assert returned.startswith(GENERATED_PREFIX)

    @pytest.mark.asyncio
    async def test_id_does_not_leak_past_the_request(self, client, auth_headers_admin):
        """The identifier belongs to the request, not to the process.

        The test client awaits the application in this very task, so a middleware
        that set the variable without resetting it would leave its value visible
        here — and in production would attribute whatever ran next to a request
        that had already finished.
        """
        response = await client.get(
            "/api/v1/users/brief",
            headers={**auth_headers_admin, REQUEST_ID_HEADER: "web-leak-check"},
        )
        assert response.status_code == 200, response.text
        assert response.headers[REQUEST_ID_HEADER.lower()] == "web-leak-check"
        assert current_request_id() is None


class TestAuditTrailLink:
    @pytest.mark.asyncio
    async def test_audit_row_carries_the_request_id_inside_details(
        self, client, auth_headers_admin, db_session
    ):
        """The link between a request and the audit table.

        ``details``, not a sixth top-level field: the five-field shape is
        published and tested separately, and a SIEM index that maps it would
        treat an extra key as noise.
        """
        response = await client.get(
            "/api/v1/users/brief",
            headers={**auth_headers_admin, REQUEST_ID_HEADER: "web-audit-link"},
        )
        assert response.status_code == 200, response.text

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "users.list")
                )
            ).scalars()
        )
        assert rows, "the users list audit row must be written"
        assert rows[0].details["request_id"] == "web-audit-link"

    @pytest.mark.asyncio
    async def test_correlation_does_not_add_a_sixth_audit_field(
        self, client, auth_headers_admin, capsys
    ):
        configure_logging(force=True)
        response = await client.get(
            "/api/v1/users/brief",
            headers={**auth_headers_admin, REQUEST_ID_HEADER: "web-six-field-check"},
        )
        assert response.status_code == 200, response.text

        import json

        audit_lines = []
        for line in capsys.readouterr().out.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get("action") == "users.list":
                audit_lines.append(payload)

        assert len(audit_lines) == 1
        assert tuple(sorted(audit_lines[0])) == tuple(sorted(AUDIT_FIELDS))
        assert audit_lines[0]["details"]["request_id"] == "web-six-field-check"


class TestLogLineLink:
    def test_processor_adds_the_id_to_platform_logs(self, capsys):
        configure_logging(force=True)
        token = request_context.set_request_id("web-log-line")
        try:
            get_logger().info("correlated_probe")
        finally:
            request_context.reset_request_id(token)

        import json

        payloads = [
            json.loads(line)
            for line in capsys.readouterr().out.splitlines()
            if line.strip().startswith("{")
        ]
        matching = [p for p in payloads if p.get("event") == "correlated_probe"]
        assert len(matching) == 1
        assert matching[0]["request_id"] == "web-log-line"

    def test_processor_adds_nothing_outside_a_request(self, capsys):
        configure_logging(force=True)
        get_logger().info("uncorrelated_probe")

        import json

        payloads = [
            json.loads(line)
            for line in capsys.readouterr().out.splitlines()
            if line.strip().startswith("{")
        ]
        matching = [p for p in payloads if p.get("event") == "uncorrelated_probe"]
        assert len(matching) == 1
        # Absent rather than null: a null forces every consumer to filter it.
        assert "request_id" not in matching[0]


class TestTaskHeaders:
    def test_request_id_header_is_empty_outside_a_request(self):
        assert request_context.request_id_header() == {}

    def test_request_id_header_carries_the_current_id(self):
        token = request_context.set_request_id(f"web-{uuid.uuid4().hex[:8]}")
        try:
            headers = request_context.request_id_header()
        finally:
            request_context.reset_request_id(token)
        assert headers[REQUEST_ID_HEADER].startswith("web-")
