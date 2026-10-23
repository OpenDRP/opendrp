"""Artifact resolution: one name, one directory, no paths from a column.

The download route, the report task's cleanup and the retention sweep all ask
this module the same question — "is this stored value an artifact this platform
wrote?" — so the table below is exercised directly rather than only through the
three callers that depend on it agreeing with itself.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from app.core.artifact_path import (
    REASON_MISSING,
    REASON_NO_NAME,
    REASON_NOT_A_NAME,
    REASON_OK,
    REASON_OUTSIDE_STORE,
    artifact_filename,
    artifact_path,
    classify_artifact,
    describe_rejection,
    resolve_artifact,
    store_directory,
)


@pytest.fixture(autouse=True)
def _store(tmp_path, monkeypatch):
    from app.core.config import settings as core_settings

    store = tmp_path / "reports_store"
    store.mkdir()
    monkeypatch.setattr(core_settings, "REPORTS_STORE_DIR", str(store))
    return store


class TestNaming:
    def test_file_name_is_derived_from_the_report_id(self):
        report_id = uuid.uuid4()
        assert artifact_filename(report_id) == f"{report_id}.pdf"
        assert artifact_filename(str(report_id)) == f"{report_id}.pdf"

    def test_path_is_the_store_directory_plus_the_name(self, _store):
        report_id = uuid.uuid4()
        assert artifact_path(report_id) == _store / f"{report_id}.pdf"

    def test_a_non_uuid_report_id_is_refused(self):
        """Nothing user-supplied reaches the filesystem as a name."""
        with pytest.raises(ValueError):
            artifact_filename("../../etc/passwd")

    def test_store_directory_is_resolved(self, _store):
        assert store_directory() == _store.resolve()


class TestClassification:
    def test_a_stored_artifact_resolves_inside_the_store(self, _store):
        report_id = uuid.uuid4()
        (artifact_path(report_id)).write_bytes(b"%PDF-1.7")

        resolved, reason = classify_artifact(artifact_filename(report_id))
        assert reason == REASON_OK
        assert resolved == artifact_path(report_id)

    def test_a_vanished_artifact_is_missing_not_rejected(self, _store):
        _resolved, reason = classify_artifact("never-written.pdf")
        assert reason == REASON_MISSING

    def test_an_empty_value_has_no_name(self, _store):
        for value in (None, "", "   "):
            _resolved, reason = classify_artifact(value)
            assert reason == REASON_NO_NAME

    @pytest.mark.parametrize(
        "value",
        [
            "/etc/passwd",
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "nested/report.pdf",
            "store_evil/report.pdf",
            "report.pdf/../../etc/passwd",
            "C:\\reports\\report.pdf",
            # A drive-relative name has a colon but no separator, so it reaches the
            # colon rule rather than the separator one. Nothing this platform writes
            # starts with a drive, and on Windows the OS would treat it as `C:`.
            "C:report.pdf",
            "report.pdf\x00.txt",
            # A single dot is the current directory, not a file name. It is refused
            # as a name rather than resolved to the store directory.
            ".",
            "..",
        ],
    )
    def test_anything_with_a_directory_component_is_refused(self, _store, value):
        resolved, reason = classify_artifact(value)
        assert resolved is None
        assert reason == REASON_NOT_A_NAME

    def test_a_name_beyond_the_filesystem_limit_is_refused(self, _store):
        """255 characters is the longest name a filesystem stores, not a name.

        A longer value is either a path from somewhere else or a payload aimed at
        the audit record, so it is refused before any stat call is made.
        """
        too_long = "a" * 252 + ".pdf"  # 256 characters
        resolved, reason = classify_artifact(too_long)
        assert resolved is None
        assert reason == REASON_NOT_A_NAME

        # One character shorter is still a name, so the bound is not off by one.
        at_limit = "a" * 251 + ".pdf"
        assert len(at_limit) == 255
        (store_directory() / at_limit).write_bytes(b"%PDF-1.7")
        resolved, reason = classify_artifact(at_limit)
        assert reason == REASON_OK
        assert resolved is not None

    @pytest.mark.parametrize("value", ["report.txt", "report", "report.pdf.exe", ".pdf"])
    def test_a_suffix_the_platform_does_not_produce_is_refused(self, _store, value):
        (store_directory() / value).write_bytes(b"x")
        resolved, reason = classify_artifact(value)
        assert resolved is None
        assert reason == REASON_NOT_A_NAME

    def test_a_symlink_out_of_the_store_is_refused(self, _store):
        outside = _store.parent / "secret.pdf"
        outside.write_bytes(b"secret")
        link = _store / "linked.pdf"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):  # pragma: no cover - platform
            pytest.skip("symlinks are not available in this environment")

        resolved, reason = classify_artifact("linked.pdf")
        assert resolved is None
        assert reason == REASON_OUTSIDE_STORE

    def test_a_resolution_that_lands_outside_the_store_is_refused(self, _store, monkeypatch):
        """The symlink branch, without needing symlink privileges.

        `test_a_symlink_out_of_the_store_is_refused` reaches this with a real link
        on Linux; the Windows runner cannot create one. What is simulated here is
        the operating system's answer, not the module's logic: `realpath` returns a
        path outside the store for the artifact name, exactly as it would for a
        planted link, and the real answer for everything else.
        """
        outside = _store.parent / "elsewhere.pdf"
        outside.write_bytes(b"secret")
        real_realpath = os.path.realpath

        # `Path.resolve()` passes `strict=` through to `realpath`, so the stand-in
        # forwards every other argument untouched.
        def _realpath(value, **kwargs):
            if str(value).endswith("outside.pdf"):
                return str(outside)
            return real_realpath(value, **kwargs)

        monkeypatch.setattr(os.path, "realpath", _realpath)
        resolved, reason = classify_artifact("outside.pdf")
        assert resolved is None
        assert reason == REASON_OUTSIDE_STORE

    def test_an_unreadable_path_is_missing_rather_than_a_server_error(self, _store, monkeypatch):
        """A resolution failure is an operational incident, not a security event.

        A link loop or a permission problem makes `realpath` raise. The caller asks
        "can this be served?", and the answer is no for a reason the operator can
        act on, rather than an exception on the download route.
        """
        real_realpath = os.path.realpath

        def _realpath(value, **kwargs):
            if str(value).endswith("looping.pdf"):
                raise OSError("too many levels of symbolic links")
            return real_realpath(value, **kwargs)

        monkeypatch.setattr(os.path, "realpath", _realpath)
        resolved, reason = classify_artifact("looping.pdf")
        assert resolved is None
        assert reason == REASON_MISSING

    def test_a_directory_named_like_an_artifact_is_not_a_file(self, _store):
        (store_directory() / "directory.pdf").mkdir()
        resolved, reason = classify_artifact("directory.pdf")
        assert resolved is None
        assert reason == REASON_MISSING

    def test_resolve_artifact_is_the_boolean_form(self, _store):
        report_id = uuid.uuid4()
        artifact_path(report_id).write_bytes(b"%PDF-1.7")
        assert resolve_artifact(artifact_filename(report_id)) is not None
        assert resolve_artifact("never-written.pdf") is None

    def test_production_image_restricts_report_store_permissions(self):
        backend_root = Path(__file__).resolve().parents[1]
        dockerfile = (backend_root / "Dockerfile").read_text(encoding="utf-8")

        assert "chmod 0700 /workspace/reports_store" in dockerfile
        assert "USER opendrp" in dockerfile


class TestAuditDetails:
    def test_rejection_details_describe_the_value_without_leaking_the_path(self, _store):
        details = describe_rejection("/srv/app/reports_store/x.pdf", REASON_NOT_A_NAME)
        assert details["artifact_name"] == "x.pdf"
        assert details["had_directory_component"] is True
        assert details["reason"] == REASON_NOT_A_NAME
        assert "/srv/app" not in str(details)

    def test_a_plain_name_reports_no_directory_component(self, _store):
        details = describe_rejection("x.pdf", REASON_MISSING)
        assert details["had_directory_component"] is False
        assert details["artifact_name"] == "x.pdf"
