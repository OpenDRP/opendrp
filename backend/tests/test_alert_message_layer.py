"""The message layer is pure, so it is asserted directly rather than through a send.

`app.services.alert_message` was lifted out of `alert_service` without changing a
single string it produces. These tests pin the extracted surface twice: the values
themselves (clip/plural/columns/paths), and the fact that the old import paths
still resolve from `alert_service`, which is what every caller in the delivery
path still uses.
"""

from app.services.alert_content import fact_text
from app.services.alert_message import (
    BREAKDOWN_CHARS,
    MAX_FIELD_CHARS,
    Notification,
    breach_event_label,
    breach_exposure_label,
    breach_subject_class,
    clip,
    counted,
    declared_column,
    digest_heading,
    highest_severity,
    plain_text,
    plural,
)

FACADE_NAMES = (
    "AlertService",
    "AlertDeliveryPermanentError",
    "AlertDeliveryTransientError",
    "AlertDeliveryAmbiguousError",
    "AlertDeliveryCancelledError",
    "bounded_smtp",
    "digest_heading",
    "phishing_alert_route",
)


def _notification(**overrides) -> Notification:
    values = {
        "label": "Phishing",
        "subject": "[OpenDRP Alert] Phishing: 2 new findings",
        "job_id": "job-1",
        "total": 2,
        "included": 2,
        "rows": [{"Domain": "evil.example"}, {"Domain": "evil2.example", "Source": "dns"}],
        "groups": [("Source", "dns × 2")],
        "link": "https://drp.example/phishing",
    }
    values.update(overrides)
    return Notification(**values)


def test_the_facade_still_exports_every_name_its_callers_import():
    from app.services import alert_service

    missing = [name for name in FACADE_NAMES if not hasattr(alert_service, name)]
    assert missing == []
    # The private aliases are the ones other modules reach for by name.
    assert alert_service._plain_text is alert_service.plain_text
    assert alert_service._highest_severity is alert_service.highest_severity
    assert alert_service._breach_subject_class is alert_service.breach_subject_class


def test_clip_is_one_bounded_line():
    assert clip(None) == "N/A"
    assert clip("  two\n lines  ") == "two lines"
    assert len(clip("x" * (MAX_FIELD_CHARS + 50))) == MAX_FIELD_CHARS
    assert clip("x" * (MAX_FIELD_CHARS + 50)).endswith("…")
    assert clip("abcdef", 4) == "abc…"


def test_counts_and_plurals_keep_the_words_the_message_had():
    assert plural(1, "finding") == "1 finding"
    assert plural(2, "finding") == "2 findings"
    assert counted(["a", "a", "b"]) == "a × 2, b × 1"
    # Beyond four distinct values the tail is counted, not listed.
    summary = counted(["a", "b", "c", "d", "e", "f"])
    assert summary.endswith("+2 more")
    assert "e ×" not in summary


def test_severity_is_the_worst_one_a_module_actually_reported():
    assert highest_severity([{"severity": "info"}, {"severity": "high"}]) == "high"
    assert highest_severity([{"severity": "warning"}]) == "warning"
    assert highest_severity([{"severity": "unheard-of"}]) is None
    assert highest_severity([{"phishing_domain": "evil.example"}]) is None


def test_only_declared_columns_reach_a_message():
    assert declared_column("phishing", "Current value")
    assert not declared_column("phishing", "id")
    assert declared_column("breach", "Account")
    assert not declared_column("breach", "attributes")
    assert not declared_column("module:acme", "title")
    assert declared_column("module:acme", "Asset")


def test_breach_vocabulary_falls_back_to_the_first_sighting():
    assert breach_event_label("incident_grew") == "Incident grew"
    assert breach_event_label(None) == "New incident"
    assert breach_exposure_label("stealer_log") == "Stealer log"
    assert breach_exposure_label("account") is None


def test_a_batch_subject_names_a_class_only_when_it_agrees():
    assert breach_subject_class([{"change_class": "incident_grew"}, {"change_class": "incident_grew"}]) == "Incident grew"
    assert breach_subject_class([{"change_class": "incident_grew"}, {"change_class": "new_incident"}]) is None
    assert breach_subject_class([{"change_class": "incident_grew"}, {}]) is None


def test_digest_headings_name_the_module_and_never_an_alert():
    label, subject = digest_heading(3)
    assert label == "Phishing digest"
    assert "3 candidates below the alert threshold" in subject
    label, subject = digest_heading(1, "breach")
    assert label == "Breach digest"
    assert "1 new incident" in subject


def test_notification_columns_are_the_union_of_every_rows_facts():
    notification = _notification()
    assert notification.columns == ["Domain", "Source"]
    assert notification.table() == [["evil.example", "—"], ["evil2.example", "dns"]]


def test_plain_text_carries_the_facts_without_markup():
    text = plain_text(_notification(included=1))
    assert "Findings: 2 (showing the first 1)" in text
    assert "Source: dns × 2" in text
    assert f"Domain={fact_text('evil.example')}" in text
    assert "Open in OpenDRP: https://drp.example/phishing" in text
    assert BREAKDOWN_CHARS == 80
