from app.core.safe_errors import sanitize_external_error


def test_provider_urls_and_secret_pairs_are_redacted():
    value = sanitize_external_error(
        "GET https://api.example.test/search?key=super-secret&query=acme "
        "token=another-secret password: hidden"
    )
    assert "super-secret" not in value
    assert "another-secret" not in value
    assert "hidden" not in value
    assert "[REDACTED]" in value


def test_provider_error_is_bounded_and_control_characters_removed():
    value = sanitize_external_error("boom\n" + "x" * 5000, limit=120)
    assert "\n" not in value
    assert len(value) <= 120
