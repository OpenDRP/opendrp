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


def test_quoted_json_secret_is_redacted():
    value = sanitize_external_error(
        'ClientResponseError: body={"error":"invalid token",'
        '"token":"eyJhbGciOiJIUzI1NiJ9.body.sig"}'
    )
    assert "eyJhbGciOiJIUzI1NiJ9" not in value
    assert "invalid token" in value


def test_authorization_scheme_value_is_redacted_whole():
    value = sanitize_external_error(
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret.sig"
    )
    assert "eyJhbGciOiJIUzI1NiJ9" not in value
    assert "Bearer eyJ" not in value


def test_spaced_secret_label_is_redacted():
    value = sanitize_external_error("API key sk-live-123456789 rejected by provider")
    assert "sk-live-123456789" not in value
    assert "rejected by provider" in value


def test_ordinary_text_is_not_mangled():
    value = sanitize_external_error(
        "host 203.0.113.9 returned 403 for tokenizer audit"
    )
    assert value == "host 203.0.113.9 returned 403 for tokenizer audit"
