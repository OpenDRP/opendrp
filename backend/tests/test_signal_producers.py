"""Every signal a rule reads has to have something that writes it.

The DNS & TLS audit found three keys that were read and written by nobody: ``jarm``
(R4 can never fire), ``org``/``asn`` (the shared-infrastructure suppression cannot
recognise a CDN, and an ``asn`` scope exception matches nothing), and
``host_lookup_confirmed`` (R1's confidence never earns its confirmation bonus). Each
one is invisible in review: the rule, the exception kind and the UI all look
implemented, and the tests that covered them fed the keys in by hand.

This gate closes that hole mechanically. ``SIGNAL_PRODUCERS`` in
``app/services/tls_identity_service.py`` declares which source writes each key the
rules read, and this file checks the declaration against the two things that can
drift from it: the keys the scoring actually reads, and the connector code that has
to contain them.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.services import tls_identity_service as tls

_ROOT = Path(__file__).resolve().parents[2]

#: Where a declared producer has to write its signal. A path, not a search: the
#: point of the gate is that these keys exist in a named place, so moving the code
#: is a deliberate edit to this map rather than a silent loss of coverage.
PRODUCER_MODULES = {
    "netlas": _ROOT / "connectors" / "intelligence" / "providers.py",
    "shodan": _ROOT / "connectors" / "dns_security" / "main.py",
}


def _source(path: Path) -> str:
    assert path.is_file(), f"declared producer module is missing: {path}"
    return path.read_text(encoding="utf-8")


def test_the_declaration_covers_every_signal_the_rules_read():
    # A signal the scoring reads but the declaration does not name is exactly the
    # bug this file exists for, in the direction a reader would not notice.
    assert set(tls.SIGNAL_KEYS) == set(tls.SIGNAL_PRODUCERS), (
        "SIGNAL_KEYS and SIGNAL_PRODUCERS must describe the same set: a key read by "
        "the rules without a declared producer can never arrive"
    )


def test_every_declared_producer_writes_its_signal():
    missing = []
    for signal, sources in tls.SIGNAL_PRODUCERS.items():
        assert sources, f"{signal} is declared with no producer at all"
        for producer in sources:
            module = PRODUCER_MODULES.get(producer)
            assert module is not None, (
                f"{signal} names an unknown producer {producer!r}; add its module to "
                "PRODUCER_MODULES so the gate can check it"
            )
            if not re.search(rf'"{re.escape(signal)}"', _source(module)):
                missing.append(f"{producer} does not write {signal} ({module.name})")
    assert missing == [], (
        "A declared signal producer no longer writes its key, so the rule or "
        "exception that reads it cannot apply: " + "; ".join(missing)
    )


def test_the_stack_echo_rule_has_both_halves_of_its_evidence():
    # R4 compares a JARM plus a title or favicon. Both halves were read from signals
    # nothing wrote, so the rule was dead while looking implemented.
    assert "jarm" in tls.SIGNAL_PRODUCERS
    echo_keys = {"title", "favicon_hash", "http_title", "http_favicon_hash"}
    assert echo_keys <= set(tls.SIGNAL_PRODUCERS), (
        "R4 needs a title or favicon to confirm an echo, so every echo key it reads "
        "must have a producer"
    )


def test_every_signal_dependent_exception_kind_has_a_declared_signal():
    kinds = set(tls.EXCEPTION_KINDS)
    for kind, signal in tls.EXCEPTION_KIND_SIGNALS.items():
        assert kind in kinds, f"{kind} guards a match kind that no longer exists"
        assert signal in tls.SIGNAL_PRODUCERS, (
            f"the {kind} exception reads {signal}, which no source produces"
        )
    # The signal-free kinds are the ones the core resolves from evidence it holds
    # itself; if one of them silently needs a signal, it belongs in the map above.
    assert kinds - set(tls.EXCEPTION_KIND_SIGNALS) == {
        "fingerprint",
        "spki",
        "ip",
        "issuer",
    }


def test_the_rules_only_read_declared_signals():
    # `_sighting_signals` is the single door provider facts come through, so the keys
    # it copies are the keys the rules can see.
    source = Path(tls.__file__).read_text(encoding="utf-8")
    assert re.search(r"for key in SIGNAL_KEYS:", source), (
        "the sighting projection must read the declared signal keys, not a second, "
        "hand-maintained list"
    )
