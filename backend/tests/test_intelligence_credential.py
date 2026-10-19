import importlib.util
from pathlib import Path

_PATH = Path("/connectors/intelligence/providers.py")
if not _PATH.exists():
    _PATH = Path(__file__).resolve().parents[2] / "connectors/intelligence/providers.py"
_spec = importlib.util.spec_from_file_location("intelligence_providers_credential", _PATH)
providers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(providers)


def test_core_credential_accepts_only_a_configured_non_empty_string():
    assert providers.core_credential({"configured": True, "api_key": "k-1"}) == "k-1"
    assert providers.core_credential({"configured": False}) is None
    assert providers.core_credential({"configured": True, "api_key": ""}) is None
    assert providers.core_credential({"configured": True, "api_key": 7}) is None
    assert providers.core_credential({"configured": "yes", "api_key": "k-1"}) is None
    assert providers.core_credential(None) is None
    assert providers.core_credential(["configured"]) is None
