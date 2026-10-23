import importlib.util
import sys
from pathlib import Path

_ROOT = (
    Path("/connectors")
    if Path("/connectors").exists()
    else Path(__file__).resolve().parents[2] / "connectors"
)
# `providers.py` imports the shared SDK by its installed name, so this module only
# collected when another test had already put `connectors/base` on the path — a
# suite run in shards found it (plan 011, pass C). Every sibling that executes
# connector code inserts the same directory; this file just never needed to while
# it ran in one process.
if str(_ROOT / "base") not in sys.path:
    sys.path.insert(0, str(_ROOT / "base"))
_PATH = _ROOT / "intelligence" / "providers.py"
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
