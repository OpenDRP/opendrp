"""The body-bound gate has to see the read it exists for.

Five bodies were read in full before their size was considered — two of them with
no bound at all — and a sixth was found only while writing the report that closed
the fifth. Each was found by reading code, one at a time. The gate turns that into
one rule a machine can check:

    a body from anywhere but this platform's own API is read through a bounded
    reader, never through `.content`, `.text` or `.json()`.

The tests below build the smallest connector tree that demonstrates a violation
and the smallest one that is allowed, because a gate is only worth its CI minute
if it fails on the shape it names. The shipped tree is asserted to be clean as
well, which is the difference between a rule and a wish.

`connectors/base/` is out of scope on purpose: it is where the bounded reader
lives, and a rule that forbade the SDK from touching a body would forbid the bound
from existing.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_GATE = _ROOT / "scripts" / "check_connector_body_bounds.py"

if not _GATE.is_file():
    # The dev overlay mounts the repository's scripts/ read-only for this suite;
    # a trimmed checkout cannot answer the question.
    pytest.skip(
        f"not a repository checkout: {_GATE.name} missing", allow_module_level=True
    )


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = _load(_GATE, "opendrp_test_check_connector_body_bounds")


def _tree(tmp_path: Path, **files: str) -> Path:
    """A checkout whose connector tree holds exactly the named modules."""
    for name, source in files.items():
        path = tmp_path / "connectors" / name.replace("__", "/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    return tmp_path


def test_the_shipped_tree_has_no_unbounded_body_read():
    assert gate.check(_ROOT) == []


def test_a_provider_body_read_through_json_is_reported_with_its_line(tmp_path):
    """The shape every one of the six defects had: read first, bound later."""
    root = _tree(
        tmp_path,
        **{
            "worker__main.py": (
                "import httpx\n"
                "\n"
                "async def fetch(client):\n"
                "    response = await client.get('https://api.example/x')\n"
                "    return response.json()\n"
            )
        },
    )
    failures = gate.check(root)

    assert len(failures) == 1
    assert failures[0].startswith(f"{root / 'connectors/worker/main.py'}:5:")
    assert "`json`" in failures[0]


def test_a_buffer_then_compare_read_is_reported(tmp_path):
    """`len(response.content) > bound` is the endpoint worker's defect verbatim."""
    root = _tree(
        tmp_path,
        **{
            "worker__main.py": (
                "MAX_BODY = 2_000_000\n"
                "\n"
                "def body(response):\n"
                "    if len(response.content) > MAX_BODY:\n"
                "        raise RuntimeError('too large')\n"
                "    return response.content\n"
            )
        },
    )
    failures = gate.check(root)

    assert len(failures) == 2, "both the comparison and the return are reads"
    assert all("`content`" in failure for failure in failures)


def test_a_body_read_through_aread_is_reported(tmp_path):
    """`await response.aread()` is the same read as `.content`, with an await in front."""
    root = _tree(
        tmp_path,
        **{
            "worker__main.py": (
                "async def body(response):\n    return await response.aread()\n"
            )
        },
    )
    failures = gate.check(root)

    assert len(failures) == 1
    assert "`aread`" in failures[0]


def test_a_body_from_the_core_is_allowed_however_it_is_read(tmp_path):
    """The platform's own answers are the one exception, and it is syntactic."""
    root = _tree(
        tmp_path,
        **{
            "worker__main.py": (
                "class Worker:\n"
                "    async def assigned(self):\n"
                "        response = await self._request('GET', '/api/v1/me/credential')\n"
                "        return response.json()\n"
                "\n"
                "    async def inlined(self):\n"
                "        return (await self._request('GET', '/api/v1/me/work')).json()\n"
            )
        },
    )

    assert gate.check(root) == []


def test_a_streamed_read_is_what_the_rule_asks_for(tmp_path):
    root = _tree(
        tmp_path,
        **{
            "worker__main.py": (
                "async def read(response):\n"
                "    content = bytearray()\n"
                "    async for chunk in response.aiter_bytes():\n"
                "        content.extend(chunk)\n"
                "    return bytes(content)\n"
            )
        },
    )

    assert gate.check(root) == []


def test_the_sdk_keeps_its_own_bound_reader(tmp_path):
    """`connectors/base/` is the reader, not a caller of one."""
    root = _tree(
        tmp_path,
        **{
            "base__opendrp_connector__client.py": (
                "def decode(response):\n    return response.json()\n"
            )
        },
    )

    assert gate.check(root) == []


def test_a_test_module_may_assert_what_production_must_not_do(tmp_path):
    root = _tree(
        tmp_path,
        **{
            "worker__test_main.py": (
                "def test_reads(response):\n    return response.json()\n"
            )
        },
    )

    assert gate.check(root) == []


def test_a_module_the_gate_cannot_parse_is_not_a_pass(tmp_path):
    """An unreadable input fails the gate rather than passing it silently."""
    root = _tree(tmp_path, **{"worker__main.py": "def broken(:\n"})

    with pytest.raises(gate.Unreadable):
        gate.check(root)


def test_a_checkout_without_a_connector_tree_is_not_a_pass(tmp_path):
    with pytest.raises(gate.Unreadable):
        gate.check(tmp_path)
