"""Assertions about text that a substring check cannot make honestly.

One question appears in several suites — "does this message name this host?" — and
the obvious way to ask it, ``"high-1.example.com" in body``, answers a different
one: ``high-1.example.com.evil.net`` contains that text too, so the assertion
passes on a message that names somebody else's domain, and a test written to
prove the right host is announced would be satisfied by the wrong one.

The boundary is what these helpers add. It is also what a static analyzer asks
for: the same shape is reported as an incomplete URL check in tests as well as in
code, and that report is fair — the assertion was always trying to say "a whole
name", not "these characters somewhere".

Kept in one module rather than in each suite because more than one suite asks it,
and because the next one should not have to rediscover why.
"""

from __future__ import annotations

import re

#: The characters a host name is made of. A match touching one of these on either
#: side is part of a longer name, which is exactly the case a substring check
#: cannot tell apart.
_NAME_CHARACTER = r"[A-Za-z0-9._-]"


def mentions(body: str, value: str) -> bool:
    """Whether ``body`` names ``value`` as a whole rather than inside a longer name."""
    return (
        re.search(
            rf"(?<!{_NAME_CHARACTER}){re.escape(value)}(?!{_NAME_CHARACTER})",
            body,
        )
        is not None
    )
