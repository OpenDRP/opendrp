"""OpenDRP platform core.

``__version__`` is the single source of truth for the platform version. The
FastAPI app, the ``/api/v1/health`` payload and the release notes all read it
from here, and ``scripts/check_version_consistency.py`` fails the build if this
file, ``backend/pyproject.toml`` and the newest ``CHANGELOG.md`` entry disagree.
Three copies of a version string is how a running instance reports a version
that was never released.
"""

__version__ = "0.1.2"
