"""OpenDRP Connector SDK.

The package version is the platform release the connectors ship with, not an
independent number: connector images are built and tagged with the same version
as the core, and ``scripts/check_version_consistency.py`` refuses a tree where
the two disagree.
"""

from .base import ConnectorBase, ConnectorPreflightError

__all__ = ["ConnectorBase", "ConnectorPreflightError"]
__version__ = "0.2.1"
