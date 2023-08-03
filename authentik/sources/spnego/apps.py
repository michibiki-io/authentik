"""authentik Sources SPNEGO config"""
from structlog.stdlib import get_logger

from authentik.blueprints.apps import ManagedAppConfig


class AuthentikSourceOAuthConfig(ManagedAppConfig):
    """authentik source.oauth config"""

    name = "authentik.sources.spnego"
    label = "authentik_sources_spnego"
    verbose_name = "authentik Sources.SPNEGO"
