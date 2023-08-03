"""authentik spnego source urls"""

from django.urls import path

from authentik.sources.spnego.api.source import SPNEGOSourceViewSet
from authentik.sources.spnego.api.source_connection import UserSPNEGOSourceConnectionViewSet
from authentik.sources.spnego.views.dispatcher import DispatcherView

urlpatterns = [
    path(
        "login/<slug:source_slug>/",
        DispatcherView.as_view(),
        name="login",
    ),
]

api_urlpatterns = [
    ("sources/user_connections/spnego", UserSPNEGOSourceConnectionViewSet),
    ("sources/spnego", SPNEGOSourceViewSet),
]
