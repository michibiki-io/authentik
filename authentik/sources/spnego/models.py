"""authentik Source SPNEGO models"""
from typing import Optional

from django.db import models
from django.http.request import HttpRequest
from django.templatetags.static import static
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import Serializer

from authentik.core.models import Source, UserSourceConnection
from authentik.core.types import UILoginButton, UserSettingSerializer
from authentik.flows.challenge import Challenge, ChallengeTypes, ShellChallenge


class SPNEGOSource(Source):
    """Login using a SPNEGO provider."""

    spn = models.TextField(blank=True)
    keytab = models.BinaryField()

    @property
    def component(self) -> str:
        return "ak-source-spnego-form"

    @property
    def serializer(self) -> type[Serializer]:
        from authentik.sources.spnego.api.source import SPNEGOSourceSerializer

        return SPNEGOSourceSerializer

    def ui_login_button(self, request: HttpRequest) -> UILoginButton:
        return UILoginButton(
            name=self.name,
            icon_url=self.get_icon,
            challenge=None,  # TODO
        )

    def ui_user_settings(self) -> Optional[UserSettingSerializer]:
        icon = self.get_icon
        if not icon:
            icon = static(f"authentik/sources/{self.slug}.svg")
        return UserSettingSerializer(
            data={
                "title": self.name,
                "component": "ak-user-settings-source-spnego",
                "configure_url": reverse(
                    "authentik_sources_spnego:login",
                    kwargs={"source_slug": self.slug},
                ),
                "icon_url": icon,  # TODO
            }
        )

    def __str__(self) -> str:
        return f"SPNEGO Source {self.name}"

    class Meta:
        verbose_name = _("SPNEGO Source")
        verbose_name_plural = _("SPNEGO Sources")


class UserSPNEGOSourceConnection(UserSourceConnection):
    """Authorized remote SPNEGO provider."""

    identifier = models.TextField()

    @property
    def serializer(self) -> type[Serializer]:
        from authentik.sources.spnego.api.source_connection import (
            UserSPNEGOSourceConnectionSerializer,
        )

        return UserSPNEGOSourceConnectionSerializer

    class Meta:
        verbose_name = _("User SPNEGO Source Connection")
        verbose_name_plural = _("User SPNEGO Source Connections")
