"""SPNEGO Login Views"""
import binascii
from base64 import b64decode, b64encode

import gssapi
from django.conf import settings
from django.contrib import messages
from django.core.exceptions import SuspiciousOperation
from django.http import (
    Http404,
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseForbidden,
)
from django.shortcuts import get_object_or_404, redirect
from django.utils.translation import gettext as _
from django.views.generic import View
from structlog.stdlib import get_logger

from authentik.core.sources.flow_manager import SourceFlowManager
from authentik.events.models import Event
from authentik.sources.spnego.models import SPNEGOSource, UserSPNEGOSourceConnection

LOGGER = get_logger()


class SPNEGOLogin(View):
    """SPNEGO login view."""

    source: SPNEGOSource

    def dispatch(self, request: HttpRequest, source_slug: str) -> HttpResponse:
        source = get_object_or_404(SPNEGOSource, slug=source_slug)
        if not self.source.enabled:
            raise Http404

        auth_header = request.META.get("HTTP_AUTHORIZATION")
        if not auth_header or not auth_header.startswith("Negotiate "):
            return HttpResponse(
                status=401,
                headers={
                    "WWW-Authenticate": "Negotiate",
                },
            )

        try:
            in_token = b64decode(
                request.headers["Authorization"][len("Negotiate ") :].strip().encode(),
            )
        except binascii.Error:
            raise SuspiciousOperation("Malformed negotiate token")

        sname = None
        if self.source.spn:
            sname = gssapi.Name(self.source.spn, gssapi.C_NT_HOSTBASED_SERVICE)
        cred = gssapi.Credentials(name=sname, usage=gssapi.C_ACCEPT)
        ctx = gssapi.AcceptContext(cred)

        out_token = ctx.step(in_token)
        if not ctx.established:
            # We canot handle extra steps with multiple backend server due to
            # load-balancing sending subsequent requests elsewhere
            out_token = ctx.delete_sec_context()
            return HttpResponseBadRequest(headers={"WWW-Authenticate": f"Negotiate {out_token}"})

        rep = HttpResponse()
        if out_token:
            out_token = b64encode(out_token).decode()
            rep["WWW-Authenticate"] = f"Negotiate {out_token}"

        if ctx.initiator_is_anonymous():
            ctx.delete_sec_context()
            return HttpResponseForbidden()

        principal = ctx.peer_name.display_as(gssapi.NameType.krb5_nt_principal)
        ctx.delete_sec_context()
        enroll_info = {
            "principal": principal,
            "attributes": ctx.peer_name.attributes,
        }
        sfm = SPNEGOSourceFlowManager(
            source=self.source,
            request=self.request,
            identifier=principal,
            enroll_info=enroll_info,
        )
        return sfm.get_flow(
            principal=principal,
        )

    def handle_login_failure(self, reason: str) -> HttpResponse:
        "Message user and redirect on error."
        LOGGER.warning("Authentication Failure", reason=reason)
        messages.error(
            self.request,
            _(
                "Authentication failed: %(reason)s"
                % {
                    "reason": reason,
                }
            ),
        )
        return redirect(self.get_error_redirect(self.source, reason))


class SPNEGOSourceFlowManager(SourceFlowManager):
    """Flow manager for oauth sources"""

    connection_type = UserSPNEGOSourceConnection

    def update_connection(
        self,
        connection: UserSPNEGOSourceConnection,
        principal: str = None,
    ) -> UserSPNEGOSourceConnection:
        """Set the access_token on the connection"""
        connection.principal = principal
        return connection
