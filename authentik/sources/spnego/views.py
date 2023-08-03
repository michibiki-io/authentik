"""OAuth Callback Views"""
from json import JSONDecodeError
from typing import Any, Optional

from django.conf import settings
from django.contrib import messages
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseForbidden, HttpResponseBadRequest
from django.shortcuts import redirect, get_object_or_404
from django.utils.translation import gettext as _
from django.views.generic import View
from structlog.stdlib import get_logger

from authentik.core.sources.flow_manager import SourceFlowManager
from authentik.events.models import Event, EventAction
from authentik.sources.spnego.models import SPNEGOSource, UserSPNEGOSourceConnection

LOGGER = get_logger()


class SPNEGOLogin(View):
    """Base SPNEGO login view."""

    source: SPNEGOSource

    def dispatch(self, request: HttpRequest, *_, **kwargs) -> HttpResponse:
        """View Get handler"""
        slug = kwargs.get("source_slug", "")

        self.source = get_object_or_404(SPNEGOSource, slug=slug)

        if not self.source.enabled:
            raise Http404(f"Source {slug} is not enabled.")

        auth_header = request.get("Authorization")
        if not auth_header or not auth_header.startswith("Negotiate "):
            rep = HttpResponse(code=401)
            rep["WWW-Authenticate"] = "Negotiate"
            return rep

        try:
            in_token = b64decode(
                request.headers['Authorization'][len("Negotiate "):].strip().encode(),
            )
        except:
            raise SuspiciousOperation("Malformed negotiate token")

        sname = ""
        if self.source.sname:
            sname = gssapi.Name(self.source.sname, gssapi.C_NT_HOSTBASED_SERVICE)
        cred = gssapi.Credential(sname, usage=gssapi.C_ACCEPT)
        ctx = gssapi.AcceptContext(cred)

        out_token = ctx.step(in_token)
        if not ctx.established:
            # We canot handle extra steps with multiple backend server due to
            # load-balancing sending subsequent requests elsewhere
            out_token = ctx.delete_sec_context()
            return HttpResponseBadRequest(
                headers={
                    rep["WWW-Authenticate"] = f"Negotiate {out_token}"
                }
            )

        rep = HttpResponse()
        if out_token:
            out_token = b64encode(out_token).decode()
            rep["WWW-Authenticate"] = f"Negotiate {out_token}"

        if ctx.initiator_is_anonymous():
            ctx.delete_sec_context()
            return HttpResponseForbidden()

        principal = ctx.peer_name.display_as(gssapi.NameType.krb5_nt_principal)
        ctx.delete_sec_context()
        enroll_info={
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

    def get_error_redirect(self, source: SPNEGOSource, reason: str) -> str:
        "Return url to redirect on login failure."
        return settings.LOGIN_URL

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


class OAuthSourceFlowManager(SourceFlowManager):
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
