"""SPNEGO Source Serializer"""
from django.urls.base import reverse_lazy
from django_filters.filters import BooleanFilter
from django_filters.filterset import FilterSet
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_field
from rest_framework.decorators import action
from rest_framework.fields import ChoiceField, SerializerMethodField
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from authentik.core.api.sources import SourceSerializer
from authentik.core.api.used_by import UsedByMixin
from authentik.sources.spnego.models import SPNEGOSource


class SPNEGOSourceSerializer(SourceSerializer):
    """SPNEGO Source Serializer"""

    class Meta:
        model = SPNEGOSource
        fields = SourceSerializer.Meta.fields + [
            "spn",
            "keytab",
        ]


class SPNEGOSourceViewSet(UsedByMixin, ModelViewSet):
    """SPNEGO Source Viewset"""

    queryset = SPNEGOSource.objects.all()
    serializer_class = SPNEGOSourceSerializer
    lookup_field = "slug"
    filterset_fields = [
        "name",
        "slug",
        "enabled",
        "authentication_flow",
        "enrollment_flow",
        "managed",
        "policy_engine_mode",
        "user_matching_mode",
        "pre_authentication_flow",
        "spn",
    ]
    search_fields = ["name", "slug"]
    ordering = ["name"]
