from typing import Annotated, List, Literal

from pydantic import Field, PlainSerializer, SecretStr
from opentip.models.configs.base_settings import ConfigBaseSettings

TLPToLower = Annotated[
    Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]

Zone = Annotated[
    Literal["Red", "Orange", "Yellow", "Green", "Grey"],
    PlainSerializer(lambda v: v, return_type=str),
]


class IndicatorZoneConfig(ConfigBaseSettings):
    """Shared indicator zone configuration - selected zones trigger indicator creation."""

    zones: List[Zone] = Field(
        default=["Red", "Orange", "Yellow"],
        description="List of zones that will trigger indicator creation. Default: Red, Orange, Yellow (threat zones).",
    )


class ConfigLoaderOpenTIP(ConfigBaseSettings):
    """Interface for loading OpenTIP dedicated configuration."""

    token: SecretStr = Field(
        description="OpenTIP API token for authentication.",
    )
    max_tlp: TLPToLower = Field(
        default="TLP:AMBER",
        description="Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI.",
    )
    replace_with_lower_score: bool = Field(
        default=False,
        description="Whether to keep the higher of the OpenTIP or existing score (false) or force the score to be updated with the OpenTIP score even if its lower than existing score (true).",
    )

    zone_score_red: int = Field(
        default=90,
        description="Score for Red zone (malware).",
    )
    zone_score_orange: int = Field(
        default=80,
        description="Score for Orange zone (not trusted).",
    )
    zone_score_yellow: int = Field(
        default=40,
        description="Score for Yellow zone (adware).",
    )
    zone_score_green: int = Field(
        default=10,
        description="Score for Green zone (clean).",
    )

    file_create_note_full_report: bool = Field(
        default=True,
        description="Whether or not to include the full report as a Note.",
    )
    file_upload_unseen_artifacts: bool = Field(
        default=False,
        description="Whether to upload artifacts that OpenTIP has no record of (not supported by OpenTIP).",
    )

    ip_add_relationships: bool = Field(
        default=False,
        description="Whether or not to add ASN and location resolution relationships.",
    )

    domain_add_relationships: bool = Field(
        default=False,
        description="Whether or not to add IP resolution relationships.",
    )

    url_upload_unseen: bool = Field(
        default=False,
        description="Whether to upload URLs that OpenTIP has no record of (not supported by OpenTIP).",
    )

    include_attributes_in_note: bool = Field(
        default=False,
        description="Whether or not to include the attributes info in Note.",
    )
    add_categories_labels: bool = Field(
        default=True,
        description="Whether or not to add category labels to observables.",
    )
    add_zone_labels: bool = Field(
        default=True,
        description="Whether or not to add zone labels to observables.",
    )

    indicator_zones: List[Zone] = Field(
        default=["Red", "Orange", "Yellow"],
        description="Zones that trigger indicator creation for all observable types.",
    )
