# -*- coding: utf-8 -*-
"""OpenTIP builder module."""
import datetime
from typing import List, Optional, Union

import stix2
from pycti import (
    STIX_EXT_OCTI_SCO,
    Indicator,
    Location,
    Note,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    StixCoreRelationship,
)

from opentip.models.configs.opentip_configs import (
    ConfigLoaderOpenTIP,
)

class OpenTIPBuilder:
    """OpenTIP builder."""

    _API_URL = "https://opentip.kaspersky.com"

    _ZONE_SCORES = {
        "Red": 90,
        "Orange": 80,
        "Yellow": 40,
        "Green": 10,
        "Grey": None,
    }

    _ZONE_LABELS = {
        "Red": "opentip/red",
        "Orange": "opentip/orange",
        "Yellow": "opentip/yellow",
        "Green": "opentip/green",
        "Grey": "opentip/grey",
    }

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        replace_with_lower_score: bool,
        stix_objects: list,
        stix_entity: dict,
        opencti_entity: dict,
        data: dict,
        config: ConfigLoaderOpenTIP,
    ) -> None:
        """Initialize OpenTIP builder."""
        self.helper = helper
        self.author = author
        self.replace_with_lower_score = replace_with_lower_score
        self.bundle = stix_objects + [self.author]
        self.opencti_entity = opencti_entity
        self.stix_entity = stix_entity
        self.data = data
        self.config = config
        self.zone = data.get("Zone")
        self.general_info = self._extract_general_info(data)
        self.score = self._compute_score(data)
        self.external_reference = None

        if self.score is not None:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "score", self.score
            )

        observable_value = opencti_entity.get("observable_value", "")
        entity_type = opencti_entity.get("entity_type", "")
        link = self._build_external_reference_url(observable_value, entity_type)
        if link is not None:
            self.helper.log_debug(f"[OpenTIP] adding external reference {link}")
            self.external_reference = self._create_external_reference(
                link, "OpenTIP Report"
            )

    def _compute_score(self, data: dict) -> Optional[int]:
        """
        Compute the score based on OpenTIP zone.

        Parameters
        ----------
        data : dict
            API response data containing the Zone field.

        Returns
        -------
        int or None
            Score based on zone, or None for Grey zone (skip).
        """
        zone = data.get("Zone")

        if zone is None:
            self.helper.log_debug("[OpenTIP] No zone found in response")
            return None

        if zone not in self._ZONE_SCORES:
            self.helper.log_warning(f"[OpenTIP] Unknown zone: {zone}")
            return None

        if zone == "Grey":
            self.helper.log_debug("[OpenTIP] Zone is Grey (no data), skipping")
            return None

        return self._ZONE_SCORES[zone]

    def _extract_general_info(self, data: dict) -> dict:
        """
        Extract the general info section from the API response.

        Parameters
        ----------
        data : dict
            API response data.

        Returns
        -------
        dict
            The *GeneralInfo section, or empty dict if not found.
        """
        general_sections = [
            "FileGeneralInfo",
            "IpGeneralInfo",
            "DomainGeneralInfo",
            "UrlGeneralInfo",
        ]
        for section in general_sections:
            if section in data and isinstance(data[section], dict):
                return data[section]
        return {}

    def _create_external_reference(
        self, url: str, description: str
    ) -> dict:
        """
        Create an external reference with the given URL.

        Parameters
        ----------
        url : str
            URL for the external reference.
        description : str
            Description for the external reference.

        Returns
        -------
        dict
            External reference object.
        """
        external_reference = {
            "source_name": self.author["name"],
            "url": url,
            "description": description,
        }
        OpenCTIStix2.put_attribute_in_extension(
            self.stix_entity,
            STIX_EXT_OCTI_SCO,
            "external_references",
            external_reference,
            True,
        )
        return external_reference

    def _create_ip_address(self, ip: str) -> dict:
        """Create an IPv4 address STIX object."""
        return stix2.IPv4Address(
            value=ip,
            custom_properties={
                "created_by_ref": self.author.id,
                "x_opencti_score": self.score,
            },
        )

    def _create_autonomous_system(self, asn: int, name: Optional[str] = None) -> dict:
        """Create an Autonomous System STIX object."""
        return stix2.AutonomousSystem(
            number=asn,
            name=name,
            custom_properties={"created_by_ref": self.author.id},
        )

    def _create_location(self, country: str) -> dict:
        """Create a Location STIX object."""
        return stix2.Location(
            id=Location.generate_id(country, "Country"),
            created_by_ref=self.author,
            country=country,
        )

    def create_indicator_based_on_zone(
        self, indicator_zones: List[str], pattern: str
    ):
        """
        Create an Indicator based on list of zones that should trigger indicators.

        Objects created are added to the bundle.

        Parameters
        ----------
        indicator_zones : List[str]
            List of zones that should trigger indicator creation.
        pattern : str
            STIX pattern for the indicator.
        """
        zone = self.zone

        if zone is None:
            return

        if zone not in indicator_zones:
            return

        now_time = datetime.datetime.utcnow()
        minutes = 2880
        valid_until = now_time + datetime.timedelta(minutes=minutes)

        indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern),
            created_by_ref=self.author,
            name=self.opencti_entity["observable_value"],
            description=f"Created by OpenTIP connector when zone was {zone}",
            confidence=self.helper.connect_confidence_level,
            pattern=pattern,
            pattern_type="stix",
            valid_from=self.helper.api.stix2.format_date(now_time),
            valid_until=self.helper.api.stix2.format_date(valid_until),
            external_references=(
                [self.external_reference]
                if self.external_reference is not None
                else None
            ),
            custom_properties={
                "x_opencti_main_observable_type": self.opencti_entity["entity_type"],
                "x_opencti_detection": True,
                "x_opencti_score": self.score,
            },
        )

        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "based-on",
                indicator.id,
                self.stix_entity["id"],
            ),
            relationship_type="based-on",
            created_by_ref=self.author,
            source_ref=indicator.id,
            target_ref=self.stix_entity["id"],
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle += [indicator, relationship]

    def create_asn_belongs_to(self):
        """Create AutonomousSystem and Relationship for IP."""
        ip_whois = self.data.get("IpWhoIs", {}) or {}
        asn_list = ip_whois.get("Asn", [])

        if not asn_list or not isinstance(asn_list, list):
            return

        for asn_obj in asn_list:
            if not isinstance(asn_obj, dict):
                continue

            asn_number = asn_obj.get("Number")
            asn_description_list = asn_obj.get("Description")

            if not asn_number:
                continue

            self.helper.log_debug(f"[OpenTIP] creating ASN {asn_number}")

            asn_name = None
            if isinstance(asn_description_list, list) and asn_description_list:
                asn_name = asn_description_list[0]

            as_stix = self._create_autonomous_system(asn_number, asn_name)
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "belongs-to",
                    self.stix_entity["id"],
                    as_stix.id,
                ),
                relationship_type="belongs-to",
                created_by_ref=self.author,
                source_ref=self.stix_entity["id"],
                target_ref=as_stix.id,
                confidence=self.helper.connect_confidence_level,
                allow_custom=True,
            )
            self.bundle += [as_stix, relationship]

    def create_location_located_at(self):
        """Create Location and Relationship for IP."""
        ip_general_info = self.general_info if self.general_info else {}
        country = ip_general_info.get("CountryCode")

        if not country:
            return

        self.helper.log_debug(f"[OpenTIP] creating location with country {country}")
        location_stix = self._create_location(country)
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "located-at",
                self.stix_entity["id"],
                location_stix.id,
            ),
            relationship_type="located-at",
            created_by_ref=self.author,
            source_ref=self.stix_entity["id"],
            target_ref=location_stix.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle += [location_stix, relationship]

    def create_ip_resolves_to(self, ipv4: str):
        """Create IPv4 address and relationship for domain."""
        self.helper.log_debug(f"[OpenTIP] creating ipv4-address {ipv4}")
        ipv4_stix = self._create_ip_address(ipv4)
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "resolves-to",
                self.stix_entity["id"],
                ipv4_stix.id,
            ),
            relationship_type="resolves-to",
            created_by_ref=self.author,
            source_ref=self.stix_entity["id"],
            target_ref=ipv4_stix.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.bundle += [ipv4_stix, relationship]

    def update_labels_from_zone(self):
        """Update labels based on the zone."""
        if not self.config.add_zone_labels:
            return

        zone = self.zone
        if not zone:
            return

        label = self._ZONE_LABELS.get(zone)
        if label:
            OpenCTIStix2.put_attribute_in_extension(
                self.stix_entity,
                STIX_EXT_OCTI_SCO,
                "labels",
                label,
                True,
            )

    def _normalize_category_name(self, name: str) -> str:
        """Normalize a category name for labeling.

        Strips 'CATEGORY_' prefix (case-insensitive) and lowercases the remainder.
        Examples:
        - CATEGORY_MALWARE -> malware
        - category_phishing -> phishing
        - General -> general
        """
        name_lower = name.lower()
        if name_lower.startswith("category_"):
            return name_lower[9:]  # Remove 'category_' prefix
        return name_lower

    def update_labels_with_categories(self):
        """Update labels based on categories."""
        if not self.config.add_categories_labels:
            return

        categories = self.general_info.get("CategoriesWithZone", [])
        if not categories:
            categories = self.general_info.get("Categories", [])

        if not categories or not isinstance(categories, list):
            return

        for cat_obj in categories:
            if isinstance(cat_obj, dict):
                category_name = cat_obj.get("Name", "")
            elif isinstance(cat_obj, str):
                category_name = cat_obj
            else:
                continue

            if not category_name:
                continue

            normalized_name = self._normalize_category_name(category_name)
            label = f"opentip/{normalized_name}"

            OpenCTIStix2.put_attribute_in_extension(
                self.stix_entity,
                STIX_EXT_OCTI_SCO,
                "labels",
                label,
                True,
            )

    def update_file_status(self):
        """Update file status in note."""
        pass

    def update_domain_status(self):
        """Update domain status in note."""
        pass

    def create_note(self, abstract: str, content: str):
        """Create a single Note with the given abstract and content."""
        self.helper.log_debug(f"[OpenTIP] creating note with abstract {abstract}")
        self.bundle.append(
            stix2.Note(
                id=Note.generate_id(datetime.datetime.now().isoformat(), content),
                abstract=abstract,
                content=content,
                created_by_ref=self.author,
                object_refs=[self.stix_entity["id"]],
            )
        )

    def create_notes(self):
        """Create notes with analysis results."""
        pass

    def create_notes_attributes_content(self) -> str:
        """Create notes attributes content."""
        return ""

    def _build_external_reference_url(self, observable_value: str, entity_type: str) -> Optional[str]:
        """
        Build the external reference URL from the observable value and type.

        Parameters
        ----------
        observable_value : str
            The observable value (hash, IP, domain, or URL).
        entity_type : str
            The OpenCTI entity type.

        Returns
        -------
        str or None
            URL to the OpenTIP GUI, or None if type is not supported.
        """
        if not observable_value:
            return None

        observable_value_encoded = observable_value.replace(" ", "%20")

        if entity_type in ["StixFile", "Artifact"]:
            return f"{self._API_URL}/{observable_value_encoded}/"
        elif entity_type == "IPv4-Addr":
            return f"{self._API_URL}/{observable_value}/"
        elif entity_type in ["Domain-Name", "Hostname"]:
            return f"{self._API_URL}/{observable_value}/"
        elif entity_type == "Url":
            return f"{self._API_URL}/{observable_value_encoded}/"

        return None

    def send_bundle(self) -> str:
        """
        Serialize and send the bundle to be inserted.

        Returns
        -------
        str
            String with the number of bundles sent.
        """
        self.helper.metric.state("idle")
        if self.bundle is not None:
            self.helper.log_debug(f"[OpenTIP] sending bundle: {self.bundle}")
            self.helper.metric.inc("record_send", len(self.bundle))
            serialized_bundle = self.helper.stix2_create_bundle(self.bundle)
            bundles_sent = self.helper.send_stix2_bundle(serialized_bundle)
            return f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        return "Nothing to attach"
