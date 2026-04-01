# -*- coding: utf-8 -*-
"""OpenTIP builder module."""
import datetime
from typing import List, Optional

import stix2
from pycti import (
    STIX_EXT_OCTI_SCO,
    AutonomousSystem,
    Indicator,
    Location,
    Note,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    StixCoreRelationship,
)


class OpenTIPBuilder:
    """OpenTIP builder."""

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
        self.attributes = data.get("attributes", {})
        self.data = data
        self.config = config
        self.score = self._compute_score(data)
        self.external_reference = None

        if self.score is not None:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "score", self.score
            )

        link = self._extract_link(data.get("links", {}).get("self", ""))
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
        zone = self.attributes.get("Zone")

        if zone is None:
            return

        if zone not in indicator_zones:
            return

        now_time = datetime.datetime.utcnow()

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
        ip_general_info = self.data.get("IpGeneralInfo", {}) or self.data.get(
            "IpGeneralInfo", {}
        )

        if not ip_general_info:
            return

        asn_list = ip_general_info.get("Asn")
        if not asn_list or not isinstance(asn_list, list):
            return

        for asn_obj in asn_list:
            if not isinstance(asn_obj, dict):
                continue

            asn_number = asn_obj.get("Number")
            asn_description = asn_obj.get("Description")

            if not asn_number:
                continue

            self.helper.log_debug(f"[OpenTIP] creating ASN {asn_number}")

            as_stix = self._create_autonomous_system(asn_number, asn_description)
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
        country = self.data.get("CountryCode")

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

        zone = self.attributes.get("Zone")
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

    def update_labels_with_categories(self):
        """Update labels based on categories."""
        if not self.config.add_categories_labels:
            return

        categories = self.attributes.get("Categories", [])
        categories_with_zone = (
            self.attributes.get("CategoriesWithZone", [])
            or self.attributes.get("CategoriesWithZone", [])
        )

        primary_category = None
        primary_zone = None

        if categories_with_zone and isinstance(categories_with_zone, list):
            zone_priority = {"Red": 4, "Orange": 3, "Yellow": 2, "Green": 1, "Grey": 0}
            max_zone = "Grey"
            for cat_zone in categories_with_zone:
                zone = cat_zone.get("Zone", "Grey")
                if zone_priority.get(zone, 0) > zone_priority.get(max_zone, 0):
                    max_zone = zone
                    primary_category = cat_zone.get("Name")

            if primary_category and max_zone != "Grey":
                primary_zone = max_zone

        elif categories and isinstance(categories, list):
            if categories:
                primary_category = categories[0]

        if primary_category and primary_zone:
            OpenCTIStix2.put_attribute_in_extension(
                self.stix_entity,
                STIX_EXT_OCTI_SCO,
                "labels",
                f"opentip/category_{primary_category.lower()}",
                True,
            )
            OpenCTIStix2.put_attribute_in_extension(
                self.stix_entity,
                STIX_EXT_OCTI_SCO,
                "labels",
                f"opentip/category_{primary_category.lower()}_{primary_zone.lower()}",
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

    @staticmethod
    def _extract_link(link: str) -> Optional[str]:
        """
        Extract the link for the external reference.

        Parameters
        ----------
        link : str
            Original link from API response.

        Returns
        -------
        str or None
            Link to the OpenTIP GUI, if available.
        """
        if not link:
            return None

        for k, v in {
            "hash": "hash",
            "ip": "ip-address",
            "domain": "domain",
            "url": "url",
        }.items():
            if k in link:
                return link.replace("/api/v1/search/", "/").replace(f"?request=", "/")
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
