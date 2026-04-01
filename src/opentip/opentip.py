# -*- coding: utf-8 -*-
"""OpenTIP enrichment module."""

from typing import Dict, List

import stix2
from pycti import Identity, OpenCTIConnectorHelper
from opentip.builder import OpenTIPBuilder
from opentip.client import OpenTIPClient
from opentip.models.configs.config_loader import ConfigLoader
from opentip.models.configs.opentip_configs import ConfigLoaderOpenTIP


class OpenTIPConnector:
    """OpenTIP connector."""

    _SOURCE_NAME = "OpenTIP"
    _API_URL = "https://opentip.kaspersky.com"

    def __init__(self, config: ConfigLoader, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.author = stix2.Identity(
            id=Identity.generate_id(self._SOURCE_NAME, "organization"),
            name=self._SOURCE_NAME,
            identity_class="organization",
            description="Kaspersky OpenTIP",
            confidence=self.helper.connect_confidence_level,
        )

        self.max_tlp = self.config.opentip.max_tlp
        self.replace_with_lower_score = self.config.opentip.replace_with_lower_score
        token = self.config.opentip.token.get_secret_value()
        self.client = OpenTIPClient(self.helper, self._API_URL, token)

        self.include_attributes_in_note = self.config.opentip.include_attributes_in_note
        self.add_categories_labels = self.config.opentip.add_categories_labels
        self.add_zone_labels = self.config.opentip.add_zone_labels

        self.ip_add_relationships = self.config.opentip.ip_add_relationships
        self.domain_add_relationships = self.config.opentip.domain_add_relationships
        self.indicator_zones = self.config.opentip.indicator_zones

    def resolve_default_value(self, stix_entity):
        if "hashes" in stix_entity and "SHA-256" in stix_entity["hashes"]:
            return stix_entity["hashes"]["SHA-256"]
        if "hashes" in stix_entity and "SHA-1" in stix_entity["hashes"]:
            return stix_entity["hashes"]["SHA-1"]
        if "hashes" in stix_entity and "MD5" in stix_entity["hashes"]:
            return stix_entity["hashes"]["MD5"]
        raise ValueError(
            "Unable to enrich the observable, the observable does not have an SHA256, SHA1, or MD5"
        )

    def _process_file(self, stix_objects, stix_entity, opencti_entity):
        hash_value = self.resolve_default_value(stix_entity)
        json_data = self.client.get_hash_info(hash_value)

        if not json_data or "error" in json_data:
            if json_data and "error" in json_data:
                raise ValueError(json_data["error"].get("message", "An error occurred"))
            raise ValueError("An error has occurred.")

        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            self.replace_with_lower_score,
            stix_objects,
            stix_entity,
            opencti_entity,
            json_data["data"],
            self.config.opentip,
        )

        builder.update_labels_from_zone()
        builder.update_labels_with_categories()

        if opencti_entity["entity_type"] == "StixFile":
            if "Size" in builder.attributes:
                stix_entity["size"] = builder.attributes.get("Size")
            if "Sha256" in builder.attributes:
                stix_entity["hashes"]["SHA-256"] = builder.attributes.get("Sha256")
            if "Sha1" in builder.attributes:
                stix_entity["hashes"]["SHA-1"] = builder.attributes.get("Sha1")
            if "Md5" in builder.attributes:
                stix_entity["hashes"]["MD5"] = builder.attributes.get("Md5")
            if "Type" in builder.attributes:
                stix_entity["name"] = builder.attributes.get("Type")

        sha256_hash = json_data["data"]["attributes"].get("Sha256", "")
        builder.create_indicator_based_on_zone(
            self.indicator_zones,
            f"""[file:hashes.'SHA-256' = '{sha256_hash}']""",
        )

        return builder.send_bundle()

    def _process_ip(self, stix_objects, stix_entity, opencti_entity):
        json_data = self.client.get_ip_info(opencti_entity["observable_value"])

        if not json_data or "error" in json_data:
            if json_data and "error" in json_data:
                raise ValueError(json_data["error"].get("message", "An error occurred"))
            raise ValueError("An error has occurred.")

        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            self.replace_with_lower_score,
            stix_objects,
            stix_entity,
            opencti_entity,
            json_data["data"],
            self.config.opentip,
        )

        if self.ip_add_relationships:
            builder.create_asn_belongs_to()
            builder.create_location_located_at()

        builder.update_labels_from_zone()
        builder.update_labels_with_categories()

        builder.create_indicator_based_on_zone(
            self.indicator_zones,
            f"""[ipv4-addr:value = '{opencti_entity["observable_value"]}']""",
        )

        return builder.send_bundle()

    def _process_domain(self, stix_objects, stix_entity, opencti_entity):
        json_data = self.client.get_domain_info(opencti_entity["observable_value"])

        if not json_data or "error" in json_data:
            if json_data and "error" in json_data:
                raise ValueError(json_data["error"].get("message", "An error occurred"))
            raise ValueError("An error has occurred.")

        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            self.replace_with_lower_score,
            stix_objects,
            stix_entity,
            opencti_entity,
            json_data["data"],
            self.config.opentip,
        )

        if self.domain_add_relationships:
            for ip in [
                r["value"]
                for r in json_data["data"]["attributes"].get("last_dns_records", [])
                if r.get("type") == "A"
            ]:
                self.helper.log_debug(
                    f'[OpenTIP] adding ip {ip} to domain {opencti_entity["observable_value"]}'
                )
                builder.create_ip_resolves_to(ip)

        builder.update_labels_from_zone()
        builder.update_labels_with_categories()

        builder.create_indicator_based_on_zone(
            self.indicator_zones,
            f"""[domain-name:value = '{opencti_entity["observable_value"]}']""",
        )

        return builder.send_bundle()

    def _process_url(self, stix_objects, stix_entity, opencti_entity):
        json_data = self.client.get_url_info(opencti_entity["observable_value"])

        if not json_data or "error" in json_data:
            if json_data and "error" in json_data:
                raise ValueError(json_data["error"].get("message", "An error occurred"))
            raise ValueError("An error has occurred.")

        if "data" not in json_data or "attributes" not in json_data["data"]:
            raise ValueError("An error has occurred.")

        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            self.replace_with_lower_score,
            stix_objects,
            stix_entity,
            opencti_entity,
            json_data["data"],
            self.config.opentip,
        )

        builder.update_labels_from_zone()
        builder.update_labels_with_categories()

        builder.create_indicator_based_on_zone(
            self.indicator_zones,
            f"""[url:value = '{opencti_entity["observable_value"]}']""",
        )

        return builder.send_bundle()

    def _process_message(self, data: Dict):
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]

        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        self.helper.log_debug(
            "[OpenTIP] starting enrichment of observable: {"
            + opencti_entity["observable_value"]
            + "}"
        )

        match opencti_entity["entity_type"]:
            case "StixFile" | "Artifact":
                return self._process_file(stix_objects, stix_entity, opencti_entity)
            case "IPv4-Addr":
                return self._process_ip(stix_objects, stix_entity, opencti_entity)
            case "Domain-Name" | "Hostname":
                return self._process_domain(stix_objects, stix_entity, opencti_entity)
            case "Url":
                return self._process_url(stix_objects, stix_entity, opencti_entity)
            case "IPv6-Addr":
                self.helper.log_warning("[OpenTIP] IPv6-Addr not supported yet")
                return "IPV6 not supported"
            case _:
                raise ValueError(
                    f'{opencti_entity["entity_type"]} is not a supported entity type.'
                )

    def start(self):
        self.helper.metric.state("idle")
        self.helper.listen(message_callback=self._process_message)
