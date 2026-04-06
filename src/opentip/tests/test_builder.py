# -*- coding: utf-8 -*-
"""OpenTIP builder unittest."""
import unittest

import stix2
from pycti import Identity
from opentip.builder import OpenTIPBuilder


class OpenTIPBuilderTest(unittest.TestCase):
    def setUp(self):
        self.helper = self._create_mock_helper()
        self.author = stix2.Identity(
            id=Identity.generate_id("OpenTIP", "Organization"),
            name="OpenTIP",
            identity_class="Organization",
            description="Kaspersky OpenTIP",
            confidence=self.helper.connect_confidence_level,
        )

    @staticmethod
    def _create_mock_helper():
        from unittest.mock import MagicMock, PropertyMock
        from datetime import datetime
        helper = MagicMock()
        type(helper).connect_confidence_level = PropertyMock(return_value=49)
        helper.api.stix2.format_date = lambda dt: dt.isoformat() + "Z" if dt.tzinfo is None else dt.isoformat().replace("+00:00", "Z")
        return helper

    @staticmethod
    def load_file(filename: str):
        import os
        import json
        filepath = os.path.join(
            os.path.dirname(__file__), "resources", filename
        )
        with open(filepath, encoding="utf-8") as json_file:
            return json.load(json_file)

    def test_init_builder_file(self):
        data = self.load_file("opentip_test_file.json")
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            {"id": "file--a7b0d7ec-0000-4000-8000-000000000001"},
            {"id": "file--a7b0d7ec-0000-4000-8000-000000000001", "observable_value": "2539170C4C1FFEEB17E87917687B5F86104CC88DE9478696CEE6E0ECADDFC9BB", "entity_type": "StixFile"},
            data,
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        self.assertEqual(len(builder.bundle), 1)
        self.assertEqual(builder.zone, "Yellow")
        self.assertEqual(builder.score, 40)
        self.assertEqual(builder.general_info.get("Sha256"), "2539170C4C1FFEEB17E87917687B5F86104CC88DE9478696CEE6E0ECADDFC9BB")

    def test_init_builder_ip(self):
        data = self.load_file("opentip_test_ipv4.json")
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            {"id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002"},
            {"id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002", "observable_value": "39.90.148.83", "entity_type": "IPv4-Addr"},
            data,
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        self.assertEqual(builder.zone, "Red")
        self.assertEqual(builder.score, 90)
        self.assertEqual(builder.general_info.get("CountryCode"), "CN")

    def test_init_builder_domain(self):
        data = self.load_file("opentip_test_domain.json")
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            {"id": "domain--a7b0d7ec-0000-4000-8000-000000000003"},
            {"id": "domain--a7b0d7ec-0000-4000-8000-000000000003", "observable_value": "tetegrams.org", "entity_type": "Domain-Name"},
            data,
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        self.assertEqual(builder.zone, "Red")
        self.assertEqual(builder.score, 90)
        self.assertEqual(builder.general_info.get("Domain"), "tetegrams.org")

    def test_init_builder_url(self):
        data = self.load_file("opentip_test_url.json")
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            {"id": "url--a7b0d7ec-0000-4000-8000-000000000004"},
            {"id": "url--a7b0d7ec-0000-4000-8000-000000000004", "observable_value": "gsocket.io/x", "entity_type": "Url"},
            data,
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        self.assertEqual(builder.zone, "Yellow")
        self.assertEqual(builder.score, 40)
        self.assertEqual(builder.general_info.get("Url"), "gsocket.io/x")

    def test_compute_score_red(self):
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            {},
            {},
            {"Zone": "Red"},
            type("Config", (), {"add_zone_labels": True, "add_categories_labels": True})(),
        )
        self.assertEqual(builder.score, 90)

    def test_compute_score_orange(self):
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            {},
            {},
            {"Zone": "Orange"},
            type("Config", (), {"add_zone_labels": True, "add_categories_labels": True})(),
        )
        self.assertEqual(builder.score, 80)

    def test_compute_score_yellow(self):
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            {},
            {},
            {"Zone": "Yellow"},
            type("Config", (), {"add_zone_labels": True, "add_categories_labels": True})(),
        )
        self.assertEqual(builder.score, 40)

    def test_compute_score_green(self):
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            {},
            {},
            {"Zone": "Green"},
            type("Config", (), {"add_zone_labels": True, "add_categories_labels": True})(),
        )
        self.assertEqual(builder.score, 10)

    def test_compute_score_grey(self):
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            {},
            {},
            {"Zone": "Grey"},
            type("Config", (), {"add_zone_labels": True, "add_categories_labels": True})(),
        )
        self.assertIsNone(builder.score)

    def test_compute_score_no_zone(self):
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            {},
            {},
            {},
            type("Config", (), {"add_zone_labels": True, "add_categories_labels": True})(),
        )
        self.assertIsNone(builder.score)

    def test_update_labels_from_zone_enabled(self):
        data = self.load_file("opentip_test_ipv4.json")
        stix_entity = {
            "id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002"
        }
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            {"id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002", "observable_value": "39.90.148.83", "entity_type": "IPv4-Addr"},
            data,
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        builder.update_labels_from_zone()
        labels = stix_entity.get("extensions", {}).get("extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82", {}).get("labels", [])
        self.assertIn("opentip/red", labels)

    def test_update_labels_from_zone_disabled(self):
        data = self.load_file("opentip_test_ipv4.json")
        stix_entity = {
            "id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002"
        }
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            {"id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002", "observable_value": "39.90.148.83", "entity_type": "IPv4-Addr"},
            data,
            type("Config", (), {
                "add_zone_labels": False,
                "add_categories_labels": True,
            })(),
        )
        builder.update_labels_from_zone()
        labels = stix_entity.get("extensions", {}).get("extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82", {}).get("labels", [])
        self.assertNotIn("opentip/red", labels)

    def test_update_labels_with_categories(self):
        data = self.load_file("opentip_test_ipv4.json")
        stix_entity = {
            "id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002"
        }
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            {"id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002", "observable_value": "39.90.148.83", "entity_type": "IPv4-Addr"},
            data,
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        builder.update_labels_with_categories()
        labels = stix_entity.get("extensions", {}).get("extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82", {}).get("labels", [])
        self.assertIn("opentip/malware", labels)

    def test_update_labels_with_categories_domain(self):
        data = self.load_file("opentip_test_domain.json")
        stix_entity = {
            "id": "domain--a7b0d7ec-0000-4000-8000-000000000003"
        }
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            {"id": "domain--a7b0d7ec-0000-4000-8000-000000000003", "observable_value": "tetegrams.org", "entity_type": "Domain-Name"},
            data,
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        builder.update_labels_with_categories()
        labels = stix_entity.get("extensions", {}).get("extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82", {}).get("labels", [])
        self.assertIn("opentip/phishing", labels)

    def test_update_labels_with_categories_url(self):
        data = self.load_file("opentip_test_url.json")
        stix_entity = {
            "id": "url--a7b0d7ec-0000-4000-8000-000000000004"
        }
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            {"id": "url--a7b0d7ec-0000-4000-8000-000000000004", "observable_value": "gsocket.io/x", "entity_type": "Url"},
            data,
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        builder.update_labels_with_categories()
        labels = stix_entity.get("extensions", {}).get("extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82", {}).get("labels", [])
        self.assertIn("opentip/other", labels)

    def test_create_asn_belongs_to(self):
        data = self.load_file("opentip_test_ipv4.json")
        stix_entity = {
            "id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002"
        }
        observable = {"id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002"}
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [stix_entity],
            stix_entity,
            observable,
            data,
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        builder.create_asn_belongs_to()
        self.assertEqual(len(builder.bundle), 4)
        as_obj = builder.bundle[2]
        self.assertEqual(as_obj.number, 4837)
        self.assertEqual(as_obj.name, "China Unicom Shandong Province Network")

    def test_create_location_located_at(self):
        data = self.load_file("opentip_test_ipv4.json")
        stix_entity = {
            "id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002"
        }
        observable = {"id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002"}
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [stix_entity],
            stix_entity,
            observable,
            data,
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        builder.create_location_located_at()
        self.assertEqual(len(builder.bundle), 4)
        location = builder.bundle[2]
        self.assertEqual(location.country, "CN")
        relationship = builder.bundle[3]
        self.assertEqual(relationship.relationship_type, "located-at")

    def test_create_ip_resolves_to(self):
        stix_entity = {"id": "domain--a7b0d7ec-0000-4000-8000-000000000005"}
        observable = {"id": "domain--a7b0d7ec-0000-4000-8000-000000000005"}
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [stix_entity],
            stix_entity,
            observable,
            {},
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        builder.create_ip_resolves_to("8.8.8.8")
        self.assertEqual(len(builder.bundle), 4)
        ip_obj = builder.bundle[2]
        self.assertEqual(ip_obj.value, "8.8.8.8")
        relationship = builder.bundle[3]
        self.assertEqual(relationship.relationship_type, "resolves-to")

    def test_create_indicator_based_on_zone_match(self):
        data = self.load_file("opentip_test_ipv4.json")
        stix_entity = {
            "id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002"
        }
        observable = {"id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002", "observable_value": "39.90.148.83", "entity_type": "IPv4-Addr"}
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [stix_entity],
            stix_entity,
            observable,
            data,
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        builder.create_indicator_based_on_zone(["Red", "Orange"], "[ipv4-addr:value = '39.90.148.83']")
        indicator_found = any(isinstance(obj, stix2.Indicator) for obj in builder.bundle)
        self.assertTrue(indicator_found)
        relationships = [obj for obj in builder.bundle if isinstance(obj, stix2.Relationship)]
        indicator_relationships = [r for r in relationships if r.relationship_type == "based-on"]
        self.assertEqual(len(indicator_relationships), 1)

    def test_create_indicator_based_on_zone_no_match(self):
        data = self.load_file("opentip_test_ipv4.json")
        stix_entity = {
            "id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002"
        }
        observable = {"id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002"}
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [stix_entity],
            stix_entity,
            observable,
            data,
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        builder.create_indicator_based_on_zone(["Green"], "[ipv4-addr:value = '39.90.148.83']")
        indicators = [obj for obj in builder.bundle if isinstance(obj, stix2.Indicator)]
        self.assertEqual(len(indicators), 0)

    def test_build_external_reference_url_hash(self):
        stix_entity = {"id": "file--a7b0d7ec-0000-4000-8000-000000000001"}
        observable = {"id": "file--a7b0d7ec-0000-4000-8000-000000000001", "observable_value": "2539170c4c1ffeeb17e87917687b5f86104cc88de9478696cee6e0ecaddfc9bb", "entity_type": "StixFile"}
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            observable,
            {},
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        url = builder._build_external_reference_url(
            observable["observable_value"],
            observable["entity_type"]
        )
        expected = "https://opentip.kaspersky.com/2539170c4c1ffeeb17e87917687b5f86104cc88de9478696cee6e0ecaddfc9bb/"
        self.assertEqual(url, expected)

    def test_build_external_reference_url_ipv4(self):
        stix_entity = {"id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002"}
        observable = {"id": "ipv4-addr--a7b0d7ec-0000-4000-8000-000000000002", "observable_value": "39.90.148.83", "entity_type": "IPv4-Addr"}
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            observable,
            {},
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        url = builder._build_external_reference_url(
            observable["observable_value"],
            observable["entity_type"]
        )
        expected = "https://opentip.kaspersky.com/39.90.148.83/"
        self.assertEqual(url, expected)

    def test_build_external_reference_url_domain(self):
        stix_entity = {"id": "domain--a7b0d7ec-0000-4000-8000-000000000003"}
        observable = {"id": "domain--a7b0d7ec-0000-4000-8000-000000000003", "observable_value": "example.com", "entity_type": "Domain-Name"}
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            observable,
            {},
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        url = builder._build_external_reference_url(
            observable["observable_value"],
            observable["entity_type"]
        )
        expected = "https://opentip.kaspersky.com/example.com/"
        self.assertEqual(url, expected)

    def test_build_external_reference_url_url(self):
        stix_entity = {"id": "url--a7b0d7ec-0000-4000-8000-000000000004"}
        observable = {"id": "url--a7b0d7ec-0000-4000-8000-000000000004", "observable_value": "https://example.com/path", "entity_type": "Url"}
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            observable,
            {},
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        url = builder._build_external_reference_url(
            observable["observable_value"],
            observable["entity_type"]
        )
        expected = "https://opentip.kaspersky.com/https://example.com/path/"
        self.assertEqual(url, expected)

    def test_build_external_reference_url_no_observable(self):
        stix_entity = {"id": "file--a7b0d7ec-0000-4000-8000-000000000001"}
        observable = {"id": "file--a7b0d7ec-0000-4000-8000-000000000001", "observable_value": "", "entity_type": "StixFile"}
        builder = OpenTIPBuilder(
            self.helper,
            self.author,
            True,
            [],
            stix_entity,
            observable,
            {},
            type("Config", (), {
                "add_zone_labels": True,
                "add_categories_labels": True,
            })(),
        )
        url = builder._build_external_reference_url("", "StixFile")
        self.assertIsNone(url)


if __name__ == "__main__":
    unittest.main()
