# -*- coding: utf-8 -*-
"""OpenTIP client unittest."""
import unittest
from unittest.mock import MagicMock, patch

import requests
from opentip.client import OpenTIPClient


class OpenTIPClientTest(unittest.TestCase):
    @patch("opentip.client.requests.Session")
    def test_get_hash_info_constructs_correct_url(self, mock_session):
        mock_response = MagicMock()
        mock_response.json.return_value = {"Zone": "Yellow"}
        mock_response.raise_for_status.return_value = None
        mock_session.return_value.get.return_value = mock_response

        client = OpenTIPClient(MagicMock(), "https://opentip.kaspersky.com", "test-token")
        client.get_hash_info("abc123")

        mock_session.return_value.get.assert_called_once_with(
            "https://opentip.kaspersky.com/api/v1/search/hash?request=abc123",
            headers={"x-api-key": "test-token", "accept": "application/json", "content-type": "application/json"},
        )

    @patch("opentip.client.requests.Session")
    def test_get_ip_info_constructs_correct_url(self, mock_session):
        mock_response = MagicMock()
        mock_response.json.return_value = {"Zone": "Red"}
        mock_response.raise_for_status.return_value = None
        mock_session.return_value.get.return_value = mock_response

        client = OpenTIPClient(MagicMock(), "https://opentip.kaspersky.com", "test-token")
        client.get_ip_info("8.8.8.8")

        mock_session.return_value.get.assert_called_once_with(
            "https://opentip.kaspersky.com/api/v1/search/ip?request=8.8.8.8",
            headers={"x-api-key": "test-token", "accept": "application/json", "content-type": "application/json"},
        )

    @patch("opentip.client.requests.Session")
    def test_get_domain_info_constructs_correct_url(self, mock_session):
        mock_response = MagicMock()
        mock_response.json.return_value = {"Zone": "Yellow"}
        mock_response.raise_for_status.return_value = None
        mock_session.return_value.get.return_value = mock_response

        client = OpenTIPClient(MagicMock(), "https://opentip.kaspersky.com", "test-token")
        client.get_domain_info("example.com")

        mock_session.return_value.get.assert_called_once_with(
            "https://opentip.kaspersky.com/api/v1/search/domain?request=example.com",
            headers={"x-api-key": "test-token", "accept": "application/json", "content-type": "application/json"},
        )

    @patch("opentip.client.requests.Session")
    def test_get_url_info_constructs_correct_url(self, mock_session):
        mock_response = MagicMock()
        mock_response.json.return_value = {"Zone": "Yellow"}
        mock_response.raise_for_status.return_value = None
        mock_session.return_value.get.return_value = mock_response

        client = OpenTIPClient(MagicMock(), "https://opentip.kaspersky.com", "test-token")
        client.get_url_info("https://example.com/malware")

        mock_session.return_value.get.assert_called_once_with(
            "https://opentip.kaspersky.com/api/v1/search/url?request=https://example.com/malware",
            headers={"x-api-key": "test-token", "accept": "application/json", "content-type": "application/json"},
        )

    @patch("opentip.client.requests.Session")
    def test_query_returns_none_on_400(self, mock_session):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.raise_for_status.side_effect = requests.HTTPError("400 error")
        mock_session.return_value.get.return_value = mock_response

        helper = MagicMock()
        client = OpenTIPClient(helper, "https://opentip.kaspersky.com", "test-token")
        result = client.get_ip_info("8.8.8.8")

        self.assertIsNone(result)
        helper.log_warning.assert_called()
        helper.metric.inc.assert_called_with("client_error_count")

    @patch("opentip.client.requests.Session")
    def test_query_returns_none_on_403(self, mock_session):
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.raise_for_status.side_effect = requests.HTTPError("403 error")
        mock_session.return_value.get.return_value = mock_response

        helper = MagicMock()
        client = OpenTIPClient(helper, "https://opentip.kaspersky.com", "test-token")
        result = client.get_ip_info("8.8.8.8")

        self.assertIsNone(result)
        helper.log_warning.assert_called()
        helper.metric.inc.assert_called_with("client_error_count")

    @patch("opentip.client.requests.Session")
    def test_query_returns_none_on_404(self, mock_session):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = requests.HTTPError("404 error")
        mock_session.return_value.get.return_value = mock_response

        helper = MagicMock()
        client = OpenTIPClient(helper, "https://opentip.kaspersky.com", "test-token")
        result = client.get_ip_info("8.8.8.8")

        self.assertIsNone(result)
        helper.log_info.assert_called()
        calls = [c for c in helper.metric.inc.call_args_list if "client_error_count" in str(c)]
        self.assertEqual(len(calls), 0)

    @patch("opentip.client.requests.Session")
    def test_query_returns_none_on_connection_error(self, mock_session):
        mock_session.return_value.get.side_effect = requests.ConnectionError("Connection refused")

        helper = MagicMock()
        client = OpenTIPClient(helper, "https://opentip.kaspersky.com", "test-token")
        result = client.get_ip_info("8.8.8.8")

        self.assertIsNone(result)
        helper.log_error.assert_called()

    @patch("opentip.client.requests.Session")
    def test_query_returns_parsed_json(self, mock_session):
        mock_response = MagicMock()
        mock_response.json.return_value = {"Zone": "Yellow", "IpGeneralInfo": {}}
        mock_response.raise_for_status.return_value = None
        mock_session.return_value.get.return_value = mock_response

        client = OpenTIPClient(MagicMock(), "https://opentip.kaspersky.com", "test-token")
        result = client.get_ip_info("8.8.8.8")

        self.assertEqual(result, {"Zone": "Yellow", "IpGeneralInfo": {}})

    def test_trailing_slash_stripped_from_base_url(self):
        client = OpenTIPClient(MagicMock(), "https://example.com/", "test-token")
        self.assertEqual(client.url, "https://example.com")

    def test_no_trailing_slash_preserved(self):
        client = OpenTIPClient(MagicMock(), "https://example.com", "test-token")
        self.assertEqual(client.url, "https://example.com")


if __name__ == "__main__":
    unittest.main()
