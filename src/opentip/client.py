# -*- coding: utf-8 -*-
"""OpenTIP client module."""

import json

import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


class OpenTIPClient:
    """OpenTIP client."""

    def __init__(
        self, helper: OpenCTIConnectorHelper, base_url: str, token: str
    ) -> None:
        """Initialize OpenTIP client."""
        self.helper = helper
        self.url = base_url[:-1] if base_url[-1] == "/" else base_url
        self.helper.log_info(f"[OpenTIP] URL: {self.url}")
        self.headers = {
            "x-api-key": token,
            "accept": "application/json",
        }

    def _query(self, url):
        """
        Execute a query to the OpenTIP API.

        Retries are done if the query fails.

        Parameters
        ----------
        url : str
            Url to query.

        Returns
        -------
        dict or None
            The result of the query, as dict or None in case of failure.
        """
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        http = requests.Session()
        http.mount("https://", adapter)
        response = None
        try:
            response = http.get(
                url, headers=self.headers | {"content-type": "application/json"}
            )

            if response.status_code == 400:
                self.helper.log_warning(
                    f"[OpenTIP] Bad request (400): invalid query parameter for {url}"
                )
                self.helper.metric.inc("client_error_count")
                return None
            if response.status_code == 403:
                self.helper.log_warning(
                    "[OpenTIP] Forbidden (403): quota or request limit exceeded"
                )
                self.helper.metric.inc("client_error_count")
                return None
            if response.status_code == 404:
                self.helper.log_info(
                    f"[OpenTIP] Not found (404): no data available for this observable"
                )
                return None

            response.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            self.helper.log_error(f"[OpenTIP] HTTP error: {errh}")
            self.helper.metric.inc("client_error_count")
            return None
        except requests.exceptions.ConnectionError as errc:
            self.helper.log_error(f"[OpenTIP] Error connecting: {errc}")
            self.helper.metric.inc("client_error_count")
            return None
        except requests.exceptions.Timeout as errt:
            self.helper.log_error(f"[OpenTIP] Timeout error: {errt}")
            self.helper.metric.inc("client_error_count")
            return None
        except requests.exceptions.RequestException as err:
            self.helper.log_error(f"[OpenTIP] Something else happened: {err}")
            self.helper.metric.inc("client_error_count")
            return None
        except Exception as err:
            self.helper.log_error(f"[OpenTIP] Unknown error: {err}")
            self.helper.metric.inc("client_error_count")
            return None
        try:
            self.helper.log_debug(f"[OpenTIP] data retrieved: {response.json()}")
            return response.json()
        except (json.JSONDecodeError, AttributeError) as err:
            self.helper.log_error(
                f"[OpenTIP] Error decoding the JSON: {err} - {getattr(response, 'text', 'No response text')}"
            )
            self.helper.metric.inc("client_error_count")
            return None

    def get_hash_info(self, hash_value: str) -> dict:
        """
        Retrieve hash information based on the given hash.

        Parameters
        ----------
        hash_value : str
            Hash (MD5, SHA-1, or SHA-256) to retrieve.

        Returns
        -------
        dict
            Hash lookup result from OpenTIP API.
        """
        url = f"{self.url}/api/v1/search/hash?request={hash_value}"
        return self._query(url)

    def get_ip_info(self, ip: str) -> dict:
        """
        Retrieve IP information based on the given IP address.

        Parameters
        ----------
        ip : str
            IP address to retrieve.

        Returns
        -------
        dict
            IP lookup result from OpenTIP API.
        """
        url = f"{self.url}/api/v1/search/ip?request={ip}"
        return self._query(url)

    def get_domain_info(self, domain: str) -> dict:
        """
        Retrieve domain information based on the given domain name.

        Parameters
        ----------
        domain : str
            Domain name to retrieve.

        Returns
        -------
        dict
            Domain lookup result from OpenTIP API.
        """
        url = f"{self.url}/api/v1/search/domain?request={domain}"
        return self._query(url)

    def get_url_info(self, url: str) -> dict:
        """
        Retrieve URL information based on the given URL.

        Parameters
        ----------
        url : str
            URL to retrieve.

        Returns
        -------
        dict
            URL lookup result from OpenTIP API.
        """
        url_encoded = url
        url_query = f"{self.url}/api/v1/search/url?request={url_encoded}"
        return self._query(url_query)
