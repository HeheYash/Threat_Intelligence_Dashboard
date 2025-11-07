import requests
import time
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone

class VirusTotalClient:
    """VirusTotal API v3 client wrapper with rate limiting and error handling"""

    def __init__(self, api_key: str, base_url: str = "https://www.virustotal.com/api/v3"):
        self.api_key = api_key
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": api_key,
            "accept": "application/json"
        })
        self.logger = logging.getLogger(__name__)

        # Rate limiting: 4 requests per minute for free tier
        self.rate_limit = 4
        self.rate_limit_window = 60  # seconds
        self.request_times = []

    def _handle_rate_limit(self):
        """Implement rate limiting with time-based tracking"""
        now = time.time()
        # Remove requests older than the rate limit window
        self.request_times = [req_time for req_time in self.request_times if now - req_time < self.rate_limit_window]

        if len(self.request_times) >= self.rate_limit:
            # Calculate sleep time needed
            oldest_request = min(self.request_times)
            sleep_time = self.rate_limit_window - (now - oldest_request)
            if sleep_time > 0:
                self.logger.info(f"Rate limit reached, sleeping for {sleep_time:.2f} seconds")
                time.sleep(sleep_time + 1)  # Add 1 second buffer

        self.request_times.append(now)

    def _make_request(self, endpoint: str, params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Make API request with error handling and rate limiting"""
        url = f"{self.base_url}{endpoint}"

        self._handle_rate_limit()

        try:
            response = self.session.get(url, params=params, timeout=30)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 204:
                self.logger.warning(f"No content for request: {endpoint}")
                return None
            elif response.status_code == 400:
                self.logger.error(f"Bad request for {endpoint}: {response.text}")
                return None
            elif response.status_code == 403:
                self.logger.error(f"Forbidden - API key invalid or insufficient permissions")
                return None
            elif response.status_code == 404:
                self.logger.warning(f"Resource not found: {endpoint}")
                return None
            elif response.status_code == 429:
                self.logger.warning(f"Rate limit exceeded for {endpoint}, backing off...")
                time.sleep(60)  # Wait 1 minute
                return None
            else:
                self.logger.error(f"Unexpected status code {response.status_code} for {endpoint}: {response.text}")
                return None

        except requests.exceptions.Timeout:
            self.logger.error(f"Request timeout for {endpoint}")
            return None
        except requests.exceptions.ConnectionError:
            self.logger.error(f"Connection error for {endpoint}")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request exception for {endpoint}: {str(e)}")
            return None

    def get_ip_report(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get IP reputation report from VirusTotal"""
        endpoint = f"/ip_addresses/{ip_address}"

        data = self._make_request(endpoint)
        if not data or 'data' not in data:
            return None

        attributes = data['data'].get('attributes', {})

        # Extract relevant information
        report = {
            'value': ip_address,
            'ioc_type': 'ip',
            'source': 'virustotal',
            'reputation': {
                'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                'harmless': attributes.get('last_analysis_stats', {}).get('harmless', 0),
                'undetected': attributes.get('last_analysis_stats', {}).get('undetected', 0),
                'timeout': attributes.get('last_analysis_stats', {}).get('timeout', 0),
                'total_engines': sum(attributes.get('last_analysis_stats', {}).values())
            },
            'meta': {
                'country': attributes.get('country'),
                'asn': attributes.get('asn'),
                'as_owner': attributes.get('as_owner'),
                'reputation': attributes.get('reputation'),
                'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                'last_modified': attributes.get('last_modified'),
                'tags': attributes.get('tags', [])
            },
            'last_seen': attributes.get('last_modified', datetime.now(timezone.utc).isoformat()),
            'sources': ['virustotal']
        }

        return report

    def get_domain_report(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get domain analysis report from VirusTotal"""
        endpoint = f"/domains/{domain}"

        data = self._make_request(endpoint)
        if not data or 'data' not in data:
            return None

        attributes = data['data'].get('attributes', {})

        report = {
            'value': domain,
            'ioc_type': 'domain',
            'source': 'virustotal',
            'reputation': {
                'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                'harmless': attributes.get('last_analysis_stats', {}).get('harmless', 0),
                'undetected': attributes.get('last_analysis_stats', {}).get('undetected', 0),
                'timeout': attributes.get('last_analysis_stats', {}).get('timeout', 0),
                'total_engines': sum(attributes.get('last_analysis_stats', {}).values())
            },
            'meta': {
                'creation_date': attributes.get('creation_date'),
                'expiration_date': attributes.get('expiration_date'),
                'last_modified': attributes.get('last_modified'),
                'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                'categories': attributes.get('categories', {}),
                'subdomains': attributes.get('subdomains', []),
                'tags': attributes.get('tags', [])
            },
            'last_seen': attributes.get('last_modified', datetime.now(timezone.utc).isoformat()),
            'sources': ['virustotal']
        }

        return report

    def get_url_report(self, url: str) -> Optional[Dict[str, Any]]:
        """Get URL scan report from VirusTotal"""
        # First, get URL ID
        scan_endpoint = "/urls"
        payload = {"url": url}

        data = self._make_request(scan_endpoint, params=payload)
        if not data or 'data' not in data:
            return None

        url_id = data['data']['id']

        # Then get the report
        report_endpoint = f"/urls/{url_id}"
        report_data = self._make_request(report_endpoint)

        if not report_data or 'data' not in report_data:
            return None

        attributes = report_data['data'].get('attributes', {})

        report = {
            'value': url,
            'ioc_type': 'url',
            'source': 'virustotal',
            'reputation': {
                'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                'harmless': attributes.get('last_analysis_stats', {}).get('harmless', 0),
                'undetected': attributes.get('last_analysis_stats', {}).get('undetected', 0),
                'timeout': attributes.get('last_analysis_stats', {}).get('timeout', 0),
                'total_engines': sum(attributes.get('last_analysis_stats', {}).values())
            },
            'meta': {
                'first_submission_date': attributes.get('first_submission_date'),
                'last_submission_date': attributes.get('last_submission_date'),
                'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                'times_submitted': attributes.get('times_submitted', 0),
                'tags': attributes.get('tags', [])
            },
            'last_seen': attributes.get('last_analysis_date', datetime.now(timezone.utc).isoformat()),
            'sources': ['virustotal']
        }

        return report

    def get_file_report(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Get file analysis report from VirusTotal"""
        endpoint = f"/files/{file_hash}"

        data = self._make_request(endpoint)
        if not data or 'data' not in data:
            return None

        attributes = data['data'].get('attributes', {})

        report = {
            'value': file_hash,
            'ioc_type': 'hash',
            'source': 'virustotal',
            'reputation': {
                'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                'harmless': attributes.get('last_analysis_stats', {}).get('harmless', 0),
                'undetected': attributes.get('last_analysis_stats', {}).get('undetected', 0),
                'timeout': attributes.get('last_analysis_stats', {}).get('timeout', 0),
                'total_engines': sum(attributes.get('last_analysis_stats', {}).values())
            },
            'meta': {
                'size': attributes.get('size'),
                'type_description': attributes.get('type_description'),
                'first_submission_date': attributes.get('first_submission_date'),
                'last_submission_date': attributes.get('last_submission_date'),
                'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                'names': attributes.get('names', []),
                'tags': attributes.get('tags', []),
                'type_tag': attributes.get('type_tag')
            },
            'last_seen': attributes.get('last_analysis_date', datetime.now(timezone.utc).isoformat()),
            'sources': ['virustotal']
        }

        return report