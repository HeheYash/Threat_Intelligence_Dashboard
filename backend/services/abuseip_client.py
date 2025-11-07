import requests
import time
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

class AbuseIPDBClient:
    """AbuseIPDB API client wrapper with rate limiting and error handling"""

    def __init__(self, api_key: str, base_url: str = "https://api.abuseipdb.com/api/v2"):
        self.api_key = api_key
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "Key": api_key,
            "Accept": "application/json"
        })
        self.logger = logging.getLogger(__name__)

        # Rate limiting: 1000 requests per day for free tier
        self.daily_limit = 1000
        self.request_times = []

    def _handle_rate_limit(self):
        """Implement rate limiting to stay within daily quota"""
        now = time.time()
        day_in_seconds = 24 * 60 * 60

        # Remove requests older than 24 hours
        self.request_times = [req_time for req_time in self.request_times if now - req_time < day_in_seconds]

        if len(self.request_times) >= self.daily_limit:
            self.logger.error("Daily rate limit exceeded for AbuseIPDB")
            raise Exception("Daily rate limit exceeded for AbuseIPDB")

        # Add delay to prevent bursting
        if len(self.request_times) > 0:
            time_since_last = now - self.request_times[-1]
            if time_since_last < 1:  # Minimum 1 second between requests
                time.sleep(1 - time_since_last)

        self.request_times.append(now)

    def _make_request(self, endpoint: str, params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Make API request with error handling and rate limiting"""
        url = f"{self.base_url}{endpoint}"

        try:
            self._handle_rate_limit()
            response = self.session.get(url, params=params, timeout=30)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 400:
                self.logger.error(f"Bad request for {endpoint}: {response.text}")
                return None
            elif response.status_code == 401:
                self.logger.error(f"Unauthorized - API key invalid for {endpoint}")
                return None
            elif response.status_code == 403:
                self.logger.error(f"Forbidden - insufficient permissions for {endpoint}")
                return None
            elif response.status_code == 429:
                self.logger.error(f"Rate limit exceeded for {endpoint}")
                return None
            elif response.status_code == 503:
                self.logger.error(f"Service unavailable for {endpoint}")
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
        except Exception as e:
            self.logger.error(f"Rate limiting exception: {str(e)}")
            return None

    def check_ip(self, ip_address: str, max_age_days: int = 30, verbose: str = "") -> Optional[Dict[str, Any]]:
        """Check IP address reputation"""
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days,
            "verbose": verbose
        }

        data = self._make_request("/check", params)
        if not data or 'data' not in data:
            return None

        ip_data = data['data']
        attributes = ip_data.get('attributes', {})

        report = {
            'value': ip_address,
            'ioc_type': 'ip',
            'source': 'abuseipdb',
            'reputation': {
                'abuse_confidence_score': attributes.get('abuse_confidence_score', 0),
                'total_reports': attributes.get('total_reports', 0),
                'num_distinct_users': attributes.get('num_distinct_users', 0),
                'is_public': attributes.get('is_public', False),
                'ip_version': attributes.get('ip_version', 4)
            },
            'meta': {
                'country_code': attributes.get('country_code'),
                'usage_type': attributes.get('usage_type'),
                'isp': attributes.get('isp'),
                'domain': attributes.get('domain'),
                'last_reported_at': attributes.get('last_reported_at'),
                'is_tor': attributes.get('is_tor', False),
                'is_whitelisted': attributes.get('is_whitelisted', False)
            },
            'last_seen': attributes.get('last_reported_at', datetime.now(timezone.utc).isoformat()),
            'sources': ['abuseipdb']
        }

        return report

    def get_recent_reports(self, ip_address: str, days: int = 30) -> Optional[List[Dict[str, Any]]]:
        """Get recent abuse reports for an IP address"""
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": days,
            "perPage": 100
        }

        data = self._make_request("/reports", params)
        if not data or 'data' not in data:
            return None

        reports = []
        for report_data in data['data']:
            attributes = report_data.get('attributes', {})

            report = {
                'reported_at': attributes.get('reported_at'),
                'comment': attributes.get('comment', ''),
                'categories': attributes.get('categories', []),
                'reporter_id': attributes.get('reporter_id'),
                'reporter_country_code': attributes.get('reporter_country_code')
            }
            reports.append(report)

        return reports

    def bulk_check(self, ip_list: List[str], max_age_days: int = 30) -> Dict[str, Any]:
        """Check multiple IP addresses (returns dictionary with results and failures)"""
        results = {}
        failures = []

        for ip_address in ip_list:
            try:
                report = self.check_ip(ip_address, max_age_days)
                if report:
                    results[ip_address] = report
                else:
                    failures.append({"ip": ip_address, "reason": "No data returned"})
            except Exception as e:
                failures.append({"ip": ip_address, "reason": str(e)})

        return {
            "results": results,
            "failures": failures,
            "total_checked": len(ip_list),
            "successful": len(results),
            "failed": len(failures)
        }

    def get_blacklist(self, limit: int = 10000, min_confidence: int = 25) -> Optional[List[str]]:
        """Get current blacklist of malicious IPs"""
        params = {
            "limit": limit,
            "confidenceMinimum": min_confidence
        }

        data = self._make_request("/blacklist", params)
        if not data:
            return None

        # AbuseIPDB returns newline-separated IPs in the data field
        if 'data' in data:
            return data['data'].split('\n') if data['data'] else []

        return None

    def get_cidr_blacklist(self, cidr: str, min_confidence: int = 25) -> Optional[List[str]]:
        """Get blacklist for specific CIDR range"""
        params = {
            "cidr": cidr,
            "confidenceMinimum": min_confidence
        }

        data = self._make_request("/blacklist", params)
        if not data:
            return None

        if 'data' in data:
            return data['data'].split('\n') if data['data'] else []

        return None

    def report_ip(self, ip_address: str, categories: List[int], comment: str = "") -> Optional[Dict[str, Any]]:
        """Report an IP address for malicious activity"""
        params = {
            "ip": ip_address,
            "categories": ",".join(map(str, categories)),
            "comment": comment
        }

        data = self._make_request("/report", params)
        if data and 'data' in data:
            return {
                'ip_address': ip_address,
                'reported_at': datetime.now(timezone.utc).isoformat(),
                'categories': categories,
                'comment': comment,
                'status': 'reported'
            }

        return None