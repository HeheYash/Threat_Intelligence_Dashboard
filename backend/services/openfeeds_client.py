import requests
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
import re

class OpenFeedsClient:
    """Client for fetching and parsing public CTI feeds"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CTI-Dashboard/1.0"
        })
        self.logger = logging.getLogger(__name__)

    def _make_request(self, url: str, timeout: int = 30) -> Optional[str]:
        """Make HTTP request with error handling"""
        try:
            response = self.session.get(url, timeout=timeout)
            if response.status_code == 200:
                return response.text
            else:
                self.logger.error(f"Failed to fetch {url}: HTTP {response.status_code}")
                return None
        except requests.exceptions.Timeout:
            self.logger.error(f"Timeout fetching {url}")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error fetching {url}: {str(e)}")
            return None

    def fetch_otx_pulses(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch latest OTX (AlienVault) pulses"""
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        params = {"limit": limit}

        try:
            response = self.session.get(url, params=params, timeout=30)
            if response.status_code != 200:
                self.logger.error(f"Failed to fetch OTX pulses: {response.status_code}")
                return []

            data = response.json()
            if 'results' not in data:
                return []

            pulses = []
            for pulse in data['results']:
                if 'indicators' not in pulse:
                    continue

                for indicator in pulse['indicators']:
                    ioc_report = {
                        'value': indicator.get('indicator', ''),
                        'ioc_type': self._determine_ioc_type(indicator.get('indicator', '')),
                        'source': 'otx',
                        'meta': {
                            'pulse_name': pulse.get('name', ''),
                            'pulse_description': pulse.get('description', ''),
                            'author': pulse.get('author_name', ''),
                            'tags': pulse.get('tags', []),
                            'created': pulse.get('created', ''),
                            'indicator_type': indicator.get('type', ''),
                            'title': indicator.get('title', ''),
                            'description': indicator.get('description', ''),
                            'malware_families': indicator.get('malware_families', [])
                        },
                        'last_seen': pulse.get('created', datetime.now(timezone.utc).isoformat()),
                        'sources': ['otx']
                    }
                    pulses.append(ioc_report)

            return pulses

        except Exception as e:
            self.logger.error(f"Error fetching OTX pulses: {str(e)}")
            return []

    def fetch_phishtank(self) -> List[Dict[str, Any]]:
        """Fetch verified phishing URLs from PhishTank"""
        # PhishTank provides data via API or downloadable CSV/XML
        # Using the XML feed for this example
        url = "https://data.phishtank.com/data/online-valid.xml"

        xml_data = self._make_request(url)
        if not xml_data:
            return []

        try:
            root = ET.fromstring(xml_data)
            phishing_entries = []

            for entry in root.findall('.//entry'):
                url_element = entry.find('url')
                if url_element is not None and url_element.text:
                    ioc_report = {
                        'value': url_element.text.strip(),
                        'ioc_type': 'url',
                        'source': 'phishtank',
                        'meta': {
                            'phish_id': entry.find('phish_id').text if entry.find('phish_id') is not None else '',
                            'phish_detail_url': entry.find('phish_detail_url').text if entry.find('phish_detail_url') is not None else '',
                            'submission_time': entry.find('submission_time').text if entry.find('submission_time') is not None else '',
                            'verified': entry.find('verified').text if entry.find('verified') is not None else 'yes',
                            'verification_time': entry.find('verification_time').text if entry.find('verification_time') is not None else '',
                            'target': entry.find('target').text if entry.find('target') is not None else ''
                        },
                        'last_seen': entry.find('verification_time').text if entry.find('verification_time') is not None else datetime.now(timezone.utc).isoformat(),
                        'sources': ['phishtank']
                    }
                    phishing_entries.append(ioc_report)

            return phishing_entries

        except ET.ParseError as e:
            self.logger.error(f"Error parsing PhishTank XML: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"Error fetching PhishTank data: {str(e)}")
            return []

    def fetch_malware_domains(self) -> List[Dict[str, Any]]:
        """Fetch malware domain lists from various sources"""
        domains = []

        # Example: Malware Domain List
        malwaredomains_url = "http://www.malwaredomainlist.com/hostslist/hosts.txt"
        data = self._make_request(malwaredomains_url)
        if data:
            try:
                lines = data.strip().split('\n')
                for line in lines:
                    if line.startswith('127.0.0.1') and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 2:
                            domain = parts[1]
                            ioc_report = {
                                'value': domain,
                                'ioc_type': 'domain',
                                'source': 'malwaredomains',
                                'meta': {
                                    'list_type': 'hostsfile',
                                    'first_seen': datetime.now(timezone.utc).isoformat()
                                },
                                'last_seen': datetime.now(timezone.utc).isoformat(),
                                'sources': ['malwaredomains']
                            }
                            domains.append(ioc_report)
            except Exception as e:
                self.logger.error(f"Error parsing malwaredomains list: {str(e)}")

        return domains

    def fetch_abuse_ch_ssl_blacklist(self) -> List[Dict[str, Any]]:
        """Fetch SSL blacklist from abuse.ch"""
        url = "https://sslbl.abuse.ch/downloads/SSL_BLACKLIST.csv"

        data = self._make_request(url)
        if not data:
            return []

        ssl_blacklist = []
        try:
            lines = data.strip().split('\n')
            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue

                parts = line.split('"')
                if len(parts) >= 9:
                    hostname = parts[7]
                    if hostname and hostname != '#':
                        ioc_report = {
                            'value': hostname,
                            'ioc_type': 'domain',
                            'source': 'abuse_ch_ssl',
                            'meta': {
                                'listing_type': parts[3],
                                'malware': parts[5],
                                'first_seen': parts[1] if parts[1] else datetime.now(timezone.utc).isoformat()
                            },
                            'last_seen': datetime.now(timezone.utc).isoformat(),
                            'sources': ['abuse_ch_ssl']
                        }
                        ssl_blacklist.append(ioc_report)

        except Exception as e:
            self.logger.error(f"Error parsing abuse.ch SSL blacklist: {str(e)}")

        return ssl_blacklist

    def fetch_feodo_tracker_ips(self) -> List[Dict[str, Any]]:
        """Fetch Feodo Tracker IP blocklist"""
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

        data = self._make_request(url)
        if not data:
            return []

        feodo_ips = []
        try:
            lines = data.strip().split('\n')
            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue

                # Check if line contains an IP address
                if self._is_valid_ip(line.strip()):
                    ioc_report = {
                        'value': line.strip(),
                        'ioc_type': 'ip',
                        'source': 'feodo_tracker',
                        'meta': {
                            'malware_family': 'feodo',
                            'last_seen': datetime.now(timezone.utc).isoformat()
                        },
                        'last_seen': datetime.now(timezone.utc).isoformat(),
                        'sources': ['feodo_tracker']
                    }
                    feodo_ips.append(ioc_report)

        except Exception as e:
            self.logger.error(f"Error parsing Feodo Tracker IP list: {str(e)}")

        return feodo_ips

    def fetch_all_feeds(self) -> Dict[str, List[Dict[str, Any]]]:
        """Fetch data from all configured feeds"""
        all_feeds = {
            'otx': [],
            'phishtank': [],
            'malwaredomains': [],
            'abuse_ch_ssl': [],
            'feodo_tracker': []
        }

        self.logger.info("Fetching data from all open feeds...")

        # OTX Pulses
        try:
            otx_data = self.fetch_otx_pulses()
            all_feeds['otx'] = otx_data
            self.logger.info(f"Fetched {len(otx_data)} indicators from OTX")
        except Exception as e:
            self.logger.error(f"Failed to fetch OTX data: {str(e)}")

        # PhishTank
        try:
            phishtank_data = self.fetch_phishtank()
            all_feeds['phishtank'] = phishtank_data
            self.logger.info(f"Fetched {len(phishtank_data)} URLs from PhishTank")
        except Exception as e:
            self.logger.error(f"Failed to fetch PhishTank data: {str(e)}")

        # Malware Domains
        try:
            malwaredomains_data = self.fetch_malware_domains()
            all_feeds['malwaredomains'] = malwaredomains_data
            self.logger.info(f"Fetched {len(malwaredomains_data)} domains from Malware Domains")
        except Exception as e:
            self.logger.error(f"Failed to fetch Malware Domains data: {str(e)}")

        # Abuse.ch SSL Blacklist
        try:
            ssl_blacklist_data = self.fetch_abuse_ch_ssl_blacklist()
            all_feeds['abuse_ch_ssl'] = ssl_blacklist_data
            self.logger.info(f"Fetched {len(ssl_blacklist_data)} domains from Abuse.ch SSL Blacklist")
        except Exception as e:
            self.logger.error(f"Failed to fetch Abuse.ch SSL data: {str(e)}")

        # Feodo Tracker
        try:
            feodo_data = self.fetch_feodo_tracker_ips()
            all_feeds['feodo_tracker'] = feodo_data
            self.logger.info(f"Fetched {len(feodo_data)} IPs from Feodo Tracker")
        except Exception as e:
            self.logger.error(f"Failed to fetch Feodo Tracker data: {str(e)}")

        return all_feeds

    def _determine_ioc_type(self, value: str) -> str:
        """Determine IOC type based on value"""
        import ipaddress
        import re

        # Check if IP address
        try:
            ipaddress.ip_address(value)
            return 'ip'
        except ValueError:
            pass

        # Check if URL
        if value.startswith(('http://', 'https://')):
            return 'url'

        # Check if hash (basic detection)
        if re.match(r'^[a-fA-F0-9]{32,64}$', value):
            return 'hash'

        # Assume domain by default
        return 'domain'

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False