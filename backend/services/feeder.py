import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from ..models.ioc_model import IOCModel
from .vt_client import VirusTotalClient
from .abuseip_client import AbuseIPDBClient
from .openfeeds_client import OpenFeedsClient
import os

class DataFeeder:
    """Data ingestion and normalization service for CTI data sources"""

    def __init__(self, db_client):
        self.db = db_client
        self.ioc_model = IOCModel(db_client)
        self.logger = logging.getLogger(__name__)

        # Initialize API clients
        self.vt_client = VirusTotalClient(os.getenv('VIRUSTOTAL_API_KEY', ''))
        self.abuseip_client = AbuseIPDBClient(os.getenv('ABUSEIPDB_API_KEY', ''))
        self.openfeeds_client = OpenFeedsClient()

    def process_virustotal_data(self, indicators: List[str]) -> Dict[str, Any]:
        """Process VirusTotal data for given indicators"""
        if not self.vt_client.api_key:
            self.logger.warning("VirusTotal API key not configured")
            return {"processed": 0, "errors": [], "details": []}

        results = {
            "processed": 0,
            "errors": [],
            "details": []
        }

        for indicator in indicators:
            try:
                # Determine IOC type and fetch appropriate report
                ioc_type = self.ioc_model.determine_ioc_type(indicator)
                if not ioc_type:
                    self.logger.warning(f"Unable to determine IOC type for: {indicator}")
                    continue

                report = None
                if ioc_type.value == 'ip':
                    report = self.vt_client.get_ip_report(indicator)
                elif ioc_type.value == 'domain':
                    report = self.vt_client.get_domain_report(indicator)
                elif ioc_type.value == 'url':
                    report = self.vt_client.get_url_report(indicator)
                elif ioc_type.value == 'hash':
                    report = self.vt_client.get_file_report(indicator)

                if report:
                    # Normalize and store IOC
                    self._store_normalized_ioc(report)
                    results["processed"] += 1
                    results["details"].append({
                        "indicator": indicator,
                        "type": ioc_type.value,
                        "status": "success",
                        "threat_score": report.get('meta', {}).get('reputation', {}).get('malicious', 0)
                    })
                    self.logger.info(f"Processed VirusTotal data for: {indicator}")
                else:
                    results["errors"].append(f"No data returned for: {indicator}")

            except Exception as e:
                error_msg = f"Error processing {indicator}: {str(e)}"
                results["errors"].append(error_msg)
                self.logger.error(error_msg)

        return results

    def process_abuseipdb_data(self, ip_addresses: List[str]) -> Dict[str, Any]:
        """Process AbuseIPDB data for given IP addresses"""
        if not self.abuseip_client.api_key:
            self.logger.warning("AbuseIPDB API key not configured")
            return {"processed": 0, "errors": [], "details": []}

        results = {
            "processed": 0,
            "errors": [],
            "details": []
        }

        # Use bulk check for efficiency
        if len(ip_addresses) > 1:
            bulk_results = self.abuseip_client.bulk_check(ip_addresses)

            for ip_address, report in bulk_results["results"].items():
                try:
                    self._store_normalized_ioc(report)
                    results["processed"] += 1
                    results["details"].append({
                        "indicator": ip_address,
                        "type": "ip",
                        "status": "success",
                        "threat_score": report.get('reputation', {}).get('abuse_confidence_score', 0)
                    })
                    self.logger.info(f"Processed AbuseIPDB data for: {ip_address}")
                except Exception as e:
                    error_msg = f"Error storing {ip_address}: {str(e)}"
                    results["errors"].append(error_msg)

            # Add bulk failures to errors
            for failure in bulk_results["failures"]:
                results["errors"].append(f"Bulk check failed for {failure['ip']}: {failure['reason']}")
        else:
            # Single IP processing
            for ip_address in ip_addresses:
                try:
                    report = self.abuseip_client.check_ip(ip_address)
                    if report:
                        self._store_normalized_ioc(report)
                        results["processed"] += 1
                        results["details"].append({
                            "indicator": ip_address,
                            "type": "ip",
                            "status": "success",
                            "threat_score": report.get('reputation', {}).get('abuse_confidence_score', 0)
                        })
                        self.logger.info(f"Processed AbuseIPDB data for: {ip_address}")
                    else:
                        results["errors"].append(f"No data returned for: {ip_address}")

                except Exception as e:
                    error_msg = f"Error processing {ip_address}: {str(e)}"
                    results["errors"].append(error_msg)

        return results

    def process_open_feeds(self) -> Dict[str, Any]:
        """Process data from all open feed sources"""
        results = {
            "processed": 0,
            "errors": [],
            "details": {},
            "sources": {}
        }

        try:
            feeds_data = self.openfeeds_client.fetch_all_feeds()

            for feed_name, indicators in feeds_data.items():
                feed_results = {
                    "processed": 0,
                    "errors": []
                }

                for indicator in indicators:
                    try:
                        self._store_normalized_ioc(indicator)
                        feed_results["processed"] += 1
                        results["processed"] += 1
                    except Exception as e:
                        error_msg = f"Error processing {indicator.get('value', 'unknown')}: {str(e)}"
                        feed_results["errors"].append(error_msg)
                        results["errors"].append(error_msg)

                results["details"][feed_name] = feed_results["processed"]
                results["sources"][feed_name] = feed_results
                self.logger.info(f"Processed {feed_results['processed']} indicators from {feed_name}")

        except Exception as e:
            error_msg = f"Error fetching open feeds: {str(e)}"
            results["errors"].append(error_msg)
            self.logger.error(error_msg)

        return results

    def _store_normalized_ioc(self, report: Dict[str, Any]) -> str:
        """Store normalized IOC in database"""
        try:
            value = report['value']
            sources = report.get('sources', [])
            meta = report.get('meta', {})

            # Add timestamp if not present
            if 'last_seen' in report:
                meta['last_seen'] = report['last_seen']

            # Store reputation data in meta for scoring
            if 'reputation' in report:
                meta['reputation'] = report['reputation']

            # Upsert IOC
            ioc_id = self.ioc_model.upsert_ioc(value, sources, meta)
            return ioc_id

        except Exception as e:
            self.logger.error(f"Error storing IOC {report.get('value', 'unknown')}: {str(e)}")
            raise

    def get_feed_status(self) -> Dict[str, Any]:
        """Get status of all data feeds"""
        status = {
            "virustotal": {
                "enabled": bool(self.vt_client.api_key),
                "name": "VirusTotal",
                "description": "Malware detection and URL scanning service",
                "rate_limit": "4 requests/minute (free tier)",
                "last_fetch": None
            },
            "abuseipdb": {
                "enabled": bool(self.abuseip_client.api_key),
                "name": "AbuseIPDB",
                "description": "IP address abuse reporting and reputation",
                "rate_limit": "1000 requests/day (free tier)",
                "last_fetch": None
            },
            "openfeeds": {
                "enabled": True,
                "name": "Open CTI Feeds",
                "description": "Public threat intelligence feeds",
                "rate_limit": "Varies by source",
                "last_fetch": None
            }
        }

        # Get last fetch times from database
        try:
            from pymongo import MongoClient
            feeds_meta_collection = self.db.feeds_meta

            for feed_name in status.keys():
                feed_meta = feeds_meta_collection.find_one({"feed_name": feed_name})
                if feed_meta and 'last_fetch' in feed_meta:
                    status[feed_name]["last_fetch"] = feed_meta["last_fetch"]
                    status[feed_name]["total_iocs"] = feed_meta.get("total_iocs", 0)
                    status[feed_name]["status"] = feed_meta.get("status", "unknown")

        except Exception as e:
            self.logger.error(f"Error getting feed status: {str(e)}")

        return status

    def update_feed_meta(self, feed_name: str, status: str = "active", error_message: str = None) -> None:
        """Update metadata for a feed"""
        try:
            feeds_meta_collection = self.db.feeds_meta

            meta_data = {
                "feed_name": feed_name,
                "last_fetch": datetime.now(timezone.utc).isoformat(),
                "status": status,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }

            if error_message:
                meta_data["error_message"] = error_message

            feeds_meta_collection.update_one(
                {"feed_name": feed_name},
                {"$set": meta_data, "$inc": {"total_iocs": 1}},
                upsert=True
            )

        except Exception as e:
            self.logger.error(f"Error updating feed meta for {feed_name}: {str(e)}")

    def run_full_ingestion(self, custom_indicators: List[str] = None) -> Dict[str, Any]:
        """Run complete data ingestion from all sources"""
        ingestion_results = {
            "start_time": datetime.now(timezone.utc).isoformat(),
            "virustotal": {},
            "abuseipdb": {},
            "openfeeds": {},
            "total_processed": 0,
            "total_errors": 0,
            "status": "completed"
        }

        self.logger.info("Starting full data ingestion...")

        try:
            # Process custom indicators if provided
            if custom_indicators:
                # Separate by type for appropriate API calls
                ips = []
                domains = []
                urls = []
                hashes = []

                for indicator in custom_indicators:
                    ioc_type = self.ioc_model.determine_ioc_type(indicator)
                    if ioc_type:
                        if ioc_type.value == 'ip':
                            ips.append(indicator)
                        elif ioc_type.value == 'domain':
                            domains.append(indicator)
                        elif ioc_type.value == 'url':
                            urls.append(indicator)
                        elif ioc_type.value == 'hash':
                            hashes.append(indicator)

                # Process with VirusTotal
                vt_results = self.process_virustotal_data(custom_indicators)
                ingestion_results["virustotal"] = vt_results
                self.update_feed_meta("virustotal", "active" if not vt_results["errors"] else "error")

                # Process IPs with AbuseIPDB
                if ips:
                    abuseip_results = self.process_abuseipdb_data(ips)
                    ingestion_results["abuseipdb"] = abuseip_results
                    self.update_feed_meta("abuseipdb", "active" if not abuseip_results["errors"] else "error")

            # Process open feeds
            openfeed_results = self.process_open_feeds()
            ingestion_results["openfeeds"] = openfeed_results
            self.update_feed_meta("openfeeds", "active" if not openfeed_results["errors"] else "error")

            # Calculate totals
            ingestion_results["total_processed"] = (
                ingestion_results["virustotal"].get("processed", 0) +
                ingestion_results["abuseipdb"].get("processed", 0) +
                ingestion_results["openfeeds"].get("processed", 0)
            )

            ingestion_results["total_errors"] = len(
                ingestion_results["virustotal"].get("errors", []) +
                ingestion_results["abuseipdb"].get("errors", []) +
                ingestion_results["openfeeds"].get("errors", [])
            )

            if ingestion_results["total_errors"] > 0:
                ingestion_results["status"] = "completed_with_errors"

            self.logger.info(f"Data ingestion completed. Processed: {ingestion_results['total_processed']}, Errors: {ingestion_results['total_errors']}")

        except Exception as e:
            error_msg = f"Critical error during data ingestion: {str(e)}"
            self.logger.error(error_msg)
            ingestion_results["status"] = "failed"
            ingestion_results["critical_error"] = error_msg

        ingestion_results["end_time"] = datetime.now(timezone.utc).isoformat()
        return ingestion_results