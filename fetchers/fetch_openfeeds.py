#!/usr/bin/env python3
"""
Open Feeds Data Fetcher
Scheduled job to fetch threat intelligence from public CTI feeds
"""

import sys
import os
import logging
from datetime import datetime, timezone
from pymongo import MongoClient
from apscheduler.schedulers.background import BackgroundScheduler
import time

# Add the backend directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

from config import Config
from services.feeder import DataFeeder

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('../logs/fetch_openfeeds.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class OpenFeedsFetcher:
    """Open CTI feeds scheduled data fetcher"""

    def __init__(self):
        self.config = Config()
        self.db_client = None
        self.feeder = None

    def initialize(self):
        """Initialize database connection and services"""
        try:
            self.db_client = MongoClient(self.config.MONGODB_URI)
            self.feeder = DataFeeder(self.db_client.ctidb)
            logger.info("Open Feeds fetcher initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Open Feeds fetcher: {str(e)}")
            return False

    def fetch_all_feeds(self):
        """Fetch data from all configured open feeds"""
        logger.info("Fetching data from all open CTI feeds")

        try:
            results = self.feeder.process_open_feeds()

            total_processed = results.get('processed', 0)
            total_errors = len(results.get('errors', []))

            logger.info(f"Open feeds fetch completed: {total_processed} indicators processed, {total_errors} errors")

            # Log details for each feed
            if 'details' in results:
                for feed_name, count in results['details'].items():
                    logger.info(f"  {feed_name}: {count} indicators")

            # Log errors (limit to first 10 to avoid spam)
            if results.get('errors'):
                for error in results['errors'][:10]:
                    logger.warning(f"Open feeds error: {error}")
                if len(results['errors']) > 10:
                    logger.warning(f"... and {len(results['errors']) - 10} more errors")

            # Update feed metadata
            status = 'active' if total_errors == 0 else 'error' if total_processed == 0 else 'completed_with_errors'
            self.feeder.update_feed_meta('openfeeds', status)

            return total_processed > 0

        except Exception as e:
            logger.error(f"Error during open feeds fetch: {str(e)}")
            self.feeder.update_feed_meta('openfeeds', 'error', str(e))
            return False

    def fetch_specific_feed(self, feed_name):
        """Fetch data from a specific feed"""
        logger.info(f"Fetching data from specific feed: {feed_name}")

        try:
            if feed_name == 'otx':
                # Fetch OTX pulses
                data = self.feeder.openfeeds_client.fetch_otx_pulses(limit=100)
            elif feed_name == 'phishtank':
                # Fetch PhishTank data
                data = self.feeder.openfeeds_client.fetch_phishtank()
            elif feed_name == 'malwaredomains':
                # Fetch malware domains
                data = self.feeder.openfeeds_client.fetch_malware_domains()
            elif feed_name == 'abuse_ch_ssl':
                # Fetch Abuse.ch SSL blacklist
                data = self.feeder.openfeeds_client.fetch_abuse_ch_ssl_blacklist()
            elif feed_name == 'feodo_tracker':
                # Fetch Feodo Tracker IPs
                data = self.feeder.openfeeds_client.fetch_feodo_tracker_ips()
            else:
                logger.error(f"Unknown feed name: {feed_name}")
                return False

            if data:
                # Process the fetched data
                processed_count = 0
                for indicator in data:
                    try:
                        self.feeder._store_normalized_ioc(indicator)
                        processed_count += 1
                    except Exception as e:
                        logger.warning(f"Error storing indicator {indicator.get('value', 'unknown')}: {str(e)}")

                logger.info(f"Processed {processed_count} indicators from {feed_name}")
                return processed_count > 0
            else:
                logger.warning(f"No data returned from {feed_name}")
                return False

        except Exception as e:
            logger.error(f"Error fetching from {feed_name}: {str(e)}")
            return False

    def validate_feeds_connectivity(self):
        """Validate connectivity to all feed sources"""
        logger.info("Validating connectivity to open feed sources")

        feeds_status = {
            'otx': False,
            'phishtank': False,
            'malwaredomains': False,
            'abuse_ch_ssl': False,
            'feodo_tracker': False
        }

        try:
            # Test OTX connectivity
            try:
                from services.openfeeds_client import OpenFeedsClient
                client = OpenFeedsClient()
                # Just try to make a simple request
                response = client.session.get("https://otx.alienvault.com/api/v1/", timeout=10)
                if response.status_code == 200:
                    feeds_status['otx'] = True
                    logger.info("OTX connectivity: OK")
            except Exception as e:
                logger.warning(f"OTX connectivity failed: {str(e)}")

            # Test PhishTank connectivity
            try:
                response = client.session.get("https://data.phishtank.com/data/", timeout=10)
                if response.status_code == 200:
                    feeds_status['phishtank'] = True
                    logger.info("PhishTank connectivity: OK")
            except Exception as e:
                logger.warning(f"PhishTank connectivity failed: {str(e)}")

            # Test other feeds (basic connectivity)
            other_feeds = [
                ('malwaredomains', 'http://www.malwaredomainlist.com/'),
                ('abuse_ch_ssl', 'https://sslbl.abuse.ch/'),
                ('feodo_tracker', 'https://feodotracker.abuse.ch/')
            ]

            for feed_name, base_url in other_feeds:
                try:
                    response = client.session.get(base_url, timeout=10)
                    if response.status_code == 200:
                        feeds_status[feed_name] = True
                        logger.info(f"{feed_name} connectivity: OK")
                except Exception as e:
                    logger.warning(f"{feed_name} connectivity failed: {str(e)}")

            successful_feeds = sum(feeds_status.values())
            total_feeds = len(feeds_status)

            logger.info(f"Connectivity validation completed: {successful_feeds}/{total_feeds} feeds reachable")

            return successful_feeds > 0

        except Exception as e:
            logger.error(f"Error during connectivity validation: {str(e)}")
            return False

    def scheduled_fetch(self):
        """Main scheduled fetch job"""
        logger.info("Starting scheduled open feeds fetch")

        if not self.initialize():
            logger.error("Failed to initialize fetcher, skipping scheduled fetch")
            return

        try:
            # First validate connectivity
            connectivity_ok = self.validate_feeds_connectivity()

            if not connectivity_ok:
                logger.warning("Some feeds are not reachable, proceeding anyway...")

            # Fetch all feeds
            success = self.fetch_all_feeds()

            if success:
                logger.info("Scheduled open feeds fetch completed successfully")
            else:
                logger.error("Scheduled open feeds fetch completed with issues")

        except Exception as e:
            logger.error(f"Critical error in scheduled fetch: {str(e)}")

        finally:
            # Cleanup database connection
            if self.db_client:
                self.db_client.close()

def main():
    """Main function for running the fetcher"""
    import argparse

    parser = argparse.ArgumentParser(description='Open Feeds Data Fetcher')
    parser.add_argument('--mode', choices=['once', 'scheduled'], default='once',
                       help='Run mode: once (immediate) or scheduled (continuous)')
    parser.add_argument('--interval', type=int, default=30,
                       help='Fetch interval in minutes (default: 30)')
    parser.add_argument('--feed', type=str,
                       help='Specific feed to fetch (otx, phishtank, malwaredomains, abuse_ch_ssl, feodo_tracker)')
    parser.add_argument('--validate', action='store_true',
                       help='Validate feed connectivity without fetching data')

    args = parser.parse_args()

    fetcher = OpenFeedsFetcher()

    if args.validate:
        # Only validate connectivity
        logger.info("Validating feed connectivity only")
        success = fetcher.initialize()
        if success:
            fetcher.validate_feeds_connectivity()
        else:
            logger.error("Failed to initialize fetcher")
            sys.exit(1)
        return

    if args.mode == 'once':
        # Run once and exit
        logger.info("Running open feeds fetch once")
        success = fetcher.initialize()
        if success:
            if args.feed:
                fetcher.fetch_specific_feed(args.feed)
            else:
                fetcher.fetch_all_feeds()
        else:
            logger.error("Failed to initialize fetcher")
            sys.exit(1)

    else:
        # Run continuously with scheduler
        logger.info(f"Starting open feeds fetcher with {args.interval} minute interval")

        scheduler = BackgroundScheduler()

        # Schedule the job
        scheduler.add_job(
            fetcher.scheduled_fetch,
            'interval',
            minutes=args.interval,
            id='openfeeds_fetch',
            name='Open Feeds Data Fetch'
        )

        try:
            scheduler.start()
            logger.info("Scheduler started successfully")

            # Run immediately on start
            fetcher.scheduled_fetch()

            # Keep the script running
            while True:
                time.sleep(60)  # Check every minute

        except KeyboardInterrupt:
            logger.info("Shutting down open feeds fetcher...")
            scheduler.shutdown()

        except Exception as e:
            logger.error(f"Scheduler error: {str(e)}")
            scheduler.shutdown()
            sys.exit(1)

if __name__ == '__main__':
    main()