#!/usr/bin/env python3
"""
AbuseIPDB Data Fetcher
Scheduled job to fetch threat intelligence from AbuseIPDB API
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
        logging.FileHandler('../logs/fetch_abuseip.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AbuseIPDBFetcher:
    """AbuseIPDB scheduled data fetcher"""

    def __init__(self):
        self.config = Config()
        self.db_client = None
        self.feeder = None

    def initialize(self):
        """Initialize database connection and services"""
        try:
            self.db_client = MongoClient(self.config.MONGODB_URI)
            self.feeder = DataFeeder(self.db_client.ctidb)
            logger.info("AbuseIPDB fetcher initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize AbuseIPDB fetcher: {str(e)}")
            return False

    def fetch_sample_ips(self):
        """Fetch data for a sample set of IP addresses"""
        if not self.config.ABUSEIPDB_API_KEY:
            logger.warning("AbuseIPDB API key not configured, skipping fetch")
            return False

        # Sample IP addresses for demonstration
        sample_ips = [
            '8.8.8.8',           # Google DNS (should be clean)
            '1.1.1.1',           # Cloudflare DNS
            '208.67.222.222',    # OpenDNS
            '192.168.1.1',       # Private IP (might not have data)
            '127.0.0.1',         # Localhost (should be clean)
        ]

        logger.info(f"Fetching AbuseIPDB data for {len(sample_ips)} sample IPs")

        try:
            results = self.feeder.process_abuseipdb_data(sample_ips)

            logger.info(f"AbuseIPDB fetch completed: {results.get('processed', 0)} processed, {len(results.get('errors', []))} errors")

            if results.get('errors'):
                for error in results['errors'][:5]:  # Log first 5 errors
                    logger.warning(f"AbuseIPDB error: {error}")

            # Update feed metadata
            self.feeder.update_feed_meta(
                'abuseipdb',
                'active' if not results.get('errors') else 'error'
            )

            return True

        except Exception as e:
            logger.error(f"Error during AbuseIPDB fetch: {str(e)}")
            self.feeder.update_feed_meta('abuseipdb', 'error', str(e))
            return False

    def fetch_blacklist_ips(self):
        """Fetch data from AbuseIPDB blacklist"""
        if not self.config.ABUSEIPDB_API_KEY:
            logger.warning("AbuseIPDB API key not configured, skipping blacklist fetch")
            return False

        logger.info("Fetching AbuseIPDB blacklist data")

        try:
            # Initialize AbuseIPDB client directly to access blacklist method
            from services.abuseip_client import AbuseIPDBClient

            client = AbuseIPDBClient(self.config.ABUSEIPDB_API_KEY)

            # Get top blacklist entries (limited to avoid rate limits)
            blacklist_ips = client.get_blacklist(limit=100, min_confidence=50)

            if blacklist_ips:
                logger.info(f"Retrieved {len(blacklist_ips)} IPs from AbuseIPDB blacklist")

                # Process the blacklist IPs
                results = self.feeder.process_abuseipdb_data(blacklist_ips[:20])  # Process first 20 to avoid rate limits

                logger.info(f"Blacklist fetch completed: {results.get('processed', 0)} processed")
                return True
            else:
                logger.warning("No blacklist data returned from AbuseIPDB")
                return False

        except Exception as e:
            logger.error(f"Error during blacklist fetch: {str(e)}")
            return False

    def fetch_recent_abusive_ips(self):
        """Fetch data for recently reported abusive IPs"""
        if not self.config.ABUSEIPDB_API_KEY:
            logger.warning("AbuseIPDB API key not configured, skipping recent abuse fetch")
            return False

        # Known problematic IP ranges for testing
        # Note: These are examples - in production, you'd get these from recent reports or other sources
        recent_abusive_ips = [
            # Example IPs that often appear in abuse reports
            # Note: These are placeholders and may not actually be abusive
        ]

        if not recent_abusive_ips:
            logger.info("No recent abusive IPs configured, skipping")
            return True

        logger.info(f"Fetching AbuseIPDB data for {len(recent_abusive_ips)} recent abusive IPs")

        try:
            results = self.feeder.process_abuseipdb_data(recent_abusive_ips)
            logger.info(f"Recent abusive IPs fetch completed: {results.get('processed', 0)} processed")
            return True
        except Exception as e:
            logger.error(f"Error during recent abusive IPs fetch: {str(e)}")
            return False

    def scheduled_fetch(self):
        """Main scheduled fetch job"""
        logger.info("Starting scheduled AbuseIPDB fetch")

        if not self.initialize():
            logger.error("Failed to initialize fetcher, skipping scheduled fetch")
            return

        try:
            # Fetch different types of data
            success1 = self.fetch_sample_ips()
            success2 = self.fetch_blacklist_ips()

            if success1 and success2:
                logger.info("Scheduled AbuseIPDB fetch completed successfully")
            else:
                logger.error("Some parts of scheduled AbuseIPDB fetch failed")

        except Exception as e:
            logger.error(f"Critical error in scheduled fetch: {str(e)}")

        finally:
            # Cleanup database connection
            if self.db_client:
                self.db_client.close()

def main():
    """Main function for running the fetcher"""
    import argparse

    parser = argparse.ArgumentParser(description='AbuseIPDB Data Fetcher')
    parser.add_argument('--mode', choices=['once', 'scheduled'], default='once',
                       help='Run mode: once (immediate) or scheduled (continuous)')
    parser.add_argument('--interval', type=int, default=30,
                       help='Fetch interval in minutes (default: 30)')

    args = parser.parse_args()

    fetcher = AbuseIPDBFetcher()

    if args.mode == 'once':
        # Run once and exit
        logger.info("Running AbuseIPDB fetch once")
        success = fetcher.initialize()
        if success:
            fetcher.fetch_sample_ips()
            fetcher.fetch_blacklist_ips()
        else:
            logger.error("Failed to initialize fetcher")
            sys.exit(1)

    else:
        # Run continuously with scheduler
        logger.info(f"Starting AbuseIPDB fetcher with {args.interval} minute interval")

        scheduler = BackgroundScheduler()

        # Schedule the job
        scheduler.add_job(
            fetcher.scheduled_fetch,
            'interval',
            minutes=args.interval,
            id='abuseipdb_fetch',
            name='AbuseIPDB Data Fetch'
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
            logger.info("Shutting down AbuseIPDB fetcher...")
            scheduler.shutdown()

        except Exception as e:
            logger.error(f"Scheduler error: {str(e)}")
            scheduler.shutdown()
            sys.exit(1)

if __name__ == '__main__':
    main()