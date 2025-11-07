#!/usr/bin/env python3
"""
VirusTotal Data Fetcher
Scheduled job to fetch threat intelligence from VirusTotal API
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
        logging.FileHandler('../logs/fetch_vt.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VirusTotalFetcher:
    """VirusTotal scheduled data fetcher"""

    def __init__(self):
        self.config = Config()
        self.db_client = None
        self.feeder = None

    def initialize(self):
        """Initialize database connection and services"""
        try:
            self.db_client = MongoClient(self.config.MONGODB_URI)
            self.feeder = DataFeeder(self.db_client.ctidb)
            logger.info("VirusTotal fetcher initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize VirusTotal fetcher: {str(e)}")
            return False

    def fetch_sample_indicators(self):
        """Fetch data for a sample set of indicators for demonstration"""
        if not self.config.VIRUSTOTAL_API_KEY:
            logger.warning("VirusTotal API key not configured, skipping fetch")
            return False

        # Sample indicators for demonstration
        sample_indicators = [
            '8.8.8.8',           # Google DNS (should be clean)
            '1.1.1.1',           # Cloudflare DNS
            'malware-test.com',  # Sample domain
            'http://example.com/test',  # Sample URL
            'd41d8cd98f00b204e9800998ecf8427e'  # MD5 of empty string
        ]

        logger.info(f"Fetching VirusTotal data for {len(sample_indicators)} sample indicators")

        try:
            results = self.feeder.process_virustotal_data(sample_indicators)

            logger.info(f"VirusTotal fetch completed: {results.get('processed', 0)} processed, {len(results.get('errors', []))} errors")

            if results.get('errors'):
                for error in results['errors'][:5]:  # Log first 5 errors
                    logger.warning(f"VirusTotal error: {error}")

            # Update feed metadata
            self.feeder.update_feed_meta(
                'virustotal',
                'active' if not results.get('errors') else 'error'
            )

            return True

        except Exception as e:
            logger.error(f"Error during VirusTotal fetch: {str(e)}")
            self.feeder.update_feed_meta('virustotal', 'error', str(e))
            return False

    def fetch_random_malicious_samples(self):
        """Fetch data for known malicious samples from public sources"""
        if not self.config.VIRUSTOTAL_API_KEY:
            logger.warning("VirusTotal API key not configured, skipping malicious sample fetch")
            return False

        # Known malicious indicators for testing
        malicious_indicators = [
            '0.0.0.0',  # Often used in malicious contexts
            'malwaredomain.example',  # Sample malicious domain
        ]

        logger.info(f"Fetching VirusTotal data for {len(malicious_indicators)} malicious indicators")

        try:
            results = self.feeder.process_virustotal_data(malicious_indicators)
            logger.info(f"Malicious samples fetch completed: {results.get('processed', 0)} processed")
            return True
        except Exception as e:
            logger.error(f"Error during malicious samples fetch: {str(e)}")
            return False

    def scheduled_fetch(self):
        """Main scheduled fetch job"""
        logger.info("Starting scheduled VirusTotal fetch")

        if not self.initialize():
            logger.error("Failed to initialize fetcher, skipping scheduled fetch")
            return

        try:
            # Fetch sample indicators
            success = self.fetch_sample_indicators()

            if success:
                logger.info("Scheduled VirusTotal fetch completed successfully")
            else:
                logger.error("Scheduled VirusTotal fetch failed")

        except Exception as e:
            logger.error(f"Critical error in scheduled fetch: {str(e)}")

        finally:
            # Cleanup database connection
            if self.db_client:
                self.db_client.close()

def main():
    """Main function for running the fetcher"""
    import argparse

    parser = argparse.ArgumentParser(description='VirusTotal Data Fetcher')
    parser.add_argument('--mode', choices=['once', 'scheduled'], default='once',
                       help='Run mode: once (immediate) or scheduled (continuous)')
    parser.add_argument('--interval', type=int, default=30,
                       help='Fetch interval in minutes (default: 30)')

    args = parser.parse_args()

    fetcher = VirusTotalFetcher()

    if args.mode == 'once':
        # Run once and exit
        logger.info("Running VirusTotal fetch once")
        success = fetcher.initialize()
        if success:
            fetcher.fetch_sample_indicators()
            fetcher.fetch_random_malicious_samples()
        else:
            logger.error("Failed to initialize fetcher")
            sys.exit(1)

    else:
        # Run continuously with scheduler
        logger.info(f"Starting VirusTotal fetcher with {args.interval} minute interval")

        scheduler = BackgroundScheduler()

        # Schedule the job
        scheduler.add_job(
            fetcher.scheduled_fetch,
            'interval',
            minutes=args.interval,
            id='virustotal_fetch',
            name='VirusTotal Data Fetch'
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
            logger.info("Shutting down VirusTotal fetcher...")
            scheduler.shutdown()

        except Exception as e:
            logger.error(f"Scheduler error: {str(e)}")
            scheduler.shutdown()
            sys.exit(1)

if __name__ == '__main__':
    main()