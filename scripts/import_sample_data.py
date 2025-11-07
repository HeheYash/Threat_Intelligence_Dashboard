#!/usr/bin/env python3
"""
Sample Data Import Script for CTI Dashboard
Imports sample threat intelligence data for demonstration and testing purposes
"""

import sys
import os
import json
from datetime import datetime, timezone, timedelta
import random

# Add the backend directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

from pymongo import MongoClient
from models.ioc_model import IOCModel

def generate_sample_iocs():
    """Generate realistic sample IOC data for testing"""

    # Sample malicious IPs (for demonstration only)
    malicious_ips = [
        "192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.10",
        "198.51.100.20", "192.0.2.30", "203.0.113.40", "198.51.100.50",
        "185.141.63.80", "185.141.63.81", "185.141.63.82", "185.141.63.83"
    ]

    # Sample benign and suspicious domains
    domains = [
        "malware-example.com", "phishing-site.net", "botnet-controller.info",
        "c2-server.org", "malware-distribution.biz", "fake-banking.com",
        "suspicious-domain.xyz", "malicious-site.online", "threat-intelligence.info"
    ]

    # Sample URLs
    urls = [
        "http://malware-example.com/payload.exe",
        "https://phishing-site.net/login.php",
        "http://botnet-controller.info/command",
        "https://fake-banking.com/secure-login",
        "http://malware-distribution.biz/download/virus.exe"
    ]

    # Sample file hashes (MD5)
    hashes = [
        "d41d8cd98f00b204e9800998ecf8427e",  # Empty file
        "5d41402abc4b2a76b9719d911017c592",  # "hello"
        "098f6bcd4621d373cade4e832627b4f6",  # "test"
        "e99a18c428cb38d5f260853678922e03",  # "abc123"
        "c4ca4238a0b923820dcc509a6f75849b",  # "1"
        "098f6bcd4621d373cade4e832627b4f6",  # "test" (duplicate for testing)
        "e10adc3949ba59abbe56e057f20f883e",  # "123456"
        "25d55ad283aa400af464c76d713c07ad"   # "password"
    ]

    sample_iocs = []

    # Generate IP IOCs
    for ip in malicious_ips:
        # Mix of threat scores
        threat_score = random.randint(60, 95)
        first_seen = datetime.now(timezone.utc) - timedelta(days=random.randint(1, 90))
        last_seen = first_seen + timedelta(hours=random.randint(1, 24))

        sources = random.sample(['virustotal', 'abuseipdb', 'otx'], k=random.randint(1, 2))

        ioc = {
            "ioc_type": "ip",
            "value": ip,
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "sources": sources,
            "threat_score": threat_score,
            "meta": {
                "country": random.choice(["US", "CN", "RU", "BR", "IN", "DE"]),
                "asn": f"AS{random.randint(1000, 99999)}",
                "as_owner": random.choice([
                    "Malicious Hosting Provider",
                    "Botnet Network",
                    "Compromised Server",
                    "Anonymous Proxy"
                ]),
                "tags": random.sample(["botnet", "malware", "c2", "proxy", "vpn"], k=random.randint(1, 3)),
                "reputation": {
                    "malicious": random.randint(5, 25),
                    "suspicious": random.randint(0, 10),
                    "harmless": random.randint(0, 5),
                    "undetected": random.randint(50, 70)
                }
            },
            "created_at": first_seen.isoformat(),
            "updated_at": last_seen.isoformat()
        }
        sample_iocs.append(ioc)

    # Generate Domain IOCs
    for domain in domains:
        threat_score = random.randint(50, 100)
        first_seen = datetime.now(timezone.utc) - timedelta(days=random.randint(1, 60))
        last_seen = first_seen + timedelta(hours=random.randint(6, 72))

        sources = random.sample(['virustotal', 'otx', 'phishtank', 'malwaredomains'], k=random.randint(1, 3))

        ioc = {
            "ioc_type": "domain",
            "value": domain,
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "sources": sources,
            "threat_score": threat_score,
            "meta": {
                "creation_date": (first_seen - timedelta(days=random.randint(30, 365))).isoformat(),
                "categories": random.choice(["malicious", "suspicious", "phishing", "malware"]),
                "subdomains": [f"www.{domain}", f"mail.{domain}"],
                "tags": random.sample(["phishing", "malware", "suspicious", "blocked"], k=random.randint(1, 2)),
                "reputation": {
                    "malicious": random.randint(3, 20),
                    "suspicious": random.randint(0, 8),
                    "harmless": random.randint(0, 10),
                    "undetected": random.randint(40, 60)
                }
            },
            "created_at": first_seen.isoformat(),
            "updated_at": last_seen.isoformat()
        }
        sample_iocs.append(ioc)

    # Generate URL IOCs
    for url in urls:
        threat_score = random.randint(70, 100)
        first_seen = datetime.now(timezone.utc) - timedelta(days=random.randint(1, 30))
        last_seen = first_seen + timedelta(hours=random.randint(1, 48))

        sources = random.sample(['virustotal', 'otx', 'phishtank'], k=random.randint(1, 2))

        ioc = {
            "ioc_type": "url",
            "value": url,
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "sources": sources,
            "threat_score": threat_score,
            "meta": {
                "first_submission_date": first_seen.isoformat(),
                "last_submission_date": last_seen.isoformat(),
                "times_submitted": random.randint(1, 10),
                "tags": random.sample(["phishing", "malware", "exploit", "drive-by"], k=random.randint(1, 2)),
                "reputation": {
                    "malicious": random.randint(8, 30),
                    "suspicious": random.randint(0, 5),
                    "harmless": random.randint(0, 3),
                    "undetected": random.randint(30, 50)
                }
            },
            "created_at": first_seen.isoformat(),
            "updated_at": last_seen.isoformat()
        }
        sample_iocs.append(ioc)

    # Generate Hash IOCs
    for hash_val in hashes:
        threat_score = random.randint(80, 100)
        first_seen = datetime.now(timezone.utc) - timedelta(days=random.randint(1, 45))
        last_seen = first_seen + timedelta(hours=random.randint(1, 24))

        sources = random.sample(['virustotal', 'otx'], k=random.randint(1, 2))

        ioc = {
            "ioc_type": "hash",
            "value": hash_val,
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "sources": sources,
            "threat_score": threat_score,
            "meta": {
                "size": random.randint(1024, 10485760),  # 1KB to 10MB
                "type_description": random.choice(["Win32 EXE", "PE32 executable", "DLL", "PDF"]),
                "names": [f"sample_{random.randint(1000, 9999)}.exe", "payload.exe", "dropper.exe"],
                "tags": random.sample(["trojan", "malware", "backdoor", "keylogger"], k=random.randint(1, 3)),
                "reputation": {
                    "malicious": random.randint(10, 40),
                    "suspicious": random.randint(0, 10),
                    "harmless": random.randint(0, 5),
                    "undetected": random.randint(20, 40)
                }
            },
            "created_at": first_seen.isoformat(),
            "updated_at": last_seen.isoformat()
        }
        sample_iocs.append(ioc)

    return sample_iocs

def import_sample_data(mongodb_uri="mongodb://localhost:27017/ctidb", count=50):
    """Import sample IOC data into MongoDB"""

    print(f"Connecting to MongoDB: {mongodb_uri}")
    try:
        client = MongoClient(mongodb_uri)
        db = client.ctidb
        ioc_model = IOCModel(db)

        print("Connected to MongoDB successfully")

        # Clear existing sample data (optional)
        response = input("Clear existing sample data? (y/N): ").strip().lower()
        if response == 'y':
            result = db.iocs.delete_many({})
            print(f"Cleared {result.deleted_count} existing IOCs")

        # Generate sample IOCs
        print(f"Generating {count} sample IOCs...")
        sample_iocs = generate_sample_iocs()

        # Limit to requested count
        if len(sample_iocs) > count:
            sample_iocs = sample_iocs[:count]

        # Insert into database
        print(f"Importing {len(sample_iocs)} IOCs...")
        imported_count = 0

        for ioc in sample_iocs:
            try:
                ioc_id = ioc_model.upsert_ioc(
                    ioc["value"],
                    ioc["sources"],
                    ioc["meta"]
                )
                imported_count += 1
                if imported_count % 10 == 0:
                    print(f"  Imported {imported_count} IOCs...")
            except Exception as e:
                print(f"  Error importing IOC {ioc['value']}: {str(e)}")

        print(f"Successfully imported {imported_count} IOCs")

        # Update feed metadata
        print("Updating feed metadata...")
        feeds_meta_collection = db.feeds_meta

        # Update last fetch times for demonstration
        now = datetime.now(timezone.utc).isoformat()
        feeds_meta_collection.update_many(
            {"feed_name": {"$in": ["virustotal", "abuseipdb", "openfeeds"]}},
            {
                "$set": {
                    "last_fetch": now,
                    "status": "active",
                    "total_iocs": imported_count // 3,
                    "updated_at": now
                }
            }
        )

        # Print summary statistics
        print("\n=== Import Summary ===")
        stats = ioc_model.get_stats()
        print(f"Total IOCs in database: {stats['total_iocs']}")
        print(f"By type: {stats['by_type']}")
        print(f"High threat IOCs: {stats['high_threat']}")
        print(f"Medium threat IOCs: {stats['medium_threat']}")
        print(f"Low threat IOCs: {stats['low_threat']}")

        client.close()
        print("\nSample data import completed successfully!")

    except Exception as e:
        print(f"Error importing sample data: {str(e)}")
        sys.exit(1)

def export_sample_data(filename="sample_iocs.json"):
    """Export sample data to JSON file for manual review"""

    print(f"Generating sample data and exporting to {filename}...")

    sample_iocs = generate_sample_iocs()

    try:
        with open(filename, 'w') as f:
            json.dump(sample_iocs, f, indent=2, default=str)
        print(f"Exported {len(sample_iocs)} sample IOCs to {filename}")
    except Exception as e:
        print(f"Error exporting sample data: {str(e)}")
        sys.exit(1)

def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='Import sample CTI data')
    parser.add_argument('--export', help='Export sample data to JSON file instead of importing')
    parser.add_argument('--mongodb-uri', default='mongodb://localhost:27017/ctidb',
                       help='MongoDB connection URI')
    parser.add_argument('--count', type=int, default=50,
                       help='Number of sample IOCs to generate (default: 50)')
    parser.add_argument('--clear', action='store_true',
                       help='Clear existing data before import')

    args = parser.parse_args()

    if args.export:
        export_sample_data(args.export)
    else:
        if args.clear:
            # Auto-clear if requested
            print("Clearing existing data before import...")
        import_sample_data(args.mongodb_uri, args.count)

if __name__ == '__main__':
    main()