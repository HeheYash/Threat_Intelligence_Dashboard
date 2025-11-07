from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import re
import ipaddress
import validators
from enum import Enum

class IOCType(Enum):
    """Supported IOC types"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"

class ThreatLevel(Enum):
    """Threat level classifications"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IOCModel:
    """IOC data model with validation and utility methods"""

    def __init__(self, db_client):
        self.db = db_client
        self.collection = self.db.iocs

    @staticmethod
    def determine_ioc_type(value: str) -> Optional[IOCType]:
        """Determine IOC type based on value format"""
        # Check if it's an IP address
        try:
            ipaddress.ip_address(value)
            return IOCType.IP
        except ValueError:
            pass

        # Check if it's a domain
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', value):
            return IOCType.DOMAIN

        # Check if it's a URL
        if validators.url(value):
            return IOCType.URL

        # Check if it's a hash (MD5, SHA1, SHA256)
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return IOCType.HASH  # MD5
        elif re.match(r'^[a-fA-F0-9]{40}$', value):
            return IOCType.HASH  # SHA1
        elif re.match(r'^[a-fA-F0-9]{64}$', value):
            return IOCType.HASH  # SHA256

        return None

    @staticmethod
    def calculate_threat_score(sources: List[str], meta: Dict[str, Any]) -> int:
        """Calculate composite threat score based on sources and metadata"""
        score = 0

        # Source-based scoring
        source_scores = {
            'virustotal': 50,
            'abuseipdb': 30,
            'otx': 20,
            'phishtank': 25,
            'malwaredomains': 15
        }

        for source in sources:
            score += source_scores.get(source.lower(), 10)

        # Additional scoring based on metadata
        if 'reputation' in meta:
            reputation = meta['reputation']
            if isinstance(reputation, dict):
                # VirusTotal malicious detections
                if 'malicious' in reputation:
                    score += reputation['malicious'] * 5

                # AbuseIPDB confidence score
                if 'abuse_confidence_score' in reputation:
                    if reputation['abuse_confidence_score'] > 50:
                        score += 20

        # Recency bonus (if seen in last 7 days)
        if 'last_seen' in meta:
            try:
                last_seen = datetime.fromisoformat(meta['last_seen'].replace('Z', '+00:00'))
                days_since = (datetime.now(timezone.utc) - last_seen).days
                if days_since <= 7:
                    score += 10
            except (ValueError, TypeError):
                pass

        return min(score, 100)  # Cap at 100

    @staticmethod
    def get_threat_level(score: int) -> ThreatLevel:
        """Convert threat score to threat level"""
        if score >= 80:
            return ThreatLevel.CRITICAL
        elif score >= 60:
            return ThreatLevel.HIGH
        elif score >= 40:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def create_ioc_document(self, value: str, sources: List[str], meta: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create a standardized IOC document"""
        now = datetime.now(timezone.utc).isoformat()
        ioc_type = self.determine_ioc_type(value)

        if not ioc_type:
            raise ValueError(f"Unable to determine IOC type for value: {value}")

        threat_score = self.calculate_threat_score(sources, meta or {})
        threat_level = self.get_threat_level(threat_score)

        document = {
            "ioc_type": ioc_type.value,
            "value": value,
            "first_seen": now,
            "last_seen": now,
            "sources": sources,
            "threat_score": threat_score,
            "threat_level": threat_level.value,
            "meta": meta or {},
            "created_at": now,
            "updated_at": now
        }

        return document

    def upsert_ioc(self, value: str, sources: List[str], meta: Dict[str, Any] = None) -> str:
        """Insert or update IOC in database"""
        now = datetime.now(timezone.utc).isoformat()
        ioc_type = self.determine_ioc_type(value)

        if not ioc_type:
            raise ValueError(f"Unable to determine IOC type for value: {value}")

        # Check if IOC already exists
        existing = self.collection.find_one({"ioc_type": ioc_type.value, "value": value})

        if existing:
            # Update existing IOC
            updated_sources = list(set(existing["sources"] + sources))
            updated_meta = {**existing.get("meta", {}), **(meta or {})}

            # Recalculate threat score
            threat_score = self.calculate_threat_score(updated_sources, updated_meta)
            threat_level = self.get_threat_level(threat_score)

            result = self.collection.update_one(
                {"_id": existing["_id"]},
                {
                    "$set": {
                        "sources": updated_sources,
                        "threat_score": threat_score,
                        "threat_level": threat_level.value,
                        "meta": updated_meta,
                        "last_seen": now,
                        "updated_at": now
                    }
                }
            )
            return str(existing["_id"])
        else:
            # Create new IOC
            document = self.create_ioc_document(value, sources, meta)
            result = self.collection.insert_one(document)
            return str(result.inserted_id)

    def get_ioc_by_value(self, value: str, ioc_type: str = None) -> Optional[Dict[str, Any]]:
        """Get IOC by value"""
        query = {"value": value}
        if ioc_type:
            query["ioc_type"] = ioc_type

        return self.collection.find_one(query)

    def get_iocs_by_type(self, ioc_type: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get IOCs by type"""
        return list(self.collection.find({"ioc_type": ioc_type}).limit(limit))

    def get_high_threat_iocs(self, min_score: int = 70, limit: int = 50) -> List[Dict[str, Any]]:
        """Get high-threat IOCs"""
        return list(self.collection.find(
            {"threat_score": {"$gte": min_score}}
        ).sort("threat_score", -1).limit(limit))

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        pipeline = [
            {"$group": {"_id": "$ioc_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        type_counts = list(self.collection.aggregate(pipeline))

        stats = {
            "total_iocs": self.collection.count_documents({}),
            "by_type": {item["_id"]: item["count"] for item in type_counts},
            "high_threat": self.collection.count_documents({"threat_score": {"$gte": 80}}),
            "medium_threat": self.collection.count_documents({"threat_score": {"$gte": 40, "$lt": 80}}),
            "low_threat": self.collection.count_documents({"threat_score": {"$lt": 40}}),
            "last_update": self.collection.find_one({}, sort=[("updated_at", -1)])["updated_at"] if self.collection.count_documents({}) > 0 else None
        }

        return stats

    def get_trends(self, days: int = 30) -> Dict[str, Any]:
        """Get IOC discovery trends over time"""
        from datetime import datetime, timedelta, timezone

        start_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        pipeline = [
            {"$match": {"created_at": {"$gte": start_date}}},
            {"$group": {
                "_id": {"$dateFromString": {"dateString": "$created_at"}},
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id": 1}}
        ]

        # Group by date
        daily_data = {}
        for item in self.collection.aggregate(pipeline):
            date_str = item["_id"].strftime("%Y-%m-%d")
            daily_data[date_str] = item["count"]

        return {
            "dates": list(daily_data.keys()),
            "counts": list(daily_data.values()),
            "period_days": days
        }