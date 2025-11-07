from flask import request, jsonify, render_template
import logging
from datetime import datetime, timezone
from ..services.feeder import DataFeeder
from ..models.ioc_model import IOCModel
import json
from . import api_bp

# Initialize services
def init_services(db_client):
    global feeder, ioc_model
    feeder = DataFeeder(db_client)
    ioc_model = IOCModel(db_client)

@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    try:
        stats = ioc_model.get_stats()
        return jsonify({
            "success": True,
            "data": stats,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to fetch statistics: {str(e)}"
        }), 500

@api_bp.route('/trends', methods=['GET'])
def get_trends():
    """Get IOC discovery trends over time"""
    try:
        days = int(request.args.get('days', 30))
        ioc_type = request.args.get('type', 'all')

        trends = ioc_model.get_trends(days)

        # Filter by type if specified
        if ioc_type != 'all':
            # Add type filtering logic here if needed
            pass

        return jsonify({
            "success": True,
            "data": trends,
            "parameters": {
                "days": days,
                "type": ioc_type
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to fetch trends: {str(e)}"
        }), 500

@api_bp.route('/lookup', methods=['GET'])
def lookup_ioc():
    """Lookup IOC details"""
    try:
        value = request.args.get('value')
        if not value:
            return jsonify({
                "success": False,
                "error": "IOC value is required"
            }), 400

        ioc_type = request.args.get('type')

        ioc = ioc_model.get_ioc_by_value(value, ioc_type)
        if not ioc:
            return jsonify({
                "success": False,
                "error": "IOC not found"
            }), 404

        # Convert ObjectId to string for JSON serialization
        ioc['_id'] = str(ioc['_id'])

        return jsonify({
            "success": True,
            "data": ioc,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to lookup IOC: {str(e)}"
        }), 500

@api_bp.route('/bulk-lookup', methods=['POST'])
def bulk_lookup_iocs():
    """Bulk lookup multiple IOCs"""
    try:
        data = request.get_json()
        if not data or 'values' not in data:
            return jsonify({
                "success": False,
                "error": "IOC values array is required"
            }), 400

        values = data['values']
        if not isinstance(values, list):
            return jsonify({
                "success": False,
                "error": "Values must be an array"
            }), 400

        if len(values) > 100:  # Limit bulk requests
            return jsonify({
                "success": False,
                "error": "Maximum 100 IOCs allowed per bulk request"
            }), 400

        results = []
        not_found = []

        for value in values:
            ioc = ioc_model.get_ioc_by_value(value)
            if ioc:
                ioc['_id'] = str(ioc['_id'])
                results.append(ioc)
            else:
                not_found.append(value)

        return jsonify({
            "success": True,
            "data": {
                "results": results,
                "not_found": not_found,
                "total_requested": len(values),
                "found": len(results),
                "not_found_count": len(not_found)
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to perform bulk lookup: {str(e)}"
        }), 500

@api_bp.route('/feeds/status', methods=['GET'])
def get_feed_status():
    """Get status of all configured feeds"""
    try:
        feed_status = feeder.get_feed_status()
        return jsonify({
            "success": True,
            "data": feed_status,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to fetch feed status: {str(e)}"
        }), 500

@api_bp.route('/feeds/refresh', methods=['POST'])
def refresh_feed():
    """Trigger immediate refresh of specified feed"""
    try:
        data = request.get_json()
        if not data or 'feed_name' not in data:
            return jsonify({
                "success": False,
                "error": "Feed name is required"
            }), 400

        feed_name = data['feed_name']

        if feed_name == 'all':
            # Run full ingestion
            results = feeder.run_full_ingestion()
        elif feed_name == 'virustotal':
            # Process VirusTotal data
            indicators = data.get('indicators', [])
            results = feeder.process_virustotal_data(indicators)
        elif feed_name == 'abuseipdb':
            # Process AbuseIPDB data
            ip_addresses = data.get('ip_addresses', [])
            results = feeder.process_abuseipdb_data(ip_addresses)
        elif feed_name == 'openfeeds':
            # Process open feeds
            results = feeder.process_open_feeds()
        else:
            return jsonify({
                "success": False,
                "error": f"Unknown feed: {feed_name}"
            }), 400

        return jsonify({
            "success": True,
            "data": results,
            "feed_name": feed_name,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to refresh feed: {str(e)}"
        }), 500

@api_bp.route('/export', methods=['GET'])
def export_iocs():
    """Export IOC data in specified format"""
    try:
        format_type = request.args.get('format', 'json')
        ioc_type = request.args.get('type', 'all')
        days = int(request.args.get('days', 30))
        min_score = int(request.args.get('min_score', 0))

        # Query parameters
        query = {"threat_score": {"$gte": min_score}}
        if ioc_type != 'all':
            query["ioc_type"] = ioc_type

        # Time filter
        from datetime import datetime, timedelta, timezone
        start_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        query["last_seen"] = {"$gte": start_date}

        iocs = list(ioc_model.collection.find(query).limit(10000))  # Limit export size

        # Convert ObjectId to string
        for ioc in iocs:
            ioc['_id'] = str(ioc['_id'])

        if format_type.lower() == 'csv':
            # Convert to CSV format
            import csv
            import io

            if not iocs:
                return "No data found for export criteria", 404

            output = io.StringIO()
            fieldnames = ['ioc_type', 'value', 'threat_score', 'threat_level', 'sources', 'first_seen', 'last_seen']
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()

            for ioc in iocs:
                row = {
                    'ioc_type': ioc.get('ioc_type', ''),
                    'value': ioc.get('value', ''),
                    'threat_score': ioc.get('threat_score', 0),
                    'threat_level': ioc.get('threat_level', ''),
                    'sources': ','.join(ioc.get('sources', [])),
                    'first_seen': ioc.get('first_seen', ''),
                    'last_seen': ioc.get('last_seen', '')
                }
                writer.writerow(row)

            csv_data = output.getvalue()
            output.close()

            from flask import Response
            return Response(
                csv_data,
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename=cti_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
            )
        else:
            # JSON format (default)
            return jsonify({
                "success": True,
                "data": iocs,
                "metadata": {
                    "count": len(iocs),
                    "format": format_type,
                    "filters": {
                        "ioc_type": ioc_type,
                        "days": days,
                        "min_score": min_score
                    },
                    "exported_at": datetime.now(timezone.utc).isoformat()
                }
            })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to export data: {str(e)}"
        }), 500

@api_bp.route('/search', methods=['GET'])
def search_iocs():
    """Search IOCs with advanced filters"""
    try:
        # Parse query parameters
        query_text = request.args.get('q', '').strip()
        ioc_type = request.args.get('type')
        min_score = int(request.args.get('min_score', 0))
        max_score = int(request.args.get('max_score', 100))
        days = int(request.args.get('days', 30))
        limit = min(int(request.args.get('limit', 50)), 200)  # Cap at 200
        offset = int(request.args.get('offset', 0))

        # Build MongoDB query
        query = {
            "threat_score": {"$gte": min_score, "$lte": max_score}
        }

        if ioc_type and ioc_type != 'all':
            query["ioc_type"] = ioc_type

        if query_text:
            query["$or"] = [
                {"value": {"$regex": query_text, "$options": "i"}},
                {"meta.tags": {"$in": [query_text]}},
                {"sources": {"$in": [query_text]}}
            ]

        # Time filter
        from datetime import datetime, timedelta, timezone
        start_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        query["last_seen"] = {"$gte": start_date}

        # Execute query
        iocs = list(ioc_model.collection.find(query)
                   .sort("threat_score", -1)
                   .skip(offset)
                   .limit(limit))

        # Get total count
        total_count = ioc_model.collection.count_documents(query)

        # Convert ObjectId to string
        for ioc in iocs:
            ioc['_id'] = str(ioc['_id'])

        return jsonify({
            "success": True,
            "data": {
                "results": iocs,
                "pagination": {
                    "total": total_count,
                    "limit": limit,
                    "offset": offset,
                    "has_more": offset + limit < total_count
                },
                "filters": {
                    "query": query_text,
                    "ioc_type": ioc_type,
                    "min_score": min_score,
                    "max_score": max_score,
                    "days": days
                }
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Search failed: {str(e)}"
        }), 500

@api_bp.route('/ingest', methods=['POST'])
def ingest_custom_data():
    """Ingest custom IOC data"""
    try:
        data = request.get_json()
        if not data or 'indicators' not in data:
            return jsonify({
                "success": False,
                "error": "Indicators array is required"
            }), 400

        indicators = data['indicators']
        if not isinstance(indicators, list):
            return jsonify({
                "success": False,
                "error": "Indicators must be an array"
            }), 400

        if len(indicators) > 1000:
            return jsonify({
                "success": False,
                "error": "Maximum 1000 indicators allowed per request"
            }), 400

        # Run ingestion for custom indicators
        results = feeder.run_full_ingestion(indicators)

        return jsonify({
            "success": True,
            "data": results,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to ingest custom data: {str(e)}"
        }), 500

@api_bp.route('/health', methods=['GET'])
def health_check():
    """API health check endpoint"""
    try:
        # Check database connectivity
        db_status = "connected"
        try:
            ioc_model.collection.count_documents({})
        except Exception as db_error:
            db_status = f"error: {str(db_error)}"

        return jsonify({
            "success": True,
            "data": {
                "status": "healthy",
                "database": db_status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": "1.0.0"
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Health check failed: {str(e)}"
        }), 500

# Error handlers
@api_bp.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success": False,
        "error": "Bad request",
        "message": str(error)
    }), 400

@api_bp.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Resource not found",
        "message": str(error)
    }), 404

@api_bp.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "error": "Internal server error",
        "message": "An unexpected error occurred"
    }), 500