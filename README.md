# Threat Intelligence Dashboard

A comprehensive web dashboard that aggregates threat intelligence feeds from multiple sources, stores indicators of compromise (IOCs), visualizes threat trends, and provides advanced lookup capabilities with export functionality.

## 🛡️ Features

### Core Functionality
- **Multi-source Data Ingestion**: Aggregates threat intelligence from VirusTotal, AbuseIPDB, and public CTI feeds
- **Real-time Dashboard**: Interactive web interface with threat trends and statistics
- **IOC Lookup**: Advanced search and detailed IOC analysis with enrichment
- **Threat Scoring**: Composite threat scoring algorithm based on source confidence
- **Data Export**: Export IOC data in JSON and CSV formats
- **Scheduled Updates**: Automated data fetching with configurable intervals

### Data Sources
- **VirusTotal**: Malware detection and URL analysis (4 req/min free tier)
- **AbuseIPDB**: IP abuse confidence and reporting (1000 req/day free tier)
- **AlienVault OTX**: Community threat intelligence pulses
- **PhishTank**: Verified phishing URL feeds
- **Malware Domain Lists**: Known malicious domains
- **Abuse.ch SSL**: SSL certificate blacklist
- **Feodo Tracker**: C2 infrastructure tracking

### Visualization & Analytics
- Interactive threat discovery trends (Chart.js)
- IOC type distribution charts
- Top threats identification
- Geographic threat mapping (GeoIP integration)
- Real-time feed status monitoring
- Advanced search with filters

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend API   │    │   Database      │
│   (HTML/JS)     │◄──►│   (Flask)       │◄──►│   (MongoDB)     │
│                 │    │                 │    │                 │
│ • Dashboard     │    │ • REST APIs     │    │ • IOC Storage   │
│ • Charts        │    │ • Data Ingestion│    │ • Metadata      │
│ • Search UI     │    │ • Threat Scoring│    │ • Indexes       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐              │
         │              │   Scheduler     │              │
         └──────────────►│   (APScheduler) │◄─────────────┘
                        │                 │
                        │ • Data Fetchers │
                        │ • Rate Limits   │
                        │ • Error Handling│
                        └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- MongoDB 6.0+
- Docker & Docker Compose (optional)
- API keys for VirusTotal and/or AbuseIPDB

### Using Docker Compose (Recommended)

1. **Clone the repository**
```bash
git clone <repository-url>
cd Cyber_Threat_Intelligence_Dashboard
```

2. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your API keys and configuration
```

3. **Start the application**
```bash
docker-compose up -d
```

4. **Access the dashboard**
- Dashboard: http://localhost
- API Health: http://localhost/api/health
- MongoDB: localhost:27017

### Manual Installation

1. **Install dependencies**
```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Frontend dependencies are served via CDN
```

2. **Configure MongoDB**
```bash
# Start MongoDB
mongod --dbpath /path/to/your/db

# Create database and user (optional)
mongo
use ctidb
db.createUser({user: "cti_user", pwd: "password", roles: ["readWrite"]})
```

3. **Set environment variables**
```bash
export MONGODB_URI="mongodb://localhost:27017/ctidb"
export VIRUSTOTAL_API_KEY="your_vt_api_key"
export ABUSEIPDB_API_KEY="your_abuseip_api_key"
export SECRET_KEY="your-secret-key"
```

4. **Start the application**
```bash
cd backend
python app.py
```

5. **Set up scheduled fetchers**
```bash
# Run in separate terminals or use a process manager
python ../fetchers/fetch_vt.py --mode scheduled &
python ../fetchers/fetch_abuseip.py --mode scheduled &
python ../fetchers/fetch_openfeeds.py --mode scheduled &
```

## 📊 Configuration

### Environment Variables

Key configuration options in `.env`:

```bash
# Database
MONGODB_URI=mongodb://localhost:27017/ctidb

# API Keys (Required for data ingestion)
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key

# Application
SECRET_KEY=your-super-secret-key
FLASK_ENV=production

# Scheduler
FETCH_INTERVAL_MINUTES=30
MAX_RETRY_ATTEMPTS=3

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
```

### API Rate Limits
- **VirusTotal**: 4 requests/minute (free tier)
- **AbuseIPDB**: 1000 requests/day (free tier)
- **Open Feeds**: Varies by source

## 🔧 API Documentation

### Core Endpoints

#### Dashboard Statistics
```http
GET /api/stats
```
Returns dashboard statistics including total IOCs, threat levels, and type distribution.

#### Threat Trends
```http
GET /api/trends?days=30&type=all
```
Returns time-series data for IOC discovery trends.

#### IOC Lookup
```http
GET /api/lookup?value=8.8.8.8&type=ip
```
Lookup detailed IOC information with enrichment data.

#### Bulk Lookup
```http
POST /api/bulk-lookup
Content-Type: application/json

{
  "values": ["8.8.8.8", "malware.com", "d41d8cd98f00b204e9800998ecf8427e"]
}
```

#### Advanced Search
```http
GET /api/search?q=malware&type=domain&min_score=70&days=30&limit=50
```

#### Data Export
```http
GET /api/export?format=json&type=ip&days=30&min_score=50
```

#### Feed Management
```http
GET /api/feeds/status
POST /api/feeds/refresh
```

### Response Format

All API responses follow this structure:
```json
{
  "success": true,
  "data": { ... },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

Error responses:
```json
{
  "success": false,
  "error": "Error description",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## 🎯 Usage Examples

### IOC Lookup
```python
import requests

# Simple IOC lookup
response = requests.get('http://localhost/api/lookup', params={
    'value': '8.8.8.8'
})

ioc_data = response.json()
if ioc_data['success']:
    print(f"Threat Score: {ioc_data['data']['threat_score']}")
    print(f"Sources: {', '.join(ioc_data['data']['sources'])}")
```

### Bulk Analysis
```python
import requests

# Bulk lookup multiple IOCs
indicators = ['192.168.1.1', 'malware.com', 'd41d8cd98f00b204e9800998ecf8427e']

response = requests.post('http://localhost/api/bulk-lookup', json={
    'values': indicators
})

results = response.json()
print(f"Analyzed {len(results['data']['results'])} IOCs")
```

### Data Export
```bash
# Export JSON data
curl "http://localhost/api/export?format=json&days=30" -o ioc_export.json

# Export CSV data
curl "http://localhost/api/export?format=csv&type=ip" -o ioc_export.csv
```

## 🧪 Testing

### Import Sample Data
```bash
# Import 50 sample IOCs
python scripts/import_sample_data.py --count 50

# Export sample data to file
python scripts/import_sample_data.py --export sample_data.json
```

### Manual Testing
```bash
# Test API health
curl http://localhost/api/health

# Test IOC lookup
curl "http://localhost/api/lookup?value=8.8.8.8"

# Test feed status
curl http://localhost/api/feeds/status
```

### Unit Tests
```bash
# Run backend tests
cd backend
python -m pytest tests/

# Run with coverage
python -m pytest --cov=. tests/
```

## 🔒 Security Considerations

### API Key Management
- Never commit API keys to version control
- Use environment variables or secret management
- Rotate API keys regularly
- Monitor API usage and limits

### Database Security
- Use authentication for MongoDB in production
- Enable network encryption (TLS/SSL)
- Implement proper access controls
- Regular backups and monitoring

### Web Security
- Enable HTTPS in production
- Configure proper CORS origins
- Implement rate limiting
- Use CSP headers
- Regular security updates

### Operational Security
- Audit logging for all data access
- Monitor feed sources for data integrity
- Implement data retention policies
- Regular security assessments

## 📈 Monitoring & Maintenance

### Health Checks
- Application health: `/api/health`
- Database connectivity
- Feed source availability
- API rate limit monitoring

### Logs
- Application logs: `logs/cti_dashboard.log`
- Fetcher logs: `logs/fetch_*.log`
- Access logs: Nginx access logs
- Error logs: Application error tracking

### Performance Monitoring
- API response times
- Database query performance
- Memory usage tracking
- Feed processing times

## 🛠️ Development

### Project Structure
```
Cyber_Threat_Intelligence_Dashboard/
├── backend/                    # Flask application
│   ├── app.py                 # Main application entry point
│   ├── api/                   # API routes
│   ├── services/              # External API clients
│   ├── models/                # Database models
│   └── config.py              # Configuration
├── frontend/                   # Web interface
│   ├── templates/             # HTML templates
│   ├── static/                # CSS and JavaScript
├── fetchers/                   # Data collection scripts
├── scripts/                    # Utility scripts
├── nginx/                      # Web server configuration
├── docker-compose.yml          # Container orchestration
└── docs/                       # Documentation
```

### Adding New Data Sources

1. **Create API client** in `backend/services/`
2. **Add to feeder service** in `backend/services/feeder.py`
3. **Update scheduler** in `fetchers/`
4. **Add to documentation**

### Contributing
1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Update documentation
5. Submit pull request

## 📚 Additional Documentation

- [API Reference](docs/API_DOCUMENTATION.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Configuration Guide](docs/CONFIGURATION.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## 🤝 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting guide
- Review API documentation
- Join our community discussions

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **VirusTotal** - Malware detection and analysis
- **AbuseIPDB** - IP abuse reporting
- **AlienVault OTX** - Open threat intelligence
- **PhishTank** - Anti-phishing community
- **Chart.js** - Data visualization
- **Bootstrap** - UI framework

---

**⚠️ Important**: This tool is designed for defensive security purposes only. Users must comply with all applicable laws, regulations, and terms of service of integrated APIs.
