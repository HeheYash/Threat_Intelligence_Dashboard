import os
from datetime import timedelta

class Config:
    """Application configuration class"""

    # Database
    MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/ctidb')

    # API Keys (should be in environment variables)
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')

    # Application
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')

    # Scheduler Configuration
    FETCH_INTERVAL_MINUTES = int(os.getenv('FETCH_INTERVAL_MINUTES', '30'))
    MAX_RETRY_ATTEMPTS = int(os.getenv('MAX_RETRY_ATTEMPTS', '3'))
    RETRY_DELAY_SECONDS = int(os.getenv('RETRY_DELAY_SECONDS', '60'))

    # API Rate Limits
    VIRUSTOTAL_RATE_LIMIT = 4  # requests per minute (free tier)
    ABUSEIPDB_RATE_LIMIT = 1000  # requests per day (free tier)

    # Security
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000').split(',')
    RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', '60'))

    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/cti_dashboard.log')

    # Data Retention
    IOC_RETENTION_DAYS = int(os.getenv('IOC_RETENTION_DAYS', '365'))

    # Threat Scoring
    THREAT_SCORE_THRESHOLDS = {
        'high': 80,
        'medium': 50,
        'low': 20
    }

    # Cache settings
    CACHE_TIMEOUT_MINUTES = int(os.getenv('CACHE_TIMEOUT_MINUTES', '15'))

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    MONGODB_URI = 'mongodb://localhost:27017/ctidb_test'

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}