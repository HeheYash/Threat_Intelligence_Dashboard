from flask import Flask, render_template
from flask_cors import CORS
from pymongo import MongoClient
import os
from datetime import datetime
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def create_app():
    app = Flask(__name__,
                template_folder='../frontend/templates',
                static_folder='../frontend/static')

    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['MONGODB_URI'] = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/ctidb')

    # Enable CORS for frontend
    CORS(app)

    # Initialize MongoDB connection
    try:
        client = MongoClient(app.config['MONGODB_URI'])
        app.db = client.ctidb
        app.logger.info("Connected to MongoDB successfully")
    except Exception as e:
        app.logger.error(f"Failed to connect to MongoDB: {str(e)}")
        app.db = None

    # Setup logging
    os.makedirs(os.path.dirname(os.getenv('LOG_FILE', 'logs/cti_dashboard.log')), exist_ok=True)

    logging.basicConfig(
        level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.getenv('LOG_FILE', 'logs/cti_dashboard.log')),
            logging.StreamHandler()
        ]
    )
    app.logger = logging.getLogger(__name__)

    # Register API routes
    try:
        from api.routes import api_bp, init_services
        # Initialize services with database connection
        if app.db:
            init_services(app.db)
        app.register_blueprint(api_bp, url_prefix='/api')
        app.logger.info("API routes registered successfully")
    except ImportError as e:
        app.logger.error(f"Failed to import API routes: {str(e)}")

    # Serve frontend templates
    @app.route('/')
    def index():
        try:
            return render_template('index.html')
        except Exception as e:
            app.logger.error(f"Error rendering index template: {str(e)}")
            return f"<h1>Cyber Threat Intelligence Dashboard</h1><p>Template error: {str(e)}</p>", 500

    @app.route('/lookup')
    def lookup():
        try:
            return render_template('lookup.html')
        except Exception as e:
            app.logger.error(f"Error rendering lookup template: {str(e)}")
            return f"<h1>IOC Lookup</h1><p>Template error: {str(e)}</p>", 500

    # Health check endpoint
    @app.route('/health')
    def health():
        try:
            db_status = "connected" if app.db else "disconnected"
            return {
                "status": "healthy",
                "database": db_status,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }, 500

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)