"""Configuration management for OSDU Viewer"""
import os
from dotenv import load_dotenv
from pathlib import Path


class Config:
    def __init__(self):
        # Load environment variables from .env file
        env_path = Path(__file__).parent / '.env'
        load_dotenv(env_path)
        
        # OSDU Configuration
        self.OSDU_BASE_URL = os.getenv('OSDU_BASE_URL', 'http://osdu.vts.cloud')
        self.OSDU_PARTITION_ID = os.getenv('OSDU_PARTITION_ID', 'osdu')
        
        # Token Configuration
        self.OSDU_TOKEN_ENDPOINT = os.getenv('OSDU_TOKEN_ENDPOINT')
        self.OSDU_CLIENT_ID = os.getenv('OSDU_CLIENT_ID')
        self.OSDU_CLIENT_SECRET = os.getenv('OSDU_CLIENT_SECRET')
        self.OSDU_REFRESH_TOKEN = os.getenv('OSDU_REFRESH_TOKEN', '')
        self.OSDU_VERIFY_SSL = os.getenv('OSDU_VERIFY_SSL', 'False')
        
        # Flask Configuration
        self.FLASK_ENV = os.getenv('FLASK_ENV', 'development')
        self.FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'True') == 'True'
        self.FLASK_HOST = os.getenv('FLASK_HOST', '0.0.0.0')
        self.FLASK_PORT = int(os.getenv('FLASK_PORT', 5000))

    def to_dict(self):
        """Convert config to dictionary for TokenManager"""
        return {
            'OSDU_BASE_URL': self.OSDU_BASE_URL,
            'OSDU_PARTITION_ID': self.OSDU_PARTITION_ID,
            'OSDU_TOKEN_ENDPOINT': self.OSDU_TOKEN_ENDPOINT,
            'OSDU_CLIENT_ID': self.OSDU_CLIENT_ID,
            'OSDU_CLIENT_SECRET': self.OSDU_CLIENT_SECRET,
            'OSDU_REFRESH_TOKEN': self.OSDU_REFRESH_TOKEN,
            'OSDU_VERIFY_SSL': self.OSDU_VERIFY_SSL
        }

    def validate(self):
        """Validate required configuration"""
        required_fields = [
            'OSDU_BASE_URL',
            'OSDU_PARTITION_ID', 
            'OSDU_TOKEN_ENDPOINT',
            'OSDU_CLIENT_ID',
            'OSDU_CLIENT_SECRET'
        ]
        
        missing = []
        for field in required_fields:
            if not getattr(self, field):
                missing.append(field)
        
        if missing:
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")
        
        return True

    def get_flask_config(self):
        """Get Flask configuration"""
        return {
            'ENV': self.FLASK_ENV,
            'DEBUG': self.FLASK_DEBUG,
            'HOST': self.FLASK_HOST,
            'PORT': self.FLASK_PORT
        }


# Global config instance
config = Config()