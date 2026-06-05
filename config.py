"""Configuration management for the OSDU web console."""
import os
from dotenv import load_dotenv
from pathlib import Path


class Config:
    def __init__(self):
        # Load environment variables from .env file
        env_path = Path(__file__).parent / '.env'
        load_dotenv(env_path)
        
        # OSDU Core Configuration
        self.OSDU_BASE_URL = self._first_env(
            'OSDU_BASE_URL',
            'OSDU_EXTERNAL_BASE_URL',
            default=''
        ).rstrip('/')
        self.OSDU_BASE_HOST = os.getenv('OSDU_BASE_HOST')  # Optional Host header bypass
        self.OSDU_PARTITION_ID = self._first_env(
            'OSDU_PARTITION_ID',
            'OSDU_DATA_PARTITION_ID',
            'OSDU_PARTITION',
            default='osdu'
        )

        # OSDU service paths
        self.OSDU_ENTITLEMENTS_BASE_PATH = os.getenv('OSDU_ENTITLEMENTS_BASE_PATH', '/api/entitlements/v2')
        self.OSDU_LEGAL_BASE_PATH = os.getenv('OSDU_LEGAL_BASE_PATH', '/api/legal/v1')
        self.OSDU_PARTITION_BASE_PATH = os.getenv('OSDU_PARTITION_BASE_PATH', '/api/partition/v1')
        self.OSDU_STORAGE_BASE_PATH = os.getenv('OSDU_STORAGE_BASE_PATH', '/api/storage/v2')
        self.OSDU_TIMEOUT_SECONDS = int(os.getenv('OSDU_TIMEOUT_SECONDS', '30'))
        self.OSDU_GROUP_SCAN_LIMIT = int(os.getenv('OSDU_GROUP_SCAN_LIMIT', '5000'))
        self.OSDU_MAX_PAGE_SIZE = int(os.getenv('OSDU_MAX_PAGE_SIZE', '100'))

        # Token Configuration
        self.OSDU_TOKEN_ENDPOINT = self._first_env(
            'OSDU_TOKEN_ENDPOINT',
            'OSDU_AUTH_URL',
            'OSDU_EXTERNAL_TOKEN_URL',
            'OSDU_EXTERNAL_AUTH_URL'
        )
        self.OSDU_AUTH_BASE_URL = self._first_env('OSDU_AUTH_BASE_URL', 'OSDU_EXTERNAL_AUTH_URL', default='')
        self.OSDU_AUTH_REALM = self._first_env('OSDU_AUTH_REALM', 'OSDU_EXTERNAL_REALM', default='')
        self._derive_keycloak_admin_config()
        self.OSDU_TOKEN_HOST = os.getenv('OSDU_TOKEN_HOST')  # Optional Host header bypass
        self.OSDU_TOKEN_GRANT_TYPE = os.getenv('OSDU_TOKEN_GRANT_TYPE', 'client_credentials').strip().lower()
        self.OSDU_CLIENT_ID = self._first_env('OSDU_CLIENT_ID', 'OSDU_EXTERNAL_CLIENT_ID')
        self.OSDU_CLIENT_SECRET = self._first_env('OSDU_CLIENT_SECRET', 'OSDU_EXTERNAL_CLIENT_SECRET', default='')
        self.OSDU_REFRESH_TOKEN = self._first_env('OSDU_REFRESH_TOKEN', 'OSDU_EXTERNAL_REFRESH_TOKEN', default='')
        self.OSDU_SHARED_ACCESS_TOKEN = os.getenv('OSDU_SHARED_ACCESS_TOKEN', '')
        self.OSDU_USERNAME = self._first_env('OSDU_USERNAME', 'OSDU_EXTERNAL_USERNAME', default='')
        self.OSDU_PASSWORD = self._first_env('OSDU_PASSWORD', 'OSDU_EXTERNAL_PASSWORD', default='')
        self.OSDU_EXTERNAL_ADMIN_USERNAME = os.getenv('OSDU_EXTERNAL_ADMIN_USERNAME', '')
        self.OSDU_EXTERNAL_ADMIN_PASSWORD = os.getenv('OSDU_EXTERNAL_ADMIN_PASSWORD', '')
        self.OSDU_TOKEN_SCOPE = os.getenv('OSDU_TOKEN_SCOPE', 'openid profile email')
        self.OSDU_VERIFY_SSL = self._first_env('OSDU_VERIFY_SSL', 'OSDU_EXTERNAL_VERIFY_SSL', default='False')
        self.OSDU_TOKEN_DEFAULT_EXPIRES_SECONDS = int(os.getenv('OSDU_TOKEN_DEFAULT_EXPIRES_SECONDS', '3600'))
        
        # Flask Configuration
        self.FLASK_ENV = os.getenv('FLASK_ENV', 'development')
        self.FLASK_DEBUG = self.as_bool(os.getenv('FLASK_DEBUG', 'False'))
        self.FLASK_HOST = os.getenv('FLASK_HOST', '0.0.0.0')
        self.FLASK_PORT = int(os.getenv('FLASK_PORT', 5000))

    @staticmethod
    def _first_env(*names, default=None):
        for name in names:
            value = os.getenv(name)
            if value not in (None, ''):
                return value
        return default

    def _derive_keycloak_admin_config(self):
        """Infer Keycloak admin base URL and realm from a standard token endpoint."""
        token_source = self.OSDU_TOKEN_ENDPOINT or ''
        marker = '/realms/'
        suffix = '/protocol/openid-connect/token'
        if marker not in token_source or suffix not in token_source:
            return
        auth_base, tail = token_source.split(marker, 1)
        realm = tail.split('/', 1)[0]
        if not self.OSDU_AUTH_BASE_URL:
            self.OSDU_AUTH_BASE_URL = auth_base.rstrip('/')
        if not self.OSDU_AUTH_REALM:
            self.OSDU_AUTH_REALM = realm

    @staticmethod
    def _mask(value: str, visible: int = 4) -> str:
        if not value:
            return ''
        if len(value) <= visible:
            return '*' * len(value)
        return f"{value[:visible]}{'*' * 8}"

    @staticmethod
    def as_bool(value: str) -> bool:
        return str(value).strip().lower() in ('1', 'true', 'yes', 'y', 'on')

    def is_configured(self):
        """Return True when the current auth mode has enough config to request a token."""
        try:
            self.validate()
            return True
        except ValueError:
            return False

    def apply_runtime_overrides(self, values):
        """Apply UI-provided runtime config without writing secrets to disk."""
        allowed = {
            'OSDU_BASE_URL',
            'OSDU_BASE_HOST',
            'OSDU_PARTITION_ID',
            'OSDU_VERIFY_SSL',
            'OSDU_TIMEOUT_SECONDS',
            'OSDU_ENTITLEMENTS_BASE_PATH',
            'OSDU_LEGAL_BASE_PATH',
            'OSDU_PARTITION_BASE_PATH',
            'OSDU_STORAGE_BASE_PATH',
            'OSDU_GROUP_SCAN_LIMIT',
            'OSDU_MAX_PAGE_SIZE',
            'OSDU_TOKEN_ENDPOINT',
            'OSDU_TOKEN_HOST',
            'OSDU_AUTH_BASE_URL',
            'OSDU_AUTH_REALM',
            'OSDU_TOKEN_GRANT_TYPE',
            'OSDU_CLIENT_ID',
            'OSDU_CLIENT_SECRET',
            'OSDU_REFRESH_TOKEN',
            'OSDU_SHARED_ACCESS_TOKEN',
            'OSDU_TOKEN_SCOPE',
            'OSDU_TOKEN_DEFAULT_EXPIRES_SECONDS',
            'OSDU_USERNAME',
            'OSDU_PASSWORD',
            'OSDU_EXTERNAL_ADMIN_USERNAME',
            'OSDU_EXTERNAL_ADMIN_PASSWORD',
        }

        int_fields = {
            'OSDU_TIMEOUT_SECONDS',
            'OSDU_GROUP_SCAN_LIMIT',
            'OSDU_MAX_PAGE_SIZE',
            'OSDU_TOKEN_DEFAULT_EXPIRES_SECONDS',
        }

        for key, value in values.items():
            if key not in allowed:
                continue
            if value is None:
                continue
            if isinstance(value, str):
                value = value.strip()
                if value == '' and key not in {
                    'OSDU_BASE_HOST',
                    'OSDU_TOKEN_HOST',
                    'OSDU_AUTH_BASE_URL',
                    'OSDU_AUTH_REALM',
                    'OSDU_REFRESH_TOKEN',
                    'OSDU_SHARED_ACCESS_TOKEN',
                    'OSDU_USERNAME',
                    'OSDU_PASSWORD',
                    'OSDU_EXTERNAL_ADMIN_USERNAME',
                    'OSDU_EXTERNAL_ADMIN_PASSWORD',
                    'OSDU_CLIENT_SECRET',
                }:
                    continue
            if key in int_fields:
                value = int(value) if str(value).strip() else getattr(self, key)
            if key == 'OSDU_BASE_URL' and isinstance(value, str):
                value = value.rstrip('/')
            if key == 'OSDU_TOKEN_GRANT_TYPE' and isinstance(value, str):
                value = value.lower()
            setattr(self, key, value)
        self._derive_keycloak_admin_config()

    def auth_form_defaults(self):
        """Return values safe to prefill in the Environment & Auth screen."""
        return {
            'OSDU_BASE_URL': self.OSDU_BASE_URL,
            'OSDU_BASE_HOST': self.OSDU_BASE_HOST or '',
            'OSDU_PARTITION_ID': self.OSDU_PARTITION_ID,
            'OSDU_VERIFY_SSL': self.OSDU_VERIFY_SSL,
            'OSDU_TOKEN_ENDPOINT': self.OSDU_TOKEN_ENDPOINT or '',
            'OSDU_TOKEN_HOST': self.OSDU_TOKEN_HOST or '',
            'OSDU_AUTH_BASE_URL': self.OSDU_AUTH_BASE_URL or '',
            'OSDU_AUTH_REALM': self.OSDU_AUTH_REALM or '',
            'OSDU_TOKEN_GRANT_TYPE': self.OSDU_TOKEN_GRANT_TYPE,
            'OSDU_CLIENT_ID': self.OSDU_CLIENT_ID or '',
            'OSDU_CLIENT_SECRET': '',
            'OSDU_REFRESH_TOKEN': '',
            'OSDU_TOKEN_SCOPE': self.OSDU_TOKEN_SCOPE,
            'OSDU_USERNAME': self.OSDU_USERNAME or '',
            'OSDU_PASSWORD': '',
        }

    def to_dict(self):
        """Convert config to dictionary for TokenManager"""
        return {
            'OSDU_BASE_URL': self.OSDU_BASE_URL,
            'OSDU_BASE_HOST': self.OSDU_BASE_HOST,
            'OSDU_PARTITION_ID': self.OSDU_PARTITION_ID,
            'OSDU_TOKEN_ENDPOINT': self.OSDU_TOKEN_ENDPOINT,
            'OSDU_TOKEN_HOST': self.OSDU_TOKEN_HOST,
            'OSDU_TOKEN_GRANT_TYPE': self.OSDU_TOKEN_GRANT_TYPE,
            'OSDU_CLIENT_ID': self.OSDU_CLIENT_ID,
            'OSDU_CLIENT_SECRET': self.OSDU_CLIENT_SECRET,
            'OSDU_REFRESH_TOKEN': self.OSDU_REFRESH_TOKEN,
            'OSDU_SHARED_ACCESS_TOKEN': self.OSDU_SHARED_ACCESS_TOKEN,
            'OSDU_USERNAME': self.OSDU_USERNAME,
            'OSDU_PASSWORD': self.OSDU_PASSWORD,
            'OSDU_EXTERNAL_ADMIN_USERNAME': self.OSDU_EXTERNAL_ADMIN_USERNAME,
            'OSDU_EXTERNAL_ADMIN_PASSWORD': self.OSDU_EXTERNAL_ADMIN_PASSWORD,
            'OSDU_TOKEN_SCOPE': self.OSDU_TOKEN_SCOPE,
            'OSDU_VERIFY_SSL': self.OSDU_VERIFY_SSL,
            'OSDU_TOKEN_DEFAULT_EXPIRES_SECONDS': self.OSDU_TOKEN_DEFAULT_EXPIRES_SECONDS
        }

    def validate(self):
        """Validate required configuration"""
        required_fields = ['OSDU_BASE_URL', 'OSDU_PARTITION_ID', 'OSDU_TOKEN_ENDPOINT', 'OSDU_CLIENT_ID']

        if self.OSDU_TOKEN_GRANT_TYPE == 'client_credentials':
            required_fields.append('OSDU_CLIENT_SECRET')
        elif self.OSDU_TOKEN_GRANT_TYPE == 'password':
            required_fields.extend(['OSDU_USERNAME', 'OSDU_PASSWORD'])
        else:
            raise ValueError(
                "OSDU_TOKEN_GRANT_TYPE must be 'client_credentials' or 'password'"
            )
        
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

    def public_summary(self):
        """Return a UI-safe config summary without secrets."""
        identity = self.OSDU_USERNAME if self.OSDU_TOKEN_GRANT_TYPE == 'password' else self.OSDU_CLIENT_ID
        return {
            'base_url': self.OSDU_BASE_URL,
            'partition_id': self.OSDU_PARTITION_ID,
            'token_endpoint': self.OSDU_TOKEN_ENDPOINT,
            'token_grant_type': self.OSDU_TOKEN_GRANT_TYPE,
            'auth_mode_label': 'user_login' if self.OSDU_TOKEN_GRANT_TYPE == 'password' else self.OSDU_TOKEN_GRANT_TYPE,
            'identity': identity,
            'client_id': self.OSDU_CLIENT_ID,
            'client_secret': self._mask(self.OSDU_CLIENT_SECRET),
            'username': self.OSDU_USERNAME,
            'verify_ssl': self.as_bool(self.OSDU_VERIFY_SSL),
            'auth_base_url': self.OSDU_AUTH_BASE_URL,
            'auth_realm': self.OSDU_AUTH_REALM,
            'entitlements_path': self.OSDU_ENTITLEMENTS_BASE_PATH,
            'legal_path': self.OSDU_LEGAL_BASE_PATH,
            'storage_path': self.OSDU_STORAGE_BASE_PATH,
            'timeout_seconds': self.OSDU_TIMEOUT_SECONDS
        }


# Global config instance
config = Config()
