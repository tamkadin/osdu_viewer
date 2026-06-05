"""Token Manager for OSDU API - Simplified for Web App"""
import logging
import time
import requests
import json
import os
import threading
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class TokenManager:
    def __init__(self, config: Dict):
        self.token_endpoint = config.get('OSDU_TOKEN_ENDPOINT')
        self.token_host = config.get('OSDU_TOKEN_HOST')
        self.grant_type = str(config.get('OSDU_TOKEN_GRANT_TYPE', 'client_credentials')).strip().lower()
        self.client_id = config.get('OSDU_CLIENT_ID')
        self.client_secret = config.get('OSDU_CLIENT_SECRET')
        self.refresh_token = config.get('OSDU_REFRESH_TOKEN', '')
        self.username = config.get('OSDU_USERNAME', '')
        self.password = config.get('OSDU_PASSWORD', '')
        self.scope = config.get('OSDU_TOKEN_SCOPE', 'openid profile email')
        self.default_expires_seconds = int(config.get('OSDU_TOKEN_DEFAULT_EXPIRES_SECONDS', 3600))
        self.shared_access_token = config.get('OSDU_SHARED_ACCESS_TOKEN', '')
        self.verify_ssl = self._as_bool(config.get('OSDU_VERIFY_SSL', 'False'))
        self._cache_identity = {
            'token_endpoint': self.token_endpoint,
            'grant_type': self.grant_type,
            'client_id': self.client_id,
            'username': self.username if self.grant_type == 'password' else ''
        }
        
        self._cached_token = None
        self._token_expiry = 0
        self._cache_file = os.path.join(os.path.dirname(__file__), '.token_cache')
        self._lock = threading.Lock()
        self._refresh_thread = None
        self._stop_refresh = False

    def get_token(self) -> str:
        """Get valid access token, refresh if needed"""
        with self._lock:
            shared_token = self._read_shared_access_token()
            if shared_token:
                return shared_token

            if self._cached_token and time.time() < self._token_expiry - 300:
                return self._cached_token
                
            if self._load_from_cache():
                if time.time() < self._token_expiry - 300:
                    return self._cached_token
            
            return self._request_new_token()

    def _load_from_cache(self) -> bool:
        """Load token from cache file"""
        try:
            if os.path.exists(self._cache_file):
                with open(self._cache_file, 'r') as f:
                    cache_data = json.load(f)
                    if cache_data.get('source') != self._cache_identity:
                        return False
                    self._cached_token = cache_data.get('access_token')
                    self._token_expiry = cache_data.get('expiry', 0)
                    return True
        except Exception as e:
            logger.warning(f"Failed to load token cache: {e}")
        return False

    def _save_to_cache(self, token: str, expiry: float):
        """Save token to cache file"""
        try:
            cache_data = {
                'access_token': token,
                'expiry': expiry,
                'cached_at': time.time(),
                'source': self._cache_identity
            }
            with open(self._cache_file, 'w') as f:
                json.dump(cache_data, f)
        except Exception as e:
            logger.warning(f"Failed to save token cache: {e}")

    def _request_new_token(self) -> str:
        """Request new access token"""
        if not self.token_endpoint or not self.client_id:
            raise Exception("Missing required token configuration")

        # Try refresh token first if available
        if self.refresh_token:
            try:
                return self._request_with_refresh_token()
            except Exception as e:
                logger.warning(f"Refresh token failed, trying client credentials: {e}")

        if self.grant_type == 'password':
            return self._request_with_password_credentials()
        if self.grant_type == 'client_credentials':
            return self._request_with_client_credentials()
        raise Exception("Unsupported OSDU_TOKEN_GRANT_TYPE. Use client_credentials or password")

    def _request_with_refresh_token(self) -> str:
        """Request token using refresh token"""
        logger.info(f"Requesting token with refresh_token from: {self.token_endpoint}")
        
        payload = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": self.refresh_token
        }
        if self.client_secret:
            payload["client_secret"] = self.client_secret

        # Prepare headers with Host bypass for DNS resolution
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.token_host:
            headers["Host"] = self.token_host
            logger.info(f"Using Host header: {self.token_host} for IP endpoint")

        response = requests.post(
            self.token_endpoint,
            data=payload,
            headers=headers,
            verify=self.verify_ssl
        )

        if response.status_code != 200:
            logger.error(f"Refresh token request failed - Status: {response.status_code}")
            logger.error(f"Response: {response.text}")
            raise Exception(f"Refresh token request failed: {response.text}")

        token_data = response.json()
        
        # Update refresh token if provided
        if "refresh_token" in token_data:
            self.refresh_token = token_data["refresh_token"]

        return self._process_token_response(token_data)

    def _request_with_client_credentials(self) -> str:
        """Request token using client credentials"""
        if not self.client_secret:
            raise Exception("OSDU_CLIENT_SECRET is required for client_credentials grant")

        logger.info(f"Requesting token with client_credentials from: {self.token_endpoint}")
        
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

        # Prepare headers with Host bypass for DNS resolution
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.token_host:
            headers["Host"] = self.token_host
            logger.info(f"Using Host header: {self.token_host} for IP endpoint")

        response = requests.post(
            self.token_endpoint,
            data=payload,
            headers=headers,
            verify=self.verify_ssl
        )

        if response.status_code != 200:
            logger.error(f"Client credentials request failed - Status: {response.status_code}")
            logger.error(f"Response: {response.text}")
            raise Exception(f"Client credentials failed: {response.text}")

        token_data = response.json()
        return self._process_token_response(token_data)

    def _request_with_password_credentials(self) -> str:
        """Request token using username/email and password."""
        if not self.username or not self.password:
            raise Exception("OSDU_USERNAME and OSDU_PASSWORD are required for password grant")

        logger.info(f"Requesting token with password grant from: {self.token_endpoint}")

        payload = {
            "grant_type": "password",
            "client_id": self.client_id,
            "username": self.username,
            "password": self.password,
            "scope": self.scope
        }
        if self.client_secret:
            payload["client_secret"] = self.client_secret

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.token_host:
            headers["Host"] = self.token_host
            logger.info(f"Using Host header: {self.token_host} for IP endpoint")

        response = requests.post(
            self.token_endpoint,
            data=payload,
            headers=headers,
            verify=self.verify_ssl
        )

        if response.status_code != 200:
            logger.error(f"Password grant request failed - Status: {response.status_code}")
            logger.error(f"Response: {response.text}")
            raise Exception(f"Password grant failed: {response.text}")

        token_data = response.json()
        if "refresh_token" in token_data:
            self.refresh_token = token_data["refresh_token"]
        return self._process_token_response(token_data)

    def _process_token_response(self, token_data: Dict) -> str:
        """Process token response and cache"""
        access_token = token_data.get("access_token")
        if not access_token:
            raise Exception("No access token in response")

        expires_in = token_data.get("expires_in", self.default_expires_seconds)
        self._token_expiry = time.time() + int(expires_in)
        self._cached_token = access_token

        # Save to cache
        self._save_to_cache(access_token, self._token_expiry)

        logger.info("Successfully obtained new access token")
        return access_token

    def clear_cache(self):
        """Clear token cache"""
        self._cached_token = None
        self._token_expiry = 0
        try:
            if os.path.exists(self._cache_file):
                os.remove(self._cache_file)
        except Exception as e:
            logger.warning(f"Failed to remove cache file: {e}")

    def is_token_valid(self) -> bool:
        """Check if current token is valid"""
        if self._read_shared_access_token():
            return True
        return (self._cached_token and time.time() < self._token_expiry - 300)

    def _read_shared_access_token(self) -> Optional[str]:
        """Read a shared token from env. Supports raw JWT or JSON with expiry."""
        if not self.shared_access_token:
            return None
        try:
            payload = json.loads(self.shared_access_token)
            token = payload.get('access_token')
            expiry = float(payload.get('expiry') or 0)
            if token and time.time() < expiry - 300:
                return token
            return None
        except (json.JSONDecodeError, TypeError, ValueError):
            return self.shared_access_token

    @staticmethod
    def _as_bool(value) -> bool:
        return str(value).strip().lower() in ('1', 'true', 'yes', 'y', 'on')

    def start_background_refresh(self, interval: int = 3000):
        """Start background thread to refresh token periodically"""
        if self._refresh_thread and self._refresh_thread.is_alive():
            return
        
        self._stop_refresh = False
        self._refresh_thread = threading.Thread(
            target=self._background_refresh_loop,
            args=(interval,),
            daemon=True
        )
        self._refresh_thread.start()
        logger.info(f"Started background token refresh (interval: {interval}s)")

    def _background_refresh_loop(self, interval: int):
        """Background loop to refresh token"""
        while not self._stop_refresh:
            try:
                with self._lock:
                    if not self._cached_token or time.time() >= self._token_expiry - 600:
                        logger.info("Background refresh: requesting new token")
                        self._request_new_token()
            except Exception as e:
                logger.error(f"Background refresh failed: {e}")
            
            for _ in range(interval):
                if self._stop_refresh:
                    break
                time.sleep(1)

    def stop_background_refresh(self):
        """Stop background refresh thread"""
        self._stop_refresh = True
        if self._refresh_thread:
            self._refresh_thread.join(timeout=2)

    def prewarm(self):
        """Pre-fetch token in background thread"""
        def _fetch():
            try:
                logger.info("Pre-warming token...")
                self.get_token()
                logger.info("Token pre-warmed successfully")
            except Exception as e:
                logger.error(f"Token pre-warm failed: {e}")
        
        thread = threading.Thread(target=_fetch, daemon=True)
        thread.start()
