"""Token Manager for OSDU API - Simplified for Web App"""
import logging
import time
import requests
import json
import os
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class TokenManager:
    def __init__(self, config: Dict):
        self.token_endpoint = config.get('OSDU_TOKEN_ENDPOINT')
        self.client_id = config.get('OSDU_CLIENT_ID')
        self.client_secret = config.get('OSDU_CLIENT_SECRET')
        self.refresh_token = config.get('OSDU_REFRESH_TOKEN', '')
        self.verify_ssl = config.get('OSDU_VERIFY_SSL', 'False') == 'True'
        
        # Cache token in memory
        self._cached_token = None
        self._token_expiry = 0
        
        # Cache file for persistent storage
        self._cache_file = os.path.join(os.path.dirname(__file__), '.token_cache')

    def get_token(self) -> str:
        """Get valid access token, refresh if needed"""
        # Check memory cache first
        if self._cached_token and time.time() < self._token_expiry - 300:  # 5min buffer
            return self._cached_token
            
        # Check file cache
        if self._load_from_cache():
            if time.time() < self._token_expiry - 300:
                return self._cached_token
        
        # Request new token
        return self._request_new_token()

    def _load_from_cache(self) -> bool:
        """Load token from cache file"""
        try:
            if os.path.exists(self._cache_file):
                with open(self._cache_file, 'r') as f:
                    cache_data = json.load(f)
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
                'cached_at': time.time()
            }
            with open(self._cache_file, 'w') as f:
                json.dump(cache_data, f)
        except Exception as e:
            logger.warning(f"Failed to save token cache: {e}")

    def _request_new_token(self) -> str:
        """Request new access token"""
        if not all([self.token_endpoint, self.client_id, self.client_secret]):
            raise Exception("Missing required token configuration")

        # Try refresh token first if available
        if self.refresh_token:
            try:
                return self._request_with_refresh_token()
            except Exception as e:
                logger.warning(f"Refresh token failed, trying client credentials: {e}")

        # Fall back to client credentials
        return self._request_with_client_credentials()

    def _request_with_refresh_token(self) -> str:
        """Request token using refresh token"""
        payload = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.refresh_token
        }

        response = requests.post(
            self.token_endpoint,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify=self.verify_ssl
        )

        if response.status_code != 200:
            raise Exception(f"Refresh token request failed: {response.text}")

        token_data = response.json()
        
        # Update refresh token if provided
        if "refresh_token" in token_data:
            self.refresh_token = token_data["refresh_token"]

        return self._process_token_response(token_data)

    def _request_with_client_credentials(self) -> str:
        """Request token using client credentials"""
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

        response = requests.post(
            self.token_endpoint,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify=self.verify_ssl
        )

        if response.status_code != 200:
            raise Exception(f"Client credentials failed: {response.text}")

        token_data = response.json()
        return self._process_token_response(token_data)

    def _process_token_response(self, token_data: Dict) -> str:
        """Process token response and cache"""
        access_token = token_data.get("access_token")
        if not access_token:
            raise Exception("No access token in response")

        expires_in = token_data.get("expires_in", 3600)
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
        return (self._cached_token and 
                time.time() < self._token_expiry - 300)