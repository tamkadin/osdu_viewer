#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSDU Record Viewer - Flask Application
Xem các record OSDU theo domain và entities với TokenManager
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
import base64
from concurrent.futures import ThreadPoolExecutor
import requests
import json
import logging
import time
from typing import Dict, List, Optional
from urllib.parse import unquote

from config import config
from token_manager import TokenManager
from domains import DOMAINS, get_domain_info, get_entity_info
from access_control import (
    ACCESS_ADMIN_GROUPS,
    DANGEROUS_GROUPS,
    AccessControlService,
    is_valid_group_email,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

token_manager = None
admin_permission_cache = {}
PUBLIC_ENDPOINTS = {
    'connect_page',
    'auth_page',
    'api_auth_status',
    'api_auth_token',
    'api_auth_connect',
    'api_auth_clear',
    'api_config',
    'api_health',
    'static',
}


def is_public_request() -> bool:
    """Return True for routes that must stay reachable before auth."""
    if request.path.startswith('/static/'):
        return True
    if request.endpoint in PUBLIC_ENDPOINTS:
        return True
    if request.path in {'/auth', '/connect', '/api/config', '/api/health', '/api/auth/status', '/api/auth/token', '/api/auth/connect', '/api/auth/clear'}:
        return True
    if request.path.startswith('/api/auth/'):
        return True
    return False


def clear_auth_state():
    """Drop the active token cache and reset request-time services."""
    global token_manager, osdu_service, access_control_service, admin_permission_cache
    if token_manager:
        token_manager.clear_cache()
        token_manager.stop_background_refresh()
    token_manager = None
    admin_permission_cache = {}
    osdu_service = OSDUService()
    access_control_service = AccessControlService(token_manager)


def auth_required_response():
    """Return the correct unauthenticated response for API or page requests."""
    if request.path.startswith('/api/'):
        return jsonify({"error": "Authentication required"}), 401
    return redirect(url_for('connect_page', next=request.full_path.rstrip('?')))


def rebuild_token_manager(prewarm: bool = True):
    """Rebuild TokenManager from the current in-memory config."""
    global token_manager, osdu_service, access_control_service
    if token_manager:
        token_manager.stop_background_refresh()

    config.validate()
    token_manager = TokenManager(config.to_dict())
    if prewarm:
        token_manager.prewarm()
        token_manager.start_background_refresh(interval=3000)

    if 'osdu_service' in globals():
        osdu_service = OSDUService()
    if 'access_control_service' in globals():
        access_control_service = AccessControlService(token_manager)

    logger.info("TokenManager rebuilt with grant type: %s", config.OSDU_TOKEN_GRANT_TYPE)
    return token_manager


def osdu_auth_ready(refresh: bool = False) -> bool:
    """Check whether OSDU token is available for business tabs."""
    if not token_manager:
        return False
    if token_manager.is_token_valid():
        return True
    if refresh:
        try:
            token_manager.get_token()
            return token_manager.is_token_valid()
        except Exception as exc:
            logger.warning("OSDU auth check failed: %s", exc)
    return False


def current_token_status() -> str:
    """Return a UI status without triggering network refresh."""
    if not token_manager:
        return "Missing"
    if token_manager.is_token_valid():
        return "Ready"
    if getattr(token_manager, '_cached_token', None):
        return "Expired"
    return "Missing"


def auth_status_payload() -> Dict:
    """Return auth state for UI without exposing secrets."""
    summary = config.public_summary()
    return {
        "ready": osdu_auth_ready(refresh=False),
        "token_status": current_token_status(),
        "grant_type": summary.get("token_grant_type"),
        "auth_mode": summary.get("auth_mode_label"),
        "identity": summary.get("identity"),
        "partition": summary.get("partition_id"),
        "base_url": summary.get("base_url"),
    }


def mask_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return headers safe for logs/debug output."""
    masked = {}
    for key, value in dict(headers or {}).items():
        if key.lower() == "authorization":
            masked[key] = "Bearer ***MASKED***" if value else value
        else:
            masked[key] = value
    return masked


def _decode_jwt_claims(token: str) -> Dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")).decode("utf-8"))
    except Exception:
        return {}


def current_caller_identity_candidates() -> List[str]:
    """Resolve likely Entitlements member identifiers for the current token."""
    candidates = []
    if config.OSDU_TOKEN_GRANT_TYPE == "password" and config.OSDU_USERNAME:
        candidates.append(config.OSDU_USERNAME)
    try:
        token = token_manager.get_token() if token_manager else ""
        claims = _decode_jwt_claims(token) if token else {}
        for key in ("email", "preferred_username", "client_id", "azp", "appid", "sub"):
            value = claims.get(key)
            if isinstance(value, str) and value.strip():
                candidates.append(value)
    except Exception as exc:
        logger.warning("Could not resolve current caller identity from token: %s", exc)
    if config.OSDU_CLIENT_ID:
        candidates.append(config.OSDU_CLIENT_ID)

    normalized = []
    seen = set()
    for item in candidates:
        value = str(item or "").strip().lower()
        if value and value not in seen:
            normalized.append(value)
            seen.add(value)
    return normalized


def current_user_has_access_admin_permission(partition_id: str) -> bool:
    """Return True when the current caller belongs to an allowed admin group."""
    identities = tuple(current_caller_identity_candidates())
    cache_key = f"{partition_id}:{'|'.join(identities)}"
    cached = admin_permission_cache.get(cache_key)
    now = time.time()
    if cached and now - cached.get("created_at", 0) < cached.get("ttl", 0):
        return bool(cached.get("allowed"))

    admin_groups = {group.lower() for group in ACCESS_ADMIN_GROUPS}
    allowed = False
    for identity in identities:
        try:
            payload = access_control_service.inspect_user_groups(identity, partition_id)
            memberships = {group.get("name", "").lower() for group in payload.get("groups", [])}
            if memberships.intersection(admin_groups):
                allowed = True
                break
        except Exception as exc:
            logger.warning("Could not inspect admin permission for caller %s: %s", identity, exc)
    admin_permission_cache[cache_key] = {
        "created_at": now,
        "ttl": 300 if allowed else 60,
        "allowed": allowed,
    }
    return allowed


def is_current_caller(target_email: str) -> bool:
    normalized_target = (target_email or "").strip().lower()
    return bool(normalized_target and normalized_target in current_caller_identity_candidates())


# Initialize TokenManager from environment when enough config is present.
try:
    if config.is_configured():
        rebuild_token_manager(prewarm=False)
    else:
        logger.info("OSDU TokenManager is not initialized yet; open Environment & Auth to configure it.")
except Exception as e:
    logger.error(f"Failed to initialize TokenManager: {e}")
    token_manager = None


class OSDUService:
    """OSDU API Service with token management"""
    
    def __init__(self):
        self.base_url = config.OSDU_BASE_URL
        self.base_host = config.OSDU_BASE_HOST  # Host header bypass
        self.partition_id = config.OSDU_PARTITION_ID

    def get_headers(self, accept_json: bool = True) -> Dict[str, str]:
        """Get headers with access token and Host bypass"""
        if not token_manager:
            raise Exception("TokenManager not initialized")
        
        try:
            token = token_manager.get_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "data-partition-id": self.partition_id,
                "Content-Type": "application/json"
            }
            
            if accept_json:
                headers["Accept"] = "application/json"
            
            if self.base_host:
                headers["Host"] = self.base_host
                logger.debug(f"Using Host header: {self.base_host} for OSDU API")
                
            return headers
            
        except Exception as e:
            logger.error(f"Failed to get token: {e}")
            raise Exception(f"Authentication failed: {e}")

    def search_records(self, kind: str, limit: int = 50, offset: int = 0, 
                      returned_fields: Optional[List[str]] = None, try_alternatives: bool = True) -> Dict:
        """Search records by kind with fallback strategies"""
        
        # Strategy 1: Try primary kind
        result = self._try_search_with_kind(kind, limit, offset, returned_fields)
        
        if not result.get('error'):
            return result
            
        if not try_alternatives:
            return result
            
        logger.warning(f"Primary search failed, trying alternatives...")
        
        # Strategy 2: Try ddms-wellbore domain if using wks
        if ':wks:' in kind:
            alt_kind = kind.replace(':wks:', ':ddms-wellbore:')
            logger.info(f"Trying ddms-wellbore: {alt_kind}")
            alt_result = self._try_search_with_kind(alt_kind, limit, offset, returned_fields)
            if not alt_result.get('error'):
                return alt_result
        
        # Strategy 3: Try wildcard search with entity name
        entity_name = kind.split('--')[-1].split(':')[0] if '--' in kind else None
        if entity_name:
            wild_kind = f"*{entity_name}*"
            logger.info(f"Trying wildcard search: {wild_kind}")
            wildcard_result = self._try_search_with_query(wild_kind, limit, offset)
            if not wildcard_result.get('error'):
                return wildcard_result
                
        # Strategy 4: Try general query search
        if entity_name:
            logger.info(f"Trying general query search for: {entity_name}")
            query_result = self._try_search_with_query(f"kind:*{entity_name}*", limit, offset)
            if not query_result.get('error'):
                return query_result
        
        # All strategies failed, return original error
        return result

    def _try_search_with_kind(self, kind: str, limit: int = 50, offset: int = 0, 
                             returned_fields: Optional[List[str]] = None) -> Dict:
        """Try search with a specific kind"""
        url = f"{self.base_url}/api/search/v2/query"
        
        payload = {
            "kind": kind,
            "limit": min(limit, 1000),  # Max 1000 để tránh quá tải
            "offset": offset
        }
        
        if returned_fields:
            if isinstance(returned_fields, str):
                # Handle predefined field sets
                if returned_fields == "basic":
                    payload["returnedFields"] = ["id", "kind", "data"]
                elif returned_fields == "all":
                    pass  # Don't set returnedFields to get all
                else:
                    # Single field
                    payload["returnedFields"] = ["id", "kind", f"data.{returned_fields}"]
            else:
                payload["returnedFields"] = returned_fields
        
        # Search records
        try:
            # Log request details for debugging
            logger.info(f"Making search request to: {url}")
            logger.info(f"Kind: {kind}")
            logger.info(f"Payload: {json.dumps(payload, indent=2)}")
            
            response = requests.post(url, headers=self.get_headers(), json=payload)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Search completed: {len(result.get('results', []))} records found")
            return result
            
        except requests.exceptions.HTTPError as e:
            if response.status_code == 401:
                # Token might be expired, try to refresh
                logger.warning("Token expired, attempting refresh")
                token_manager.clear_cache()
                try:
                    response = requests.post(url, headers=self.get_headers(), json=payload)
                    response.raise_for_status()
                    return response.json()
                except:
                    pass
            
            # Log detailed error information
            error_detail = ""
            try:
                error_detail = response.text[:500]  # First 500 chars of response
            except:
                error_detail = "Could not read response"
            
            logger.error(f"HTTP error searching records: {e}")
            logger.error(f"Status: {response.status_code}")
            logger.error(f"URL: {url}")
            logger.error(f"Payload: {json.dumps(payload, indent=2)}")
            logger.error(f"Headers: {mask_headers(self.get_headers())}")
            logger.error(f"Response: {error_detail}")
            
            return {"error": f"API request failed: {response.status_code} - {error_detail[:100]}", "results": []}
            
        except Exception as e:
            logger.error(f"Error searching records: {e}")
            return {"error": str(e), "results": []}

    def _try_search_with_query(self, query: str, limit: int = 50, offset: int = 0) -> Dict:
        """Try search with query instead of kind"""
        url = f"{self.base_url}/api/search/v2/query"
        
        payload = {
            "query": query,
            "limit": min(limit, 1000),
            "offset": offset,
            "returnedFields": ["id", "kind", "data"]
        }
        
        try:
            logger.info(f"Making query search request: {query}")
            logger.info(f"Payload: {json.dumps(payload, indent=2)}")
            
            response = requests.post(url, headers=self.get_headers(), json=payload)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Query search completed: {len(result.get('results', []))} records found")
            return result
            
        except requests.exceptions.HTTPError as e:
            error_detail = ""
            try:
                error_detail = response.text[:200]
            except:
                error_detail = "Could not read response"
            
            logger.error(f"HTTP error in query search: {e}")
            logger.error(f"Query: {query}")
            logger.error(f"Response: {error_detail}")
            
            return {"error": f"Query search failed: {response.status_code} - {error_detail[:100]}", "results": []}
            
        except Exception as e:
            logger.error(f"Error in query search: {e}")
            return {"error": str(e), "results": []}

    def get_record_details(self, record_ids: List[str]) -> Dict:
        """Get record details by IDs with multiple endpoint strategies"""
        
        if not record_ids:
            return {"error": "No record IDs provided", "records": []}
            
        record_id = record_ids[0]  # Focus on single record first
        
        # Strategy 1: Try individual record endpoint
        result = self._try_get_record_by_id(record_id)
        if not result.get('error'):
            return {"records": [result]}
            
        # Strategy 2: Try batch endpoint with different format
        result = self._try_batch_records_v1(record_ids)
        if not result.get('error'):
            return result
            
        # Strategy 3: Try batch endpoint v2 with different method
        result = self._try_batch_records_v2(record_ids)
        if not result.get('error'):
            return result
            
        # Strategy 4: Use search to get full record instead
        result = self._try_get_record_via_search(record_id)
        if not result.get('error'):
            return {"records": [result]}
            
        return {"error": "Could not retrieve record details", "records": []}

    def _try_get_record_by_id(self, record_id: str) -> Dict:
        """Try GET /api/storage/v2/records/{id}"""
        url = f"{self.base_url}/api/storage/v2/records/{record_id}"
        
        try:
            logger.info(f"Trying individual record endpoint: {url}")
            response = requests.get(url, headers=self.get_headers())
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Successfully retrieved record via individual endpoint")
            return result
            
        except Exception as e:
            logger.warning(f"Individual record endpoint failed: {e}")
            return {"error": str(e)}

    def _try_batch_records_v1(self, record_ids: List[str]) -> Dict:
        """Try POST /api/storage/v2/records with different payload"""
        url = f"{self.base_url}/api/storage/v2/records"
        
        payload = {
            "recordIds": record_ids
        }
        
        try:
            logger.info(f"Trying batch records v1: {url}")
            response = requests.post(url, headers=self.get_headers(), json=payload)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Successfully retrieved records via batch v1")
            return result
            
        except Exception as e:
            logger.warning(f"Batch records v1 failed: {e}")
            return {"error": str(e)}
    
    def _try_batch_records_v2(self, record_ids: List[str]) -> Dict:
        """Try GET /api/storage/v2/query/records"""
        url = f"{self.base_url}/api/storage/v2/query/records"
        
        payload = {
            "records": record_ids
        }
        
        try:
            logger.info(f"Trying batch records v2: {url}")
            response = requests.post(url, headers=self.get_headers(), json=payload)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Successfully retrieved records via batch v2")
            return result
            
        except Exception as e:
            logger.warning(f"Batch records v2 failed: {e}")
            return {"error": str(e)}
    
    def _try_get_record_via_search(self, record_id: str) -> Dict:
        """Try to get record details via search API"""
        url = f"{self.base_url}/api/search/v2/query"
        
        # Search for specific record ID
        payload = {
            "query": f"id:{record_id}",
            "limit": 1,
            "returnedFields": ["*"]  # Get all fields
        }
        
        try:
            logger.info(f"Trying to get record via search: {record_id}")
            response = requests.post(url, headers=self.get_headers(), json=payload)
            response.raise_for_status()
            
            result = response.json()
            records = result.get('results', [])
            
            if records:
                logger.info(f"Successfully retrieved record via search")
                return records[0]
            else:
                return {"error": "Record not found in search results"}
            
        except Exception as e:
            logger.warning(f"Search-based record retrieval failed: {e}")
            return {"error": str(e)}

    def delete_record(self, record_id: str) -> Dict:
        """Soft delete a record using Storage API"""
        url = f"{self.base_url}/api/storage/v2/records/{record_id}:delete"
        
        try:
            logger.info(f"Deleting record: {record_id}")
            response = requests.post(url, headers=self.get_headers(), timeout=600)
            response.raise_for_status()
            
            logger.info(f"Successfully deleted record: {record_id}")
            return {"success": True, "message": "Record deleted successfully"}
            
        except requests.exceptions.HTTPError as e:
            error_detail = ""
            try:
                error_detail = response.text[:500]
            except:
                error_detail = "Could not read response"
            
            logger.error(f"HTTP error deleting record: {e}")
            logger.error(f"Status: {response.status_code}")
            logger.error(f"Response: {error_detail}")
            
            return {"success": False, "error": f"Delete failed: {response.status_code} - {error_detail[:100]}"}
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout deleting record: {record_id}")
            return {"success": False, "error": "Request timeout after 10 minutes"}
            
        except Exception as e:
            logger.error(f"Error deleting record: {e}")
            return {"success": False, "error": str(e)}

    def bulk_delete_records(self, record_ids: List[str]) -> Dict:
        """Bulk soft delete multiple records by looping individual delete API"""
        logger.info(f"Bulk deleting {len(record_ids)} records (individual delete loop)")
        
        success_count = 0
        failed_count = 0
        errors = []
        
        for record_id in record_ids:
            url = f"{self.base_url}/api/storage/v2/records/{record_id}:delete"
            
            try:
                logger.info(f"Deleting record {success_count + failed_count + 1}/{len(record_ids)}: {record_id}")
                response = requests.post(url, headers=self.get_headers(), timeout=600)
                response.raise_for_status()
                success_count += 1
                logger.info(f"Successfully deleted: {record_id}")
                
            except requests.exceptions.HTTPError as e:
                failed_count += 1
                error_detail = ""
                try:
                    error_detail = response.text[:200]
                except:
                    error_detail = str(e)
                
                error_msg = f"{record_id}: {response.status_code} - {error_detail[:100]}"
                errors.append(error_msg)
                logger.error(f"Failed to delete {record_id}: {error_msg}")
                
            except requests.exceptions.Timeout:
                failed_count += 1
                error_msg = f"{record_id}: Timeout after 10 minutes"
                errors.append(error_msg)
                logger.error(f"Timeout deleting {record_id}")
                
            except Exception as e:
                failed_count += 1
                error_msg = f"{record_id}: {str(e)}"
                errors.append(error_msg)
                logger.error(f"Error deleting {record_id}: {e}")
        
        logger.info(f"Bulk delete completed: {success_count} succeeded, {failed_count} failed")
        
        if failed_count == 0:
            return {
                "success": True,
                "message": f"Successfully deleted all {success_count} records",
                "count": success_count,
                "failed_count": 0
            }
        elif success_count > 0:
            return {
                "success": True,
                "message": f"Deleted {success_count}/{len(record_ids)} records. {failed_count} failed.",
                "count": success_count,
                "failed_count": failed_count,
                "errors": errors[:10]
            }
        else:
            return {
                "success": False,
                "error": f"Failed to delete all {failed_count} records",
                "errors": errors[:10]
            }


# Initialize OSDU Service
osdu_service = OSDUService()
access_control_service = AccessControlService(token_manager)


# Helper functions
def calculate_total_entities():
    """Calculate total number of entities across all domains"""
    return sum(len(domain['entities']) for domain in DOMAINS.values())


# Routes
@app.before_request
def require_auth_for_ui_routes():
    """Auth-first gate for HTML pages while keeping API contracts intact."""
    if is_public_request():
        return None
    if not osdu_auth_ready(refresh=False):
        clear_auth_state()
        return auth_required_response()
    return None


@app.route('/auth')
def auth_page():
    return redirect(url_for('connect_page'))


@app.route('/connect')
def connect_page():
    """Standalone auth-first connection screen."""
    if osdu_auth_ready(refresh=False) and request.args.get('switch') != '1':
        return redirect(url_for('home'))
    return render_template(
        'connect.html',
        defaults=config.auth_form_defaults(),
        auth_ready=osdu_auth_ready(refresh=False),
        token_status=current_token_status(),
        next_url=request.args.get('next') or url_for('home')
    )


@app.route('/')
def home():
    """Authenticated home dashboard."""
    return render_template('home.html', domains=DOMAINS)


@app.route('/home')
def home_alias():
    return redirect(url_for('home'))


@app.route('/catalog')
def catalog_page():
    """Data Catalog dashboard showing all domains."""
    total_entities = calculate_total_entities()
    return render_template('catalog.html',
                         domains=DOMAINS, 
                         total_entities=total_entities)


@app.route('/data-catalog')
def data_catalog_page():
    return redirect(url_for('catalog_page'))


@app.route('/domain/<domain_name>')
def domain_page(domain_name):
    """Domain page showing entities"""
    domain_name = unquote(domain_name)
    domain_info = get_domain_info(domain_name)
    
    if not domain_info:
        return f"Domain '{domain_name}' not found", 404
    
    return render_template('domain.html', 
                         domain_name=domain_name, 
                         domain_info=domain_info,
                         domains=DOMAINS)


@app.route('/records/<domain_name>')
def records_domain_redirect(domain_name):
    return redirect(url_for('domain_page', domain_name=domain_name))


@app.route('/records/<domain_name>/<entity_name>')
def records_page(domain_name, entity_name):
    """Records page showing list of records for an entity"""
    domain_name = unquote(domain_name)
    entity_name = unquote(entity_name)
    
    domain_info = get_domain_info(domain_name)
    if not domain_info:
        return f"Domain '{domain_name}' not found", 404
    
    entity_info = get_entity_info(domain_name, entity_name)
    if not entity_info:
        return f"Entity '{entity_name}' not found in domain '{domain_name}'", 404
    
    return render_template('records.html',
                         domain_name=domain_name,
                         domain_icon=domain_info.get('icon', '📁'),
                         entity_name=entity_name,
                         entity_kind=entity_info['kind'],
                         entity_description=entity_info.get('description', ''),
                         entity_fields=entity_info.get('fields', []),
                         domains=DOMAINS)


@app.route('/access-control')
def access_control_page():
    """OSDU access-control workspace."""
    return render_template(
        'access_control.html',
        partition_id=config.OSDU_PARTITION_ID,
        group_scan_limit=config.OSDU_GROUP_SCAN_LIMIT,
        initial_section=request.args.get('section') or 'dashboard',
        initial_record_id=request.args.get('record_id') or ''
    )


@app.route('/access-governance')
def access_governance_page():
    return redirect(url_for('access_control_page'))


@app.route('/governance')
def governance_page():
    return redirect(url_for('access_control_page'))


@app.route('/governance/groups')
def governance_groups_page():
    return redirect(url_for('access_control_page', section='groups'))


@app.route('/governance/legal-tags')
def governance_legal_tags_page():
    return redirect(url_for('access_control_page', section='legal'))


@app.route('/governance/access-checker')
def governance_access_checker_page():
    return redirect(url_for('access_control_page', section='checker'))


@app.route('/governance/acl-policies')
def governance_acl_policies_page():
    return redirect(url_for('access_control_page', section='policies'))


@app.route('/governance/audit-logs')
def governance_audit_logs_page():
    return redirect(url_for('access_control_page', section='audit'))


@app.route('/governance/partitions')
def governance_partitions_page():
    return redirect(url_for('access_control_page', section='partitions'))


@app.route('/governance/users')
def governance_users_page():
    return redirect(url_for('access_control_page', section='users'))


@app.route('/record/<path:record_id>')
def record_detail_page(record_id):
    """Record detail page"""
    record_id = unquote(record_id)
    return render_template('record_detail.html', record_id=record_id, domains=DOMAINS)


@app.route('/osdu-config')
def osdu_config_page():
    """Environment and authentication configuration page."""
    return render_template(
        'osdu_config.html',
        summary=config.public_summary(),
        defaults=config.auth_form_defaults(),
        auth_ready=osdu_auth_ready(refresh=False)
    )


@app.context_processor
def inject_auth_state():
    summary = config.public_summary()
    return {
        "auth_ready": osdu_auth_ready(refresh=False),
        "token_status": current_token_status(),
        "active_token_mode": config.OSDU_TOKEN_GRANT_TYPE,
        "active_auth_label": summary.get("auth_mode_label"),
        "auth_identity": summary.get("identity"),
        "active_partition": summary.get("partition_id"),
        "defaults": config.auth_form_defaults()
    }


# API Routes
@app.route('/api/records/<domain_name>/<entity_name>')
def api_records(domain_name, entity_name):
    """API endpoint to get records for an entity"""
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "OSDU access token is not configured or not valid"}), 401
    domain_name = unquote(domain_name)
    entity_name = unquote(entity_name)
    
    # Validate inputs
    domain_info = get_domain_info(domain_name)
    if not domain_info:
        return jsonify({"error": f"Domain '{domain_name}' not found"}), 404
    
    entity_info = get_entity_info(domain_name, entity_name)
    if not entity_info:
        return jsonify({"error": f"Entity '{entity_name}' not found"}), 404
    
    # Get parameters
    limit = min(int(request.args.get('limit', 50)), 1000)
    offset = int(request.args.get('offset', 0))
    fields = request.args.get('fields', '')
    
    # Determine returned fields
    returned_fields = None
    if fields:
        if fields == "basic":
            returned_fields = ["id", "kind", "data"]
        elif fields != "all":
            # Specific field or entity default fields
            if fields in entity_info.get('fields', []):
                returned_fields = ["id", "kind", f"data.{fields}"]
            else:
                returned_fields = ["id", "kind", "data"]
    else:
        # Default: return full data for better UX
        returned_fields = ["id", "kind", "data"]
    
    # Search records
    try:
        result = osdu_service.search_records(
            entity_info['kind'], 
            limit, 
            offset, 
            returned_fields
        )
        
        # Add some metadata
        if 'results' in result:
            for record in result['results']:
                record['_entity'] = entity_name
                record['_domain'] = domain_name
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in api_records: {e}")
        return jsonify({"error": str(e), "results": []}), 500


@app.route('/api/record/<path:record_id>')
def api_record_detail(record_id):
    """API endpoint to get record details"""
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "OSDU access token is not configured or not valid", "records": []}), 401
    record_id = unquote(record_id)
    
    try:
        result = osdu_service.get_record_details([record_id])
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in api_record_detail: {e}")
        return jsonify({"error": str(e), "records": []}), 500


@app.route('/api/delete-record/<path:record_id>', methods=['POST'])
def api_delete_record(record_id):
    """API endpoint to delete a record (soft delete)"""
    if not osdu_auth_ready(refresh=True):
        return jsonify({"success": False, "error": "OSDU access token is not configured or not valid"}), 401
    record_id = unquote(record_id)
    
    try:
        result = osdu_service.delete_record(record_id)
        if result.get('success'):
            return jsonify(result), 200
        else:
            return jsonify(result), 400
        
    except Exception as e:
        logger.error(f"Error in api_delete_record: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/bulk-delete-records', methods=['POST'])
def api_bulk_delete_records():
    """API endpoint to bulk delete multiple records (soft delete)"""
    if not osdu_auth_ready(refresh=True):
        return jsonify({"success": False, "error": "OSDU access token is not configured or not valid"}), 401
    try:
        data = request.get_json()
        record_ids = data.get('record_ids', [])
        
        if not record_ids:
            return jsonify({"success": False, "error": "No record IDs provided"}), 400
        
        if len(record_ids) > 100:
            return jsonify({"success": False, "error": "Cannot delete more than 100 records at once"}), 400
        
        result = osdu_service.bulk_delete_records(record_ids)
        
        if result.get('success'):
            return jsonify(result), 200
        else:
            return jsonify(result), 400
        
    except Exception as e:
        logger.error(f"Error in api_bulk_delete_records: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/health')
def api_health():
    """Health check endpoint"""
    try:
        # Check token validity
        is_token_valid = token_manager and token_manager.is_token_valid()
        
        return jsonify({
            "status": "healthy",
            "token_manager": "initialized" if token_manager else "not_initialized",
            "token_valid": is_token_valid,
            "base_url": config.OSDU_BASE_URL,
            "partition_id": config.OSDU_PARTITION_ID,
            "token_grant_type": config.OSDU_TOKEN_GRANT_TYPE,
            "domains": len(DOMAINS),
            "entities": calculate_total_entities()
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500


@app.route('/api/config')
def api_config():
    """UI-safe runtime configuration."""
    return jsonify({
        "status": "ok",
        "token_manager": "initialized" if token_manager else "not_initialized",
        "token_valid": bool(token_manager and token_manager.is_token_valid()),
        "token_status": current_token_status(),
        "auth_ready": osdu_auth_ready(refresh=False),
        "summary": config.public_summary()
    })


@app.route('/api/auth/status')
def api_auth_status():
    """UI-safe auth status summary."""
    return jsonify(auth_status_payload())


@app.route('/api/auth/token', methods=['POST'])
def api_auth_token():
    """Apply runtime auth settings and request an OSDU access token."""
    payload = request.get_json() or {}
    try:
        config.apply_runtime_overrides({
            'OSDU_BASE_URL': payload.get('base_url'),
            'OSDU_BASE_HOST': payload.get('base_host'),
            'OSDU_PARTITION_ID': payload.get('partition_id'),
            'OSDU_VERIFY_SSL': payload.get('verify_ssl'),
            'OSDU_TOKEN_ENDPOINT': payload.get('token_endpoint'),
            'OSDU_TOKEN_HOST': payload.get('token_host'),
            'OSDU_AUTH_BASE_URL': payload.get('auth_base_url'),
            'OSDU_AUTH_REALM': payload.get('auth_realm'),
            'OSDU_TOKEN_GRANT_TYPE': payload.get('grant_type'),
            'OSDU_CLIENT_ID': payload.get('client_id'),
            'OSDU_CLIENT_SECRET': payload.get('client_secret'),
            'OSDU_REFRESH_TOKEN': payload.get('refresh_token'),
            'OSDU_TOKEN_SCOPE': payload.get('token_scope'),
            'OSDU_USERNAME': payload.get('username'),
            'OSDU_PASSWORD': payload.get('password'),
        })
        manager = rebuild_token_manager(prewarm=False)
        token = manager.get_token()
        manager.start_background_refresh(interval=3000)
        return jsonify({
            "success": True,
            "token_preview": f"{token[:12]}...{token[-8:]}" if len(token) > 24 else "received",
            "summary": config.public_summary()
        })
    except Exception as e:
        logger.error("Runtime token request failed: %s", e)
        return jsonify({"success": False, "error": str(e), "summary": config.public_summary()}), 400


@app.route('/api/auth/connect', methods=['POST'])
def api_auth_connect():
    return api_auth_token()


@app.route('/api/auth/clear', methods=['POST'])
def api_auth_clear():
    """Clear the current runtime token cache."""
    clear_auth_state()
    return jsonify({"success": True, "summary": config.public_summary()})


@app.route('/api/access-control/summary')
def api_access_control_summary():
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "OSDU access token is not configured or not valid"}), 401
    try:
        return jsonify(access_control_service.summary())
    except Exception as e:
        logger.error(f"Error reading access-control summary: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/access-control/partitions')
def api_access_control_partitions():
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "OSDU access token is not configured or not valid", "items": []}), 401
    try:
        return jsonify(access_control_service.list_partitions())
    except Exception as e:
        logger.error(f"Error listing OSDU partitions: {e}")
        return jsonify({"error": str(e), "items": []}), 500


@app.route('/api/access-control/users')
def api_access_control_users():
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "OSDU access token is not configured or not valid", "items": []}), 401
    try:
        search = request.args.get('search', '')
        return jsonify(access_control_service.list_users(search=search))
    except Exception as e:
        logger.error(f"Error listing OSDU users: {e}")
        return jsonify({"error": str(e), "items": []}), 500


@app.route('/api/access-control/users/<path:user_email>/groups')
def api_access_control_user_groups(user_email):
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "OSDU access token is not configured or not valid", "groups": []}), 401
    try:
        partition_id = request.args.get('partition_id') or config.OSDU_PARTITION_ID
        return jsonify(access_control_service.inspect_user_groups(unquote(user_email), partition_id))
    except requests.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else 500
        if status_code == 403:
            return jsonify({
                "error": "Current token cannot inspect user group membership.",
                "groups": [],
                "summary": {"total": 0, "data": 0, "user": 0, "service": 0, "system": 0, "unknown": 0}
            }), 403
        logger.error(f"Error inspecting OSDU user groups: {e}")
        return jsonify({"error": str(e), "groups": []}), status_code
    except Exception as e:
        logger.error(f"Error inspecting OSDU user groups: {e}")
        return jsonify({"error": str(e), "groups": []}), 500


@app.route('/api/access-control/users/<path:user_email>/groups', methods=['DELETE'])
def api_access_control_remove_user_groups(user_email):
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "Authentication required"}), 401
    try:
        target_email = unquote(user_email).strip().lower()
        if not target_email:
            return jsonify({"error": "email is required"}), 400

        payload = request.get_json(silent=True) or {}
        partition_id = (payload.get('partition_id') or payload.get('partitionId') or config.OSDU_PARTITION_ID or 'osdu').strip()
        if not partition_id:
            return jsonify({"error": "partition_id is required"}), 400

        groups = payload.get("groups")
        if not isinstance(groups, list) or not groups:
            return jsonify({"error": "groups must be a non-empty list"}), 400

        normalized_groups = []
        for group in groups:
            if not isinstance(group, str):
                return jsonify({"error": "group name must be a string"}), 400
            group_name = group.strip()
            if not is_valid_group_email(group_name):
                return jsonify({"error": f"invalid group name: {group_name}"}), 400
            normalized_groups.append(group_name)

        if not current_user_has_access_admin_permission(partition_id):
            return jsonify({"error": "Current user does not have permission to remove group membership"}), 403

        dangerous_groups = sorted(
            group for group in normalized_groups
            if group.lower() in {item.lower() for item in DANGEROUS_GROUPS}
        )
        if dangerous_groups and is_current_caller(target_email) and payload.get("confirm_dangerous_self_remove") is not True:
            return jsonify({
                "error": "Dangerous self-removal requires confirm_dangerous_self_remove=true",
                "dangerous_groups": dangerous_groups,
            }), 400

        logger.info(
            "Removing group memberships: target=%s partition=%s requested=%s groups=%s",
            target_email,
            partition_id,
            len(normalized_groups),
            normalized_groups,
        )
        def remove_one_group(group_name: str) -> Dict:
            try:
                return access_control_service.remove_member_from_group(group_name, target_email, partition_id)
            except Exception as exc:
                return {"group": group_name, "ok": False, "status": 500, "error": str(exc)}

        if len(normalized_groups) == 1:
            results = [remove_one_group(normalized_groups[0])]
        else:
            max_workers = min(5, len(normalized_groups))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                results = list(executor.map(remove_one_group, normalized_groups))

        for result in results:
            logger.info(
                "Remove group membership result: target=%s partition=%s group=%s status=%s ok=%s",
                target_email,
                partition_id,
                result.get("group"),
                result.get("status"),
                result.get("ok"),
            )

        if any(item.get("ok") for item in results):
            admin_permission_cache.clear()

        succeeded = sum(1 for item in results if item.get("ok"))
        response = {
            "user": target_email,
            "partition_id": partition_id,
            "requested": len(normalized_groups),
            "succeeded": succeeded,
            "failed": len(normalized_groups) - succeeded,
            "results": results,
        }
        return jsonify(response), 200 if succeeded == len(normalized_groups) else 207
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("Error removing OSDU user groups: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route('/api/access-control/groups', methods=['POST'])
def api_access_control_create_group():
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "Authentication required"}), 401
    try:
        payload = request.get_json() or {}
        name = (payload.get('name') or payload.get('groupEmail') or payload.get('group_email') or '').strip()
        if not name:
            return jsonify({"error": "Group name is required"}), 400
        if '@' not in name:
            return jsonify({"error": "Group name must include @"}), 400
        result = access_control_service.create_group(
            name=name,
            description=(payload.get('description') or '').strip(),
            group_type=(payload.get('type') or payload.get('groupType') or '').strip().upper(),
            initial_members=payload.get('initial_members') or payload.get('initialMembers') or [],
            partition_id=payload.get('partition_id') or payload.get('partitionId') or config.OSDU_PARTITION_ID,
        )
        return jsonify(result), 201 if not result.get("partial") else 207
    except requests.HTTPError as e:
        return _entitlements_error_response(e, "create Entitlements groups")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error creating Entitlements group: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/access-control/groups')
def api_access_control_groups():
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "OSDU access token is not configured or not valid", "items": []}), 401
    try:
        partition_id = request.args.get('partition_id') or config.OSDU_PARTITION_ID
        return jsonify(access_control_service.list_groups(partition_id))
    except Exception as e:
        logger.error(f"Error listing OSDU groups: {e}")
        return jsonify({"error": str(e), "items": []}), 500


@app.route('/api/access-control/groups/<path:group_email>/members')
def api_access_control_group_members(group_email):
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "OSDU access token is not configured or not valid", "items": []}), 401
    try:
        partition_id = request.args.get('partition_id') or config.OSDU_PARTITION_ID
        return jsonify(access_control_service.list_members(unquote(group_email), partition_id))
    except Exception as e:
        logger.error(f"Error listing OSDU group members: {e}")
        return jsonify({"error": str(e), "items": []}), 500


@app.route('/api/access-control/groups/<path:group_email>/members', methods=['POST'])
def api_access_control_add_group_member(group_email):
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "Authentication required"}), 401
    try:
        payload = request.get_json() or {}
        email = (payload.get('email') or payload.get('memberEmail') or '').strip()
        role = (payload.get('role') or 'MEMBER').strip().upper()
        result = access_control_service.add_group_member(
            unquote(group_email),
            email,
            role,
            payload.get('partition_id') or payload.get('partitionId') or config.OSDU_PARTITION_ID,
        )
        return jsonify(result)
    except requests.HTTPError as e:
        return _entitlements_error_response(e, "manage group members")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Error adding OSDU group member: {e}")
        return jsonify({"error": str(e)}), 500


def _entitlements_error_response(error: requests.HTTPError, action: str):
    status_code = error.response.status_code if error.response is not None else 500
    detail = ""
    try:
        detail_data = error.response.json() if error.response is not None else {}
        detail = detail_data.get("message") or detail_data.get("error") or detail_data.get("reason") or ""
    except Exception:
        detail = ""
    if status_code == 403:
        message = "Current token does not have Entitlements admin permission"
    elif status_code == 409:
        message = "Member already exists" if "member" in action.lower() else "Group already exists"
    elif status_code == 404:
        message = "Group not found"
    elif status_code == 400:
        message = detail or "Invalid Entitlements request"
    elif status_code >= 500:
        message = "OSDU Entitlements error"
    else:
        message = detail or f"Cannot {action}"
    return jsonify({"error": message, "detail": detail}), status_code


@app.route('/api/access-control/legal-tags')
def api_access_control_legal_tags():
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "OSDU access token is not configured or not valid", "items": []}), 401
    try:
        partition_id = request.args.get('partition_id') or config.OSDU_PARTITION_ID
        return jsonify(access_control_service.list_legal_tags(partition_id))
    except Exception as e:
        logger.error(f"Error listing OSDU legal tags: {e}")
        return jsonify({"error": str(e), "items": []}), 500


@app.route('/api/access-control/legal-tags', methods=['POST'])
def api_access_control_create_legal_tag():
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "Authentication required"}), 401
    try:
        payload = request.get_json() or {}
        partition_id = (payload.get('partition_id') or payload.get('partitionId') or config.OSDU_PARTITION_ID).strip()
        name = (payload.get('legalTagName') or payload.get('name') or '').strip()
        if not name:
            return jsonify({"error": "Legal tag name is required"}), 400

        properties = payload.get("properties") if isinstance(payload.get("properties"), dict) else {}
        countries = (
            properties.get("countryOfOrigin")
            or payload.get("countryOfOrigin")
            or payload.get("countries")
            or []
        )
        if isinstance(countries, str):
            countries = [item.strip() for item in countries.replace(';', ',').split(',') if item.strip()]
        if not isinstance(countries, list) or not countries:
            return jsonify({"error": "countryOfOrigin/countries must be a non-empty list"}), 400

        merged_properties = {
            "countryOfOrigin": countries,
            "contractId": properties.get("contractId") or payload.get("contractId") or "A1234",
            "expirationDate": properties.get("expirationDate") or payload.get("expirationDate") or "2099-12-31",
            "originator": properties.get("originator") or payload.get("originator") or "OSDU Web Console",
            "dataType": properties.get("dataType") or payload.get("dataType") or "Public Domain Data",
            "securityClassification": properties.get("securityClassification") or payload.get("securityClassification") or "Public",
            "personalData": properties.get("personalData") or payload.get("personalData") or "No Personal Data",
            "exportClassification": properties.get("exportClassification") or payload.get("exportClassification") or "EAR99",
        }
        if properties.get("description") or payload.get("description"):
            merged_properties["description"] = properties.get("description") or payload.get("description")

        result = access_control_service.create_legal_tag(name, merged_properties, partition_id)
        logger.info("Created Legal Tag: name=%s partition=%s", name, partition_id)
        return jsonify(result), 201
    except requests.HTTPError as e:
        return _osdu_http_error_response(e, "create Legal Tag", service_name="OSDU Legal")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("Error creating OSDU legal tag: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route('/api/access-control/legal-tags/<path:legal_tag_name>', methods=['DELETE'])
def api_access_control_delete_legal_tag(legal_tag_name):
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "Authentication required"}), 401
    try:
        partition_id = (request.args.get('partition_id') or config.OSDU_PARTITION_ID).strip()
        name = unquote(legal_tag_name).strip()
        if not name:
            return jsonify({"error": "Legal tag name is required"}), 400
        result = access_control_service.delete_legal_tag(name, partition_id)
        logger.info("Deleted Legal Tag: name=%s partition=%s", name, partition_id)
        return jsonify(result)
    except requests.HTTPError as e:
        return _osdu_http_error_response(e, "delete Legal Tag", service_name="OSDU Legal")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("Error deleting OSDU legal tag: %s", e)
        return jsonify({"error": str(e)}), 500


def _osdu_http_error_response(error: requests.HTTPError, action: str, service_name: str = "OSDU"):
    status_code = error.response.status_code if error.response is not None else 500
    detail = ""
    try:
        detail_data = error.response.json() if error.response is not None and error.response.text else {}
        detail = detail_data.get("message") or detail_data.get("error") or detail_data.get("reason") or ""
    except Exception:
        detail = ""
    if status_code == 403:
        message = f"Current token does not have permission to {action}"
    elif status_code == 404:
        message = f"{action} endpoint or resource was not found"
    elif status_code == 409:
        message = f"{action} conflicts with an existing resource"
    elif status_code == 400:
        message = detail or f"Invalid request to {action}"
    elif status_code >= 500:
        message = f"{service_name} error"
    else:
        message = detail or f"Cannot {action}"
    return jsonify({"error": message, "detail": detail}), status_code


@app.route('/api/access-control/check', methods=['POST'])
def api_access_control_check():
    if not osdu_auth_ready(refresh=True):
        return jsonify({"error": "OSDU access token is not configured or not valid"}), 401
    try:
        payload = request.get_json() or {}
        record_id = (payload.get('record_id') or payload.get('recordId') or '').strip()
        if not record_id:
            return jsonify({"error": "record_id is required"}), 400
        user_groups_text = payload.get('user_groups') or payload.get('userGroups') or []
        if isinstance(user_groups_text, str):
            user_groups = [item.strip() for item in user_groups_text.replace(',', '\n').splitlines() if item.strip()]
        else:
            user_groups = [str(item).strip() for item in user_groups_text if str(item).strip()]

        result = access_control_service.check_record_access(
            record_id=record_id,
            user_email=(payload.get('user_email') or payload.get('userEmail') or '').strip(),
            partition_id=(payload.get('partition_id') or payload.get('partitionId') or config.OSDU_PARTITION_ID).strip(),
            user_groups=user_groups,
            scan_memberships=bool(payload.get('scan_memberships') or payload.get('scanMemberships')),
            action=(payload.get('action') or 'view')
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error checking OSDU record access: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/debug/test-search')
def api_debug_test_search():
    """Debug endpoint to test OSDU search API"""
    try:
        # Test with different kinds
        test_kinds = [
            "osdu:wks:master-data--Basin:*",
            "osdu:ddms-wellbore:master-data--Basin:*", 
            "osdu:*:*:*",
            "*Basin*"
        ]
        
        results = {}
        
        for kind in test_kinds:
            url = f"{osdu_service.base_url}/api/search/v2/query"
            
            payload = {
                "kind": kind,
                "limit": 1,
                "offset": 0
            }
            
            headers = osdu_service.get_headers()
            
            logger.info(f"Testing search with kind: {kind}")
            
            try:
                response = requests.post(url, headers=headers, json=payload)
                
                results[kind] = {
                    "status_code": response.status_code,
                    "response_text": response.text[:200] + "..." if len(response.text) > 200 else response.text,
                    "success": response.status_code == 200
                }
                
            except Exception as e:
                results[kind] = {
                    "error": str(e),
                    "success": False
                }
        
        return jsonify({
            "test_results": results,
            "request_url": url,
            "request_headers": mask_headers(osdu_service.get_headers()),
            "base_config": {
                "base_url": config.OSDU_BASE_URL,
                "partition_id": config.OSDU_PARTITION_ID
            }
        })
        
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@app.route('/api/debug/test-record-retrieval/<path:record_id>')
def api_debug_test_record_retrieval(record_id):
    """Debug endpoint to test record retrieval strategies"""
    try:
        from urllib.parse import unquote
        record_id = unquote(record_id)
        
        strategies = []
        
        # Strategy 1: Individual record endpoint
        result1 = osdu_service._try_get_record_by_id(record_id)
        strategies.append({
            "name": "Individual Record GET",
            "url": f"/api/storage/v2/records/{record_id}",
            "method": "GET",
            "success": not result1.get('error'),
            "error": result1.get('error', None)
        })
        
        # Strategy 2: Batch v1
        result2 = osdu_service._try_batch_records_v1([record_id])
        strategies.append({
            "name": "Batch Records V1",
            "url": "/api/storage/v2/records",
            "method": "POST",
            "payload": {"recordIds": [record_id]},
            "success": not result2.get('error'),
            "error": result2.get('error', None)
        })
        
        # Strategy 3: Batch v2  
        result3 = osdu_service._try_batch_records_v2([record_id])
        strategies.append({
            "name": "Batch Records V2",
            "url": "/api/storage/v2/query/records", 
            "method": "POST",
            "payload": {"records": [record_id]},
            "success": not result3.get('error'),
            "error": result3.get('error', None)
        })
        
        # Strategy 4: Search-based
        result4 = osdu_service._try_get_record_via_search(record_id)
        strategies.append({
            "name": "Search-Based Retrieval",
            "url": "/api/search/v2/query",
            "method": "POST", 
            "payload": {"query": f"id:{record_id}", "limit": 1, "returnedFields": ["*"]},
            "success": not result4.get('error'),
            "error": result4.get('error', None)
        })
        
        # Find the first successful strategy
        successful_result = None
        for i, strategy in enumerate(strategies):
            if strategy['success']:
                results = [result1, result2, result3, result4]
                successful_result = results[i]
                break
        
        return jsonify({
            "record_id": record_id,
            "strategies": strategies,
            "summary": {
                "total_strategies": len(strategies),
                "successful": len([s for s in strategies if s['success']]),
                "failed": len([s for s in strategies if not s['success']])
            },
            "successful_data": successful_result if successful_result and not successful_result.get('error') else None
        })
        
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@app.route('/api/debug/test-all-strategies')
def api_debug_test_all_strategies():
    """Debug endpoint to test all search strategies"""
    try:
        entity_name = "Basin"
        strategies = []
        
        # Strategy 1: wks domain
        kind1 = "osdu:wks:master-data--Basin:*"
        result1 = osdu_service._try_search_with_kind(kind1, 1, 0, ["id", "kind"])
        strategies.append({
            "name": "WKS Domain",
            "kind": kind1,
            "success": not result1.get('error'),
            "error": result1.get('error', ''),
            "count": len(result1.get('results', []))
        })
        
        # Strategy 2: ddms-wellbore domain  
        kind2 = "osdu:ddms-wellbore:master-data--Basin:*"
        result2 = osdu_service._try_search_with_kind(kind2, 1, 0, ["id", "kind"])
        strategies.append({
            "name": "DDMS-Wellbore Domain",
            "kind": kind2,
            "success": not result2.get('error'),
            "error": result2.get('error', ''),
            "count": len(result2.get('results', []))
        })
        
        # Strategy 3: Wildcard query
        query1 = "*Basin*"
        result3 = osdu_service._try_search_with_query(query1, 1, 0)
        strategies.append({
            "name": "Wildcard Query",
            "query": query1,
            "success": not result3.get('error'),
            "error": result3.get('error', ''),
            "count": len(result3.get('results', []))
        })
        
        # Strategy 4: Kind query
        query2 = "kind:*Basin*"
        result4 = osdu_service._try_search_with_query(query2, 1, 0)
        strategies.append({
            "name": "Kind Query",
            "query": query2,
            "success": not result4.get('error'),
            "error": result4.get('error', ''),
            "count": len(result4.get('results', []))
        })
        
        # Strategy 5: General search
        query3 = "*"
        result5 = osdu_service._try_search_with_query(query3, 5, 0)
        strategies.append({
            "name": "General Search (5 records)",
            "query": query3,
            "success": not result5.get('error'),
            "error": result5.get('error', ''),
            "count": len(result5.get('results', []))
        })
        
        return jsonify({
            "strategies": strategies,
            "summary": {
                "total_strategies": len(strategies),
                "successful": len([s for s in strategies if s['success']]),
                "failed": len([s for s in strategies if not s['success']])
            }
        })
        
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@app.route('/api/debug/simple-search')
def api_debug_simple_search():
    """Very simple search test"""
    try:
        url = f"{osdu_service.base_url}/api/search/v2/query"
        
        # Try general query first
        payload = {
            "query": "*",
            "limit": 1
        }
        
        headers = osdu_service.get_headers()
        response = requests.post(url, headers=headers, json=payload)
        
        return jsonify({
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "response_text": response.text,
            "request_payload": payload
        })
        
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == '__main__':
    print("🛢️ OSDU Record Viewer")
    print("=" * 60)
    print(f"📍 Base URL: {config.OSDU_BASE_URL}")
    print(f"📊 Partition: {config.OSDU_PARTITION_ID}")
    print(f"🏗️  Domains: {len(DOMAINS)}")
    print(f"📋 Entities: {calculate_total_entities()}")
    print("=" * 60)
    
    if not token_manager:
        print("⚠️  WARNING: TokenManager not initialized!")
        print("   Please check your .env configuration:")
        print("   - OSDU_TOKEN_ENDPOINT")
        print("   - OSDU_CLIENT_ID") 
        print("   - OSDU_CLIENT_SECRET")
        print()
    else:
        print("✅ TokenManager initialized successfully")
        
    print("🚀 Starting Flask app...")
    print(f"🌐 URL: http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    print("=" * 60)
    
    try:
        flask_config = config.get_flask_config()
        app.run(
            host=flask_config['HOST'],
            port=flask_config['PORT'],
            debug=flask_config['DEBUG']
        )
    except Exception as e:
        logger.error(f"Failed to start Flask app: {e}")
        print(f"❌ Error: {e}")
