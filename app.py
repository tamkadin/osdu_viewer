#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSDU Record Viewer - Flask Application
Xem các record OSDU theo domain và entities với TokenManager
"""

from flask import Flask, render_template, request, jsonify
import requests
import json
import logging
from typing import Dict, List, Optional
from urllib.parse import unquote

from config import config
from token_manager import TokenManager
from domains import DOMAINS, get_domain_info, get_entity_info

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Initialize TokenManager
try:
    config.validate()
    token_manager = TokenManager(config.to_dict())
    logger.info("TokenManager initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize TokenManager: {e}")
    token_manager = None


class OSDUService:
    """OSDU API Service with token management"""
    
    def __init__(self):
        self.base_url = config.OSDU_BASE_URL
        self.partition_id = config.OSDU_PARTITION_ID

    def get_headers(self) -> Dict[str, str]:
        """Get headers with access token"""
        if not token_manager:
            raise Exception("TokenManager not initialized")
        
        try:
            token = token_manager.get_token()
            return {
                "Authorization": f"Bearer {token}",
                "data-partition-id": self.partition_id,
                "Content-Type": "application/json"
            }
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
            logger.error(f"Headers: {dict(self.get_headers())}")
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


# Initialize OSDU Service
osdu_service = OSDUService()


# Helper functions
def calculate_total_entities():
    """Calculate total number of entities across all domains"""
    return sum(len(domain['entities']) for domain in DOMAINS.values())


# Routes
@app.route('/')
def home():
    """Home page showing all domains"""
    total_entities = calculate_total_entities()
    return render_template('home.html', 
                         domains=DOMAINS, 
                         total_entities=total_entities)


@app.route('/domain/<domain_name>')
def domain_page(domain_name):
    """Domain page showing entities"""
    domain_name = unquote(domain_name)
    domain_info = get_domain_info(domain_name)
    
    if not domain_info:
        return f"Domain '{domain_name}' not found", 404
    
    return render_template('domain.html', 
                         domain_name=domain_name, 
                         domain_info=domain_info)


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
                         entity_fields=entity_info.get('fields', []))


@app.route('/record/<path:record_id>')
def record_detail_page(record_id):
    """Record detail page"""
    record_id = unquote(record_id)
    return render_template('record_detail.html', record_id=record_id)


# API Routes
@app.route('/api/records/<domain_name>/<entity_name>')
def api_records(domain_name, entity_name):
    """API endpoint to get records for an entity"""
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
    record_id = unquote(record_id)
    
    try:
        result = osdu_service.get_record_details([record_id])
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in api_record_detail: {e}")
        return jsonify({"error": str(e), "records": []}), 500


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
            "domains": len(DOMAINS),
            "entities": calculate_total_entities()
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500


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
            url = f"{config.OSDU_BASE_URL}/api/search/v2/query"
            
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
            "request_headers": dict(osdu_service.get_headers()),
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
        url = f"{config.OSDU_BASE_URL}/api/search/v2/query"
        
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