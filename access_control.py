"""OSDU access-control helpers for the Flask console."""
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from urllib.parse import quote

import requests
import urllib3

from config import config

logger = logging.getLogger(__name__)

ACCESS_ADMIN_GROUPS = {
    "service.entitlements.admin@osdu.group",
    "users.datalake.admins@osdu.group",
    "users.data.root@osdu.group",
}

DANGEROUS_GROUPS = {
    "users@osdu.group",
    "users.data.root@osdu.group",
    "users.datalake.admins@osdu.group",
    "users.datalake.ops@osdu.group",
    "users.datalake.delegation@osdu.group",
    "users.datalake.impersonation@osdu.group",
    "service.entitlements.admin@osdu.group",
    "service.partition.admin@osdu.group",
    "service.storage.admin@osdu.group",
    "service.policy.admin@osdu.group",
    "service.legal.admin@osdu.group",
    "service.schema-service.system-admin@osdu.group",
}

GROUP_EMAIL_RE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+\.group$")


def infer_group_type(group_email: str) -> str:
    """Infer OSDU group type from the conventional group email prefix."""
    lowered = (group_email or "").lower()
    if lowered.startswith("data."):
        return "DATA"
    if lowered.startswith("service."):
        return "SERVICE"
    if lowered.startswith("users."):
        return "USER"
    if re.match(r"^users@[a-z0-9._-]+\.group$", lowered):
        return "USER"
    if lowered.startswith(("notification.", "partition.", "cron.")):
        return "SYSTEM"
    return "UNKNOWN"


def is_valid_group_email(group_email: str) -> bool:
    """Return True for a syntactically valid OSDU Entitlements group email."""
    value = (group_email or "").strip()
    return bool(value and "@" in value and value.endswith(".group") and GROUP_EMAIL_RE.match(value))


def _first_attr(attrs: Dict, key: str) -> str:
    value = attrs.get(key)
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value or "")


class AccessControlService:
    """Read-only OSDU access-control API facade."""

    def __init__(self, token_manager):
        self.token_manager = token_manager
        self.base_url = config.OSDU_BASE_URL
        self.base_host = config.OSDU_BASE_HOST
        self.partition_id = config.OSDU_PARTITION_ID
        self.timeout = config.OSDU_TIMEOUT_SECONDS
        self.verify_ssl = config.as_bool(config.OSDU_VERIFY_SSL)
        self._user_groups_cache: Dict[str, Dict] = {}
        self._user_groups_cache_ttl = 180
        self._groups_cache: Dict[str, Dict] = {}
        self._groups_cache_ttl = 180
        self._direct_user_groups_disabled_until = 0
        self._member_scan_workers = 12
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def get_headers(self, partition_id: Optional[str] = None) -> Dict[str, str]:
        if not self.token_manager:
            raise RuntimeError("TokenManager is not initialized")
        headers = {
            "Authorization": f"Bearer {self.token_manager.get_token()}",
            "data-partition-id": partition_id or self.partition_id,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.base_host:
            headers["Host"] = self.base_host
        return headers

    def _request(self, method: str, path: str, *, partition_id: Optional[str] = None, **kwargs):
        url = f"{self.base_url.rstrip('/')}{path}"
        response = requests.request(
            method,
            url,
            headers=self.get_headers(partition_id),
            timeout=self.timeout,
            verify=self.verify_ssl,
            **kwargs,
        )
        response.raise_for_status()
        if not response.text:
            return {}
        return response.json()

    def summary(self) -> Dict:
        return {
            "configured": bool(config.OSDU_BASE_URL and config.OSDU_TOKEN_ENDPOINT and config.OSDU_CLIENT_ID),
            "token_valid": bool(self.token_manager and self.token_manager.is_token_valid()),
            "config": config.public_summary(),
            "defaults": {
                "partition_id": self.partition_id,
                "group_scan_limit": config.OSDU_GROUP_SCAN_LIMIT,
            },
        }

    def list_partitions(self) -> Dict:
        path = f"{config.OSDU_PARTITION_BASE_PATH.rstrip('/')}/partitions"
        data = self._request("GET", path, partition_id=self.partition_id)
        if isinstance(data, list):
            items = data
        else:
            items = data.get("partitions", data.get("data", []))
        if isinstance(items, dict):
            items = list(items.keys())
        normalized = [self._normalize_partition(item) for item in items]
        if not normalized:
            normalized = [{
                "partitionId": self.partition_id,
                "displayName": self.partition_id,
                "source": "CONFIGURED",
                "status": "ACTIVE",
            }]
        return {"items": normalized}

    def list_users(self, search: str = "", max_items: int = 500) -> Dict:
        if not config.OSDU_AUTH_BASE_URL or not config.OSDU_AUTH_REALM:
            return {
                "items": [],
                "warning": "Keycloak admin URL is not configured; cannot list external IAM users.",
            }

        token = self._get_keycloak_admin_token()
        url = f"{config.OSDU_AUTH_BASE_URL.rstrip('/')}/admin/realms/{config.OSDU_AUTH_REALM}/users"
        params = {
            "max": max(1, min(int(max_items or 500), 1000)),
            "briefRepresentation": "false",
        }
        if search:
            params["search"] = search.strip()
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            params=params,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        items = response.json() if response.text else []
        return {"items": [self._normalize_user(item) for item in items]}

    def list_groups(self, partition_id: Optional[str] = None) -> Dict:
        partition = partition_id or self.partition_id
        cache_key = partition
        cached = self._groups_cache.get(cache_key)
        now = time.time()
        if cached and now - cached.get("created_at", 0) < self._groups_cache_ttl:
            return cached["payload"]

        last_error = None
        for base_path in self._entitlements_paths():
            try:
                data = self._request(
                    "GET",
                    f"{base_path}/groups",
                    partition_id=partition,
                    params={"roleRequired": "true"},
                )
                items = self._items_from_response(data, "groups")
                payload = {"items": [self._normalize_group(item) for item in items]}
                self._groups_cache[cache_key] = {"created_at": now, "payload": payload}
                return payload
            except requests.HTTPError as exc:
                last_error = exc
                if exc.response.status_code not in (403, 404):
                    raise
        raise last_error or RuntimeError("No Entitlements endpoint is configured")

    def create_group(
        self,
        name: str,
        description: str = "",
        group_type: str = "",
        initial_members: Optional[List[Dict]] = None,
        partition_id: Optional[str] = None,
    ) -> Dict:
        group_email = name.strip()
        if not group_email:
            raise ValueError("Group name is required")
        if "@" not in group_email:
            raise ValueError("Group name must be a full Entitlements group email")
        partition = partition_id or self.partition_id
        payload = {
            "email": group_email,
            "name": group_email.split("@", 1)[0],
            "description": description or "",
        }
        try:
            created = self._entitlements_mutation("POST", "/groups", partition_id=partition, json=payload)
        except requests.HTTPError as exc:
            if exc.response is None or exc.response.status_code != 400:
                raise
            created = self._entitlements_mutation(
                "POST",
                "/groups",
                partition_id=partition,
                json={"name": group_email, "description": description or ""},
            )
        member_results = []
        member_errors = []
        for member in initial_members or []:
            email = str(member.get("email") or member.get("memberEmail") or "").strip()
            if not email:
                continue
            role = str(member.get("role") or "MEMBER").strip().upper()
            try:
                member_results.append(self.add_group_member(group_email, email, role, partition))
            except Exception as exc:
                member_errors.append({"email": email, "error": str(exc)})
        group = self._normalize_group({
            "email": group_email,
            "name": group_email.split("@", 1)[0],
            "description": description,
            "source": "OSDU",
        })
        self._invalidate_groups_cache(partition)
        return {
            "success": not member_errors,
            "partial": bool(member_errors),
            "group": {
                "name": group_email,
                "type": group_type or infer_group_type(group_email),
                "description": description or "",
                **group,
            },
            "osduResponse": created,
            "membersAdded": member_results,
            "memberErrors": member_errors,
        }

    def list_members(self, group_email: str, partition_id: Optional[str] = None) -> Dict:
        encoded_group = quote(group_email, safe="")
        last_error = None
        for base_path in self._entitlements_paths():
            try:
                data = self._request(
                    "GET",
                    f"{base_path}/groups/{encoded_group}/members",
                    partition_id=partition_id or self.partition_id,
                    params={"includeType": "true", "roleRequired": "true"},
                )
                items = self._items_from_response(data, "members")
                return {"items": [self._normalize_member(item) for item in items]}
            except requests.HTTPError as exc:
                last_error = exc
                if exc.response.status_code not in (403, 404):
                    raise
        raise last_error or RuntimeError("No Entitlements endpoint is configured")

    def add_group_member(
        self,
        group_email: str,
        email: str,
        role: str = "MEMBER",
        partition_id: Optional[str] = None,
    ) -> Dict:
        member_email = email.strip().lower()
        normalized_role = (role or "MEMBER").strip().upper()
        if not member_email:
            raise ValueError("Member email is required")
        if normalized_role not in {"MEMBER", "OWNER"}:
            raise ValueError("Role must be MEMBER or OWNER")
        encoded_group = quote(group_email, safe="")
        payload = {"email": member_email, "role": normalized_role}
        data = self._entitlements_mutation(
            "POST",
            f"/groups/{encoded_group}/members",
            partition_id=partition_id or self.partition_id,
            json=payload,
        )
        self._invalidate_user_groups_cache(member_email, partition_id or self.partition_id)
        return {
            "success": True,
            "group": group_email,
            "member": {
                "email": member_email,
                "role": normalized_role,
            },
            "osduResponse": data,
        }

    def remove_member_from_group(
        self,
        group_email: str,
        member_email: str,
        partition_id: Optional[str] = None,
    ) -> Dict:
        group = group_email.strip()
        member = member_email.strip().lower()
        if not group:
            raise ValueError("Group name is required")
        if not member:
            raise ValueError("Member email is required")

        encoded_group = quote(group, safe="")
        encoded_member = quote(member, safe="")
        partition = partition_id or self.partition_id
        last_result = None
        for base_path in self._entitlements_paths():
            url = (
                f"{self.base_url.rstrip('/')}{base_path}"
                f"/groups/{encoded_group}/members/{encoded_member}"
            )
            response = requests.delete(
                url,
                headers=self.get_headers(partition),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            status = response.status_code
            if 200 <= status < 300:
                self._invalidate_user_groups_cache(member, partition)
                logger.info(
                    "Removed member from group: target=%s partition=%s group=%s status=%s ok=True",
                    member,
                    partition,
                    group,
                    status,
                )
                return {"group": group, "ok": True, "status": status}

            error = self._response_error_message(response)
            last_result = {"group": group, "ok": False, "status": status, "error": error}
            if status not in (403, 404):
                break

        logger.info(
            "Remove member from group failed: target=%s partition=%s group=%s status=%s ok=False",
            member,
            partition,
            group,
            (last_result or {}).get("status"),
        )
        return last_result or {"group": group, "ok": False, "status": 500, "error": "No Entitlements endpoint is configured"}

    def list_legal_tags(self, partition_id: Optional[str] = None) -> Dict:
        path = f"{config.OSDU_LEGAL_BASE_PATH.rstrip('/')}/legaltags"
        data = self._request("GET", path, partition_id=partition_id or self.partition_id)
        items = data.get("legalTags", data.get("data", data if isinstance(data, list) else []))
        return {"items": [self._normalize_legal_tag(item) for item in items]}

    def create_legal_tag(
        self,
        name: str,
        properties: Dict,
        partition_id: Optional[str] = None,
    ) -> Dict:
        tag_name = name.strip()
        if not tag_name:
            raise ValueError("Legal tag name is required")
        if not isinstance(properties, dict):
            raise ValueError("properties must be an object")

        tag_properties = dict(properties)
        payload = {
            "name": tag_name,
            "description": tag_properties.pop("description", ""),
            "properties": tag_properties,
        }
        data = self._request(
            "POST",
            f"{config.OSDU_LEGAL_BASE_PATH.rstrip('/')}/legaltags",
            partition_id=partition_id or self.partition_id,
            json=payload,
        )
        return {
            "success": True,
            "legalTag": self._normalize_legal_tag(data.get("legalTag") or data or payload),
            "osduResponse": data,
        }

    def delete_legal_tag(self, name: str, partition_id: Optional[str] = None) -> Dict:
        tag_name = name.strip()
        if not tag_name:
            raise ValueError("Legal tag name is required")
        encoded_name = quote(tag_name, safe="")
        data = self._request(
            "DELETE",
            f"{config.OSDU_LEGAL_BASE_PATH.rstrip('/')}/legaltags/{encoded_name}",
            partition_id=partition_id or self.partition_id,
        )
        return {
            "success": True,
            "name": tag_name,
            "osduResponse": data,
        }

    def check_record_access(
        self,
        record_id: str,
        user_email: str = "",
        partition_id: Optional[str] = None,
        user_groups: Optional[List[str]] = None,
        scan_memberships: bool = False,
        action: str = "view",
    ) -> Dict:
        partition = partition_id or self.partition_id
        normalized_action = (action or "view").strip().lower()
        groups = sorted(set(user_groups or []))
        if scan_memberships and user_email and not groups:
            groups = self.find_user_memberships(user_email, partition)

        record = self.get_record(record_id, partition)
        acl = record.get("acl", {}) if isinstance(record, dict) else {}
        legal = record.get("legal", {}) if isinstance(record, dict) else {}
        viewers = list(acl.get("viewers") or [])
        owners = list(acl.get("owners") or [])
        legal_tags = list(legal.get("legaltags") or legal.get("legalTags") or [])
        legal_status = legal.get("status") or legal.get("legalStatus") or ""
        data_countries = list(
            legal.get("otherRelevantDataCountries")
            or legal.get("dataCountries")
            or []
        )

        matched_viewers = sorted(set(groups).intersection(viewers))
        matched_owners = sorted(set(groups).intersection(owners))
        missing_groups = sorted(set(viewers + owners).difference(groups))

        if normalized_action in ("owner", "delete"):
            allowed = bool(matched_owners)
        else:
            allowed = bool(matched_viewers or matched_owners)

        if matched_owners:
            decision = "ALLOW_OWNER"
            explanation = "User is in an owner group declared in the record ACL."
        elif matched_viewers:
            decision = "ALLOW_VIEW"
            explanation = "User is in a viewer group declared in the record ACL."
        elif groups:
            decision = "DENY_NO_GROUP_MATCH"
            explanation = "User groups were resolved, but none match the record ACL."
        else:
            decision = "UNKNOWN_NO_MEMBERSHIP"
            explanation = "No user group was provided or found, so ACL matching cannot allow access."

        layers = [
            {"name": "Token valid", "status": "PASS", "detail": "A valid bearer token was available for the Storage request."},
            {"name": "Partition", "status": "PASS", "detail": f"Checked record in partition '{partition}'."},
            {"name": "Service permission", "status": "UNKNOWN", "detail": "Not evaluated by local checker; OSDU service authorization handled the Storage API call."},
            {
                "name": "User/group membership",
                "status": "PASS" if groups else "UNKNOWN",
                "detail": f"{len(groups)} group(s) provided or resolved." if groups else "No user groups were provided or resolved.",
            },
            {
                "name": "Record ACL viewers/owners",
                "status": "PASS" if allowed else "FAIL",
                "detail": explanation,
            },
            {
                "name": "Legal tag/status",
                "status": "INFO" if legal_tags or legal_status else "UNKNOWN",
                "detail": f"Tags: {', '.join(legal_tags) or 'None'}; status: {legal_status or 'not provided'}.",
            },
            {"name": "Policy/OPA", "status": "UNKNOWN", "detail": "Not evaluated by local checker."},
        ]

        return {
            "partitionId": partition,
            "recordId": record_id,
            "userEmail": user_email,
            "action": normalized_action,
            "userGroups": groups,
            "result": "ALLOW" if allowed else "DENY",
            "canView": bool(matched_viewers or matched_owners),
            "canEdit": bool(matched_owners),
            "matchedViewerGroups": matched_viewers,
            "matchedOwnerGroups": matched_owners,
            "missingGroups": missing_groups,
            "recordViewers": viewers,
            "recordOwners": owners,
            "recordLegalTags": legal_tags,
            "recordLegalStatus": legal_status,
            "otherRelevantDataCountries": data_countries,
            "decision": decision,
            "explanation": explanation,
            "layers": layers,
        }

    def find_user_memberships(self, user_email: str, partition_id: str) -> List[str]:
        result = self.inspect_user_groups(user_email, partition_id)
        return [group.get("name", "") for group in result.get("groups", []) if group.get("name")]

    def inspect_user_groups(self, user_email: str, partition_id: Optional[str] = None) -> Dict:
        partition = partition_id or self.partition_id
        normalized_user = user_email.strip().lower()
        cache_key = f"{partition}:{normalized_user}"
        cached = self._user_groups_cache.get(cache_key)
        now = time.time()
        if cached and now - cached.get("created_at", 0) < self._user_groups_cache_ttl:
            return cached["payload"]

        if now >= self._direct_user_groups_disabled_until:
            try:
                payload = self._inspect_user_groups_direct(normalized_user, partition)
                self._user_groups_cache[cache_key] = {"created_at": now, "payload": payload}
                return payload
            except Exception as exc:
                logger.warning(
                    "Direct member group lookup failed for %s in %s; falling back to group scan: %s",
                    normalized_user,
                    partition,
                    exc,
                )

        payload = self._inspect_user_groups_by_scan(normalized_user, partition)
        self._user_groups_cache[cache_key] = {"created_at": now, "payload": payload}
        return payload

    def _inspect_user_groups_direct(self, normalized_user: str, partition: str) -> Dict:
        encoded_member = quote(normalized_user, safe="")
        last_error = None
        for base_path in self._entitlements_paths():
            try:
                data = self._request(
                    "GET",
                    f"{base_path}/members/{encoded_member}/groups",
                    partition_id=partition,
                    params={"roleRequired": "true"},
                )
                items = self._items_from_response(data, "groups")
                memberships = [
                    self._normalize_user_membership_group(item, source="OSDU_ENTITLEMENTS_DIRECT")
                    for item in items
                ]
                memberships = [item for item in memberships if item.get("name")]
                return self._user_groups_payload(normalized_user, partition, memberships, source="OSDU_ENTITLEMENTS_DIRECT")
            except requests.HTTPError as exc:
                last_error = exc
                if exc.response is not None and exc.response.status_code in (401,):
                    raise
                continue
        if last_error is not None and last_error.response is not None:
            status_code = last_error.response.status_code
            if status_code in (403, 404, 405):
                self._direct_user_groups_disabled_until = time.time() + 300
        raise last_error or RuntimeError("Direct Entitlements member group lookup is not available")

    def _inspect_user_groups_by_scan(self, normalized_user: str, partition: str) -> Dict:
        started_at = time.time()
        groups = self.list_groups(partition).get("items", [])
        scanned_groups = groups[: config.OSDU_GROUP_SCAN_LIMIT]
        memberships: List[Dict] = []

        def read_group_members(group: Dict):
            group_email = group.get("groupEmail", "")
            try:
                members = self.list_members(group_email, partition).get("items", [])
                return group, members, None
            except requests.HTTPError as exc:
                return group, [], exc
            except Exception as exc:
                return group, [], exc

        errors = []
        max_workers = max(1, min(self._member_scan_workers, len(scanned_groups) or 1))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(read_group_members, group) for group in scanned_groups]
            for future in as_completed(futures):
                group, members, error = future.result()
                group_email = group.get("groupEmail", "")
                if error:
                    if isinstance(error, requests.HTTPError) and error.response is not None and error.response.status_code == 403:
                        errors.append(error)
                    else:
                        logger.warning("Could not read members for %s: %s", group_email, error)
                    continue
                matched_member = next(
                    (member for member in members if member.get("memberEmail", "").lower() == normalized_user),
                    None,
                )
                if matched_member:
                    group_type = group.get("groupType") or infer_group_type(group_email)
                    memberships.append({
                        "name": group_email,
                        "groupName": group.get("groupName") or group_email.split("@", 1)[0],
                        "type": group_type,
                        "role": matched_member.get("role") or "MEMBER",
                        "description": group.get("description") or "",
                        "source": "OSDU_ENTITLEMENTS",
                    })

        if errors and len(errors) == len(scanned_groups):
            raise errors[0]

        logger.info(
            "Scanned user memberships: user=%s partition=%s groups=%s memberships=%s elapsed=%.2fs workers=%s",
            normalized_user,
            partition,
            len(scanned_groups),
            len(memberships),
            time.time() - started_at,
            max_workers,
        )

        return self._user_groups_payload(normalized_user, partition, memberships, source="OSDU_ENTITLEMENTS")

    def _user_groups_payload(self, normalized_user: str, partition: str, memberships: List[Dict], source: str) -> Dict:
        summary = {
            "total": len(memberships),
            "data": sum(1 for item in memberships if item.get("type") == "DATA"),
            "user": sum(1 for item in memberships if item.get("type") == "USER"),
            "service": sum(1 for item in memberships if item.get("type") == "SERVICE"),
            "system": sum(1 for item in memberships if item.get("type") == "SYSTEM"),
            "unknown": sum(1 for item in memberships if item.get("type") == "UNKNOWN"),
        }
        payload = {
            "user": normalized_user,
            "partitionId": partition,
            "groups": sorted(memberships, key=lambda item: item.get("name", "")),
            "summary": summary,
            "source": source,
            "cacheTtlSeconds": self._user_groups_cache_ttl,
        }
        return payload

    @staticmethod
    def _normalize_user_membership_group(item, source: str) -> Dict:
        if isinstance(item, str):
            group_email = item
            return {
                "name": group_email,
                "groupName": group_email.split("@", 1)[0],
                "type": infer_group_type(group_email),
                "role": "MEMBER",
                "description": "",
                "source": source,
            }
        if not isinstance(item, dict):
            group_email = str(item)
            return {
                "name": group_email,
                "groupName": group_email.split("@", 1)[0],
                "type": infer_group_type(group_email),
                "role": "MEMBER",
                "description": "",
                "source": source,
            }
        group_email = item.get("email") or item.get("groupEmail") or item.get("name") or ""
        return {
            "name": group_email,
            "groupName": item.get("displayName") or item.get("groupName") or group_email.split("@", 1)[0],
            "type": item.get("groupType") or infer_group_type(group_email),
            "role": item.get("role") or item.get("memberRole") or "MEMBER",
            "description": item.get("description") or "",
            "source": source,
        }

    def get_record(self, record_id: str, partition_id: str) -> Dict:
        encoded = quote(record_id, safe="")
        path = f"{config.OSDU_STORAGE_BASE_PATH.rstrip('/')}/records/{encoded}"
        return self._request("GET", path, partition_id=partition_id)

    def _entitlements_paths(self) -> List[str]:
        configured = config.OSDU_ENTITLEMENTS_BASE_PATH.rstrip("/")
        result = []
        for item in (configured, "/entitlements/v1"):
            if item and item not in result:
                result.append(item)
        return result

    def _entitlements_mutation(self, method: str, suffix: str, *, partition_id: str, **kwargs):
        last_error = None
        for base_path in self._entitlements_paths():
            try:
                return self._request(method, f"{base_path}{suffix}", partition_id=partition_id, **kwargs)
            except requests.HTTPError as exc:
                last_error = exc
                if exc.response.status_code not in (403, 404):
                    raise
        raise last_error or RuntimeError("No Entitlements endpoint is configured")

    def _invalidate_user_groups_cache(self, user_email: str, partition_id: str = ""):
        normalized_user = user_email.strip().lower()
        partition = partition_id or self.partition_id
        self._user_groups_cache.pop(f"{partition}:{normalized_user}", None)

    def _invalidate_groups_cache(self, partition_id: str = ""):
        partition = partition_id or self.partition_id
        self._groups_cache.pop(partition, None)

    @staticmethod
    def _response_error_message(response) -> str:
        try:
            data = response.json() if response is not None and response.text else {}
            if isinstance(data, dict):
                return data.get("message") or data.get("error") or data.get("reason") or response.text[:200]
        except Exception:
            pass
        return (response.text or response.reason or "OSDU Entitlements error")[:300]

    @staticmethod
    def _items_from_response(data, key: str) -> List:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get(key, data.get("data", []))
        return []

    def _get_keycloak_admin_token(self) -> str:
        if config.OSDU_EXTERNAL_ADMIN_USERNAME and config.OSDU_EXTERNAL_ADMIN_PASSWORD:
            payload = {
                "grant_type": "password",
                "client_id": config.OSDU_CLIENT_ID,
                "client_secret": config.OSDU_CLIENT_SECRET,
                "username": config.OSDU_EXTERNAL_ADMIN_USERNAME,
                "password": config.OSDU_EXTERNAL_ADMIN_PASSWORD,
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            if config.OSDU_TOKEN_HOST:
                headers["Host"] = config.OSDU_TOKEN_HOST
            response = requests.post(
                config.OSDU_TOKEN_ENDPOINT,
                data=payload,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            token = response.json().get("access_token")
            if not token:
                raise RuntimeError("Keycloak admin token response did not include access_token")
            return token
        return self.token_manager.get_token()

    @staticmethod
    def _normalize_partition(item) -> Dict:
        if isinstance(item, str):
            return {"partitionId": item, "displayName": item, "source": "OSDU", "status": "ACTIVE"}
        if not isinstance(item, dict):
            value = str(item)
            return {"partitionId": value, "displayName": value, "source": "OSDU", "status": "ACTIVE"}
        partition_id = item.get("partitionId") or item.get("id") or item.get("name") or ""
        return {
            "partitionId": str(partition_id),
            "displayName": item.get("displayName") or item.get("name") or str(partition_id),
            "source": item.get("source") or "OSDU",
            "status": item.get("status") or "ACTIVE",
        }

    @staticmethod
    def _normalize_user(item) -> Dict:
        if not isinstance(item, dict):
            return {"email": str(item), "username": str(item), "source": "EXTERNAL_KEYCLOAK", "status": "ACTIVE"}
        email = str(item.get("email") or item.get("username") or "").lower()
        full_name = item.get("name") or " ".join(part for part in [item.get("firstName"), item.get("lastName")] if part)
        attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
        return {
            "id": item.get("id") or "",
            "username": item.get("username") or email,
            "email": email,
            "fullName": full_name,
            "company": _first_attr(attrs, "company"),
            "department": _first_attr(attrs, "department"),
            "location": _first_attr(attrs, "location"),
            "nationality": _first_attr(attrs, "nationality"),
            "source": "EXTERNAL_KEYCLOAK",
            "status": "ACTIVE" if item.get("enabled", True) else "DISABLED",
        }

    @staticmethod
    def _normalize_group(item) -> Dict:
        if isinstance(item, str):
            email = item
            return {
                "groupEmail": email,
                "groupName": email.split("@", 1)[0],
                "groupType": infer_group_type(email),
                "source": "OSDU",
                "status": "ACTIVE",
            }
        email = item.get("email") or item.get("groupEmail") or item.get("name") or ""
        return {
            "groupEmail": email,
            "groupName": item.get("name") or item.get("displayName") or email.split("@", 1)[0],
            "groupType": infer_group_type(email),
            "description": item.get("description") or "",
            "source": item.get("source") or "OSDU",
            "status": item.get("status") or "ACTIVE",
        }

    @staticmethod
    def _normalize_member(item) -> Dict:
        if isinstance(item, str):
            return {"memberEmail": item, "role": "", "memberType": ""}
        return {
            "memberEmail": item.get("email") or item.get("memberEmail") or item.get("id") or "",
            "role": item.get("role") or item.get("memberRole") or "",
            "memberType": item.get("type") or item.get("memberType") or "",
        }

    @staticmethod
    def _normalize_legal_tag(item) -> Dict:
        if not isinstance(item, dict):
            return {"name": str(item)}
        props = item.get("properties", item)
        countries = props.get("countryOfOrigin") or props.get("country_of_origin") or []
        if isinstance(countries, str):
            countries = [countries]
        return {
            "name": item.get("name") or props.get("name") or "",
            "status": item.get("status") or props.get("status") or "",
            "description": props.get("description") or "",
            "countryOfOrigin": countries,
            "contractId": props.get("contractId") or "",
            "expirationDate": props.get("expirationDate") or "",
            "originator": props.get("originator") or "",
            "dataType": props.get("dataType") or "",
            "securityClassification": props.get("securityClassification") or "",
            "exportClassification": props.get("exportClassification") or "",
            "personalData": props.get("personalData") or "",
        }
