import os
import sys
import json
import pathlib
import requests
import re
from datetime import datetime
from typing import Optional, Dict, Any

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("canary-console-mcp", json_response=True)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _log(message: str) -> None:
    """Log to stderr (stdout is reserved for JSON-RPC)"""
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {message}", file=sys.stderr)

def _must_env(name: str) -> str:
    """Get required environment variable or raise error"""
    v = os.environ.get(name, "").strip()
    if not v:
        raise RuntimeError(f"Missing required env var: {name}")
    return v

def _base_url() -> str:
    """Get base URL from environment"""
    domain = _must_env("CANARY_DOMAIN")
    url = f"https://{domain}"
    _log(f"Using Canary Console: {url}")
    return url

def _auth_token() -> str:
    """Get auth token from environment"""
    token = _must_env("CANARY_AUTH_TOKEN")
    _log(f"Auth token loaded (length: {len(token)})")
    return token

def _api_call(method: str, path: str, data: Optional[Dict] = None, params: Optional[Dict] = None) -> Dict:
    """Generic API call handler"""
    url = _base_url() + path
    _log(f"{method} {url}")
    
    kwargs = {"timeout": 60 if "download" in path else 30}
    if method == "POST":
        kwargs["data"] = data or {}
        resp = requests.post(url, **kwargs)
    else:
        kwargs["params"] = params or {}
        resp = requests.get(url, **kwargs)
    
    _log(f"Response status: {resp.status_code}")
    
    try:
        result = resp.json()
        _log(f"Response result: {result.get('result', 'unknown')}")
        return result
    except Exception as e:
        _log(f"ERROR: Non-JSON response: {e}")
        raise RuntimeError(f"Non-JSON response from {url}: HTTP {resp.status_code} {resp.text[:500]}")

def _get_bytes(path: str, params: Dict) -> bytes:
    """Download binary content"""
    url = _base_url() + path
    _log(f"GET {url} (binary)")
    resp = requests.get(url, params=params, allow_redirects=True, timeout=60)
    
    if not resp.ok:
        raise RuntimeError(f"Download failed: HTTP {resp.status_code} {resp.text[:500]}")
    
    _log(f"Downloaded {len(resp.content)} bytes")
    return resp.content

def _safe_filename(name: str) -> str:
    """Sanitize filename"""
    return "".join(ch if ch.isalnum() or ch in " ._-()+[]" else "_" for ch in name)[:180]

def _format_value(value: Any) -> str:
    """Format value for API"""
    if isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, (list, dict)):
        return json.dumps(value)
    return str(value)

def _find_device(device_id: Optional[str] = None, device_name: Optional[str] = None) -> str:
    """Find device ID by name or return provided ID"""
    if device_id:
        return device_id
    if not device_name:
        raise RuntimeError("Must specify either device_id or device_name")
    
    devices = list_devices()["devices"]
    for device in devices:
        if device["name"] and device_name.lower() in device["name"].lower():
            return device["id"]
    
    raise RuntimeError(f"Device '{device_name}' not found")

def _get_update_tag(device_id: str) -> str:
    """Get update_tag for device"""
    result = _api_call("GET", "/api/v1/device/info", params={
        "auth_token": _auth_token(),
        "node_id": device_id
    })
    if result.get("result") != "success":
        raise RuntimeError(f"Failed to get device info: {result.get('message')}")
    return result["device"]["update_tag"]

def _flatten_dict(d: Dict, parent_key: str = '') -> Dict:
    """Flatten nested dict to dot notation"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}.{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten_dict(v, new_key).items())
        elif isinstance(v, list):
            items.append((new_key, json.dumps(v)))
        else:
            items.append((new_key, _format_value(v)))
    return dict(items)

# ============================================================================
# DEVICE MANAGEMENT
# ============================================================================

@mcp.tool()
def list_devices() -> Dict:
    """List all Canary devices"""
    _log("=" * 60)
    _log("LISTING ALL DEVICES")
    
    result = _api_call("GET", "/api/v1/devices/all", params={"auth_token": _auth_token()})
    if result.get("result") != "success":
        raise RuntimeError(f"List devices failed: {result.get('message', result)}")
    
    devices = result.get("devices", [])
    _log(f"Found {len(devices)} devices")
    
    device_list = [{
        "id": d.get("id"),
        "name": d.get("name"),
        "description": d.get("description"),
        "personality": d.get("personality"),
        "ip_address": d.get("ip_address"),
        "live": d.get("live"),
        "mac_address": d.get("mac"),
        "uptime": d.get("uptime")
    } for d in devices]
    
    return {"count": len(device_list), "devices": device_list}

@mcp.tool()
def get_device_info(device_id: Optional[str] = None, device_name: Optional[str] = None) -> Dict:
    """Get detailed device information"""
    device_id = _find_device(device_id, device_name)
    _log(f"Getting info for device: {device_id}")
    
    result = _api_call("GET", "/api/v1/device/info", params={
        "auth_token": _auth_token(),
        "node_id": device_id
    })
    
    if result.get("result") != "success":
        raise RuntimeError(f"Get device info failed: {result.get('message', result)}")
    
    return {"device_id": device_id, "device": result.get("device", {}), "raw_response": result}

@mcp.tool()
def configure_device_personality(device_id: str, personality: str) -> Dict:
    """
    Configure device personality.
    Options: windows, linux, osx-fileshare, network
    """
    _log(f"Configure personality: {device_id} -> {personality}")
    
    result = _api_call("POST", "/api/v1/device/configure_personality", data={
        "auth_token": _auth_token(),
        "node_id": device_id,
        "personality": personality
    })
    
    if result.get("result") != "success":
        raise RuntimeError(f"Configure personality failed: {result.get('message', result)}")
    
    _log("Personality configured successfully!")
    return {"device_id": device_id, "personality": personality, "status": "success", "raw_response": result}

@mcp.tool()
def update_device_description(device_id: str, description: str) -> Dict:
    """Update device description"""
    _log(f"Update description: {device_id}")
    
    update_tag = _get_update_tag(device_id)
    result = _api_call("POST", "/api/v1/device/update", data={
        "auth_token": _auth_token(),
        "node_id": device_id,
        "update_tag": update_tag,
        "device.desc": description
    })
    
    if result.get("result") != "success":
        raise RuntimeError(f"Description update failed: {result.get('message', result)}")
    
    _log("Description updated successfully!")
    return {"device_id": device_id, "description": description, "status": "success", "raw_response": result}

@mcp.tool()
def reboot_device(device_id: str) -> Dict:
    """Reboot a Canary device"""
    _log(f"Rebooting device: {device_id}")
    
    result = _api_call("POST", "/api/v1/device/reboot", data={
        "auth_token": _auth_token(),
        "node_id": device_id
    })
    
    if result.get("result") != "success":
        raise RuntimeError(f"Reboot failed: {result.get('message', result)}")
    
    _log("Device reboot initiated!")
    return {"device_id": device_id, "status": "rebooting", "raw_response": result}

@mcp.tool()
def configure_device_from_prompt(prompt: str) -> Dict:
    """
    Configure a Canary device from natural language.
    Example: "Configure my Canary01 as a Windows file server"
    """
    _log(f"Configure from prompt: {prompt}")
    
    # Extract device name
    patterns = [
        r'\bmy\s+(\S+)',
        r'\b(?:device|canary|bird)\s+(?:named|called)\s+(\S+)',
        r'\b(Canary\w+)'
    ]
    device_name = None
    for pattern in patterns:
        match = re.search(pattern, prompt, re.IGNORECASE)
        if match:
            device_name = match.group(1)
            break
    
    if not device_name:
        raise RuntimeError("Could not identify device name in prompt")
    
    device_id = _find_device(device_name=device_name)
    _log(f"Found device ID: {device_id}")
    
    # Infer personality
    prompt_lower = prompt.lower()
    personality_map = {
        "windows": ["windows", "win", "smb", "file server", "fileshare", "cifs"],
        "osx-fileshare": ["mac", "osx", "apple", "macos"],
        "linux": ["linux", "unix", "ssh"],
        "network": ["network", "cisco", "router", "switch"]
    }
    
    personality = "windows"  # default
    for p, keywords in personality_map.items():
        if any(word in prompt_lower for word in keywords):
            personality = p
            break
    
    _log(f"Inferred personality: {personality}")
    result = configure_device_personality(device_id, personality)
    
    # Extract and update description if specified
    desc_match = re.search(r'description\s+["\']([^"\']+)["\']', prompt, re.IGNORECASE)
    if desc_match:
        description = desc_match.group(1)
        update_device_description(device_id, description)
        result["description_updated"] = True
        result["description"] = description
    
    return result

@mcp.tool()
def get_device_settings(device_id: Optional[str] = None, device_name: Optional[str] = None) -> Dict:
    """Get all device configuration settings"""
    device_id = _find_device(device_id, device_name)
    _log(f"Getting settings for: {device_id}")
    
    result = _api_call("GET", "/api/v1/device/info", params={
        "auth_token": _auth_token(),
        "node_id": device_id,
        "settings": "true"
    })
    
    if result.get("result") != "success":
        raise RuntimeError(f"Get settings failed: {result.get('message', result)}")
    
    device = result.get("device", {})
    return {
        "device_id": device_id,
        "device_name": device.get("name"),
        "settings": device.get("settings", {}),
        "update_tag": device.get("update_tag")
    }

@mcp.tool()
def update_device_settings(device_id: str, settings: Dict) -> Dict:
    """Update full device settings object"""
    _log(f"Updating settings for: {device_id}")
    
    update_tag = _get_update_tag(device_id)
    payload = {
        "auth_token": _auth_token(),
        "node_id": device_id,
        "update_tag": update_tag
    }
    payload.update(_flatten_dict(settings))
    
    result = _api_call("POST", "/api/v1/device/update", data=payload)
    if result.get("result") != "success":
        raise RuntimeError(f"Settings update failed: {result.get('message', result)}")
    
    _log("Settings updated successfully!")
    return {"device_id": device_id, "status": "success", "settings_updated": len(settings), "raw_response": result}

@mcp.tool()
def update_device_setting(device_id: str, setting_key: str, value: Any) -> Dict:
    """
    Update single device setting using dot notation.
    Examples: 'device.name', 'ssh.instances.0.enabled', 'smb.enabled'
    """
    _log(f"Update setting: {device_id} -> {setting_key} = {value}")
    
    update_tag = _get_update_tag(device_id)
    result = _api_call("POST", "/api/v1/device/update", data={
        "auth_token": _auth_token(),
        "node_id": device_id,
        "update_tag": update_tag,
        setting_key: _format_value(value)
    })
    
    if result.get("result") != "success":
        raise RuntimeError(f"Setting update failed: {result.get('message', result)}")
    
    _log("Setting updated successfully!")
    return {"device_id": device_id, "setting_key": setting_key, "value": value, "status": "success", "raw_response": result}

# ============================================================================
# FLOCK MANAGEMENT
# ============================================================================

@mcp.tool()
def list_flocks() -> Dict:
    """List all Flocks (device groupings)"""
    _log("LISTING ALL FLOCKS")
    
    result = _api_call("GET", "/api/v1/flocks/list", params={"auth_token": _auth_token()})
    if result.get("result") != "success":
        raise RuntimeError(f"List flocks failed: {result.get('message', result)}")
    
    flocks = result.get("flocks", [])
    flock_list = [{
        "id": f.get("id"),
        "name": f.get("name"),
        "note": f.get("note"),
        "device_count": len(f.get("devices", []))
    } for f in flocks]
    
    return {"count": len(flock_list), "flocks": flock_list}

# ============================================================================
# CANARYTOKEN MANAGEMENT
# ============================================================================

@mcp.tool()
def list_canarytokens(flock_id: Optional[str] = None) -> Dict:
    """List all Canarytokens"""
    _log("LISTING ALL CANARYTOKENS")
    
    params = {"auth_token": _auth_token()}
    if flock_id:
        params["flock_id"] = flock_id
    
    result = _api_call("GET", "/api/v1/canarytokens/fetch", params=params)
    if result.get("result") != "success":
        raise RuntimeError(f"List tokens failed: {result.get('message', result)}")
    
    tokens = result.get("tokens", [])
    type_counts = {}
    
    token_list = []
    for t in tokens:
        token_list.append({
            "token_id": t.get("canarytoken"),
            "kind": t.get("kind"),
            "memo": t.get("memo"),
            "enabled": t.get("enabled"),
            "triggered_count": t.get("triggered_count", 0),
            "created": t.get("created"),
            "created_printable": t.get("created_printable"),
            "url": t.get("url"),
            "hostname": t.get("hostname")
        })
        kind = t.get("kind", "unknown")
        type_counts[kind] = type_counts.get(kind, 0) + 1
    
    return {"total_count": len(token_list), "tokens": token_list, "summary_by_type": type_counts}

@mcp.tool()
def get_canarytokens_summary() -> Dict:
    """Get summary of Canarytokens by type"""
    tokens_result = list_canarytokens()
    
    type_names = {
        "doc-msword": "Word Documents",
        "msexcel-macro": "Excel Spreadsheets",
        "pdf-acrobat-reader": "PDF Documents",
        "web": "Web URLs",
        "dns": "DNS Tokens",
        "smtp": "Email Tokens",
        "aws-id": "AWS Keys",
        "qr-code": "QR Codes",
        "clonedsite": "Cloned Sites"
    }
    
    by_type = [
        {"type": kind, "name": type_names.get(kind, kind), "count": count}
        for kind, count in tokens_result["summary_by_type"].items()
    ]
    by_type.sort(key=lambda x: x["count"], reverse=True)
    
    return {"total_tokens": tokens_result["total_count"], "by_type": by_type}

@mcp.tool()
def create_canarytoken(
    kind: str,
    memo: str,
    flock_id: Optional[str] = None,
    custom_domain: Optional[str] = None
) -> Dict:
    """
    Create a Canarytoken.
    Kinds: doc-msword, msexcel-macro, pdf-acrobat-reader, web, dns, smtp, aws-id, qr-code, clonedsite
    """
    _log(f"Creating {kind} token: {memo}")
    
    data = {
        "auth_token": _auth_token(),
        "kind": kind,
        "memo": memo
    }
    if flock_id:
        data["flock_id"] = flock_id
    if custom_domain:
        data["custom_domain"] = custom_domain
    
    result = _api_call("POST", "/api/v1/canarytoken/create", data=data)
    if result.get("result") != "success":
        raise RuntimeError(f"Create failed: {result.get('message', result)}")
    
    token_obj = result.get("canarytoken", {})
    token_id = token_obj.get("canarytoken")
    if not token_id:
        raise RuntimeError(f"No token_id in response: {result}")
    
    _log(f"Token created: {token_id}")
    return {
        "token_id": token_id,
        "kind": token_obj.get("kind"),
        "url": token_obj.get("url"),
        "hostname": token_obj.get("hostname"),
        "raw": result
    }

# Convenience functions for specific token types
@mcp.tool()
def create_word_token(memo: str, flock_id: Optional[str] = None, custom_domain: Optional[str] = None) -> Dict:
    """Create Word document token"""
    return create_canarytoken("doc-msword", memo, flock_id, custom_domain)

@mcp.tool()
def create_excel_token(memo: str, flock_id: Optional[str] = None, custom_domain: Optional[str] = None) -> Dict:
    """Create Excel spreadsheet token"""
    return create_canarytoken("msexcel-macro", memo, flock_id, custom_domain)

@mcp.tool()
def create_pdf_token(memo: str, flock_id: Optional[str] = None, custom_domain: Optional[str] = None) -> Dict:
    """Create PDF document token"""
    return create_canarytoken("pdf-acrobat-reader", memo, flock_id, custom_domain)

@mcp.tool()
def create_dns_token(memo: str, flock_id: Optional[str] = None) -> Dict:
    """Create DNS token"""
    return create_canarytoken("dns", memo, flock_id)

@mcp.tool()
def create_web_token(memo: str, flock_id: Optional[str] = None) -> Dict:
    """Create Web/URL token"""
    return create_canarytoken("web", memo, flock_id)

@mcp.tool()
def create_token_from_prompt(
    prompt: str,
    flock_id: Optional[str] = None,
    custom_domain: Optional[str] = None,
    output_dir: str = "/mnt/user-data/outputs"
) -> Dict:
    """
    Create Canarytoken from natural language.
    Auto-downloads file-based tokens.
    """
    _log(f"Create token from prompt: {prompt}")
    
    # Infer token kind
    prompt_lower = prompt.lower()
    kind_map = {
        "doc-msword": ["word", "doc", "document", ".docx"],
        "msexcel-macro": ["excel", "spreadsheet", ".xlsx", "xls"],
        "pdf-acrobat-reader": ["pdf", ".pdf"],
        "web": ["url", "web", "link", "http"],
        "dns": ["dns", "domain"],
        "smtp": ["email", "mail", "smtp"],
        "aws-id": ["aws", "amazon", "s3"],
        "qr-code": ["qr", "qr code"],
        "clonedsite": ["cloned", "clone", "fake site"]
    }
    
    kind = "doc-msword"  # default
    for k, keywords in kind_map.items():
        if any(word in prompt_lower for word in keywords):
            kind = k
            break
    
    # Extract memo
    quoted = re.findall(r'["\'](.+?)["\']', prompt)
    if quoted:
        memo = quoted[0]
    else:
        memo = re.sub(r'\b(create|make|generate|build|token|canarytoken)\b', '', prompt, flags=re.IGNORECASE).strip()
        memo = memo[:97] + "..." if len(memo) > 100 else memo or "Canarytoken via MCP"
    
    _log(f"Inferred: kind={kind}, memo={memo}")
    
    response = create_canarytoken(kind, memo, flock_id, custom_domain)
    
    # Auto-download file-based tokens
    file_kinds = {"doc-msword": ".docx", "msexcel-macro": ".xlsx", "pdf-acrobat-reader": ".pdf"}
    if kind in file_kinds:
        try:
            filename = _safe_filename(memo) + file_kinds[kind]
            download_result = download_token_file(response["token_id"], output_dir, filename)
            response["file_path"] = download_result["path"]
            response["file_size"] = download_result["size_bytes"]
        except Exception as e:
            _log(f"WARNING: Download failed: {e}")
            response["download_error"] = str(e)
    
    return response

@mcp.tool()
def download_token_file(token_id: str, output_dir: str, filename_hint: Optional[str] = None) -> Dict:
    """Download token file (Word, Excel, PDF, etc.)"""
    _log(f"Downloading token file: {token_id}")
    
    b = _get_bytes("/api/v1/canarytoken/download", {
        "auth_token": _auth_token(),
        "canarytoken": token_id
    })
    
    out_dir = pathlib.Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    base = filename_hint or f"canarytoken_{token_id}.docx"
    base = _safe_filename(base)
    if not base.lower().endswith((".docx", ".xlsx", ".pdf")):
        base += ".docx"
    
    out_path = out_dir / base
    out_path.write_bytes(b)
    
    _log(f"File saved: {out_path}")
    return {"token_id": token_id, "path": str(out_path), "size_bytes": len(b)}

@mcp.tool()
def set_token_enabled(token_id: str, enabled: bool) -> Dict:
    """Enable or disable a Canarytoken"""
    endpoint = "/api/v1/canarytoken/enable" if enabled else "/api/v1/canarytoken/disable"
    result = _api_call("POST", endpoint, data={
        "auth_token": _auth_token(),
        "canarytoken": token_id
    })
    
    if result.get("result") != "success":
        raise RuntimeError(f"Enable/disable failed: {result.get('message', result)}")
    
    return {"token_id": token_id, "enabled": enabled, "raw": result}

@mcp.tool()
def delete_canarytoken(token_id: str) -> Dict:
    """Delete a Canarytoken"""
    _log(f"Deleting token: {token_id}")
    
    result = _api_call("POST", "/api/v1/canarytoken/delete", data={
        "auth_token": _auth_token(),
        "canarytoken": token_id
    })
    
    if result.get("result") != "success":
        raise RuntimeError(f"Delete failed: {result.get('message', result)}")
    
    return {"token_id": token_id, "status": "deleted", "raw": result}

@mcp.tool()
def list_token_types() -> Dict:
    """List supported Canarytoken types"""
    return {
        "supported_types": {
            "doc-msword": "Microsoft Word document",
            "msexcel-macro": "Microsoft Excel spreadsheet",
            "pdf-acrobat-reader": "Adobe PDF document",
            "web": "Web URL",
            "dns": "DNS query",
            "smtp": "Email token",
            "aws-id": "AWS API key",
            "qr-code": "QR code",
            "clonedsite": "Cloned website"
        },
        "usage": "Use create_canarytoken(kind, memo) or natural language with create_token_from_prompt()"
    }

# ============================================================================
# FACTORY MANAGEMENT
# ============================================================================

@mcp.tool()
def list_factory_token_types() -> Dict:
    """List factory-available token types"""
    result = _api_call("GET", "/api/v1/canarytokens/factory/list", params={"auth_token": _auth_token()})
    if result.get("result") != "success":
        raise RuntimeError(f"List factory types failed: {result.get('message', result)}")
    
    factory_types = result.get("factory_canarytokens", {})
    return {"count": len(factory_types), "factory_types": factory_types, "raw_response": result}

@mcp.tool()
def create_token_factory(
    factory_auth: str,
    flock_id: Optional[str] = None,
    memo: Optional[str] = None,
    kind: Optional[str] = None
) -> Dict:
    """Create token factory for bulk generation"""
    _log(f"Creating factory: {factory_auth}")
    
    data = {"auth_token": _auth_token(), "factory_auth": factory_auth}
    if flock_id:
        data["flock_id"] = flock_id
    if memo:
        data["memo"] = memo
    if kind:
        data["kind"] = kind
    
    result = _api_call("POST", "/api/v1/canarytoken/create_factory", data=data)
    if result.get("result") != "success":
        raise RuntimeError(f"Create factory failed: {result.get('message', result)}")
    
    return {"factory_auth": factory_auth, "factory": result.get("factory", {}), "raw_response": result}

@mcp.tool()
def list_token_factories() -> Dict:
    """List all token factories"""
    result = _api_call("GET", "/api/v1/canarytoken/list_factories", params={"auth_token": _auth_token()})
    if result.get("result") != "success":
        raise RuntimeError(f"List factories failed: {result.get('message', result)}")
    
    factories = result.get("factories", [])
    factory_list = [{
        "factory_auth": f.get("factory_auth"),
        "memo": f.get("memo"),
        "kind": f.get("kind"),
        "flock_id": f.get("flock_id"),
        "created": f.get("created"),
        "created_printable": f.get("created_printable")
    } for f in factories]
    
    return {"count": len(factory_list), "factories": factory_list, "raw_response": result}

@mcp.tool()
def delete_token_factory(factory_auth: str) -> Dict:
    """Delete a token factory"""
    result = _api_call("POST", "/api/v1/canarytoken/delete_factory", data={
        "auth_token": _auth_token(),
        "factory_auth": factory_auth
    })
    
    if result.get("result") != "success":
        raise RuntimeError(f"Delete factory failed: {result.get('message', result)}")
    
    return {"factory_auth": factory_auth, "status": "deleted", "raw_response": result}

@mcp.tool()
def create_tokens_from_factory(
    factory_auth: str,
    count: int = 1,
    memo: Optional[str] = None,
    kind: Optional[str] = None
) -> Dict:
    """Create multiple tokens from factory"""
    _log(f"Creating {count} tokens from factory")
    
    data = {"factory_auth": factory_auth}
    if count:
        data["count"] = str(count)
    if memo:
        data["memo"] = memo
    if kind:
        data["kind"] = kind
    
    result = _api_call("POST", "/api/v1/canarytoken/factory/create", data=data)
    if result.get("result") != "success":
        raise RuntimeError(f"Create tokens failed: {result.get('message', result)}")
    
    tokens = result.get("tokens", [])
    return {"factory_auth": factory_auth, "count": len(tokens), "tokens": tokens, "raw_response": result}

@mcp.tool()
def download_factory_tokens(
    factory_auth: str,
    output_dir: str = "/mnt/user-data/outputs",
    filename: Optional[str] = None
) -> Dict:
    """Download factory tokens as ZIP"""
    _log(f"Downloading factory tokens: {factory_auth}")
    
    b = _get_bytes("/api/v1/canarytoken/factory/download", {
        "auth_token": _auth_token(),
        "factory_auth": factory_auth
    })
    
    out_dir = pathlib.Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    filename = filename or f"factory_tokens_{factory_auth[:8]}.zip"
    filename = _safe_filename(filename)
    if not filename.lower().endswith(".zip"):
        filename += ".zip"
    
    out_path = out_dir / filename
    out_path.write_bytes(b)
    
    _log(f"ZIP saved: {out_path} ({len(b)} bytes)")
    return {"factory_auth": factory_auth, "path": str(out_path), "size_bytes": len(b), "filename": filename}

# ============================================================================
# INCIDENT MANAGEMENT
# ============================================================================

@mcp.tool()
def list_incidents(
    incidents_since: Optional[str] = None,
    limit: int = 100,
    node_id: Optional[str] = None,
    flock_id: Optional[str] = None
) -> Dict:
    """List incidents/alerts"""
    _log("LISTING INCIDENTS")
    
    params = {"auth_token": _auth_token()}
    if incidents_since:
        params["incidents_since"] = incidents_since
    if limit:
        params["limit"] = str(limit)
    if node_id:
        params["node_id"] = node_id
    if flock_id:
        params["flock_id"] = flock_id
    
    result = _api_call("GET", "/api/v1/incidents/all", params=params)
    if result.get("result") != "success":
        raise RuntimeError(f"List incidents failed: {result.get('message', result)}")
    
    incidents = result.get("incidents", [])
    incident_list = [{
        "id": i.get("id"),
        "summary": i.get("summary"),
        "description": i.get("description"),
        "created": i.get("created"),
        "created_printable": i.get("created_printable"),
        "updated": i.get("updated"),
        "updated_printable": i.get("updated_printable"),
        "node_id": i.get("node_id"),
        "device_name": i.get("device", {}).get("name"),
        "src_host": i.get("src_host"),
        "dst_port": i.get("dst_port"),
        "logtype": i.get("logtype")
    } for i in incidents]
    
    return {"count": len(incident_list), "incidents": incident_list, "raw_response": result}

@mcp.tool()
def get_incident_details(incident_id: str) -> Dict:
    """Get detailed incident information"""
    result = _api_call("GET", "/api/v1/incident/get", params={
        "auth_token": _auth_token(),
        "incident": incident_id
    })
    
    if result.get("result") != "success":
        raise RuntimeError(f"Get incident failed: {result.get('message', result)}")
    
    return {"incident_id": incident_id, "incident": result.get("incident", {}), "raw_response": result}

@mcp.tool()
def acknowledge_incident(incident_id: str) -> Dict:
    """Acknowledge an incident"""
    result = _api_call("POST", "/api/v1/incident/acknowledge", data={
        "auth_token": _auth_token(),
        "incident": incident_id
    })
    
    if result.get("result") != "success":
        raise RuntimeError(f"Acknowledge failed: {result.get('message', result)}")
    
    return {"incident_id": incident_id, "status": "acknowledged", "raw_response": result}

@mcp.tool()
def unacknowledge_incident(incident_id: str) -> Dict:
    """Unacknowledge an incident"""
    result = _api_call("POST", "/api/v1/incident/unacknowledge", data={
        "auth_token": _auth_token(),
        "incident": incident_id
    })
    
    if result.get("result") != "success":
        raise RuntimeError(f"Unacknowledge failed: {result.get('message', result)}")
    
    return {"incident_id": incident_id, "status": "unacknowledged", "raw_response": result}

# ============================================================================
# MAIN
# ============================================================================

def main() -> None:
    """Run MCP server in stdio mode"""
    _log("=" * 60)
    _log("Canary Console MCP Server - Enhanced & Efficient")
    _log("=" * 60)
    
    try:
        domain = os.environ.get("CANARY_DOMAIN", "")
        token = os.environ.get("CANARY_AUTH_TOKEN", "")
        _log(f"CANARY_DOMAIN: {domain or 'NOT SET'}")
        _log(f"CANARY_AUTH_TOKEN: {'SET' if token else 'NOT SET'} ({len(token)} chars)")
    except Exception as e:
        _log(f"Environment check error: {e}")
    
    _log("=" * 60)
    _log("Server ready - awaiting connections")
    _log("=" * 60)
    
    mcp.run()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        _log(f"FATAL ERROR: {e}")
        raise
