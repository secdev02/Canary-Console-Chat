import os
import sys
import json
import pathlib
import requests
import re
from datetime import datetime

from mcp.server.fastmcp import FastMCP

# MCP server (stdio)
mcp = FastMCP("canary-console-mcp", json_response=True)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _log(message: str) -> None:
    """Log to stderr (stdout is reserved for JSON-RPC in stdio mode)"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("[" + timestamp + "] " + message, file=sys.stderr)


def _must_env(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise RuntimeError("Missing required env var: " + name)
    return v


def _base_url() -> str:
    domain = _must_env("CANARY_DOMAIN")
    url = "https://" + domain
    _log("Using Canary Console: " + url)
    return url


def _auth_token() -> str:
    token = _must_env("CANARY_AUTH_TOKEN")
    _log("Auth token loaded (length: " + str(len(token)) + ")")
    return token


def _post_form(path: str, data: dict) -> dict:
    url = _base_url() + path
    _log("POST " + url + " with data keys: " + str(list(data.keys())))
    resp = requests.post(url, data=data, timeout=30)
    _log("Response status: " + str(resp.status_code))
    
    try:
        result = resp.json()
        _log("Response result: " + result.get("result", "unknown"))
        return result
    except Exception as e:
        _log("ERROR: Non-JSON response: " + str(e))
        raise RuntimeError("Non-JSON response from " + url + ": HTTP " + str(resp.status_code) + " " + resp.text[:500])


def _get_json(path: str, params: dict) -> dict:
    """GET request that returns JSON"""
    url = _base_url() + path
    _log("GET " + url + " with params: " + str(list(params.keys())))
    resp = requests.get(url, params=params, timeout=30)
    _log("Response status: " + str(resp.status_code))
    
    try:
        result = resp.json()
        _log("Response result: " + result.get("result", "unknown"))
        return result
    except Exception as e:
        _log("ERROR: Non-JSON response: " + str(e))
        raise RuntimeError("Non-JSON response from " + url + ": HTTP " + str(resp.status_code) + " " + resp.text[:500])


def _get_bytes(path: str, params: dict) -> bytes:
    url = _base_url() + path
    _log("GET " + url + " with params: " + str(params.keys()))
    resp = requests.get(url, params=params, allow_redirects=True, timeout=60)
    
    if not resp.ok:
        _log("ERROR: Download failed with status " + str(resp.status_code))
        raise RuntimeError("Download failed: HTTP " + str(resp.status_code) + " " + resp.text[:500])
    
    _log("Downloaded " + str(len(resp.content)) + " bytes")
    return resp.content


def _safe_filename(name: str) -> str:
    """Conservative filename sanitizer"""
    keep = []
    for ch in name:
        if ch.isalnum() or ch in " ._-()+[]":
            keep.append(ch)
        else:
            keep.append("_")
    return "".join(keep)[:180]


# ============================================================================
# DEVICE MANAGEMENT TOOLS
# ============================================================================

@mcp.tool()
def list_devices() -> dict:
    """
    List all Canary devices in the console.
    Returns device information including names, IDs, personalities, and IP addresses.
    """
    _log("=" * 60)
    _log("LISTING ALL DEVICES")
    _log("=" * 60)
    
    result = _get_json("/api/v1/devices/all", {
        "auth_token": _auth_token()
    })
    
    if result.get("result") != "success":
        raise RuntimeError("List devices failed: " + (result.get("message") or json.dumps(result)))
    
    devices = result.get("devices", [])
    _log("Found " + str(len(devices)) + " devices")
    
    device_list = []
    for device in devices:
        device_info = {
            "id": device.get("id"),
            "name": device.get("name"),
            "description": device.get("description"),
            "personality": device.get("personality"),
            "ip_address": device.get("ip_address"),
            "live": device.get("live"),
            "mac_address": device.get("mac"),
            "uptime": device.get("uptime")
        }
        device_list.append(device_info)
        _log("  Device: " + str(device_info["name"]) + " (ID: " + str(device_info["id"]) + ", Personality: " + str(device_info["personality"]) + ")")
    
    return {
        "count": len(device_list),
        "devices": device_list
    }


@mcp.tool()
def get_device_info(device_id: str = None, device_name: str = None) -> dict:
    """
    Get detailed information for a specific Canary device.
    Specify either device_id or device_name.
    """
    if not device_id and not device_name:
        raise RuntimeError("Must specify either device_id or device_name")
    
    # If only name provided, look up the ID
    if not device_id:
        devices_result = list_devices()
        for device in devices_result["devices"]:
            if device["name"] and device_name.lower() in device["name"].lower():
                device_id = device["id"]
                break
        
        if not device_id:
            raise RuntimeError("Device '" + device_name + "' not found")
    
    _log("Getting info for device: " + device_id)
    
    result = _get_json("/api/v1/device/info", {
        "auth_token": _auth_token(),
        "node_id": device_id
    })
    
    if result.get("result") != "success":
        raise RuntimeError("Get device info failed: " + (result.get("message") or json.dumps(result)))
    
    device = result.get("device", {})
    
    return {
        "device_id": device_id,
        "device": device,
        "raw_response": result
    }


@mcp.tool()
def configure_device_personality(device_id: str, personality: str) -> dict:
    """
    Configure a Canary device's personality.
    
    Uses the correct API endpoint: /api/v1/device/configure_personality
    Docs: https://docs.canary.tools/bird-management/service-configuration.html
    
    Args:
        device_id: The node_id of the device to configure
        personality: The personality to set - options:
            - 'windows' - Windows server
            - 'linux' - Linux server
            - 'osx-fileshare' - Mac file share
            - 'network' - Network device (router/switch)
    
    Returns:
        dict: Configuration result
    """
    _log("=" * 60)
    _log("CONFIGURE DEVICE PERSONALITY")
    _log("Device ID: " + device_id)
    _log("Personality: " + personality)
    _log("=" * 60)
    
    payload = {
        "auth_token": _auth_token(),
        "node_id": device_id,
        "personality": personality
    }
    
    result = _post_form("/api/v1/device/configure_personality", payload)
    
    if result.get("result") != "success":
        error_msg = result.get("message") or json.dumps(result)
        _log("ERROR: Configure personality failed: " + error_msg)
        raise RuntimeError("Configure personality failed: " + error_msg)
    
    _log("Personality configured successfully!")
    _log("=" * 60)
    
    return {
        "device_id": device_id,
        "personality": personality,
        "status": "success",
        "raw_response": result
    }


@mcp.tool()
def update_device_description(device_id: str, description: str) -> dict:
    """
    Update a Canary device's description.
    
    Args:
        device_id: The node_id of the device
        description: New description text
    
    Returns:
        dict: Update result
    """
    _log("=" * 60)
    _log("UPDATE DEVICE DESCRIPTION")
    _log("Device ID: " + device_id)
    _log("Description: " + description)
    _log("=" * 60)
    
    # Get current device info to obtain update_tag
    _log("Fetching current device info to get update_tag...")
    device_info_result = _get_json("/api/v1/device/info", {
        "auth_token": _auth_token(),
        "node_id": device_id
    })
    
    if device_info_result.get("result") != "success":
        raise RuntimeError("Failed to get device info: " + (device_info_result.get("message") or json.dumps(device_info_result)))
    
    device = device_info_result.get("device", {})
    update_tag = device.get("update_tag")
    
    if not update_tag:
        raise RuntimeError("Could not retrieve update_tag from device info")
    
    _log("Got update_tag: " + update_tag)
    
    # Update description
    payload = {
        "auth_token": _auth_token(),
        "node_id": device_id,
        "update_tag": update_tag,
        "device.desc": description
    }
    
    result = _post_form("/api/v1/device/update", payload)
    
    if result.get("result") != "success":
        error_msg = result.get("message") or json.dumps(result)
        _log("ERROR: Description update failed: " + error_msg)
        raise RuntimeError("Description update failed: " + error_msg)
    
    _log("Description updated successfully!")
    _log("=" * 60)
    
    return {
        "device_id": device_id,
        "description": description,
        "status": "success",
        "raw_response": result
    }


@mcp.tool()
def reboot_device(device_id: str) -> dict:
    """
    Reboot a Canary device.
    
    Args:
        device_id: The node_id of the device to reboot
    
    Returns:
        dict: Reboot result
    """
    _log("=" * 60)
    _log("REBOOTING DEVICE: " + device_id)
    _log("=" * 60)
    
    result = _post_form("/api/v1/device/reboot", {
        "auth_token": _auth_token(),
        "node_id": device_id
    })
    
    if result.get("result") != "success":
        error_msg = result.get("message") or json.dumps(result)
        _log("ERROR: Reboot failed: " + error_msg)
        raise RuntimeError("Reboot failed: " + error_msg)
    
    _log("Device reboot initiated successfully!")
    _log("=" * 60)
    
    return {
        "device_id": device_id,
        "status": "rebooting",
        "raw_response": result
    }


def _infer_device_personality(prompt: str) -> str:
    """Infer the device personality from a natural language prompt."""
    prompt_lower = prompt.lower()
    
    if any(word in prompt_lower for word in ["windows", "win", "smb", "file server", "fileshare", "cifs"]):
        return "windows"
    elif any(word in prompt_lower for word in ["mac", "osx", "apple", "macos"]):
        return "osx-fileshare"
    elif any(word in prompt_lower for word in ["linux", "unix", "ssh"]):
        return "linux"
    elif any(word in prompt_lower for word in ["network", "cisco", "router", "switch"]):
        return "network"
    else:
        _log("No specific personality detected, defaulting to windows")
        return "windows"


def _extract_device_name(prompt: str) -> str:
    """Extract device name from prompt."""
    # Pattern: "my CanaryXX" or "Canary XX"
    match = re.search(r'\bmy\s+(\S+)', prompt, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Try "device named/called XX"
    match = re.search(r'\b(?:device|canary|bird)\s+(?:named|called)\s+(\S+)', prompt, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Try just "CanaryXX" pattern
    match = re.search(r'\b(Canary\w+)', prompt, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None


@mcp.tool()
def configure_device_from_prompt(prompt: str) -> dict:
    """
    Configure a Canary device based on a natural language prompt.
    
    Examples:
    - "Configure my Canary01 as a Windows file server"
    - "Set up device Canary-Lab as a Linux SSH server"
    - "Make my Canary02 look like an OSX file share"
    - "Update my CanaryTest to be a network device with description 'Test Router'"
    
    The function will:
    1. Find the device by name
    2. Infer the desired personality
    3. Apply the configuration
    4. Update description if specified
    
    Args:
        prompt: Natural language description of desired configuration
    
    Returns:
        dict: Configuration result
    """
    _log("=" * 60)
    _log("CONFIGURE DEVICE FROM PROMPT: " + prompt)
    _log("=" * 60)
    
    # Extract device name
    device_name = _extract_device_name(prompt)
    if not device_name:
        raise RuntimeError("Could not identify device name in prompt. Please specify like 'my Canary01' or 'device named XYZ'")
    
    _log("Target device: " + device_name)
    
    # Get list of devices to find the ID
    devices_result = list_devices()
    target_device = None
    
    for device in devices_result["devices"]:
        if device["name"] and device_name.lower() in device["name"].lower():
            target_device = device
            break
    
    if not target_device:
        available = [d["name"] for d in devices_result["devices"]]
        raise RuntimeError("Device '" + device_name + "' not found. Available devices: " + str(available))
    
    _log("Found device ID: " + target_device["id"])
    
    # Infer personality from prompt
    personality = _infer_device_personality(prompt)
    _log("Inferred personality: " + personality)
    
    # Configure the personality using the CORRECT endpoint
    result = configure_device_personality(target_device["id"], personality)
    
    # Extract description if specified
    description = None
    desc_patterns = [
        r'description\s+["\']([^"\']+)["\']',
        r'(?:set|with)\s+description\s+["\']([^"\']+)["\']'
    ]
    
    for pattern in desc_patterns:
        match = re.search(pattern, prompt, re.IGNORECASE)
        if match:
            description = match.group(1)
            _log("Extracted description: " + description)
            break
    
    # Update description if specified
    if description:
        desc_result = update_device_description(target_device["id"], description)
        result["description_updated"] = True
        result["description"] = description
    
    _log("=" * 60)
    return result


# ============================================================================
# FLOCK MANAGEMENT TOOLS
# ============================================================================

@mcp.tool()
def list_flocks() -> dict:
    """
    List all Flocks (device groupings) in the console.
    Returns flock information including names, IDs, and notes.
    """
    _log("=" * 60)
    _log("LISTING ALL FLOCKS")
    _log("=" * 60)
    
    result = _get_json("/api/v1/flocks/list", {
        "auth_token": _auth_token()
    })
    
    if result.get("result") != "success":
        raise RuntimeError("List flocks failed: " + (result.get("message") or json.dumps(result)))
    
    flocks = result.get("flocks", [])
    _log("Found " + str(len(flocks)) + " flocks")
    
    flock_list = []
    for flock in flocks:
        flock_info = {
            "id": flock.get("id"),
            "name": flock.get("name"),
            "note": flock.get("note"),
            "device_count": len(flock.get("devices", []))
        }
        flock_list.append(flock_info)
        _log("  Flock: " + str(flock_info["name"]) + " (ID: " + str(flock_info["id"]) + ", Devices: " + str(flock_info["device_count"]) + ")")
    
    return {
        "count": len(flock_list),
        "flocks": flock_list
    }


# ============================================================================
# CANARYTOKEN MANAGEMENT TOOLS
# ============================================================================

@mcp.tool()
def list_canarytokens(flock_id: str = None) -> dict:
    """
    List all Canarytokens in the console.
    Returns detailed information about each token including type, memo, status, and trigger count.
    
    Args:
        flock_id: Optional flock ID to filter results
    
    Returns:
        dict: List of tokens with summary statistics
    """
    _log("=" * 60)
    _log("LISTING ALL CANARYTOKENS")
    _log("=" * 60)
    
    params = {
        "auth_token": _auth_token()
    }
    
    if flock_id:
        params["flock_id"] = flock_id
        _log("Filtering by flock_id: " + flock_id)
    
    result = _get_json("/api/v1/canarytokens/fetch", params)
    
    if result.get("result") != "success":
        raise RuntimeError("List canarytokens failed: " + (result.get("message") or json.dumps(result)))
    
    tokens = result.get("tokens", [])
    _log("Found " + str(len(tokens)) + " canarytokens")
    
    token_list = []
    type_counts = {}
    
    for token in tokens:
        token_info = {
            "token_id": token.get("canarytoken"),
            "kind": token.get("kind"),
            "memo": token.get("memo"),
            "enabled": token.get("enabled"),
            "triggered_count": token.get("triggered_count", 0),
            "created": token.get("created"),
            "created_printable": token.get("created_printable"),
            "url": token.get("url"),
            "hostname": token.get("hostname")
        }
        token_list.append(token_info)
        
        # Count by type
        kind = token.get("kind", "unknown")
        type_counts[kind] = type_counts.get(kind, 0) + 1
    
    return {
        "total_count": len(token_list),
        "tokens": token_list,
        "summary_by_type": type_counts
    }


@mcp.tool()
def get_canarytokens_summary() -> dict:
    """
    Get a summary of Canarytokens grouped by type and count.
    Useful for quick overview of token deployment.
    """
    _log("Getting canarytokens summary")
    
    # Get all tokens
    tokens_result = list_canarytokens()
    
    summary = {
        "total_tokens": tokens_result["total_count"],
        "by_type": []
    }
    
    # Create readable summary
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
    
    for kind, count in tokens_result["summary_by_type"].items():
        readable_name = type_names.get(kind, kind)
        summary["by_type"].append({
            "type": kind,
            "name": readable_name,
            "count": count
        })
    
    # Sort by count descending
    summary["by_type"].sort(key=lambda x: x["count"], reverse=True)
    
    return summary


def _infer_token_kind(prompt: str) -> str:
    """Infer the Canarytoken kind from a natural language prompt."""
    prompt_lower = prompt.lower()
    
    if any(word in prompt_lower for word in ["word", "doc", "document", ".docx"]):
        return "doc-msword"
    elif any(word in prompt_lower for word in ["excel", "spreadsheet", ".xlsx", "xls"]):
        return "msexcel-macro"
    elif any(word in prompt_lower for word in ["pdf", ".pdf"]):
        return "pdf-acrobat-reader"
    elif any(word in prompt_lower for word in ["url", "web", "link", "http"]):
        return "web"
    elif any(word in prompt_lower for word in ["dns", "domain"]):
        return "dns"
    elif any(word in prompt_lower for word in ["email", "mail", "smtp"]):
        return "smtp"
    elif any(word in prompt_lower for word in ["aws", "amazon", "s3"]):
        return "aws-id"
    elif any(word in prompt_lower for word in ["qr", "qr code"]):
        return "qr-code"
    elif any(word in prompt_lower for word in ["cloned", "clone", "fake site"]):
        return "clonedsite"
    else:
        # Default to Word doc as it's widely applicable
        _log("No specific token type detected, defaulting to doc-msword")
        return "doc-msword"


def _extract_memo(prompt: str) -> str:
    """Extract a reasonable memo from the prompt."""
    # Look for quoted text
    quoted = re.findall(r'["\'](.+?)["\']', prompt)
    if quoted:
        return quoted[0]
    
    # Otherwise clean and truncate the prompt
    memo = re.sub(r'\b(create|make|generate|build|token|canarytoken)\b', '', prompt, flags=re.IGNORECASE)
    memo = memo.strip()
    
    if len(memo) > 100:
        memo = memo[:97] + "..."
    
    return memo if memo else "Canarytoken created via MCP"


@mcp.tool()
def create_token_from_prompt(
    prompt: str,
    flock_id: str = None,
    custom_domain: str = None,
    output_dir: str = "/mnt/user-data/outputs"
) -> dict:
    """
    Create a Canarytoken based on a natural language prompt.
    Automatically infers the token type and creates it.
    For file-based tokens (Word, Excel, PDF), automatically downloads the file.
    
    Examples:
    - "Create a Word document token for the HR folder called 'Salary Review 2024'"
    - "Make a PDF token to detect document access"
    - "Generate a DNS token for subdomain monitoring"
    
    Args:
        prompt: Natural language description of the token to create
        flock_id: Optional flock ID to assign the token to
        custom_domain: Optional custom domain for the token
        output_dir: Directory to save downloaded files (default: /mnt/user-data/outputs)
    
    Returns:
        dict: Token creation result with download info for file-based tokens
    """
    _log("=" * 60)
    _log("CREATE TOKEN FROM PROMPT: " + prompt)
    
    # Infer token kind
    kind = _infer_token_kind(prompt)
    _log("Inferred token kind: " + kind)
    
    # Extract memo
    memo = _extract_memo(prompt)
    _log("Extracted memo: " + memo)
    
    # Create the token
    payload = {
        "auth_token": _auth_token(),
        "kind": kind,
        "memo": memo,
    }
    
    if flock_id:
        payload["flock_id"] = flock_id
        _log("Using flock_id: " + flock_id)
    
    if custom_domain:
        payload["custom_domain"] = custom_domain
        _log("Using custom_domain: " + custom_domain)
    
    result = _post_form("/api/v1/canarytoken/create", payload)
    
    if result.get("result") != "success":
        error_msg = result.get("message") or json.dumps(result)
        _log("ERROR: Create failed: " + error_msg)
        raise RuntimeError("Create failed: " + error_msg)
    
    token_obj = result.get("canarytoken") or {}
    token_id = token_obj.get("canarytoken")
    
    if not token_id:
        _log("ERROR: No token_id in response")
        raise RuntimeError("Create succeeded but no token id returned: " + json.dumps(result))
    
    _log("Token created successfully: " + token_id)
    
    response = {
        "token_id": token_id,
        "kind": kind,
        "memo": memo,
        "url": token_obj.get("url"),
        "hostname": token_obj.get("hostname"),
    }
    
    # For file-based tokens, automatically download
    file_kinds = ["doc-msword", "msexcel-macro", "pdf-acrobat-reader"]
    if kind in file_kinds:
        _log("File-based token detected, downloading...")
        try:
            extension_map = {
                "doc-msword": ".docx",
                "msexcel-macro": ".xlsx",
                "pdf-acrobat-reader": ".pdf"
            }
            ext = extension_map.get(kind, ".file")
            
            filename = _safe_filename(memo) + ext
            download_result = download_token_file(token_id, output_dir, filename)
            response["file_path"] = download_result["path"]
            response["file_size"] = download_result["size_bytes"]
            _log("File downloaded to: " + download_result["path"])
        except Exception as e:
            _log("WARNING: Failed to download file: " + str(e))
            response["download_error"] = str(e)
    
    _log("=" * 60)
    return response


@mcp.tool()
def create_word_token(memo: str, flock_id: str = None, custom_domain: str = None) -> dict:
    """
    Create a Microsoft Word Canarytoken (kind=doc-msword).
    
    Args:
        memo: Description/name for the token
        flock_id: Optional flock ID
        custom_domain: Optional custom domain
    
    Returns:
        dict: Token creation result
    """
    _log("Creating Word token with memo: " + memo)
    
    payload = {
        "auth_token": _auth_token(),
        "kind": "doc-msword",
        "memo": memo,
    }
    if flock_id:
        payload["flock_id"] = flock_id
    if custom_domain:
        payload["custom_domain"] = custom_domain

    result = _post_form("/api/v1/canarytoken/create", payload)

    if result.get("result") != "success":
        raise RuntimeError("Create failed: " + (result.get("message") or json.dumps(result)))

    token_obj = result.get("canarytoken") or {}
    token_id = token_obj.get("canarytoken")
    if not token_id:
        raise RuntimeError("Create succeeded but no token id returned: " + json.dumps(result))

    _log("Word token created: " + token_id)
    return {
        "token_id": token_id,
        "kind": token_obj.get("kind"),
        "url": token_obj.get("url"),
        "raw": result,
    }


@mcp.tool()
def create_excel_token(memo: str, flock_id: str = None, custom_domain: str = None) -> dict:
    """
    Create a Microsoft Excel Canarytoken (kind=msexcel-macro).
    
    Args:
        memo: Description/name for the token
        flock_id: Optional flock ID
        custom_domain: Optional custom domain
    
    Returns:
        dict: Token creation result
    """
    _log("Creating Excel token with memo: " + memo)
    
    payload = {
        "auth_token": _auth_token(),
        "kind": "msexcel-macro",
        "memo": memo,
    }
    if flock_id:
        payload["flock_id"] = flock_id
    if custom_domain:
        payload["custom_domain"] = custom_domain

    result = _post_form("/api/v1/canarytoken/create", payload)

    if result.get("result") != "success":
        raise RuntimeError("Create failed: " + (result.get("message") or json.dumps(result)))

    token_obj = result.get("canarytoken") or {}
    token_id = token_obj.get("canarytoken")
    if not token_id:
        raise RuntimeError("Create succeeded but no token id returned: " + json.dumps(result))

    _log("Excel token created: " + token_id)
    return {
        "token_id": token_id,
        "kind": token_obj.get("kind"),
        "url": token_obj.get("url"),
        "raw": result,
    }


@mcp.tool()
def create_pdf_token(memo: str, flock_id: str = None, custom_domain: str = None) -> dict:
    """
    Create a PDF Canarytoken (kind=pdf-acrobat-reader).
    
    Args:
        memo: Description/name for the token
        flock_id: Optional flock ID
        custom_domain: Optional custom domain
    
    Returns:
        dict: Token creation result
    """
    _log("Creating PDF token with memo: " + memo)
    
    payload = {
        "auth_token": _auth_token(),
        "kind": "pdf-acrobat-reader",
        "memo": memo,
    }
    if flock_id:
        payload["flock_id"] = flock_id
    if custom_domain:
        payload["custom_domain"] = custom_domain

    result = _post_form("/api/v1/canarytoken/create", payload)

    if result.get("result") != "success":
        raise RuntimeError("Create failed: " + (result.get("message") or json.dumps(result)))

    token_obj = result.get("canarytoken") or {}
    token_id = token_obj.get("canarytoken")
    if not token_id:
        raise RuntimeError("Create succeeded but no token id returned: " + json.dumps(result))

    _log("PDF token created: " + token_id)
    return {
        "token_id": token_id,
        "kind": token_obj.get("kind"),
        "url": token_obj.get("url"),
        "raw": result,
    }


@mcp.tool()
def create_dns_token(memo: str, flock_id: str = None) -> dict:
    """
    Create a DNS Canarytoken (kind=dns).
    
    Args:
        memo: Description/name for the token
        flock_id: Optional flock ID
    
    Returns:
        dict: Token creation result with hostname
    """
    _log("Creating DNS token with memo: " + memo)
    
    payload = {
        "auth_token": _auth_token(),
        "kind": "dns",
        "memo": memo,
    }
    if flock_id:
        payload["flock_id"] = flock_id

    result = _post_form("/api/v1/canarytoken/create", payload)

    if result.get("result") != "success":
        raise RuntimeError("Create failed: " + (result.get("message") or json.dumps(result)))

    token_obj = result.get("canarytoken") or {}
    token_id = token_obj.get("canarytoken")
    if not token_id:
        raise RuntimeError("Create succeeded but no token id returned: " + json.dumps(result))

    _log("DNS token created: " + token_id)
    return {
        "token_id": token_id,
        "kind": token_obj.get("kind"),
        "hostname": token_obj.get("hostname"),
        "raw": result,
    }


@mcp.tool()
def create_web_token(memo: str, flock_id: str = None) -> dict:
    """
    Create a Web/URL Canarytoken (kind=web).
    
    Args:
        memo: Description/name for the token
        flock_id: Optional flock ID
    
    Returns:
        dict: Token creation result with URL
    """
    _log("Creating Web token with memo: " + memo)
    
    payload = {
        "auth_token": _auth_token(),
        "kind": "web",
        "memo": memo,
    }
    if flock_id:
        payload["flock_id"] = flock_id

    result = _post_form("/api/v1/canarytoken/create", payload)

    if result.get("result") != "success":
        raise RuntimeError("Create failed: " + (result.get("message") or json.dumps(result)))

    token_obj = result.get("canarytoken") or {}
    token_id = token_obj.get("canarytoken")
    if not token_id:
        raise RuntimeError("Create succeeded but no token id returned: " + json.dumps(result))

    _log("Web token created: " + token_id)
    return {
        "token_id": token_id,
        "kind": token_obj.get("kind"),
        "url": token_obj.get("url"),
        "raw": result,
    }


@mcp.tool()
def download_token_file(token_id: str, output_dir: str, filename_hint: str = None) -> dict:
    """
    Download the generated file for a token (Word doc, Excel, PDF, etc.) and save it locally.
    
    Args:
        token_id: The token ID to download
        output_dir: Directory to save the file
        filename_hint: Optional filename (will be sanitized)
    
    Returns:
        dict: Download result with file path and size
    """
    _log("=" * 60)
    _log("DOWNLOADING TOKEN FILE: " + token_id)
    _log("=" * 60)
    
    b = _get_bytes("/api/v1/canarytoken/download", {
        "auth_token": _auth_token(),
        "canarytoken": token_id,
    })

    out_dir = pathlib.Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    base = filename_hint or ("canarytoken_" + token_id + ".docx")
    base = _safe_filename(base)
    if not base.lower().endswith((".docx", ".xlsx", ".pdf")):
        base = base + ".docx"

    out_path = out_dir / base
    out_path.write_bytes(b)

    _log("File saved to: " + str(out_path))
    return {"token_id": token_id, "path": str(out_path), "size_bytes": len(b)}


@mcp.tool()
def set_token_enabled(token_id: str, enabled: bool) -> dict:
    """
    Enable or disable a Canarytoken.
    
    Args:
        token_id: The token ID
        enabled: True to enable, False to disable
    
    Returns:
        dict: Result of the operation
    """
    action = "enable" if enabled else "disable"
    _log("Setting token " + token_id + " to " + action)
    
    endpoint = "/api/v1/canarytoken/enable" if enabled else "/api/v1/canarytoken/disable"
    result = _post_form(endpoint, {
        "auth_token": _auth_token(),
        "canarytoken": token_id,
    })

    if result.get("result") != "success":
        raise RuntimeError("Enable/disable failed: " + (result.get("message") or json.dumps(result)))

    return {"token_id": token_id, "enabled": enabled, "raw": result}


@mcp.tool()
def delete_canarytoken(token_id: str) -> dict:
    """
    Delete a Canarytoken.
    
    Args:
        token_id: The token ID to delete
    
    Returns:
        dict: Result of the deletion
    """
    _log("Deleting canarytoken: " + token_id)
    
    result = _post_form("/api/v1/canarytoken/delete", {
        "auth_token": _auth_token(),
        "canarytoken": token_id,
    })

    if result.get("result") != "success":
        raise RuntimeError("Delete failed: " + (result.get("message") or json.dumps(result)))

    _log("Token deleted successfully")
    return {"token_id": token_id, "status": "deleted", "raw": result}


@mcp.tool()
def list_token_types() -> dict:
    """
    List all supported Canarytoken types that can be created.
    """
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
        "usage": "Use natural language prompts like 'Create a Word token' or 'Make a PDF for contract monitoring'"
    }


# ============================================================================
# CANARYTOKEN FACTORY TOOLS
# ============================================================================

@mcp.tool()
def list_factory_token_types() -> dict:
    """
    List all Canarytoken types available via the factory.
    Factory tokens allow bulk creation and download of multiple tokens at once.
    
    Returns:
        dict: Available factory token types
    """
    _log("=" * 60)
    _log("LISTING FACTORY TOKEN TYPES")
    _log("=" * 60)
    
    result = _get_json("/api/v1/canarytokens/factory/list", {
        "auth_token": _auth_token()
    })
    
    if result.get("result") != "success":
        raise RuntimeError("List factory types failed: " + (result.get("message") or json.dumps(result)))
    
    factory_types = result.get("factory_canarytokens", {})
    _log("Found " + str(len(factory_types)) + " factory token types")
    
    return {
        "count": len(factory_types),
        "factory_types": factory_types,
        "raw_response": result
    }


@mcp.tool()
def create_token_factory(
    factory_auth: str,
    flock_id: str = None,
    memo: str = None,
    kind: str = None
) -> dict:
    """
    Create a new Canarytoken factory for bulk token generation.
    
    Args:
        factory_auth: Authentication string for the factory (acts as password)
        flock_id: Optional flock ID to assign created tokens to
        memo: Optional memo for the factory
        kind: Optional token kind to restrict factory to (e.g., 'doc-msword', 'pdf-acrobat-reader')
    
    Returns:
        dict: Factory creation result with factory_auth token
    """
    _log("=" * 60)
    _log("CREATING TOKEN FACTORY")
    _log("=" * 60)
    
    payload = {
        "auth_token": _auth_token(),
        "factory_auth": factory_auth
    }
    
    if flock_id:
        payload["flock_id"] = flock_id
        _log("Flock ID: " + flock_id)
    
    if memo:
        payload["memo"] = memo
        _log("Memo: " + memo)
    
    if kind:
        payload["kind"] = kind
        _log("Kind: " + kind)
    
    result = _post_form("/api/v1/canarytoken/create_factory", payload)
    
    if result.get("result") != "success":
        error_msg = result.get("message") or json.dumps(result)
        _log("ERROR: Create factory failed: " + error_msg)
        raise RuntimeError("Create factory failed: " + error_msg)
    
    factory = result.get("factory", {})
    _log("Factory created successfully")
    _log("Factory auth: " + factory_auth)
    _log("=" * 60)
    
    return {
        "factory_auth": factory_auth,
        "factory": factory,
        "raw_response": result
    }


@mcp.tool()
def list_token_factories() -> dict:
    """
    List all existing Canarytoken factories.
    
    Returns:
        dict: List of factories with their details
    """
    _log("=" * 60)
    _log("LISTING TOKEN FACTORIES")
    _log("=" * 60)
    
    result = _get_json("/api/v1/canarytoken/list_factories", {
        "auth_token": _auth_token()
    })
    
    if result.get("result") != "success":
        raise RuntimeError("List factories failed: " + (result.get("message") or json.dumps(result)))
    
    factories = result.get("factories", [])
    _log("Found " + str(len(factories)) + " factories")
    
    factory_list = []
    for factory in factories:
        factory_info = {
            "factory_auth": factory.get("factory_auth"),
            "memo": factory.get("memo"),
            "kind": factory.get("kind"),
            "flock_id": factory.get("flock_id"),
            "created": factory.get("created"),
            "created_printable": factory.get("created_printable")
        }
        factory_list.append(factory_info)
        _log("  Factory: " + str(factory_info["factory_auth"]) + " (Kind: " + str(factory_info["kind"]) + ")")
    
    return {
        "count": len(factory_list),
        "factories": factory_list,
        "raw_response": result
    }


@mcp.tool()
def delete_token_factory(factory_auth: str) -> dict:
    """
    Delete a Canarytoken factory.
    
    Args:
        factory_auth: The factory authentication string
    
    Returns:
        dict: Deletion result
    """
    _log("Deleting token factory: " + factory_auth)
    
    result = _post_form("/api/v1/canarytoken/delete_factory", {
        "auth_token": _auth_token(),
        "factory_auth": factory_auth
    })
    
    if result.get("result") != "success":
        error_msg = result.get("message") or json.dumps(result)
        _log("ERROR: Delete factory failed: " + error_msg)
        raise RuntimeError("Delete factory failed: " + error_msg)
    
    _log("Factory deleted successfully")
    return {
        "factory_auth": factory_auth,
        "status": "deleted",
        "raw_response": result
    }


@mcp.tool()
def create_tokens_from_factory(
    factory_auth: str,
    count: int = 1,
    memo: str = None,
    kind: str = None
) -> dict:
    """
    Create multiple tokens from a factory.
    
    Args:
        factory_auth: The factory authentication string
        count: Number of tokens to create (default 1)
        memo: Optional memo for the tokens
        kind: Optional token kind (if not set by factory)
    
    Returns:
        dict: Creation result with token IDs
    """
    _log("=" * 60)
    _log("CREATING TOKENS FROM FACTORY")
    _log("Factory auth: " + factory_auth)
    _log("Count: " + str(count))
    _log("=" * 60)
    
    payload = {
        "factory_auth": factory_auth
    }
    
    if count:
        payload["count"] = str(count)
    
    if memo:
        payload["memo"] = memo
    
    if kind:
        payload["kind"] = kind
    
    result = _post_form("/api/v1/canarytoken/factory/create", payload)
    
    if result.get("result") != "success":
        error_msg = result.get("message") or json.dumps(result)
        _log("ERROR: Create tokens failed: " + error_msg)
        raise RuntimeError("Create tokens failed: " + error_msg)
    
    tokens = result.get("tokens", [])
    _log("Created " + str(len(tokens)) + " tokens successfully")
    
    return {
        "factory_auth": factory_auth,
        "count": len(tokens),
        "tokens": tokens,
        "raw_response": result
    }


@mcp.tool()
def download_factory_tokens(
    factory_auth: str,
    output_dir: str = "/mnt/user-data/outputs",
    filename: str = None
) -> dict:
    """
    Download all tokens from a factory as a ZIP file.
    Useful for downloading multiple token files at once.
    
    Args:
        factory_auth: The factory authentication string
        output_dir: Directory to save the ZIP file (default: /mnt/user-data/outputs)
        filename: Optional filename for the ZIP (default: factory_tokens_FACTORY_AUTH.zip)
    
    Returns:
        dict: Download result with file path and size
    """
    _log("=" * 60)
    _log("DOWNLOADING FACTORY TOKENS")
    _log("Factory auth: " + factory_auth)
    _log("=" * 60)
    
    b = _get_bytes("/api/v1/canarytoken/factory/download", {
        "factory_auth": factory_auth
    })
    
    out_dir = pathlib.Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    if not filename:
        filename = "factory_tokens_" + factory_auth[:8] + ".zip"
    
    filename = _safe_filename(filename)
    if not filename.lower().endswith(".zip"):
        filename = filename + ".zip"
    
    out_path = out_dir / filename
    out_path.write_bytes(b)
    
    _log("ZIP file saved to: " + str(out_path))
    _log("Size: " + str(len(b)) + " bytes")
    _log("=" * 60)
    
    return {
        "factory_auth": factory_auth,
        "path": str(out_path),
        "size_bytes": len(b),
        "filename": filename
    }


# ============================================================================
# INCIDENT MANAGEMENT TOOLS
# ============================================================================

@mcp.tool()
def list_incidents(
    incidents_since: str = None,
    limit: int = 100,
    node_id: str = None,
    flock_id: str = None
) -> dict:
    """
    List incidents/alerts from Canary devices and tokens.
    
    Args:
        incidents_since: Optional timestamp to filter incidents (Unix timestamp or ISO format)
        limit: Maximum number of incidents to return (default 100, max 1000)
        node_id: Optional device ID to filter incidents
        flock_id: Optional flock ID to filter incidents
    
    Returns:
        dict: List of incidents with details
    """
    _log("=" * 60)
    _log("LISTING INCIDENTS")
    _log("=" * 60)
    
    params = {
        "auth_token": _auth_token()
    }
    
    if incidents_since:
        params["incidents_since"] = incidents_since
        _log("Filtering incidents since: " + incidents_since)
    
    if limit:
        params["limit"] = str(limit)
    
    if node_id:
        params["node_id"] = node_id
        _log("Filtering by node_id: " + node_id)
    
    if flock_id:
        params["flock_id"] = flock_id
        _log("Filtering by flock_id: " + flock_id)
    
    result = _get_json("/api/v1/incidents/all", params)
    
    if result.get("result") != "success":
        raise RuntimeError("List incidents failed: " + (result.get("message") or json.dumps(result)))
    
    incidents = result.get("incidents", [])
    _log("Found " + str(len(incidents)) + " incidents")
    
    incident_list = []
    for incident in incidents:
        incident_info = {
            "id": incident.get("id"),
            "summary": incident.get("summary"),
            "description": incident.get("description"),
            "created": incident.get("created"),
            "created_printable": incident.get("created_printable"),
            "updated": incident.get("updated"),
            "updated_printable": incident.get("updated_printable"),
            "node_id": incident.get("node_id"),
            "device_name": incident.get("device", {}).get("name"),
            "src_host": incident.get("src_host"),
            "dst_port": incident.get("dst_port"),
            "logtype": incident.get("logtype")
        }
        incident_list.append(incident_info)
    
    return {
        "count": len(incident_list),
        "incidents": incident_list,
        "raw_response": result
    }


@mcp.tool()
def get_incident_details(incident_id: str) -> dict:
    """
    Get detailed information about a specific incident.
    
    Args:
        incident_id: The incident ID
    
    Returns:
        dict: Detailed incident information
    """
    _log("Getting details for incident: " + incident_id)
    
    result = _get_json("/api/v1/incident/get", {
        "auth_token": _auth_token(),
        "incident": incident_id
    })
    
    if result.get("result") != "success":
        raise RuntimeError("Get incident details failed: " + (result.get("message") or json.dumps(result)))
    
    return {
        "incident_id": incident_id,
        "incident": result.get("incident", {}),
        "raw_response": result
    }


@mcp.tool()
def acknowledge_incident(incident_id: str) -> dict:
    """
    Acknowledge an incident.
    
    Args:
        incident_id: The incident ID to acknowledge
    
    Returns:
        dict: Acknowledgement result
    """
    _log("Acknowledging incident: " + incident_id)
    
    result = _post_form("/api/v1/incident/acknowledge", {
        "auth_token": _auth_token(),
        "incident": incident_id
    })
    
    if result.get("result") != "success":
        raise RuntimeError("Acknowledge incident failed: " + (result.get("message") or json.dumps(result)))
    
    _log("Incident acknowledged successfully")
    return {
        "incident_id": incident_id,
        "status": "acknowledged",
        "raw_response": result
    }


@mcp.tool()
def unacknowledge_incident(incident_id: str) -> dict:
    """
    Unacknowledge an incident.
    
    Args:
        incident_id: The incident ID to unacknowledge
    
    Returns:
        dict: Unacknowledgement result
    """
    _log("Unacknowledging incident: " + incident_id)
    
    result = _post_form("/api/v1/incident/unacknowledge", {
        "auth_token": _auth_token(),
        "incident": incident_id
    })
    
    if result.get("result") != "success":
        raise RuntimeError("Unacknowledge incident failed: " + (result.get("message") or json.dumps(result)))
    
    _log("Incident unacknowledged successfully")
    return {
        "incident_id": incident_id,
        "status": "unacknowledged",
        "raw_response": result
    }


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:
    """
    Run the MCP server in stdio mode.
    IMPORTANT: Don't print to stdout - it will corrupt JSON-RPC. Use stderr for logs.
    """
    _log("=" * 60)
    _log("Starting Canary Console MCP Server (FULL VERSION)")
    _log("=" * 60)
    _log("Environment check:")
    
    try:
        domain = os.environ.get("CANARY_DOMAIN", "")
        token = os.environ.get("CANARY_AUTH_TOKEN", "")
        
        if domain:
            _log("  CANARY_DOMAIN: " + domain)
        else:
            _log("  CANARY_DOMAIN: NOT SET")
            
        if token:
            _log("  CANARY_AUTH_TOKEN: SET (length: " + str(len(token)) + ")")
        else:
            _log("  CANARY_AUTH_TOKEN: NOT SET")
            
    except Exception as e:
        _log("Environment check error: " + str(e))
    
    _log("=" * 60)
    _log("Available Tools:")
    _log("  DEVICES:")
    _log("    - list_devices() - List all Canary devices")
    _log("    - get_device_info() - Get detailed device information")
    _log("    - configure_device_personality() - Set device personality")
    _log("    - update_device_description() - Update device description")
    _log("    - configure_device_from_prompt() - Natural language configuration")
    _log("    - reboot_device() - Reboot a device")
    _log("  FLOCKS:")
    _log("    - list_flocks() - List all flocks (device groups)")
    _log("  TOKENS:")
    _log("    - list_canarytokens() - List all Canarytokens")
    _log("    - get_canarytokens_summary() - Get token summary by type")
    _log("    - create_token_from_prompt() - Create token from natural language")
    _log("    - create_word_token() - Create Word document token")
    _log("    - create_excel_token() - Create Excel spreadsheet token")
    _log("    - create_pdf_token() - Create PDF document token")
    _log("    - create_dns_token() - Create DNS token")
    _log("    - create_web_token() - Create Web URL token")
    _log("    - download_token_file() - Download token file")
    _log("    - set_token_enabled() - Enable/disable a token")
    _log("    - delete_canarytoken() - Delete a token")
    _log("    - list_token_types() - List supported token types")
    _log("  FACTORY:")
    _log("    - list_factory_token_types() - List factory token types")
    _log("    - create_token_factory() - Create token factory")
    _log("    - list_token_factories() - List all factories")
    _log("    - delete_token_factory() - Delete a factory")
    _log("    - create_tokens_from_factory() - Create tokens from factory")
    _log("    - download_factory_tokens() - Download factory tokens as ZIP")
    _log("  INCIDENTS:")
    _log("    - list_incidents() - List all incidents/alerts")
    _log("    - get_incident_details() - Get detailed incident information")
    _log("    - acknowledge_incident() - Acknowledge an incident")
    _log("    - unacknowledge_incident() - Unacknowledge an incident")
    _log("=" * 60)
    _log("Server ready for connections")
    _log("=" * 60)
    
    mcp.run()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        _log("FATAL ERROR: " + str(e))
        print(str(e), file=sys.stderr)
        raise
