"""
The Neo C2 Framework is a post-exploitation command and control framework.

This file is part of Neo C2 Framework.
Copyright (C) 2025 @stillbigjosh

The Neo C2 Framework of this edition is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

The Neo C2 Framework is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Neo.  If not, see <http://www.gnu.org/licenses/>

"""

import threading
import base64
import logging
import re

logger = logging.getLogger(__name__)

_payload_lock = threading.Lock()
uploaded_payload_data = None
uploaded_payload_filename = None
uploaded_payload_uri = None  # New field for dynamic URI

def validate_base64_payload(data):
    try:
        base64.b64decode(data.encode('utf-8'))
        return True
    except Exception:
        logger.error("Invalid base64 payload data")
        return False

def validate_uri(uri):
    if not uri:
        return True  # None/empty URI is valid (uses default)

    # Remove leading slash for validation if present
    clean_uri = uri.lstrip('/')

    # Check for dangerous patterns
    if '..' in clean_uri or clean_uri.startswith('/') or '../' in clean_uri:
        logger.error("Invalid URI: contains directory traversal patterns")
        return False

    # Only allow alphanumeric, hyphens, underscores, dots, and forward slashes
    if not re.match(r'^[a-zA-Z0-9/_.-]+$', clean_uri):
        logger.error("Invalid URI: contains invalid characters")
        return False

    # Check for length limits
    if len(clean_uri) > 100:
        logger.error("Invalid URI: exceeds maximum length of 100 characters")
        return False

    return True

def set_uploaded_payload(data, filename):
    global uploaded_payload_data, uploaded_payload_filename, uploaded_payload_uri

    if not data or not filename:
        logger.error("Invalid payload data or filename provided")
        return False

    if not validate_base64_payload(data):
        logger.error("Invalid base64 payload provided")
        return False

    if len(data.encode('utf-8')) > 50 * 1024 * 1024:
        logger.error("Payload exceeds maximum allowed size of 50MB")
        return False

    with _payload_lock:
        if uploaded_payload_data is not None:
            logger.info(f"Replacing previous payload {uploaded_payload_filename}")

        uploaded_payload_data = data
        uploaded_payload_filename = filename
        uploaded_payload_uri = None  # Reset to default URI
        logger.info(f"Payload {filename} set in storage ({len(data)} base64 characters) with default URI")
        return True

def set_uploaded_payload_with_uri(data, filename, uri):
    global uploaded_payload_data, uploaded_payload_filename, uploaded_payload_uri

    if not data or not filename:
        logger.error("Invalid payload data or filename provided")
        return False

    if not validate_base64_payload(data):
        logger.error("Invalid base64 payload provided")
        return False

    if not validate_uri(uri):
        logger.error("Invalid URI provided")
        return False

    if len(data.encode('utf-8')) > 50 * 1024 * 1024:
        logger.error("Payload exceeds maximum allowed size of 50MB")
        return False

    # Normalize the URI by removing leading slash for internal storage
    normalized_uri = uri.lstrip('/') if uri else None

    with _payload_lock:
        if uploaded_payload_data is not None:
            logger.info(f"Replacing previous payload {uploaded_payload_filename}")

        uploaded_payload_data = data
        uploaded_payload_filename = filename
        uploaded_payload_uri = normalized_uri
        logger.info(f"Payload {filename} set in storage ({len(data)} base64 characters) with URI: /{normalized_uri if normalized_uri else 'api/assets/main.js'}")
        return True

def get_uploaded_payload():
    global uploaded_payload_data, uploaded_payload_filename
    with _payload_lock:
        return uploaded_payload_data, uploaded_payload_filename

def get_uploaded_payload_with_uri():
    global uploaded_payload_data, uploaded_payload_filename, uploaded_payload_uri
    with _payload_lock:
        return uploaded_payload_data, uploaded_payload_filename, uploaded_payload_uri

def get_payload_by_uri(requested_uri):
    """Get payload data based on the requested URI"""
    global uploaded_payload_data, uploaded_payload_filename, uploaded_payload_uri
    with _payload_lock:
        # Normalize the requested URI by removing leading slash for comparison
        normalized_requested_uri = requested_uri.lstrip('/')

        # If no custom URI is set, only return the payload for the default URI
        if not uploaded_payload_uri:
            if normalized_requested_uri == 'api/assets/main.js':
                return uploaded_payload_data, uploaded_payload_filename
            else:
                return None, None

        # If a custom URI is set, return the payload only if the requested URI matches
        if uploaded_payload_uri == normalized_requested_uri:
            return uploaded_payload_data, uploaded_payload_filename
        else:
            return None, None

def clear_uploaded_payload():
    global uploaded_payload_data, uploaded_payload_filename, uploaded_payload_uri
    with _payload_lock:
        if uploaded_payload_data is not None:
            logger.info(f"Payload {uploaded_payload_filename} cleared from storage")
        uploaded_payload_data = None
        uploaded_payload_filename = None
        uploaded_payload_uri = None  # Reset URI as well
