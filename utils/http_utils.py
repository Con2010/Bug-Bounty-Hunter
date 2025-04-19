#!/usr/bin/env python3
"""
HTTP Utility Functions

This module provides utility functions for HTTP operations.
"""

import logging
import requests
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("bug_bounty_hunter.utils.http")

def make_request(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, 
                data: Optional[Dict[str, Any]] = None, timeout: int = 30, 
                verify_ssl: bool = True) -> Tuple[Optional[requests.Response], Optional[Exception]]:
    """
    Make an HTTP request with error handling.
    
    Args:
        url: The URL to request
        method: HTTP method (GET, POST, etc.)
        headers: Optional HTTP headers
        data: Optional data for POST/PUT requests
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        
    Returns:
        Tuple containing (Response object or None, Exception or None)
    """
    logger.debug(f"Making {method} request to {url}")
    
    try:
        response = requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            json=data if method.upper() in ["POST", "PUT", "PATCH"] else None,
            params=data if method.upper() == "GET" else None,
            timeout=timeout,
            verify=verify_ssl
        )
        
        logger.debug(f"Request to {url} completed with status code {response.status_code}")
        return response, None
    except requests.RequestException as e:
        logger.error(f"Request to {url} failed: {e}")
        return None, e

def check_url_accessibility(url: str, timeout: int = 10) -> bool:
    """
    Check if a URL is accessible.
    
    Args:
        url: The URL to check
        timeout: Request timeout in seconds
        
    Returns:
        Boolean indicating whether the URL is accessible
    """
    logger.debug(f"Checking accessibility of {url}")
    
    response, error = make_request(url, timeout=timeout)
    
    if error:
        logger.warning(f"URL {url} is not accessible: {error}")
        return False
    
    if response and 200 <= response.status_code < 400:
        logger.debug(f"URL {url} is accessible")
        return True
    else:
        status_code = response.status_code if response else "Unknown"
        logger.warning(f"URL {url} returned status code {status_code}")
        return False

def extract_headers(response: requests.Response) -> Dict[str, str]:
    """
    Extract and analyze headers from an HTTP response.
    
    Args:
        response: The HTTP response object
        
    Returns:
        Dictionary containing header analysis
    """
    if not response:
        return {}
    
    security_headers = {
        "strict-transport-security": "Missing HSTS header",
        "content-security-policy": "Missing Content-Security-Policy header",
        "x-content-type-options": "Missing X-Content-Type-Options header",
        "x-frame-options": "Missing X-Frame-Options header",
        "x-xss-protection": "Missing X-XSS-Protection header"
    }
    
    results = {}
    
    # Check for security headers
    for header, message in security_headers.items():
        if header in response.headers:
            results[header] = response.headers[header]
        else:
            results[header] = message
    
    # Add all other headers
    for header, value in response.headers.items():
        if header.lower() not in results:
            results[header] = value
    
    return results