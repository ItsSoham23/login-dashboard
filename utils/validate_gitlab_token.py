from datetime import datetime, timedelta
from collections import defaultdict
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dateutil.parser import parse as parse_datetime
import time
import re
from urllib.parse import quote
import json
import os
import pytz

GITLAB_URL = "https://code.swecha.org"


def safe_api_request(url, headers, params=None, timeout=30, retries=3):
    """Make API request with enhanced error handling and retry logic"""
    for attempt in range(retries):
        try:    
            time.sleep(0.1)  # basic rate limiting
            print(f"🌐 Attempting request to: {url} (Attempt {attempt + 1})")

            response = requests.get(url, headers=headers, params=params, timeout=timeout)

            if response.status_code == 200:
                try:
                    data = response.json()
                    return {"success": True, "data": data}
                except json.JSONDecodeError:
                    return {"success": False, "error": "Invalid JSON response"}

            elif response.status_code == 404:
                return {"success": False, "error": "Resource not found (404)"}
            elif response.status_code == 401:
                return {"success": False, "error": "Authentication failed (401)"}
            elif response.status_code == 403:
                return {"success": False, "error": "Access forbidden (403)"}
            elif response.status_code == 429:
                print("⚠️ Rate limited. Retrying with backoff...")
                time.sleep(2 ** attempt)
            else:
                if attempt == retries - 1:
                    return {
                        "success": False,
                        "error": f"HTTP {response.status_code}: {response.text[:200]}"
                    }
                time.sleep(1)
                continue

        except requests.exceptions.Timeout:
            if attempt == retries - 1:
                return {"success": False, "error": "Request timeout"}
            time.sleep(2)

        except requests.exceptions.ConnectionError:
            if attempt == retries - 1:
                return {"success": False, "error": "Connection error"}
            time.sleep(2)

        except Exception as e:
            if attempt == retries - 1:
                return {"success": False, "error": f"Request failed: {str(e)}"}
            time.sleep(1)

    return {"success": False, "error": "Max retries exceeded"}

def validate_gitlab_token(token):
    """Validate GitLab token by making a test API call"""
    headers = {"PRIVATE-TOKEN": token, "Content-Type": "application/json"}
    url = f"{GITLAB_URL}/api/v4/user"

    print(f"🔍 Validating token with URL: {url}")
    print(f"🔐 Using headers: {headers}")

    try:
        result = safe_api_request(url, headers, timeout=10)

        print("📦 API Response from safe_api_request:", result)

        if result["success"]:
            user_info = result["data"]
            print(f"✅ Token is valid. User info: {user_info}")
            return {
                "success": True,
                "user_info": user_info,
                "message": f"Authenticated as {user_info.get('name', 'Unknown')}"
            }
        else:
            print(f"❌ Token invalid. Error: {result['error']}")
            return {"success": False, "error": result["error"]}

    except Exception as e:
        print(f"💥 Exception during validation: {e}")
        return {"success": False, "error": f"Token validation failed: {str(e)}"}
    