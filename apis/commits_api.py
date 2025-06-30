from utils.fetch import fetch_paginated_data, make_api_request
from utils.auth import get_gitlab_headers
from datetime import datetime, timedelta
from urllib.parse import quote
import streamlit as st
import os
import time
import requests
import json
import requests

GITLAB_BASE_URL = "https://code.swecha.org/api/v4"


def safe_api_request(url, headers, params=None):
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return {"success": True, "data": response.json()}
        else:
            return {"success": False, "error": f"{response.status_code} - {response.text}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_gitlab_headers():
    token = st.session_state.get("gitlab_token", "")
    if not token:
        return None
    return {
        "PRIVATE-TOKEN": token
    }


def get_projects(group_id_or_path):
    """Get all projects in a group with comprehensive error handling"""
    try:
        headers = get_gitlab_headers()
        encoded_group = quote(str(group_id_or_path), safe='')
        
        # First verify group exists
        group_url = f"{GITLAB_BASE_URL}/groups/{encoded_group}"
        group_info = make_api_request(group_url, headers)
        
        if not group_info:
            st.error(f"❌ Group not found or inaccessible: {group_id_or_path}")
            return []
        
        # Get projects using confirmed group ID
        projects_url = f"{GITLAB_BASE_URL}/groups/{group_info['id']}/projects?membership=true"

        projects = fetch_paginated_data(projects_url, headers)
        
        if not projects:
            st.warning(f"ℹ️ Group '{group_info['name']}' exists but contains no projects")
        
        return projects
        
    except Exception as e:
        st.error(f"🚨 Error fetching projects: {str(e)}")
        return []

def get_commits_for_project(project_id, since_date):
    """Get commits for a specific project"""
    url = f"{GITLAB_BASE_URL}/projects/{project_id}/repository/commits"
    params = {
        'since': since_date.isoformat(),
        'per_page': 100  # Get maximum allowed per request
    }
    return fetch_paginated_data(url, get_gitlab_headers(), params)

def summarize_commit(message):
    """Create user-friendly commit summaries"""
    message = message.lower()
    if any(word in message for word in ['fix', 'bug', 'error']):
        return "🛠️ Bug fix"
    elif any(word in message for word in ['add', 'create', 'new']):
        return "➕ New feature"
    elif any(word in message for word in ['update', 'upgrade', 'improve']):
        return "🔄 Update"
    elif any(word in message for word in ['remove', 'delete', 'clean']):
        return "❌ Removal"
    elif 'refactor' in message:
        return "♻️ Code refactor"
    elif 'merge' in message:
        return "🔀 Merge"
    return "📝 " + message.capitalize()


def run_commits():
    print("\n📜 Fetching Commits")

    group_id_or_path = input("📥 Enter Group ID or Path: ").strip()
    days_input = input("📆 Days back to check commits (default 1): ").strip()
    try:
        days = int(days_input) if days_input else 1
    except ValueError:
        print("❌ Invalid number of days. Defaulting to 1.")
        days = 1

    since_date = datetime.now() - timedelta(days=days)
    projects = get_projects(group_id_or_path)

    if not projects:
        print("❌ No projects found.")
        return

    print(f"🔍 Found {len(projects)} project(s). Checking commits...")

    for project in projects:
        print(f"\n📂 {project['name']}:")
        try:
            commits = get_commits_for_project(project['id'], since_date)
        except Exception as e:
            print(f"❌ Failed to fetch commits: {e}")
            continue

        if not commits:
            print("ℹ️ No commits found.")
            continue

        for commit in commits[:5]:  # show only first 5 per project
            summary = summarize_commit(commit['title'])
            print(f"✅ {commit['title']} by {commit['author_name']} on {commit['created_at'][:10]} - {summary}")



def get_gitlab_headers(debug_mode=False):  # noqa: F811
    """Get GitLab API headers with improved token handling"""
    token = None
    
    # Primary source: session state (user-provided token)
    if st.session_state.get('gitlab_token'):
        token = st.session_state.gitlab_token
    else:
        # Fallback to secrets/environment (for development)
        try:
            if hasattr(st, 'secrets') and "GITLAB_TOKEN" in st.secrets:
                token = st.secrets["GITLAB_TOKEN"]
        except Exception as e:
            if debug_mode:
                st.write(f"Secrets access error: {e}")
        
        # Try environment variable as last resort
        if not token:
            token = os.getenv("GITLAB_TOKEN")
    
    if not token:
        return None
    
    # Validate token format for user guidance
    if not token.startswith(('glpat-', 'gloas-', 'gldt-')) and len(token) < 20:
        if debug_mode:
            st.warning("⚠️ Token format looks incorrect. GitLab tokens usually start with 'glpat-', 'gloas-', or 'gldt-'")
    
    return {"PRIVATE-TOKEN": token, "Content-Type": "application/json"}

def safe_api_request(url, headers, params=None, timeout=30, retries=3,debug_mode=False):
    """Make API request with enhanced error handling and retry logic"""
    for attempt in range(retries):
        try:
            if debug_mode and attempt == 0:
                st.write(f"🔗 API Request: {url}")
                if params:
                    st.write(f"📋 Parameters: {params}")
            
            # Rate limiting
            time.sleep(0.1)
            
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
            
            if debug_mode and attempt == 0:
                st.write(f"📊 Response Status: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if debug_mode and isinstance(data, list) and attempt == 0:
                        st.write(f"📝 Returned {len(data)} items")
                    return {"success": True, "data": data}
                except json.JSONDecodeError:
                    return {"success": False, "error": "Invalid JSON response"}
            
            elif response.status_code == 404:
                return {"success": False, "error": "Resource not found (404)"}
            elif response.status_code == 401:
                return {"success": False, "error": "Authentication failed (401)"}
            elif response.status_code == 403:
                return {"success": False, "error": "Access forbidden (403)"}
            elif response.status_code == 429:  # Rate limited
                wait_time = 2 ** attempt  # Exponential backoff
                if debug_mode:
                    st.write(f"⏳ Rate limited, waiting {wait_time}s...")
                time.sleep(wait_time)
                continue
            else:
                if attempt == retries - 1:  # Last attempt
                    return {"success": False, "error": f"HTTP {response.status_code}: {response.text[:200]}"}
                time.sleep(1)  # Brief wait before retry
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
