import requests
from apis.commits_api import get_gitlab_headers,safe_api_request


# GitLab Configuration
GITLAB_URL = "https://code.swecha.org"

def fetch_json(headers, url):
    """Fetch JSON content from a URL using GitLab auth."""
    response = requests.get(GITLAB_URL+url, headers=headers)

    if response.status_code != 200:
        print(f"[ERROR] Could not fetch file from {GITLAB_URL}")
        print(f"Status code: {response.status_code}")
        return None

    try:
        return response.json()
    except ValueError:
        print(f"[ERROR] Invalid JSON at {GITLAB_URL}")
        return None
    
    
def validate_gitlab_token(token):
    """Validate GitLab token by making a test API call"""
    headers = {"PRIVATE-TOKEN": token, "Content-Type": "application/json"}
    
    try:
        result = safe_api_request(f"{GITLAB_URL}/api/v4/user", headers, timeout=10)
        
        if result["success"]:
            user_info = result["data"]
            return {
                "success": True, 
                "user_info": user_info,
                "message": f"Authenticated as {user_info.get('name', 'Unknown')}"
            }
        else:
            return {"success": False, "error": result["error"]}
    except Exception as e:
        return {"success": False, "error": f"Token validation failed: {str(e)}"}
    
def validate_group_access(group_id):
    """Validate if the user has access to the specified group"""
    headers = get_gitlab_headers()
    if not headers:
        return {"success": False, "error": "No valid GitLab token found"}
    
    url = f"{GITLAB_URL}/api/v4/groups/{group_id}"
    result = safe_api_request(url, headers, timeout=10)
    
    if result["success"]:
        group_info = result["data"]
        return {
            "success": True, 
            "group_info": group_info,
            "message": f"Access confirmed for group: {group_info.get('name', 'Unknown')}"
        }
    else:
        return {"success": False, "error": result["error"]}
