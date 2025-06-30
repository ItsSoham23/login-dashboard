# apis/users_api.py
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
from utils.fetch import make_api_request
from utils.auth import get_gitlab_headers
import requests
from utils.auth import get_gitlab_headers  # adjust import if needed  # noqa: F811
import streamlit as st
from apis.commits_api import safe_api_request

GITLAB_URL = "https://code.swecha.org"

def get_user_id(username):
    url = f"{GITLAB_URL}/api/v4/users"
    params = {"username": username}
    response = make_api_request(url, get_gitlab_headers(), params=params)
    if response and isinstance(response, list) and len(response) > 0:
        return response[0]["id"]
    print(f"❌ User '{username}' not found.")
    return None

def run_users():
    print("\n👤 Get User Info")
    username = input("📥 Enter GitLab username: ").strip()
    user_id = get_user_id(username)
    if user_id:
        print(f"✅ User ID for '{username}': {user_id}")




GITLAB_API_URL = "https://code.swecha.org/api/v4"  # change if needed


def get_group_members(group_id):
    """
    Fetch all members of a GitLab group.

    Returns a list of member dicts, each including at least:
    - id
    - username
    - name
    - access_level
    """
    headers = get_gitlab_headers()
    members = []
    page = 1
    per_page = 100

    while True:
        url = f"{GITLAB_API_URL}/groups/{group_id}/members"
        params = {
            "per_page": per_page,
            "page": page,
        }
        response = requests.get(url, headers=headers, params=params, timeout=30)
        if response.status_code != 200:
            print(f"Failed to fetch group members: {response.status_code} {response.text}")
            break

        batch = response.json()
        if not batch:
            break

        members.extend(batch)
        if len(batch) < per_page:
            break
        page += 1

    return members


def get_user_details(user_id):
    """
    Fetch detailed info for a GitLab user by user_id.

    Returns dict including fields like:
    - id
    - username
    - name
    - last_activity_on
    - last_sign_in_at
    """
    headers = get_gitlab_headers()
    url = f"{GITLAB_API_URL}/users/{user_id}"
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code != 200:
        print(f"Failed to fetch user details for {user_id}: {response.status_code} {response.text}")
        return None
    return response.json()






def check_readme_exists_api(username,debug_mode=False):
    """Check if user has a README in their profile repository"""
    headers = get_gitlab_headers()
    if not headers:
        return False
    
    try:
        # List of possible README file names and branches to check
        readme_files = ["README.md", "readme.md", "README.MD", "README.rst", "README.txt", "README"]
        branches = ["main", "master"]
        
        for readme_file in readme_files:
            for branch in branches:
                # Check for README in user's profile repository (username/username)
                url = f"{GITLAB_URL}/api/v4/projects/{quote(username + '/' + username, safe='')}/repository/files/{quote(readme_file, safe='')}"
                params = {"ref": branch}
                
                result = safe_api_request(url, headers, params, timeout=10)
                if result["success"]:
                    if debug_mode:
                        st.write(f"✅ Found {readme_file} in {branch} branch for {username}")
                    return True
        
        if debug_mode:
            st.write(f"❌ No README found for {username}")
        return False
        
    except Exception as e:
        if debug_mode:
            st.write(f"Error checking README for {username}: {e}")
        return False




def fetch_readme_status(users, name_to_username,debug_mode=False):
    """Fetch README status for multiple users in parallel"""
    statuses = {}
    
    # Check which users have valid username mappings
    valid_users = []
    for user in users:
        username = name_to_username.get(user)
        if username:
            valid_users.append((user, username))
        else:
            statuses[user] = "❌ (no username)"
            if debug_mode:
                st.write(f"⚠️ No username mapping found for: {user}")
    
    if debug_mode:
        st.write(f"📊 README Check: {len(valid_users)} users have valid usernames out of {len(users)} total")
    
    # Process valid users
    with ThreadPoolExecutor(max_workers=6) as executor:  # Reduced workers to avoid rate limiting
        futures = {}
        for user, username in valid_users:
            futures[executor.submit(check_readme_exists_api, username)] = (user, username)
        
        completed = 0
        total = len(futures)
        
        for future in as_completed(futures):
            user, username = futures[future]
            try:
                result = future.result()
                statuses[user] = "✅" if result else "❌"
                if debug_mode:
                    st.write(f"README check for {user} ({username}): {'✅' if result else '❌'}")
            except Exception as e:
                statuses[user] = "❌ (error)"
                if debug_mode:
                    st.write(f"Error checking README for {user} ({username}): {e}")
            
            completed += 1
            if debug_mode and completed % 10 == 0:  # Show progress every 10 completions
                st.write(f"README check progress: {completed}/{total}")
    
    return statuses
