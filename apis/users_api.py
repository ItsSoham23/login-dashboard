# apis/users_api.py
from utils.fetch import make_api_request
from utils.auth import get_gitlab_headers
import requests
from utils.auth import get_gitlab_headers  # adjust import if needed

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
