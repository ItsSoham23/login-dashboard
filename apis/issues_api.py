# apis/issues_api.py
from utils.fetch import make_api_request
from datetime import datetime, timedelta
import os
import requests

GITLAB_URL = "https://code.swecha.org/api/v4"



def fetch_project_info(headers, project_id):
    url = f"https://code.swecha.org/api/v4/projects/{project_id}"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Failed to fetch project info: {e}")
        return None


def fetch_issues(headers, project_id, user_id, since):
    url = f"https://code.swecha.org/api/v4/projects/{project_id}/issues"
    params = {
        "updated_after": since,
        "per_page": 100,
    }
    response = requests.get(url, headers=headers, params=params)
    if not response.ok:
        print(f"⚠️ Failed to fetch issues for user {user_id}: {response.status_code}")
        return []
    issues = response.json()
    return [issue for issue in issues if issue.get("assignee", {}).get("id") == user_id]

def fetch_project_members(headers, project_id):
    url_base = f"{GITLAB_URL}/projects/{project_id}/members/all"
    return make_api_request(url_base, headers)

def fetch_issues_by_assignee(headers, project_id, user_id, since):
    url_base = f"{GITLAB_URL}/projects/{project_id}/issues"
    extra_params = {
        "assignee_id": user_id,
        "updated_after": since,
        "state": "all",
        "per_page": 100
    }
    return make_api_request(url_base, headers, params=extra_params)

def fetch_issues_by_username(headers, project_id, username, since):
    url_base = f"{GITLAB_URL}/projects/{project_id}/issues"
    extra_params = {
        "assignee_username": username,
        "updated_after": since,
        "state": "all",
        "per_page": 100
    }
    return make_api_request(url_base, headers, params=extra_params)

def fetch_authored_issues(headers, project_id, user_id, since):
    url_base = f"{GITLAB_URL}/projects/{project_id}/issues"
    extra_params = {
        "author_id": user_id,
        "updated_after": since,
        "state": "all",
        "per_page": 100
    }
    return make_api_request(url_base, headers, params=extra_params)

def fetch_all_project_issues(headers, project_id, since):
    url_base = f"{GITLAB_URL}/projects/{project_id}/issues"
    extra_params = {
        "updated_after": since,
        "state": "all",
        "per_page": 100
    }
    return make_api_request(url_base, headers, params=extra_params)

def fetch_notes(headers, project_id, issue_iid):
    url = f"{GITLAB_URL}/projects/{project_id}/issues/{issue_iid}/notes"
    return make_api_request(url, headers)

def run_issues():
    print("\n📊 Fetching GitLab Issues...")
    project_id = input("📥 Enter Project ID: ").strip()
    days_input = input("📆 Days back to check issues (default 7): ").strip()
    days = int(days_input) if days_input else 7
    since = (datetime.now() - timedelta(days=days)).isoformat()

    headers = {"PRIVATE-TOKEN": os.getenv("GITLAB_TOKEN")}
    
    all_issues = fetch_all_project_issues(headers, project_id, since)
    if not all_issues:
        print("❌ No issues found.")
        return

    print(f"\n🔍 Found {len(all_issues)} issues in the last {days} day(s):")
    for issue in all_issues[:5]:  # Show summary of first 5 issues
        title = issue['title']
        author = issue['author']['name'] if 'author' in issue else 'Unknown'
        assignees = ', '.join([a['name'] for a in issue.get('assignees', [])])
        print(f"📌 {title}")
        print(f"   👤 Author: {author}")
        print(f"   🧑‍🤝‍🧑 Assignees: {assignees or 'None'}")
        print(f"   🔖 Labels: {', '.join(issue.get('labels', []))}")