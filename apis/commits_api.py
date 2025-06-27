from utils.fetch import fetch_paginated_data, make_api_request
from utils.auth import get_gitlab_headers
from datetime import datetime, timedelta
from urllib.parse import quote
import streamlit as st

GITLAB_BASE_URL = "https://code.swecha.org/api/v4"

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
