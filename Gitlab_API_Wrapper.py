import streamlit as st
from streamlit_option_menu import option_menu
from dotenv import load_dotenv 
load_dotenv()  
import os
from datetime import datetime, timedelta
from urllib.parse import quote
from utils.fetch import make_api_request, fetch_paginated_data
from utils.auth import get_gitlab_headers
from apis.groups_api import get_all_users_from_group
from apis.projects_api import get_project_id
from apis.merge_api import get_merge_requests, accept_merge_request
from apis.commits_api import summarize_commit, get_commits_for_project, get_projects
from apis.issues_api import fetch_all_project_issues
from apis.users_api import get_user_id as fetch_user_id
import csv
import requests
import os
from datetime import timezone, datetime, timedelta  
from Issueboard.issueboard_automation import summarize_issue, parse_gitlab_date
from apis.issues_api import (
    fetch_all_project_issues,
    fetch_notes

)
from utils.formatter import generate_summary

 

import os
token = os.getenv("GITLAB_TOKEN")








GITLAB_API_URL = "https://code.swecha.org/api/v4"
GITLAB_URL = "https://code.swecha.org"
GITLAB_BASE_URL = "https://code.swecha.org/api/v4"

st.set_page_config(page_title="🚀 GitLab Wrapper UI", layout="wide")

st.title("🚀 GitLab Wrapper UI")

# --- Mode selection with icons ---
mode = option_menu(
    menu_title="",
    options=[
        "Get Commits",
        "Manage Group Members",
        "Generate Issue Summary",
        "List Merge Requests",
        "Check File in Project",
        "Get User ID"
    ],
    icons=[
        "clock-history",
        "people-fill",
        "sticky",
        "git-merge",
        "file-earmark-text",
        "person-badge"
    ],
    menu_icon="app-indicator",
    default_index=0,
    orientation="horizontal",
)

# ----------------------------- Functions -----------------------------


def check_file_in_project(project_path, file_path):
    project_path = project_path.strip()
    file_path = file_path.strip()
    encoded_file = quote(file_path, safe="")
    project_id = get_project_id(project_path)
    if not project_id:
        return None
    url = f"{GITLAB_API_URL}/projects/{project_id}/repository/files/{encoded_file}/raw"
    headers = {"PRIVATE-TOKEN": os.getenv("GITLAB_TOKEN")}
    response = make_api_request(url, headers, params={"ref": "main"}, return_raw=True)
    return response is not None

def run_issues():
    st.subheader("📊 GitLab Issues (Formatted)")
    
    project_id = st.text_input("📥 Project ID:").strip()
    days = int(st.text_input("📆 Days back (default 7):", "7").strip())

    if not project_id:
        return

    since = (datetime.now() - timedelta(days=days)).isoformat()
    headers = {"PRIVATE-TOKEN": os.getenv("GITLAB_TOKEN")}

    issues = fetch_all_project_issues(headers, project_id, since)

    if not issues:
        st.warning("❌ No issues found.")
        return
    
   


    # Build user-wise categorized dictionary
    final = {}

    now = datetime.now()
    start_of_today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    start_of_yesterday = start_of_today - timedelta(days=1)

    for issue in issues:
        author = issue.get('author', {})
        name = author.get('name', 'Unknown')
        if name not in final:
            final[name] = {"yesterday": [], "today": [], "blockers": []}

        updated_at = parse_gitlab_date(issue.get("updated_at"))
        if not updated_at:
            continue

        # Add notes & ai_summary
        issue["notes"] = fetch_notes(headers, issue["project_id"], issue["iid"])
        issue["ai_summary"] = summarize_issue(issue)
        labels = [lbl.lower() for lbl in issue.get("labels", [])]

        is_blocker = any(l in ["blocked", "blocker", "impediment"] for l in labels)

        if is_blocker:
            final[name]["blockers"].append(issue)
        elif updated_at >= start_of_today:
            final[name]["today"].append(issue)
        elif start_of_yesterday <= updated_at < start_of_today and issue.get('state') != 'closed':
            final[name]["yesterday"].append(issue)

    html_summary = generate_summary(final)

    # Display the HTML in Streamlit
    st.components.v1.html(html_summary, height=800, scrolling=True)

def run_merge_requests():
    st.subheader("🔄 Merge Requests")
    project_id = st.text_input("📥 Project ID:").strip()
    if not project_id:
        st.info("Please enter a Project ID to fetch merge requests.")
        return
    mrs = get_merge_requests(project_id)
    if not mrs:
        st.write("❌ No open merge requests.")
        return
    for mr in mrs:
        st.write(f"📌 #{mr['iid']} - {mr['title']}")
        st.write(f"   👤 {mr['author']['name']}")
        st.write(f"   💬 {mr.get('description', 'No description')[:80]}...")
    if st.checkbox("✅ Accept a Merge Request?"):
        mr_iid = st.text_input("🔢 Enter MR IID:")
        if mr_iid:
            result = accept_merge_request(project_id, mr_iid)
            if result:
                st.success("✅ Merge request accepted!")

def run_check_file():
    st.subheader("📁 Check File in Project")
    project_path = st.text_input("📥 Project Path (e.g. group/project):").strip()
    file_path = st.text_input("📄 File Path (e.g. README.md):").strip()
    if not project_path or not file_path:
        st.info("Please enter both project path and file path.")
        return
    exists = check_file_in_project(project_path, file_path)
    if exists:
        st.success(f"✅ File exists in project.")
        st.info(f"Project ID: {get_project_id(project_path)}")
    elif exists is False:
        st.error("❌ File not found.")
    else:
        st.error("❌ Project not found.")

def search_group_members(group_id, query):
        if not group_id or not query:
            return []

        url = f"{GITLAB_API_URL}/groups/{group_id}/members/all?query={quote(query)}"
        headers = {"PRIVATE-TOKEN": os.getenv("GITLAB_TOKEN")}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"❌ Error {response.status_code}: {response.text}")
            return []




# -------------------------- Modes ---------------------------

if mode == "Get User ID":
    st.subheader("🔍 Search Group Members (partial match)")

    group_id = st.text_input("🏷️ Enter Group ID (e.g. 69994)").strip()
    partial_query = st.text_input("🔎 Enter part of a username or name").strip()

    search_group_members(group_id,partial_query) 

    

    if group_id and partial_query:
        matching = search_group_members(group_id, partial_query)

        if matching:
            options = {
                f"{user['name']} (@{user['username']})": user["id"]
                for user in matching
            }

            selected = st.selectbox("👤 Select a user", list(options.keys()))
            if selected:
                st.success(f"✅ User ID for {selected}: {options[selected]}")
        else:
            st.warning("❌ No matching users in that group.")
    else:
        st.info("Please enter a group ID and partial query to search.")


elif mode == "Check File in Project":
    run_check_file()

elif mode == "List Merge Requests":
    run_merge_requests()

elif mode == "Generate Issue Summary":
    run_issues()

elif mode == "Get Commits":
    st.subheader("📜 Commit Explorer")

    col1, col2 = st.columns(2)
    with col1:
        group_input = st.text_input(
            "Group ID or Path",
            help="Can use numeric ID or path like 'mygroup/mysubgroup'"
        )
    with col2:
        days_input = st.number_input(
            "Days to look back",
            min_value=1,
            max_value=365,
            value=7,
            help="How many days of commits to show"
        )

    if group_input.strip():
        if st.button("🚀 Fetch Commits", type="primary"):
            with st.spinner(f"Fetching projects in group '{group_input.strip()}'... ⏳"):
                try:
                    projects = get_projects(group_input.strip())

                    if not projects:
                        st.error(
                            "❌ No projects found. Please check the Group ID/path and your permissions."
                        )
                    else:
                        st.success(f"✅ Found {len(projects)} project(s). Fetching commits...")

                        since_date = datetime.now() - timedelta(days=days_input)

                        progress_bar = st.progress(0)
                        total_projects = len(projects)

                        for idx, project in enumerate(projects):
                            progress_bar.progress((idx + 1) / total_projects)

                            with st.expander(f"📁 {project['name']}"):
                                commits = get_commits_for_project(project["id"], since_date)

                                if not commits:
                                    st.info(f"No commits in the last {days_input} days.")
                                else:
                                    st.write(f"**{len(commits)} commit(s) found:**")
                                    for commit in commits:
                                        st.markdown(
                                            f"""
                                            **{commit['title']}**  
                                            👤 {commit['author_name']}  
                                            📅 {commit['created_at'][:10]}  
                                            {summarize_commit(commit['title'])}
                                            """
                                        )
                        progress_bar.empty()
                        st.success("🎉 Completed fetching commits for all projects!")

                except FileNotFoundError as fnf_err:
                    st.error(f"❌ File or resource not found: {fnf_err}. Please check your configuration or resource paths.")
                except Exception as e:
                    st.error(f"❌ An unexpected error occurred: {e}")
    else:
        st.info("Please enter a Group ID or Path above to enable commit fetching.")

elif mode == "Manage Group Members":
    st.header("👥 Group Member Management")
    group_id = st.text_input("Enter Group ID")

    action = st.selectbox("Choose action to perform", ["List Members", "Add Members", "Update Access Level"])



    def add_members_to_group(group_id, uploaded_file, access_level=30):
        reader = csv.DictReader(uploaded_file.read().decode('utf-8').splitlines())
        for row in reader:
            username = row["username"].strip()
            user_id = fetch_user_id(username)
            if not user_id:
                st.error(f"❌ User '{username}' not found.")
                continue
            url = f"{GITLAB_URL}/api/v4/groups/{group_id}/members"
            data = {"user_id": user_id, "access_level": access_level}
            response = make_api_request(url, get_gitlab_headers(), data=data)
            if response:
                st.success(f"✅ Added '{username}' to the group.")

    def update_access_level(group_id, uploaded_file, level):
        reader = csv.DictReader(uploaded_file.read().decode('utf-8').splitlines())
        for row in reader:
            username = row["username"].strip()
            user_id = fetch_user_id(username)
            if not user_id:
                st.error(f"❌ User '{username}' not found.")
                continue
            url = f"{GITLAB_URL}/api/v4/groups/{group_id}/members/{user_id}"
            data = {"access_level": level}
            response = make_api_request(url, get_gitlab_headers(), data=data)
            if response:
                st.success(f"🔄 Updated access level for '{username}'")

    if group_id:
        if action == "List Members":
            if st.button("👥 Show Members"):
                members = get_all_users_from_group(group_id)
                if members:
                    st.write(f"👥 Members in group {group_id}:")
                    for m in members:
                        st.markdown(f"- **{m['name']}** (`{m['username']}`)")
                else:
                    st.error("❌ No members found or invalid group ID.")

        elif action == "Add Members":
            uploaded_file = st.file_uploader("📄 Upload CSV with `username` column", type="csv", key="add")
            access_level = st.selectbox("🔒 Access Level", [10, 20, 30, 40, 50], index=2)
            if st.button("➕ Add Members") and uploaded_file:
                add_members_to_group(group_id, uploaded_file, access_level)

        elif action == "Update Access Level":
            uploaded_file = st.file_uploader("📄 Upload CSV with `username` column", type="csv", key="update")
            new_level = st.selectbox("🔁 New Access Level", [10, 20, 30, 40, 50], index=2)
            if st.button("🔄 Update Members") and uploaded_file:
                update_access_level(group_id, uploaded_file, new_level)
    else:
        st.info(" Please enter a valid Group ID.")
