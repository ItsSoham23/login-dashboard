# apis/merge_api.py
from utils.fetch import make_api_request
from datetime import datetime
import os

GITLAB_URL = "https://code.swecha.org"

def get_merge_requests(project_id):
    headers = {"PRIVATE-TOKEN": os.getenv("GITLAB_TOKEN")}
    url_base = f"{GITLAB_URL}/api/v4/projects/{project_id}/merge_requests"
    extra_params = {"state": "opened"}
    return make_api_request(url_base, headers, params=extra_params)

def get_merge_request_changes(project_id, mr_iid):
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/changes"
    return make_api_request(url, {"PRIVATE-TOKEN": os.getenv("GITLAB_TOKEN")})

def accept_merge_request(project_id, mr_iid):
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/merge"
    return make_api_request(url, {"PRIVATE-TOKEN": os.getenv("GITLAB_TOKEN")}, data={})

def comment_on_merge_request(project_id, mr_iid, message):
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes"
    data = {"body": message}
    return make_api_request(url, {"PRIVATE-TOKEN": os.getenv("GITLAB_TOKEN")}, data=data)

def run_merge_requests():
    print("\n🔄 Listing Merge Requests...")
    project_id = input("📥 Enter Project ID: ").strip()
    mrs = get_merge_requests(project_id)
    if not mrs:
        print("❌ No open merge requests found.")
        return

    print(f"\n📋 Open Merge Requests in Project {project_id}:")
    for mr in mrs:
        print(f"📌 #{mr['iid']} - {mr['title']}")
        print(f"   👤 Author: {mr['author']['name']}")
        print(f"   💬 Description: {mr.get('description', 'No description')[:80]}...")

    choice = input("\nWould you like to accept any MR? (y/n): ").strip().lower()
    if choice == 'y':
        mr_iid = input("🔢 Enter MR IID to accept: ")
        result = accept_merge_request(project_id, mr_iid)
        if result:
            print("✅ Merge request accepted!")