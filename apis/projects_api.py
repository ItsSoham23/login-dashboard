from urllib.parse import quote
from utils.fetch import make_api_request
import os
from utils.fetch import fetch_paginated_data
from utils.auth import get_gitlab_headers

GITLAB_API_URL = "https://code.swecha.org/api/v4"

# apis/projects_api.py



GITLAB_API_URL = "https://code.swecha.org/api/v4"

def get_projects(group_id_or_path):
    url = f"{GITLAB_API_URL}/groups/{group_id_or_path}/projects"
    headers = get_gitlab_headers()
    return fetch_paginated_data(url, headers)


def get_project_id(project_path):
    encoded_path = quote(project_path, safe="")
    url = f"{GITLAB_API_URL}/projects/{encoded_path}"
    headers = {"PRIVATE-TOKEN": os.getenv("GITLAB_TOKEN")}
    response = make_api_request(url, headers)
    if response and "id" in response:
        return response["id"]
    return None

def check_file_in_project(project_path, file_path):
    project_path = project_path.strip()
    file_path = file_path.strip()
    encoded_file = quote(file_path, safe="")

    project_id = get_project_id(project_path)
    if not project_id:
        print(f"❌ Project '{project_path}' not found.")
        return False

    url = f"{GITLAB_API_URL}/projects/{project_id}/repository/files/{encoded_file}/raw"
    headers = {"PRIVATE-TOKEN": os.getenv("GITLAB_TOKEN")}
    response = make_api_request(url, headers, params={"ref": "main"}, return_raw=True)

    return response is not None

def run_check_file():
    print("\n📁 Check File in Project Repository")
    project_path = input("📥 Enter Project Path (e.g., group/project): ").strip()
    file_path = input("📄 Enter File Path (e.g., README.md): ").strip()

    exists = check_file_in_project(project_path, file_path)
    if exists:
        print(f"✅ File '{file_path}' exists in '{project_path}'.")
    else:
        print(f"❌ File '{file_path}' NOT FOUND in '{project_path}'.")
