# utils/auth.py
from dotenv import load_dotenv
import os


def get_gitlab_headers():
    token = os.getenv("GITLAB_TOKEN")
    return {"PRIVATE-TOKEN": token}


def get_base_url():
    load_dotenv()
    return os.getenv("GITLAB_BASE_URL", "https://code.swecha.org/api/v4")

def get_group_id():
    load_dotenv()
    return os.getenv("GROUP_ID")

def get_project_id():
    load_dotenv()
    return os.getenv("PROJECT_ID")