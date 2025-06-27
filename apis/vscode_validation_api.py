import requests

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