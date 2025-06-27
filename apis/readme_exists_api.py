import requests

def check_readme_exists_api(username: str, private_token: str = None) -> bool:
    """
    Checks whether a README.md file exists in a GitLab user's repo using the GitLab API.

    Args:
        username (str): GitLab username (also assumed to be the project name).
        private_token (str, optional): GitLab private token, if needed for private repos.

    Returns:
        bool: True if README.md exists, False otherwise.
    """
    base_url = "https://code.swecha.org/api/v4"
    project_path = f"{username}/{username}"

    encoded_project_path = requests.utils.quote(project_path, safe='')

    headers = {}
    if private_token:
        headers["PRIVATE-TOKEN"] = private_token

    project_url = f"{base_url}/projects/{encoded_project_path}"
    project_response = requests.get(project_url, headers=headers)
    if project_response.status_code != 200:
        return False

    file_url = f"{base_url}/projects/{encoded_project_path}/repository/files/README.md?ref=main"
    file_response = requests.get(file_url, headers=headers)

    return file_response.status_code == 200