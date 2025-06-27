import os
import re
from typing import List, Tuple
import validators

# Import API functions
from add import (
    get_merge_requests,
    get_merge_request_changes,
    accept_merge_request,
    comment_on_merge_request
)

import requests  # Still needed for some things like exception catching

# CONFIGURATION
GITLAB_URL = "https://code.swecha.org"
ACCESS_TOKEN = os.getenv("GITLAB_ACCESS_TOKEN", "")
GROUP_ID = "44410"
PROJECT_ID = "17159"
HEADERS = {
    "Private-Token": ACCESS_TOKEN
}

SAMPLE_PROFILE_TEMPLATE = r"""
:bust_in_silhouette: GitLab Profile Card
\| Field.*Details.*
\|-------------------\|------------------------------------------\|
\| \*\*Name\*\*.*Gurram Ashok kumar.*
\| \*\*code\.swecha\.org Username\*\*.*Ashokkumargurram.*
\| \*\*Profile Link\*\*.*\$\$Ashokkumargurram\$\$https://code\.swecha\.org/Ashokkumargurram\$\$.*
\| \*\*Bio\*\*.*Innovative tech enthusiast focused on AI.*
\| \*\*Location\*\*.*Hyderabad.*
\| \*\*Skills/Tech\*\*.*Python,FastAPI,Sql,Postgresql,N8N.*
\| \*\*Website/Portfolio\*\*.*\$\$Ashokkumargurram\$\$https://www\.linkedin\.com/in/ashokkumar-gurram/.*\$\$.*
\| \*\*Fun Fact\*\*.*
## :sparkles: About Me.*
Hi, Iam \*\*Gurram Ashok Kumar\*\*
🧑‍💻 About Me.*
I’m Gurram Ashok Kumar, a final-year B\.Tech Information Technology student.*
Stock Prediction Model.*
Image Caption Generator.*
Clothing Classifier.*
internship at Swecha.*
TensorFlow, Pandas, Numpy.*
Rotaract Club.*
## :star2: Sample Projects.*
- \$\$Project 1\$\$.*\/Ashokkumargurram\/gitlab.*AI corpus development.*
- \$\$Project 2\$\$.*\/Ashokkumargurram\/Python_learning.*House price prediction.*
"""

PROFILE_REGEX_PATTERN = re.compile(SAMPLE_PROFILE_TEMPLATE.strip(), re.DOTALL)

def validate_profile_template(content: str) -> Tuple[bool, List[str]]:
    errors = []
    match = PROFILE_REGEX_PATTERN.search(content)
    if not match:
        errors.append("Profile does not match the expected template layout.")

    url_pattern = re.compile(r"\$\$[^$]+\$\$(https?://[^\s$]+)\$\$")
    for match in url_pattern.finditer(content):
        url = match.group(1)
        if not validators.url(url):
            errors.append(f"Invalid URL found: {url}")
    return len(errors) == 0, errors

def get_group_members(group_id: str) -> List[dict]:
    url = f"{GITLAB_URL}/api/v4/groups/{group_id}/members/all"
    members = []
    page = 1
    per_page = 100
    while True:
        try:
            response = requests.get(url, headers=HEADERS, params={"page": page, "per_page": per_page})
            response.raise_for_status()
            page_members = response.json()
            if not page_members:
                break
            members.extend(page_members)
            page += 1
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching group members (page {page}): {e}, Response: {e.response.text if e.response else 'No response'}")
            raise
    print(f"Group members: {[member['username'] for member in members]}")
    return members

def check_profile_in_changes(changes: dict) -> Tuple[bool, str, List[str]]:
    for change in changes.get('changes', []):
        file_path = change.get('new_path', '')
        if 'readme.md' in file_path.lower() or 'profile' in file_path.lower():
            new_file_content = change.get('diff', '')
            added_lines = [line[1:] for line in new_file_content.split('\n') if line.startswith('+') and not line.startswith('+++')]
            profile_content = '\n'.join(added_lines)
            if profile_content.strip():
                is_valid, errors = validate_profile_template(profile_content)
                return True, profile_content, errors
    return False, "", ["No profile file found in changes"]

def process_merge_requests():
    print("🔍 Fetching group members...")
    members = get_group_members(GROUP_ID)
    usernames = [member["username"].lower() for member in members]

    print("📋 Fetching open merge requests...")
    try:
        mrs = get_merge_requests(HEADERS, PROJECT_ID)
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching merge requests: {e}, Response: {e.response.text if e.response else 'No response'}")
        return

    print(f"\n📊 Found {len(mrs)} open merge requests")
    print("=" * 50)

    accepted_count = 0
    for mr in mrs:
        if accepted_count >= 2:
            print("✅ Processed 2 valid profiles. Exiting.")
            break

        mr_iid = mr['iid']
        author = mr['author']['username']
        title = mr['title']
        print(f"\n🔍 Checking MR #{mr_iid}: {title}")
        print(f"👤 Author: {author}")
        if author.lower() not in usernames:
            print(f"⚠️  Author {author} is not a group member")
            continue

        try:
            changes = get_merge_request_changes(HEADERS, PROJECT_ID, mr_iid)
            has_profile, profile_content, validation_errors = check_profile_in_changes(changes)
            if not has_profile:
                print("❌ No profile found in changes")
                continue
            if validation_errors:
                print("❌ Profile template validation failed:")
                for error in validation_errors:
                    print(f"   - {error}")
                try:
                    comment_msg = "Your profile card is invalid. Can you please check it once and update "
                    comment_on_merge_request(HEADERS, PROJECT_ID, mr_iid, comment_msg)
                except Exception as comment_err:
                    print(f"⚠️  Failed to comment on MR #{mr_iid}: {comment_err}")
                continue
            print("✅ Profile template is valid!")
            print("🚀 Accepting merge request...")
            accept_merge_request(HEADERS, PROJECT_ID, mr_iid)
            print(f"✅ Merge request #{mr_iid} has been accepted!")
            accepted_count += 1
        except requests.exceptions.RequestException as e:
            print(f"❌ Error processing MR #{mr_iid}: {e}, Response: {e.response.text if e.response else 'No response'}")
        except Exception as e:
            print(f"🐛 Unexpected error with MR #{mr_iid}: {e}")

def display_template_example():
    print("\n📋 **Sample Profile Template Format:**")
    print(SAMPLE_PROFILE_TEMPLATE.strip())

def main():
    if not ACCESS_TOKEN or not GROUP_ID or not PROJECT_ID:
        print("❌ Please configure ACCESS_TOKEN, GROUP_ID, and PROJECT_ID")
        return
    print("🎯 GitLab Profile Template Checker & Auto-Merger")
    print("=" * 50)
    display_template_example()
    process_merge_requests()
    print("\n✨ Processing complete!")

if __name__ == "__main__":
    main()
