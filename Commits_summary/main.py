# main.py

import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from commits_api import get_projects, get_commits_for_project
from utils import summarize_commit

load_dotenv()

token = os.getenv("GITLAB_TOKEN")


def get_user_input():
    group = input("📥 Enter Group ID or Path: ").strip()
    days_input = input("📆 Enter number of days to check commits (default 1): ").strip()
    days = int(days_input) if days_input else 1
    return group, days


def generate_summary(projects, token, days):
    since_date = datetime.now().astimezone() - timedelta(days=days)

    print("\n🔍 GitLab Contribution Summary:\n")
    for project in projects:
        project_name = project['name_with_namespace']
        project_id = project['id']
        commits = get_commits_for_project(project_id, token, since_date)

        print(f"\n📁 {project_name}")
        if not commits:
            print(f"   ⚠️ No recent commits in the last {days} day(s).")
            continue

        author_commits = {}
        for commit in commits:
            author = commit['author_name']
            author_commits.setdefault(author, []).append(commit)

        for author, commit_list in author_commits.items():
            print(f"  👤 {author}: {len(commit_list)} commit(s)")
            for commit in commit_list:
                msg = commit['title']
                date = commit['created_at']
                summary = summarize_commit(msg)
                print(f"     - [{date[:10]}] {summary}")


def main():
    group_id_or_path, days = get_user_input()
    projects = get_projects(group_id_or_path, token)

    if not projects:
        print(f"❌ No projects found or invalid group/path: {group_id_or_path}")
        exit(1)

    generate_summary(projects, token, days)


if __name__ == "__main__":
    main()
