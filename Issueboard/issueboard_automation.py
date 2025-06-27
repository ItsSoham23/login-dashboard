
import os
import re
from datetime import datetime, timedelta, timezone
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


from dotenv import load_dotenv

from apis.issues_api import (
    fetch_project_info, fetch_project_members, fetch_issues,
    fetch_issues_by_username, fetch_authored_issues,
    fetch_all_project_issues, fetch_notes
)

from utils.formatter import generate_summary

load_dotenv()

GITLAB_URL = os.getenv('GITLAB_URL', 'https://code.swecha.org').strip()
GITLAB_API_URL = f"{GITLAB_URL}/api/v4"
GITLAB_TOKEN = os.getenv('GITLAB_TOKEN')
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SENDER_EMAIL = os.getenv('SENDER_EMAIL', '')
SENDER_PASSWORD = os.getenv('SENDER_PASSWORD', '')
RECIPIENT_EMAIL = os.getenv('RECIPIENT_EMAIL', '')

def clean_text(text):
    if not isinstance(text, str):
        text = ""
    text = re.sub(r'\s+', ' ', text).strip()
    text = re.sub(r'@\w+', '', text)
    return text

def parse_gitlab_date(date_str):
    formats = ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"]
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except:
            continue
    return None

def summarize_issue(issue):
    title = issue.get("title", "")
    labels = ", ".join(issue.get("labels", []))
    status = issue.get("status", "")
    
    # Safely default to empty list if notes is None
    notes = issue.get("notes") or []

    comments = "\n".join([
        f"{note.get('author', {}).get('username', 'user')} said: {note.get('body', '')}"
        for note in notes
    ])

    full_context = f"Title: {title}\nLabels: {labels}\nStatus: {status}\nComments:\n{comments}"

    if "bug" in labels.lower():
        return "This bug issue has ongoing discussion and needs review."
    elif "feature" in labels.lower():
        return "This feature is being discussed actively. Review required."
    elif comments:
        return f"Summary: {clean_text(comments[:200])}..."
    else:
        return "No significant updates."


def enrich_issue(issue, project_name, headers):
    issue['project'] = project_name
    issue['labels'] = issue.get('labels', [])
    issue['status'] = issue.get('state', '').capitalize()
    issue['notes'] = fetch_notes(headers, issue['project_id'], issue['iid'])
    issue['ai_summary'] = summarize_issue(issue)
    return issue

def main(project_id):
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}

    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=2)).isoformat()

    project = fetch_project_info(headers, project_id)
    if not project:
        print("Invalid project ID")
        return
    project_name = project.get('name', 'Unknown Project')

    members = fetch_project_members(headers, project_id)
    final = {}

    for member in members:
        uid = member['id']
        uname = member['username']
        name = member['name']
        final[name] = {"yesterday": [], "today": [], "blockers": []}

        seen = set()
        issues = fetch_issues(headers, project_id, uid, since)
        for issue in issues:
            seen.add(issue['id'])

        for issue in fetch_issues_by_username(headers, project_id, uname, since):
            if issue['id'] not in seen:
                issues.append(issue)
                seen.add(issue['id'])

        for issue in fetch_authored_issues(headers, project_id, uid, since):
            if issue['id'] not in seen:
                issues.append(issue)
                seen.add(issue['id'])

        for issue in fetch_all_project_issues(headers, project_id, since):
            if issue['id'] in seen:
                continue
            title = (issue.get("title") or '').lower()
            desc = (issue.get("description") or '').lower()
            if name.lower() in title or name.lower() in desc:
                issues.append(issue)

        for issue in issues:
            updated_at = parse_gitlab_date(issue.get("updated_at"))
            if not updated_at:
                continue
            today = now.replace(hour=0, minute=0, second=0, microsecond=0)
            yesterday = today - timedelta(days=1)

            category = None
            if updated_at >= today:
                category = "today"
            elif yesterday <= updated_at < today:
                category = "yesterday"
            else:
                continue

            labels = [lbl.lower() for lbl in issue.get("labels", [])]
            is_blocker = any(l in ["blocked", "blocker", "impediment"] for l in labels)

            enriched_issue = enrich_issue(issue, project_name, headers)

            if is_blocker:
                final[name]["blockers"].append(enriched_issue)
            else:
                final[name][category].append(enriched_issue)

    html = generate_summary(final)

    with open("standup_summary.html", "w", encoding="utf-8") as f:
        f.write(html)

    send_email(html)

def send_email(html_summary):
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"Daily Standup Summary - {datetime.now().strftime('%Y-%m-%d')}"
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECIPIENT_EMAIL
        msg.attach(MIMEText(html_summary, 'html'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)

        print("✅ Email sent successfully!")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python backend_main.py <project_id>")
    else:
        main(int(sys.argv[1]))