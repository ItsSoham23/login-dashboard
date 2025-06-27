import os
os.environ["STREAMLIT_CONFIG_DIR"] = "/tmp/.streamlit"
import sys
import tempfile
import pandas as pd
import streamlit as st
try:
    import gitlab
except ModuleNotFoundError as e:
    st.error(f"Error: {e}")
    st.error(f"Python version: {sys.version}")
    st.error(f"Python executable: {sys.executable}")
    st.error("Install with: 'pip install streamlit pandas python-gitlab python-dotenv'")
    st.stop()
from gitlab.exceptions import GitlabGetError, GitlabAuthenticationError
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
GITLAB_TOKEN = os.getenv("GITLAB_TOKEN")
GITLAB_URL = "https://code.swecha.org"

# Streamlit setup
st.title("GitLab Resume Analyzer")
st.write("Analyze README.md resumes in user profile repositories. Either upload a CSV with 'username', 'enrollment_number', and 'faculty_name' columns or enter details for a single user.")

# Check token
if not GITLAB_TOKEN:
    st.error("Missing GITLAB_TOKEN in .env.")
    st.stop()

# Initialize GitLab client
try:
    gl = gitlab.Gitlab(GITLAB_URL, private_token=GITLAB_TOKEN)
    st.success("GitLab client initialized.")
except Exception as e:
    st.error(f"Failed to initialize GitLab client: {e}")
    st.stop()

# Scoring criteria
RESUME_SECTIONS = {
    "education": r"(?i)\b(education|academic)\b",
    "experience": r"(?i)\b(experience|work[-|\s]?history|employment)\b",
    "skills": r"(?i)\b(skills|technologies|proficiencies)\b"
}
KEYWORD_POINTS = 2
LENGTH_POINTS = 1
SECTION_POINTS = 20
RELEVANT_KEYWORDS = [
    "python", "javascript", "java", "sql", "aws", "docker", "leadership",
    "project management", "software development", "data analysis"
]

def analyze_readme_content(content):
    """Analyze README, return score and feedback."""
    score = 0
    found_sections = []
    found_keywords = []
    feedback = []

    # Sections
    for section, pattern in RESUME_SECTIONS.items():
        if re.search(pattern, content):
            score += SECTION_POINTS
            found_sections.append(section)
        else:
            feedback.append(f"Add '{section.capitalize()}' section.")

    # Keywords
    content_lower = content.lower()
    for keyword in RELEVANT_KEYWORDS:
        if keyword in content_lower:
            score += KEYWORD_POINTS
            found_keywords.append(keyword)
    if len(found_keywords) < 5:
        feedback.append(f"Add keywords like {', '.join(RELEVANT_KEYWORDS[:3] + ['...'])}.")

    # Length
    content_length = len(content)
    length_score = min((content_length // 100) * LENGTH_POINTS, 20)
    score += length_score
    if content_length < 500:
        feedback.append("Expand content with details.")
    elif content_length > 2000:
        feedback.append("Condense content for clarity.")

    # General tips
    feedback.extend([
        "Use action verbs and quantify achievements.",
        "Format with headings and bullets."
    ])

    return score, feedback

def get_user_readmes(username, enrollment_number, faculty_name):
    """Fetch and analyze README.md from the user's profile repository."""
    results = []
    try:
        users = gl.users.list(username=username)
        if not users:
            return results, f"User {username} not found."

        user = users[0]
        # Target the profile repository (username/username)
        profile_repo_path = f"{username}/{username}"
        try:
            full_project = gl.projects.get(profile_repo_path)
            readme = full_project.files.get(file_path="README.md", ref="main")
            content = readme.decode().decode("utf-8")

            if any(re.search(p, content, re.IGNORECASE) for p in RESUME_SECTIONS.values()):
                score, feedback = analyze_readme_content(content)
                results.append({
                    "username": username,
                    "project_name": full_project.name,
                    "score": score,
                    "feedback": "; ".join(feedback),
                    "faculty_name": faculty_name,
                    "enrollment_number": enrollment_number
                })
        except GitlabGetError:
            return results, f"No README.md found in profile repository {profile_repo_path}"
        except UnicodeDecodeError:
            return results, f"Unable to decode README.md in {profile_repo_path}"
        return results, None
    except GitlabAuthenticationError as e:
        return [], f"Authentication error: {e}"
    except Exception as e:
        return [], f"Error for {username}: {e}"

def process_single_user():
    """Process a single user's input."""
    st.subheader("Single User Analysis")
    username = st.text_input("GitLab Username")
    enrollment_number = st.text_input("Enrollment Number")
    faculty_name = st.text_input("Faculty Name")

    if st.button("Analyze Single User Resume"):
        if not username or not enrollment_number or not faculty_name:
            st.error("Please provide username, enrollment number, and faculty name.")
            return

        results, error = get_user_readmes(username.strip(), enrollment_number.strip(), faculty_name.strip())
        if error:
            st.warning(error)
            return

        if not results:
            st.warning(f"No resume-like README found for {username}.")
            return

        # Display results
        st.header("Resume Analysis Results")
        result_df = pd.DataFrame(results)
        for _, row in result_df.iterrows():
            st.subheader(f"User: {row['username']} | Project: {row['project_name']}")
            st.write(f"**Score**: {row['score']}/100")
            st.write(f"**Faculty Name**: {row['faculty_name']}")
            st.write(f"**Enrollment Number**: {row['enrollment_number']}")
            st.write("**Feedback**:")
            for tip in row['feedback'].split("; "):
                st.write(f"- {tip}")
            st.markdown("---")

        # Download results
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
            result_df[["username", "project_name", "score", "faculty_name", "enrollment_number", "feedback"]].to_csv(tmp.name, index=False)
            with open(tmp.name, "rb") as f:
                st.download_button(
                    "Download Score and Feedback",
                    f,
                    file_name=f"{username}_resume_scores_feedback.csv",
                    mime="text/csv"
                )
        os.unlink(tmp.name)

def process_csv():
    """Process CSV file for batch analysis."""
    st.subheader("Upload CSV File")
    uploaded_file = st.file_uploader("Upload CSV with 'username', 'enrollment_number', 'faculty_name'", type="csv")

    if uploaded_file and st.button("Analyze Resumes"):
        try:
            # Read CSV
            df = pd.read_csv(uploaded_file)

            # Validate columns
            required_cols = ['username', 'enrollment_number', 'faculty_name']
            missing_cols = [col for col in required_cols if col.lower() not in [c.lower() for c in df.columns]]
            if missing_cols:
                st.error(f"CSV missing columns: {', '.join(missing_cols)}")
                return

            # Normalize column names
            df.columns = [col.lower() for col in df.columns]

            # Drop duplicates
            user_data_df = df.drop_duplicates(subset='username', keep='first')
            usernames = user_data_df['username'].dropna().unique()
        except Exception as e:
            st.error(f"Error reading CSV: {e}")
            return

        all_results = []
        progress = st.progress(0)
        status_text = st.empty()

        for i, username in enumerate(usernames):
            status_text.text(f"Processing {username} ({i+1}/{len(usernames)})...")
            # Create a temporary DataFrame for the current user
            user_row = user_data_df[user_data_df['username'].str.lower() == username.lower()]
            enrollment = user_row['enrollment_number'].iloc[0] if not user_row.empty else "Not found"
            faculty = user_row['faculty_name'].iloc[0] if not user_row.empty else "Not found"
            results, error = get_user_readmes(username.strip(), enrollment, faculty)
            if error:
                st.warning(error)
            all_results.extend(results)
            progress.progress((i + 1) / len(usernames))

        if not all_results:
            st.warning("No resume-like READMEs found in profile repositories.")
            return

        # Display results
        st.header("Resume Analysis Results")
        result_df = pd.DataFrame(all_results)
        for _, row in result_df.iterrows():
            st.subheader(f"User: {row['username']} | Project: {row['project_name']}")
            st.write(f"**Score**: {row['score']}/100")
            st.write(f"**Faculty Name**: {row['faculty_name']}")
            st.write(f"**Enrollment Number**: {row['enrollment_number']}")
            st.write("**Feedback**:")
            for tip in row['feedback'].split("; "):
                st.write(f"- {tip}")
            st.markdown("---")

        # Download results
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
            result_df[["username", "project_name", "score", "faculty_name", "enrollment_number", "feedback"]].to_csv(tmp.name, index=False)
            with open(tmp.name, "rb") as f:
                st.download_button(
                    "Download Score and Feedback",
                    f,
                    file_name="resume_scores_feedback.csv",
                    mime="text/csv"
                )
        os.unlink(tmp.name)

def main():
    # Tabs for single user and CSV processing
    tab1, tab2 = st.tabs(["Single User", "Batch CSV Processing"])
    
    with tab1:
        process_single_user()
    
    with tab2:
        process_csv()

if __name__ == "__main__":
    main()