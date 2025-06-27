import streamlit as st
from datetime import datetime, timedelta, date  
from collections import defaultdict
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dateutil.parser import parse as parse_datetime
import time
import re
from urllib.parse import quote
import json
import os
import pytz 
from utils.validate_gitlab_token import validate_gitlab_token
from apis.commits_api import get_gitlab_headers,safe_api_request
from apis.vscode_validation_api import validate_gitlab_token,validate_group_access  # noqa: F811
from apis.groups_api import get_group_members
from apis.projects_api import get_all_accessible_projects
from apis.projects_api import get_project_activity
from apis.users_api import check_readme_exists_api,fetch_readme_status
import hashlib

# Timezone configuration for IST
LOCAL_TIMEZONE = pytz.timezone('Asia/Kolkata')  # IST - Indian Standard Time

DEFAULT_USERNAME = "intern_user"
DEFAULT_PASSWORD = "intern2024"
DEFAULT_ADMIN_USERNAME = "admin_user"
DEFAULT_ADMIN_PASSWORD = "admin2024"

# Configuration
GITLAB_URL = "https://code.swecha.org"

# Enhanced styling
st.set_page_config(
    page_title="GitLab Analytics Dashboard",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Authentication Functions
def hash_password(password):
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def validate_user_credentials(username, password):
    """Validate user credentials"""
    return (username == DEFAULT_USERNAME and 
            hash_password(password) == hash_password(DEFAULT_PASSWORD))

def validate_admin_credentials(username, password):
    """Validate admin credentials"""
    return (username == DEFAULT_ADMIN_USERNAME and 
            hash_password(password) == hash_password(DEFAULT_ADMIN_PASSWORD))

# User Management Functions
def load_users():
    """Load users from JSON file"""
    users_file = "users.json"
    if os.path.exists(users_file):
        try:
            with open(users_file, 'r') as f:
                return json.load(f)
        except:
            pass
    # Default users if file doesn't exist
    return {
        DEFAULT_USERNAME: {
            "password_hash": hash_password(DEFAULT_PASSWORD),
            "access_token": "",
            "created_at": datetime.now().isoformat(),
            "is_active": True
        }
    }

def save_users(users):
    """Save users to JSON file (convert tokens to dummy values for repo safety)"""
    users_file = "users.json"
    # If pushing to repo, replace all access tokens with a placeholder
    if os.environ.get("GITHUB_ACTIONS") or os.environ.get("CI") or os.environ.get("EXPORT_USERS_DUMMY", "0") == "1":
        users_to_save = {}
        for username, user in users.items():
            user_copy = user.copy()
            if user_copy.get("access_token"):
                user_copy["access_token"] = "DUMMY_TOKEN"
            users_to_save[username] = user_copy
    else:
        users_to_save = users
    try:
        with open(users_file, 'w') as f:
            json.dump(users_to_save, f, indent=2)
        return True
    except Exception as e:
        st.error(f"Error saving users: {e}")
        return False

def validate_user_credentials_dynamic(username, password):
    """Validate user credentials dynamically from stored users"""
    users = load_users()
    if username in users:
        user = users[username]
        if user.get("is_active", True):
            return hash_password(password) == user["password_hash"]
    return False

def get_user_token(username):
    """Get user's access token"""
    users = load_users()
    if username in users:
        return users[username].get("access_token", "")
    return ""

def show_authentication_screen():
    """Show authentication screen before dashboard access"""
    st.markdown("""
    <style>
        .auth-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 3rem;
            border-radius: 20px;
            color: white;
            text-align: center;
            margin-bottom: 2rem;
            box-shadow: 0 10px 40px rgba(102, 126, 234, 0.3);
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.markdown("""
    <div class="auth-header">
        <h1>🔐 Authentication Required</h1>
        <p>GitLab Analytics Dashboard - Secure Access</p>
        <p style="font-size: 0.9em; opacity: 0.8;">Please authenticate to access the dashboard</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize session state for login flow
    if 'login_step' not in st.session_state:
        st.session_state.login_step = 'credentials'
    if 'temp_user_type' not in st.session_state:
        st.session_state.temp_user_type = None
    if 'temp_username' not in st.session_state:
        st.session_state.temp_username = None
    
    # Step 1: Username and Password
    if st.session_state.login_step == 'credentials':
        st.markdown("###  Login")
        st.info("Enter your username and password to continue.")
        
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            login_submitted = st.form_submit_button("🚀 Login", use_container_width=True)
        
        if login_submitted and username and password:
            # Check admin credentials first
            if validate_admin_credentials(username, password):
                st.session_state.login_step = 'admin_token'
                st.session_state.temp_user_type = 'admin'
                st.session_state.temp_username = username
                st.success("✅ Admin credentials verified! Please enter your GitLab token.")
                st.rerun()
            # Check faculty credentials
            elif validate_user_credentials_dynamic(username, password):
                # Faculty login - complete authentication
                st.session_state.authenticated = True
                st.session_state.user_type = "user"
                st.session_state.auth_user_info = {"username": username, "access_level": "user"}
                st.session_state.token_validated = True
                st.success("✅ Faculty Authentication Successful! Loading dashboard...")
                st.rerun()
            else:
                st.error("❌ Authentication Failed - Invalid username or password.")
        elif login_submitted:
            st.error("❌ Please fill in all fields (username and password).")
    
    # Step 2: Admin Token Input
    elif st.session_state.login_step == 'admin_token':
        st.markdown("### 🔐 Admin Token Required")
        st.info("Please enter your GitLab access token to complete admin authentication.")
        
        with st.form("admin_token_form"):
            admin_token = st.text_input(
                "GitLab Access Token",
                type="password",
                placeholder="glpat-xxxxxxxxxxxxxxxxxxxx",
                help="Enter your GitLab personal access token"
            )
            
            col1, col2 = st.columns(2)
            with col1:
                token_submitted = st.form_submit_button("🔓 Complete Login", use_container_width=True)
            with col2:
                back_button = st.form_submit_button("⬅️ Back", use_container_width=True)
        
        if back_button:
            # Reset to credentials step
            st.session_state.login_step = 'credentials'
            st.session_state.temp_user_type = None
            st.session_state.temp_username = None
            st.rerun()
        
        if token_submitted and admin_token:
            with st.spinner("🔍 Validating GitLab token..."):
                validation_result = validate_gitlab_token(admin_token)
                
                if validation_result["success"]:
                    user_info = validation_result["user_info"]
                    # Set authentication and GitLab token for dashboard
                    st.session_state.authenticated = True
                    st.session_state.user_type = "admin"
                    st.session_state.auth_user_info = user_info
                    st.session_state.gitlab_token = admin_token
                    st.session_state.token_validated = True
                    st.session_state.user_info = user_info
                    
                    # Clear temporary session state
                    st.session_state.login_step = 'credentials'
                    st.session_state.temp_user_type = None
                    st.session_state.temp_username = None
                    
                    st.success(f"✅ Admin Authentication Successful! Welcome, {user_info.get('name', 'Administrator')}")
                    st.rerun()
                else:
                    st.error(f"❌ Token Validation Failed: {validation_result.get('error', 'Invalid token')}")
        elif token_submitted:
            st.error("❌ Please enter your GitLab access token.")
    
    # Welcome message
    st.markdown("""
    <div style="background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); 
                padding: 2rem; border-radius: 15px; margin-top: 2rem; text-align: center;">
        <h3 style="color: #2c3e50; margin-bottom: 1rem;">🎉 Welcome to GitLab Analytics Dashboard</h3>
        <p style="color: #34495e; font-size: 1.1em; margin-bottom: 0.5rem;">
            Track your GitLab contributions and analyze project insights
        </p>
        <p style="color: #7f8c8d; font-size: 0.9em;">
            Please authenticate above to access your personalized dashboard
        </p>
    </div>
    """, unsafe_allow_html=True)

# Initialize authentication session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

if 'user_type' not in st.session_state:
    st.session_state.user_type = None

if 'auth_user_info' not in st.session_state:
    st.session_state.auth_user_info = None

if 'show_user_management' not in st.session_state:
    st.session_state.show_user_management = False

# Authentication Check - Show authentication screen if not authenticated
if not st.session_state.get('authenticated', False):
    show_authentication_screen()
    st.stop()  # Stop execution until authenticated

# Add logout button in sidebar for authenticated users
if st.session_state.get('authenticated', False):
    with st.sidebar:
        st.markdown("---")
        user_type = st.session_state.get('user_type', 'unknown')
        auth_user_info = st.session_state.get('auth_user_info', {})
        
        if user_type == "admin":
            st.success(f"✅ Admin: {auth_user_info.get('name', 'Unknown')}")
            st.info(f"Username: @{auth_user_info.get('username', 'Unknown')}")
            
            # Admin can change token
            if st.button("🔄 Change Token"):
                st.session_state.gitlab_token = ""
                st.session_state.token_validated = False
                st.session_state.user_info = None
                st.cache_data.clear()
                st.rerun()
        else:
            st.success(f"✅ User: {auth_user_info.get('username', 'Unknown')}")
            st.info("🔒 Using assigned access token")
        
        if st.button("🔄 Logout", use_container_width=True):
            # Clear all session state
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

# User Management Interface (Admin Only)
if st.session_state.get('user_type') == 'admin':
    st.sidebar.markdown("---")
    if st.sidebar.button("👥 Manage Users", use_container_width=True):
        st.session_state.show_user_management = True
        st.rerun()

# User Management Modal/Section
if st.session_state.get('show_user_management', False) and st.session_state.get('user_type') == 'admin':
    st.markdown("---")
    st.markdown("## 👥 User Management")
    
    # Load current users
    users = load_users()
    
    # Tabs for different management functions
    tab1, tab2, tab3 = st.tabs(["📋 View Users", "➕ Add User", "✏️ Edit User"])
    
    with tab1:
        st.markdown("### 📋 Current Users")
        if users:
            user_data = []
            for username, user_info in users.items():
                user_data.append({
                    "Username": username,
                    "Status": "🟢 Active" if user_info.get("is_active", True) else "🔴 Inactive",
                    "Created": user_info.get("created_at", "Unknown")[:10],
                    "Has Token": "✅ Yes" if user_info.get("access_token") else "❌ No"
                })
            
            df = pd.DataFrame(user_data)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No users found.")
    
    with tab2:
        st.markdown("### ➕ Add New User")
        with st.form("add_user_form"):
            new_username = st.text_input("Username", placeholder="Enter new username")
            new_password = st.text_input("Password", type="password", placeholder="Enter password")
            new_token = st.text_input("GitLab Access Token (Optional)", type="password", placeholder="glpat-xxxxxxxxxxxxxxxxxxxx")
            
            add_user_submitted = st.form_submit_button("➕ Add User")
            
            if add_user_submitted and new_username and new_password:
                if new_username in users:
                    st.error("❌ Username already exists!")
                else:
                    # Validate token if provided
                    token_valid = True
                    if new_token:
                        with st.spinner("🔍 Validating GitLab token..."):
                            validation_result = validate_gitlab_token(new_token)
                            token_valid = validation_result["success"]
                            if not token_valid:
                                st.error(f"❌ Invalid GitLab token: {validation_result.get('error', 'Unknown error')}")
                    
                    if token_valid:
                        users[new_username] = {
                            "password_hash": hash_password(new_password),
                            "access_token": new_token if new_token else "",
                            "created_at": datetime.now().isoformat(),
                            "is_active": True
                        }
                        
                        if save_users(users):
                            st.success(f"✅ User '{new_username}' added successfully!")
                            st.rerun()
                        else:
                            st.error("❌ Failed to save user data.")
            elif add_user_submitted:
                st.error("❌ Please fill in username and password.")
    
    with tab3:
        st.markdown("### ✏️ Edit User")
        if users:
            selected_user = st.selectbox("Select User to Edit", list(users.keys()))
            
            if selected_user:
                user_info = users[selected_user]
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("#### Change Password")
                    with st.form(f"change_password_{selected_user}"):
                        new_password = st.text_input("New Password", type="password", placeholder="Enter new password")
                        change_password_submitted = st.form_submit_button("🔑 Change Password")
                        
                        if change_password_submitted and new_password:
                            users[selected_user]["password_hash"] = hash_password(new_password)
                            if save_users(users):
                                st.success(f"✅ Password changed for '{selected_user}'!")
                                st.rerun()
                            else:
                                st.error("❌ Failed to save changes.")
                        elif change_password_submitted:
                            st.error("❌ Please enter a new password.")
                
                with col2:
                    st.markdown("#### Change Access Token")
                    with st.form(f"change_token_{selected_user}"):
                        new_token = st.text_input("New GitLab Access Token", type="password", 
                                                placeholder="glpat-xxxxxxxxxxxxxxxxxxxx",
                                                value="")
                        change_token_submitted = st.form_submit_button("🔑 Change Token")
                        
                        if change_token_submitted:
                            if new_token:
                                with st.spinner("🔍 Validating GitLab token..."):
                                    validation_result = validate_gitlab_token(new_token)
                                    
                                    if validation_result["success"]:
                                        users[selected_user]["access_token"] = new_token
                                        if save_users(users):
                                            st.success(f"✅ Token updated for '{selected_user}'!")
                                            st.rerun()
                                        else:
                                            st.error("❌ Failed to save changes.")
                                    else:
                                        st.error(f"❌ Invalid token: {validation_result.get('error', 'Unknown error')}")
                            else:
                                # Remove token
                                users[selected_user]["access_token"] = ""
                                if save_users(users):
                                    st.success(f"✅ Token removed for '{selected_user}'!")
                                    st.rerun()
                                else:
                                    st.error("❌ Failed to save changes.")
                
                # User status and deletion
                st.markdown("#### User Actions")
                col3, col4 = st.columns(2)
                
                with col3:
                    current_status = user_info.get("is_active", True)
                    if st.button(f"{'🔴 Deactivate' if current_status else '🟢 Activate'} User"):
                        users[selected_user]["is_active"] = not current_status
                        if save_users(users):
                            status_text = "activated" if not current_status else "deactivated"
                            st.success(f"✅ User '{selected_user}' {status_text}!")
                            st.rerun()
                        else:
                            st.error("❌ Failed to save changes.")
                
                with col4:
                    if st.button("🗑️ Delete User", type="secondary"):
                        if selected_user != DEFAULT_USERNAME:  # Prevent deleting default user
                            del users[selected_user]
                            if save_users(users):
                                st.success(f"✅ User '{selected_user}' deleted!")
                                st.rerun()
                            else:
                                st.error("❌ Failed to save changes.")
                        else:
                            st.error("❌ Cannot delete the default user!")
        else:
            st.info("No users available to edit.")
    
    # Close button
    if st.button("❌ Close User Management"):
        st.session_state.show_user_management = False
        st.rerun()

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2.5rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .metric-card {
        background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
        padding: 2rem;
        border-radius: 15px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
        border-left: 5px solid #667eea;
        margin: 1rem 0;
        transition: transform 0.3s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
    }
    
    .status-active {
        color: #28a745;
        font-weight: bold;
        background: #d4edda;
        padding: 4px 8px;
        border-radius: 20px;
        font-size: 0.9em;
    }
    
    .status-inactive {
        color: #dc3545;
        font-weight: bold;
        background: #f8d7da;
        padding: 4px 8px;
        border-radius: 20px;
        font-size: 0.9em;
    }
    
    .debug-info {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #007bff;
        margin: 1rem 0;
        font-family: monospace;
        font-size: 0.9em;
    }
    
    .error-info {
        background: #fff3cd;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #ffc107;
        margin: 1rem 0;
    }
    
    .project-list {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #28a745;
        margin: 1rem 0;
        max-height: 400px;
        overflow-y: auto;
    }
    
    .project-item {
        padding: 0.5rem;
        margin: 0.25rem 0;
        background: white;
        border-radius: 4px;
        border: 1px solid #e9ecef;
    }
</style>
""", unsafe_allow_html=True)


# Header
st.markdown("""
<div class="main-header">
    <h1>📊  GitLab Analytics Dashboard</h1>
    <p>BITS Pilani Internship - Comprehensive GitLab Contributions Analysis</p>
    <p style="font-size: 0.9em; opacity: 0.8;">Real-time activity tracking with enhanced user insights</p>
</div>
""", unsafe_allow_html=True)

# Initialize session state
if 'start_time' not in st.session_state:
    st.session_state.start_time = time.time()

if 'gitlab_token' not in st.session_state:
    st.session_state.gitlab_token = ""

if 'token_validated' not in st.session_state:
    st.session_state.token_validated = False

if 'user_info' not in st.session_state:
    st.session_state.user_info = None

if 'projects_cache' not in st.session_state:
    st.session_state.projects_cache = None

if 'members_cache' not in st.session_state:
    st.session_state.members_cache = None

# Token Management Section
st.markdown("---")
if not st.session_state.get('token_validated', False):
    st.markdown("## 🔐 GitLab Authentication Required")
    st.info("Please enter your personal GitLab access token to access the dashboard.")
    
    with st.form("token_form"):
        gitlab_token = st.text_input(
            "GitLab Access Token", 
            type="password", 
            placeholder="glpat-xxxxxxxxxxxxxxxxxxxx",
            help="Enter your GitLab personal access token with 'read_api' scope"
        )
        submitted = st.form_submit_button("🚀 Connect to GitLab")
        
        if submitted and gitlab_token:
            # Validate the token
            
            with st.spinner("🔍 Validating GitLab token..."):
                validation_result = validate_gitlab_token(gitlab_token)
                
            if validation_result["success"]:
                st.session_state.gitlab_token = gitlab_token
                st.session_state.token_validated = True
                st.session_state.user_info = validation_result["user_info"]
                st.success(f"✅ Successfully authenticated as: {validation_result['user_info']['name']}")
                st.rerun()
            else:
                st.error(f"❌ Authentication failed: {validation_result['error']}")
                st.info("Please check your token and ensure it has 'read_api' scope.")
    
    # Instructions for creating a token
    with st.expander("ℹ️ How to create a GitLab Access Token"):
        st.markdown(f"""
        1. Go to [{GITLAB_URL}/-/profile/personal_access_tokens]({GITLAB_URL}/-/profile/personal_access_tokens)
        2. Click "Add new token"
        3. Enter a name for your token
        4. Select expiration date
        5. Check the **read_api** scope
        6. Click "Create personal access token"
        7. Copy the token and paste it above
        """)
    
    st.stop()  # Stop execution until token is provided

# Show authenticated user info in sidebar if token is validated
# if st.session_state.get('token_validated', False) and st.session_state.get('user_info'):
#     st.sidebar.success(f"✅ Authenticated as: {st.session_state.user_info['name']}")
#     st.sidebar.info(f"Username: @{st.session_state.user_info['username']}")
    
#     if st.sidebar.button("🔄 Change Token"):
#         st.session_state.gitlab_token = ""
#         st.session_state.token_validated = False
#         st.session_state.user_info = None
#         st.cache_data.clear()
#         st.rerun()

# Debug mode toggle
debug_mode = False




# Sidebar configuration
st.sidebar.markdown("## ⚙️ Group Selection")

st.session_state.setdefault("group_id", None)

# Sidebar option to choose input method
group_input_method = st.sidebar.radio("Choose Group Input Method", ["Single Group"])

# Handle group ID input via buttons
if group_input_method == "Single Group":
    # Define button callbacks
    def set_group_69994():
        st.session_state.group_id = "69994"

    def set_group_72165():
        st.session_state.group_id = "72165"

    # Sidebar buttons
    st.sidebar.button("Click For Bits Interns", on_click=set_group_69994)
    st.sidebar.button("Click For ICFAI Interns", on_click=set_group_72165)

    # Convert to list
    group_ids = [st.session_state.group_id] if st.session_state.group_id else []
else:
    group_ids_text = st.sidebar.text_area(
        "🏢 GitLab Group IDs",
        value="69994",
        placeholder="Enter group IDs, one per line:\n69994\n12345\n67890",
        help="Enter multiple group IDs, one per line"
    )
    group_ids = [gid.strip() for gid in group_ids_text.split('\n') if gid.strip() and gid.strip().isdigit()]

if not group_ids:
    st.sidebar.info("Please enter at least one valid numeric group ID")
    st.stop()

st.sidebar.success(f"Analyzing {len(group_ids)} group(s)")

if not group_ids:
    st.sidebar.error("Please enter a valid numeric group ID")
    st.stop()

st.sidebar.success(f"Analyzing group: {group_ids}")


# Validate group access
if st.sidebar.button("🔍 Validate Group Access"):
    for gid in group_ids:
        with st.spinner(f"Validating access to group {gid}..."):
            validation = validate_group_access(gid)
            if validation["success"]:
                st.sidebar.success(f"✅ Group {gid}: {validation['group_info']['name']}")
            else:
                st.sidebar.error(f"❌ Group {gid}: {validation['error']}")



# Enhanced sidebar options
# days = st.sidebar.slider("📅 Analysis Period (days)", 1, 90, 30)





# Date range selection
st.sidebar.markdown("### 📅 Analysis Date Range")
col1 = st.sidebar.columns(1)[0]
with col1:
    start_date = st.date_input("Start Date", 
                             datetime.now() - timedelta(days=30),
                             key="start_date")
    formatted_start_date = start_date.strftime("%B %d").lstrip("0")
    st.info(f"{formatted_start_date} -> Today")
# with col2:
#     end_date = st.date_input("End Date", 
#                            datetime.now(),
#                            key="end_date")
end_date = datetime.now().date()

# Validate date range
if start_date > end_date:
    st.sidebar.error("Error: Start date must be before end date.")
    st.stop()

# Calculate days for any existing day-based calculations
days = (end_date - start_date).days






st.sidebar.markdown("---")

# Filters
st.sidebar.markdown("### 🔍 Filters")
show_inactive = st.sidebar.checkbox("Show inactive users", value=True)
activity_threshold = st.sidebar.slider("Minimum activity threshold", 0, 20, 1)
show_detailed_activities = st.sidebar.checkbox("Show detailed activities", value=False)

st.sidebar.markdown("---")

# Analysis options
st.sidebar.markdown("### 📊 Analysis Options")
include_comments = st.sidebar.checkbox("Include comments in activity", value=True)
use_project_based = st.sidebar.checkbox("Use project-based analysis", value=True, 
                                        help="Analyze activities from all accessible projects")
show_project_list = st.sidebar.checkbox("Show all available projects", value=False,
                                        help="Display a list of all accessible projects")

st.sidebar.markdown("---")

# Action buttons
if st.sidebar.button("🔄 Refresh Data", type="primary"):
    # Clear caches but keep token
    st.cache_data.clear()
    st.session_state.projects_cache = None
    st.session_state.members_cache = None
    st.rerun()

# Test API connection
if st.sidebar.button("🧪 Test API Connection"):
    headers = get_gitlab_headers()
    if headers:
        test_result = safe_api_request(f"{GITLAB_URL}/api/v4/user", headers)
        if test_result["success"]:
            user_info = test_result["data"]
            st.sidebar.success(f"✅ Connected as: {user_info.get('name', 'Unknown')}")
            st.sidebar.info(f"Username: @{user_info.get('username', 'Unknown')}")
            st.sidebar.info(f"User ID: {user_info.get('id', 'Unknown')}")
        else:
            st.sidebar.error(f"❌ API connection failed: {test_result['error']}")
            st.sidebar.warning("Consider refreshing your token if this persists.")
    else:
        st.sidebar.error("❌ No GitLab token available")

# Main application logic
def main():
    # Check if token is available
    headers = get_gitlab_headers()
    if not headers:
        st.error("⚠️ GitLab token not found!")
        st.info("Please provide your GitLab token in one of these ways:")
        st.code("1. Set environment variable: export GITLAB_TOKEN=your_token")
        st.code("2. Create .streamlit/secrets.toml with: GITLAB_TOKEN = 'your_token'")
        st.code("3. Enter token in the sidebar")
        st.error("⚠️ Authentication error - please refresh the page")
        return
    



    # since_date = datetime.now() - timedelta(days=days)
    
    since_date = start_date



    st.info(f"📅 Analyzing activities from {since_date.strftime('%Y-%m-%d')} to {datetime.now().strftime('%Y-%m-%d')}")
    
    # Load group members
    # Load members from all groups
    all_members = []
    with st.spinner(f"🔍 Loading members from {len(group_ids)} group(s)..."):
        for gid in group_ids:
            members_result = get_group_members(gid)
            if members_result["success"]:
                all_members.extend(members_result["data"])
                st.success(f"✅ Found {len(members_result['data'])} members in group {gid}")
            else:
                st.error(f"❌ Failed to load group {gid}: {members_result['error']}")

    # Remove duplicates based on user ID
    seen_users = set()
    members = []
    for member in all_members:
        if member["id"] not in seen_users:
            members.append(member)
            seen_users.add(member["id"])

    if not members:
        st.error("❌ No members found in any of the specified groups")
        return
    
    # Load projects if requested
    projects = []
    if use_project_based or show_project_list:
        with st.spinner("📁 Loading accessible projects..."):
            projects_result = get_all_accessible_projects()
        
        if not projects_result["success"]:
            st.error(f"❌ Unable to fetch projects: {projects_result['error']}")
            if not use_project_based:
                st.info("Project list unavailable, but analysis can continue without project-based data")
            else:
                return
        else:
            projects = projects_result["data"]
            st.success(f"📁 Found {len(projects)} accessible projects")
    
    # Show project list if requested
    if show_project_list and projects:
        st.markdown("## 📁 All Available Projects")
        
        # Create a searchable project list
        search_term = st.text_input("🔍 Search projects:", placeholder="Type to filter projects...")
        
        # Filter projects based on search
        filtered_projects = projects
        if search_term:
            filtered_projects = [
    p for p in projects
    if search_term.lower() in p['name'].lower() or
       search_term.lower() in (p.get('description') or '').lower()
]

        
        # Sort projects by last activity
        try:
            filtered_projects.sort(key=lambda x: x.get('last_activity_at', ''), reverse=True)
        except:
            pass
        
        st.info(f"Showing {len(filtered_projects)} projects" + (f" (filtered from {len(projects)})" if search_term else ""))
        
        # Display projects in a nice format
        project_data = []
        for project in filtered_projects[:100]:  # Limit display to 100 projects
            last_activity = "Never"
            if project.get('last_activity_at'):
                try:
                    last_activity_dt = parse_datetime(project['last_activity_at'])
                    last_activity = last_activity_dt.strftime('%B %d %H:%M')
                except:
                    last_activity = project.get('last_activity_at', 'Never')
            
            project_data.append({
                "Name": project['name'],
                "ID": project['id'],
                "Description": (project.get('description') or 'No description')[:100] + ("..." if len(project.get('description') or '') > 100 else ""),
                "Visibility": project.get('visibility', 'Unknown'),
                "Last Activity": last_activity,
                "Stars": project.get('star_count', 0),
                "Forks": project.get('forks_count', 0),
                "Web URL": project.get('web_url', '')
            })
        
        if project_data:
            projects_df = pd.DataFrame(project_data)
            st.dataframe(
                projects_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Name": st.column_config.TextColumn("Project Name", width="medium"),
                    "ID": st.column_config.NumberColumn("Project ID", width="small"),
                    "Description": st.column_config.TextColumn("Description", width="large"),
                    "Visibility": st.column_config.TextColumn("Visibility", width="small"),
                    "Last Activity": st.column_config.TextColumn("Last Activity", width="medium"),
                    "Stars": st.column_config.NumberColumn("⭐ Stars", width="small"),
                    "Forks": st.column_config.NumberColumn("🍴 Forks", width="small"),
                    "README": st.column_config.TextColumn("📝 README", width="small"),
                    "Web URL": st.column_config.LinkColumn("🔗 URL", width="medium")
                }
            )
            
            # Download projects list
            projects_csv = projects_df.to_csv(index=False)
            st.download_button(
                label="📥 Download Projects List",
                data=projects_csv,
                file_name=f"gitlab_projects_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        st.markdown("---")
    
    # Create valid names set
    valid_names = {member["name"] for member in members}
    
    if debug_mode:
        st.markdown(f"""
        <div class="debug-info">
            <strong>Debug Info:</strong><br>
            - Group ID: {group_id}<br>
            - GitLab URL: {GITLAB_URL}<br>
            - Members found: {len(members)}<br>
            - Projects found: {len(projects)}<br>
            - Analysis period: {days} days<br>
            - Since date: {since_date.isoformat()}<br>
            - Using project-based analysis: {use_project_based}
        </div>
        """, unsafe_allow_html=True)  # noqa: F821
    
    # Initialize user stats with all group members
    user_stats = {}
    for member in members:
        user_stats[member["name"]] = {
            "username": member["username"],
            "user_id": member["id"],
            "name": member["name"],
            "commits": 0,
            "merge_requests": 0,
            "issues": 0,
            "comments": 0,
            "push_events": 0,
            "projects": set(),
            "last_activity": None,
            "commit_dates": [],
            "mr_dates": [],
            "issue_dates": [],
            "activity_details": []
        }
    
    if use_project_based and projects:
        # Project-based analysis
        st.markdown("### 🔄 Processing Project Activities...")
        
        # Process projects with improved progress tracking
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Limit the number of projects to analyze to avoid timeout
        max_projects = min(len(projects), 150)  # Limit to 50 most recent projects
        projects_to_analyze = projects[:max_projects]
        
        if len(projects) > max_projects:
            st.warning(f"⚠️ Limiting analysis to {max_projects} most recent projects out of {len(projects)} total projects to avoid timeout.")
        
        def process_project_wrapper(args):
            project, index = args
            project_stats = get_project_activity(
                project["id"], 
                project["name"], 
                since_date, 
                valid_names
            )
            return project_stats, index, project["name"]
        
        if debug_mode:
            # Sequential processing for debugging
            for i, project in enumerate(projects_to_analyze):
                project_stats, _, project_name = process_project_wrapper((project, i))
                
                # Update user stats
                for user, stats in project_stats.items():
                    if user in user_stats:
                        user_data = user_stats[user]
                        user_data["commits"] += stats["commits"]
                        user_data["merge_requests"] += stats["merge_requests"]
                        user_data["issues"] += stats["issues"]
                        user_data["push events"].update(stats["push_events"])
                        user_data["projects"].update(stats["project_names"])
                        
                        if not user_data["last_activity"] or (stats["last_activity"] and stats["last_activity"] > user_data["last_activity"]):
                            user_data["last_activity"] = stats["last_activity"]
                
                progress = (i + 1) / len(projects_to_analyze)
                progress_bar.progress(progress)
                status_text.text(f"Processing project {i + 1}/{len(projects_to_analyze)}: {project_name}")
        else:
            # Parallel processing for speed
            with ThreadPoolExecutor(max_workers=6) as executor:
                project_args = [(project, i) for i, project in enumerate(projects_to_analyze)]
                futures = {executor.submit(process_project_wrapper, args): args for args in project_args}
                
                completed = 0
                for future in as_completed(futures):
                    try:
                        project_stats, index, project_name = future.result()
                        
                        # Update user stats
                        for user, stats in project_stats.items():
                            if user in user_stats:
                                user_data = user_stats[user]
                                user_data["commits"] += stats["commits"]
                                user_data["merge_requests"] += stats["merge_requests"]
                                user_data["issues"] += stats["issues"]
                                user_data["push_events"] += stats["push_events"]
                                user_data["projects"].update(stats["project_names"])
                                
                                if not user_data["last_activity"] or (stats["last_activity"] and stats["last_activity"] > user_data["last_activity"]):
                                    user_data["last_activity"] = stats["last_activity"]
                        
                        completed += 1
                        progress = completed / len(projects_to_analyze)
                        progress_bar.progress(progress)
                        status_text.text(f"Processing project {completed}/{len(projects_to_analyze)}: {project_name}")
                    
                    except Exception as e:
                        if debug_mode:
                            st.write(f"Error processing project: {e}")
                        completed += 1
                        progress = completed / len(projects_to_analyze)
                        progress_bar.progress(progress)
        
        progress_bar.empty()
        status_text.empty()
    else:
        st.info("⚠️ Project-based analysis is disabled. Limited data may be available.")
    
    # Calculate comprehensive statistics
    total_members = len(user_stats)
    active_members = sum(1 for stats in user_stats.values() 
                        if (stats["commits"] + stats["merge_requests"] + stats["issues"]) >= activity_threshold)
    
    total_commits = sum(stats["commits"] for stats in user_stats.values())
    total_mrs = sum(stats["merge_requests"] for stats in user_stats.values())
    total_issues = sum(stats["issues"] for stats in user_stats.values())
    total_comments = sum(stats["comments"] for stats in user_stats.values())
    total_push_events = sum(stats["push_events"] for stats in user_stats.values())
    
    all_projects = set()
    for stats in user_stats.values():
        all_projects.update(stats["projects"])

    total_activity= total_commits + total_issues + total_mrs + total_push_events
    
    # Show processing summary
    if debug_mode:
        processing_summary = f"""
        <div class="debug-info">
            <strong>Processing Summary:</strong><br>
            - Members processed: {len(user_stats)}<br>
            - Total activities found: {total_commits + total_mrs + total_issues}<br>
            - Active members: {active_members}<br>
            - Projects with activity: {len(all_projects)}<br>
            - Total commits: {total_commits}<br>
            - Total MRs: {total_mrs}<br>
            - Total issues: {total_issues}
        </div>
        """
        st.markdown(processing_summary, unsafe_allow_html=True)
    
    # Data validation warnings
    if total_commits == 0 and total_mrs == 0 and total_issues == 0:
        st.warning("""
        ⚠️ **No activities found!** This could indicate:
        - Token permissions are insufficient (needs 'read_api' scope)
        - Date range is too restrictive
        - Users haven't been active in the specified period
        - Group members don't have access to projects being analyzed
        """)
        # Display comprehensive metrics
    st.markdown("## 📊 Overall Statistics")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.markdown(f"""
    <div class="metric-card">
        <h3 style="color: #000000;">👥 Total Members</h3>
        <h2 style="color: #667eea;">{total_members}</h2>
    </div>
    """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
    <div class="metric-card">
        <h3 style="color: #000000;">🔥 Active Members</h3>
        <h2 style="color: #28a745;">{active_members}</h2>
    </div>
    """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
    <div class="metric-card">
        <h3 style="color: #000000;">💻 Total Commits</h3>
        <h2 style="color: #17a2b8;">{total_commits}</h2>
    </div>
    """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
    <div class="metric-card">
        <h3 style="color: #000000;">🔀 Merge Requests</h3>
        <h2 style="color: #ffc107;">{total_mrs}</h2>
    </div>
    """, unsafe_allow_html=True)
    
    with col5:
        st.markdown(f"""
    <div class="metric-card">
        <h3 style="color: #000000;">🐛 Issues</h3>
        <h2 style="color: #dc3545;">{total_issues}</h2>
    </div>
    """, unsafe_allow_html=True)
    
    # Activity rate calculation
    activity_rate = (active_members / total_members * 100) if total_members > 0 else 0
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"""
    <div class="metric-card">
        <h3 style="color: #000000;">📈 Activity Rate</h3>
        <h2 style="color: {'#28a745' if activity_rate >= 50 else '#ffc107' if activity_rate >= 25 else '#dc3545'};">{activity_rate:.1f}%</h2>
    </div>
    """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
    <div class="metric-card">
        <h3 style="color: #000000;">🗂️ Active Projects</h3>
        <h2 style="color: #6f42c1;">{len(all_projects)}</h2>
    </div>
    """, unsafe_allow_html=True)
    
    with col3:
        avg_activity = (total_activity) / max(active_members, 1)
        st.markdown(f"""
    <div class="metric-card">
        <h3 style="color: #000000;">⚡ Avg Activity/User</h3>
        <h2 style="color: #e83e8c;">{avg_activity:.1f}</h2>
    </div>
    """, unsafe_allow_html=True)
    
    # Filter users based on activity threshold and show_inactive setting
    filtered_users = {}
    for user, stats in user_stats.items():
        total_activity = stats["commits"] + stats["merge_requests"] + stats["issues"] + stats["push_events"]
        if total_activity >= activity_threshold and (show_inactive or total_activity > 0):
            filtered_users[user] = stats
    
    if not filtered_users:
        st.warning("⚠️ No users match the current filter criteria. Try adjusting the activity threshold or enabling 'Show inactive users'.")
        return
    
    # Create user activity table
    st.markdown("## 👤 Individual User Analysis")

    # Load college details CSV and create a mapping for Gitlab Profile -> Enrollment Number, Faculty Mentor
    try:
        college_df = pd.read_csv("Collegedetails.csv")
        # Normalize Gitlab Profile for matching (strip, lower)
        college_df["Gitlab Profile"] = college_df["Gitlab Profile"].astype(str).str.strip().str.lower()
        profile_to_enrollment = dict(zip(college_df["Gitlab Profile"], college_df["Enrollment Number"]))
        profile_to_mentor = dict(zip(college_df["Gitlab Profile"], college_df["Faculty Mentor"]))
    except Exception as e:
        profile_to_enrollment = {}
        profile_to_mentor = {}
        st.warning(f"Could not load Collegedetails.csv: {e}")
    
    user_data = []
    for idx, (user, stats) in enumerate(filtered_users.items(), 1):
        total_activity = stats["commits"] + stats["merge_requests"] + stats["issues"]+stats["push_events"]
        last_activity_str = "Never"
        days_since_activity = "N/A"
        # Use the username (Gitlab Profile) for matching
        gitlab_profile = str(stats["username"]).strip().lower()
        enrollment_number = profile_to_enrollment.get(gitlab_profile, "-")
        faculty_mentor = profile_to_mentor.get(gitlab_profile, "-").strip().lower()
        
        if stats["last_activity"]:
    # Convert to IST and format
            utc_dt = stats["last_activity"]
            if utc_dt.tzinfo is None:
                utc_dt = utc_dt.replace(tzinfo=pytz.UTC)
            ist_dt = utc_dt.astimezone(LOCAL_TIMEZONE)
            last_activity_str = ist_dt.strftime("%B %d %H:%M IST")
    
    # Calculate days since with proper timezone
            now_ist = datetime.now(LOCAL_TIMEZONE)
            days_since = (now_ist.date() - ist_dt.date()).days
            if days_since == 0:
                days_since_activity = "0 days ago"
            elif days_since == 1:
                days_since_activity = "1 day ago"
            else:
                days_since_activity = f"{days_since} days ago"
        else:
            last_activity_str = "Never"
            days_since_activity = "N/A"
        
        if activity_threshold > 0 :
            status = "🟢 Active" if total_activity >= activity_threshold else "🔴 Inactive"
        else: 
            status = "🟢 Active" if total_activity > activity_threshold else "🔴 Inactive"
        
        user_data.append({
            "S.no": idx,
            "Name": stats["name"],
            "Username": stats["username"],
            "Faculty mentor": faculty_mentor,
            "Status": status,
            "Commits": stats["commits"],
            "Merge Requests": stats["merge_requests"],
            "Issues": stats["issues"],
            "Push events":stats["push_events"],
            "Total Activity": total_activity,
            "Projects": len(stats["projects"]),
            "Project names": stats["projects"],
            "Last Activity": last_activity_str,
            "Days Since Activity": days_since_activity
        })
    
    # Sort by total activity
    user_data.sort(key=lambda x: x["Total Activity"], reverse=True)


# Add README status check
    name_to_username = {}

# First, create the basic mapping from member data (name -> username)
    for member in members:
        name_to_username[member["name"]] = member["username"]

# Add any additional custom mappings for special cases
    custom_mappings = {
        "amar": "awmar",
        "Prem-Kowshik": "premk", 
        "Phanindra Varma": "phanindra_varma",
        "sailadachetansurya": "ChetanSurya",
    # Add more custom mappings as needed
    }

    name_to_username.update(custom_mappings)
        
        # Get README status for all users
    usernames = [data["Name"] for data in user_data]
    readme_status_map = fetch_readme_status(usernames, name_to_username)
        
        # Add README column to user data
    for data in user_data:
        data["README"] = readme_status_map.get(data["Name"], "❌")

    if debug_mode:
        st.write("### 🔍 Name to Username Mapping")
        mapping_df = pd.DataFrame([
            {"Name": name, "Username": username} 
            for name, username in name_to_username.items()
        ])
        st.dataframe(mapping_df, use_container_width=True)
    
    if user_data:
        users_df = pd.DataFrame(user_data)
        
        # Faculty mentor filter
        faculty_list = users_df["Faculty mentor"].dropna().unique().tolist()
        faculty_list = [f for f in faculty_list if f != "-"]
        faculty_list.sort()
        faculty_list.insert(0, "All")
        selected_faculty = st.selectbox("Filter by Faculty Mentor", faculty_list, index=0)
        
        if selected_faculty != "All":
            users_df = users_df[users_df["Faculty mentor"] == selected_faculty].copy()
        
        # Reset serial numbers after filtering
        users_df = users_df.reset_index(drop=True)
        users_df["S.no"] = users_df.index + 1
        
        # Ensure S.no is the first column
        cols = users_df.columns.tolist()
        if "S.no" in cols:
            cols.insert(0, cols.pop(cols.index("S.no")))
            users_df = users_df[cols]

        # Create a new column with clickable links while keeping original username
        users_df["Username"] = users_df["Username"].apply(
        lambda x: f"{GITLAB_URL}/{x}"
    )
    

        # Display table with enhanced formatting
        st.dataframe(
            users_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "S.no": st.column_config.NumberColumn("S.no", width="small"),
                "Name": st.column_config.TextColumn("👤 Name", width="medium"),
                 "Username": st.column_config.LinkColumn(
                "🌐 GitLab Profile", 
                width="medium",
                display_text=f"{GITLAB_URL}/(.*)"
            ),
                "Status": st.column_config.TextColumn("📊 Status", width="small"),
                "Commits": st.column_config.NumberColumn("💻 Commits", width="small"),
                "Merge Requests": st.column_config.NumberColumn("🔀 MRs", width="small"),
                "Issues": st.column_config.NumberColumn("🐛 Issues", width="small"),
                "Push_events": st.column_config.NumberColumn("Push_Events",width="small"),
                "Total Activity": st.column_config.NumberColumn("⚡ Total", width="small"),
                "Projects": st.column_config.NumberColumn("🗂️ Projects", width="small"),
                "Last Activity": st.column_config.TextColumn("🕒 Last Activity", width="medium"),
                "Faculty mentor": st.column_config.TextColumn("Faculty Mentor", width="medium"),
                "Days Since Activity": st.column_config.TextColumn("📅 Days Ago", width="medium")
            },
        )
        
        # Download button for user data
        users_csv = users_df.to_csv(index=False)
        st.download_button(
            label="📥 Download User Report",
            data=users_csv,
            file_name=f"gitlab_user_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    
    # Create visualizations
    st.markdown("## 📈 Data Visualizations")
    
    if len(filtered_users) > 0:
        # Top contributors chart
        fig_top_users = px.bar(
            users_df.head(10),
            x="Name",
            y="Total Activity",
            color="Total Activity",
            color_continuous_scale="viridis",
            title="🏆 Top 10 Contributors",
            labels={"Total Activity": "Total Activities", "Name": "User Name"}
        )
        fig_top_users.update_layout(
            showlegend=False,
            xaxis_tickangle=-45,
            height=500
        )
        st.plotly_chart(fig_top_users, use_container_width=True)
        
        # Activity breakdown by type
        col1, col2 = st.columns(2)
        
        with col1:
            # Activity type distribution (pie chart)
            activity_types = {
                "Commits": total_commits,
                "Merge Requests": total_mrs,
                "Issues": total_issues,
                "push_events":total_push_events
            }
            
            if sum(activity_types.values()) > 0:
                fig_pie = px.pie(
                    values=list(activity_types.values()),
                    names=list(activity_types.keys()),
                    title="📊 Activity Distribution by Type",
                    color_discrete_sequence=px.colors.qualitative.Set3
                )
                fig_pie.update_traces(textposition='inside', textinfo='percent+label')
                st.plotly_chart(fig_pie, use_container_width=True)
        
        with col2:
            # Activity status distribution
            active_count = sum(1 for stats in filtered_users.values() 
                             if (stats["commits"] + stats["merge_requests"] + stats["issues"]) >= activity_threshold)
            inactive_count = len(filtered_users) - active_count
            
            status_data = {
                "Active Users": active_count,
                "Inactive Users": inactive_count
            }
            
            fig_status = px.pie(
                values=list(status_data.values()),
                names=list(status_data.keys()),
                title="👥 User Activity Status",
                color_discrete_map={"Active Users": "#28a745", "Inactive Users": "#dc3545"}
            )
            fig_status.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig_status, use_container_width=True)
        
        # Detailed activity breakdown for top users
        if show_detailed_activities and len(users_df) > 0:
            st.markdown("### 🔍 Detailed Activity Breakdown")
            
            # Create a stacked bar chart for top 15 users
            top_15_users = users_df.head(15)
            
            fig_detailed = go.Figure()
            
            fig_detailed.add_trace(go.Bar(
                name='Commits',
                x=top_15_users['Name'],
                y=top_15_users['Commits'],
                marker_color='#17a2b8'
            ))
            
            fig_detailed.add_trace(go.Bar(
                name='Merge Requests',
                x=top_15_users['Name'],
                y=top_15_users['Merge Requests'],
                marker_color='#ffc107'
            ))
            
            fig_detailed.add_trace(go.Bar(
                name='Issues',
                x=top_15_users['Name'],
                y=top_15_users['Issues'],
                marker_color='#dc3545'
            ))
            
            fig_detailed.update_layout(
                barmode='stack',
                title='📊 Detailed Activity Breakdown - Top 15 Users',
                xaxis_title='Users',
                yaxis_title='Number of Activities',
                xaxis_tickangle=-45,
                height=600,
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                )
            )
            
            st.plotly_chart(fig_detailed, use_container_width=True)
        
        # Project participation analysis
        if len(all_projects) > 0:
            st.markdown("### 🗂️ Project Participation Analysis")
            
            # Count users per project
            project_user_count = defaultdict(int)
            project_names = {}
            
            for user, stats in filtered_users.items():
                for project in stats["projects"]:
                    project_user_count[project] += 1
                    project_names[project] = project
            
            if project_user_count:
                # Convert to sorted list for visualization
                project_data = []
                for project, count in sorted(project_user_count.items(), key=lambda x: x[1], reverse=True)[:15]:
                    project_data.append({
                        "Project": project[:30] + "..." if len(project) > 30 else project,
                        "Active Contributors": count
                    })
                
                if project_data:
                    project_df = pd.DataFrame(project_data)
                    
                    fig_projects = px.bar(
                        project_df,
                        x="Active Contributors",
                        y="Project",
                        orientation='h',
                        title="🏗️ Most Active Projects (Top 15)",
                        color="Active Contributors",
                        color_continuous_scale="plasma"
                    )
                    fig_projects.update_layout(
                        height=500,
                        showlegend=False,
                        yaxis={'categoryorder': 'total ascending'}
                    )
                    st.plotly_chart(fig_projects, use_container_width=True)
        
        # Time-based activity analysis (if we have activity dates)
        st.markdown("### 📅 Activity Timeline")
        
        # Create activity timeline based on last activity dates
        timeline_data = []
        for user, stats in filtered_users.items():
            if stats["last_activity"]:
                timeline_data.append({
                    "User": stats["name"],
                    "Last Activity": stats["last_activity"],
                    "Total Activity": stats["commits"] + stats["merge_requests"] + stats["issues"]+stats["push_events"],
                    "Activity Type": "Last Active"
                })
        
        if timeline_data:
            timeline_df = pd.DataFrame(timeline_data)
            timeline_df = timeline_df.sort_values("Last Activity")
            
            fig_timeline = px.scatter(
                timeline_df,
                x="Last Activity",
                y="User",
                size="Total Activity",
                color="Total Activity",
                title="🕒 User Activity Timeline",
                hover_data=["Total Activity"],
                color_continuous_scale="viridis"
            )
            fig_timeline.update_layout(
                height=max(400, len(timeline_df) * 25),
                showlegend=False
            )
            st.plotly_chart(fig_timeline, use_container_width=True)
    
    # Summary insights
    st.markdown("## 💡 Key Insights")
    
    insights = []
    
    if activity_rate >= 70:
        insights.append("🎉 **Excellent engagement!** Over 70% of group members are actively contributing.")
    elif activity_rate >= 50:
        insights.append("👍 **Good engagement!** More than half of the group members are active.")
    elif activity_rate >= 25:
        insights.append("⚠️ **Moderate engagement.** Consider strategies to increase participation.")
    else:
        insights.append("🚨 **Low engagement detected.** Many group members may need encouragement or support.")
    
    if total_commits > total_mrs + total_issues:
        insights.append("💻 **Code-focused activity.** Most contributions are direct commits rather than collaborative workflows.")
    elif total_mrs > total_commits:
        insights.append("🔀 **Collaborative workflow.** Strong use of merge requests indicates good development practices.")
    
    if len(all_projects) > 0:
        avg_contributors_per_project = sum(len(stats["projects"]) for stats in filtered_users.values()) / len(all_projects)
        if avg_contributors_per_project < 2:
            insights.append("👤 **Limited collaboration.** Most projects have single contributors. Consider promoting cross-project collaboration.")
        else:
            insights.append(f"🤝 **Good collaboration.** Average of {avg_contributors_per_project:.1f} contributors per project.")
    
    # Display insights
    for insight in insights:
        st.info(insight)
    
    # Performance metrics
    execution_time = time.time() - st.session_state.start_time
    st.markdown("---")
    st.caption(f"⏱️ Dashboard generated in {execution_time:.2f} seconds | 📅 Data as of {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# Run the main application
if __name__ == "__main__":
    main()

