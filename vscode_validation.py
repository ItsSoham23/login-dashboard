import os
from vscode_validation_api import fetch_json

PRIVATE_TOKEN = os.environ.get("ACCESS_TOKEN")

# === 📄 HARD-CODED REFERENCE SETTINGS ===
reference_settings = {
    "project.requirements": {
        "tools": {
            "git": ">=2.0",
            "python": ">=3.11",
            "uv": ">=0.7"
        },
        "python_packages": {
            "numpy": "installed",
            "pandas": "installed",
            "streamlit": "installed"
        },
        "vscode_extensions": [
            "charliermarsh.ruff",
            "saoudrizwan.claude-dev",
            "ms-toolsai.jupyter",
            "ms-python.debugpy",
            "gitlab.gitlab-workflow"
        ]
    }
}

required_tools = reference_settings["project.requirements"]["tools"]
required_packages = reference_settings["project.requirements"]["python_packages"]
required_extensions = reference_settings["project.requirements"]["vscode_extensions"]


# Helper function to compare versions
def version_satisfied(user_version, required_version):
    if required_version.startswith(">="):
        min_version = required_version[2:].strip()
        return user_version >= min_version
    return user_version == required_version


# Start validation
def validate_settings(user_settings):
    if not user_settings:
        return False

    passed = True

    # Validate tools
    print("\n🔍 Validating Tools:")
    for tool, req_ver in required_tools.items():
        user_ver = user_settings.get("project.requirements", {}).get("tools", {}).get(tool)
        if not user_ver:
            print(f"❌ {tool}: Not found in user settings")
            passed = False
        elif not version_satisfied(str(user_ver), req_ver):
            print(f"❌ {tool}: Required {req_ver}, found {user_ver}")
            passed = False
        else:
            print(f"✅ {tool}: {user_ver}")

    # Validate packages
    print("\n🔍 Validating Python Packages:")
    for package in required_packages:
        status = user_settings.get("project.requirements", {}).get("python_packages", {}).get(package)
        if status != "installed":
            print(f"❌ {package}: Not installed")
            passed = False
        else:
            print(f"✅ {package}: Installed")

    # Validate extensions
    print("\n🔍 Validating VS Code Extensions:")
    user_exts = user_settings.get("project.requirements", {}).get("vscode_extensions", [])
    for ext in required_extensions:
        if ext not in user_exts:
            print(f"❌ Extension '{ext}' missing")
            passed = False
        else:
            print(f"✅ Extension '{ext}' present")

    return passed

def create_headers():
    """Returns authenticated headers for GitLab API."""
    return {"Private-Token": PRIVATE_TOKEN}


# === Main Function ===
def main():
    print("📌 Enter the raw GitLab URL to the user's .vscode/settings.json")
    print("Example: https://code.swecha.org/group/project/-/raw/main/.vscode/settings.json      ")
    
    user_url = input("\nEnter URL: ").strip()

    print("\n📥 Fetching user settings...")
    headers = create_headers()
    if not user_url:
        print("[ERROR] No URL provided.")
        return
    user_settings = fetch_json(headers, user_url)

    if not user_settings:
        print("[ERROR] Failed to load user settings.")
        return

    print("\n✅ Running validation...")
    result = validate_settings(user_settings)

    print("\n🎉 Validation Result 🎉")
    if result:
        print("✅ All requirements are met.")
    else:
        print("❌ Some requirements are missing.")

# Run the script
if __name__ == "__main__":
    main()