# main.py
import argparse
import importlib

# Map user choice to module/function names
MODE_MAP = {
    '1': ('commits_api', 'run_commits'),
    '2': ('groups_api', 'run_groups'),
    '3': ('issues_api', 'run_issues'),
    '4': ('merge_api', 'run_merge_requests'),
    '5': ('projects_api', 'run_check_file'),
    '6': ('users_api', 'run_users'),
}

def show_menu():
    print("\n🚀 GitLab Automation Tool - Choose an option:")
    print("1. Get Commits")
    print("2. Manage Group Members")
    print("3. Generate Issue Summary")
    print("4. List Merge Requests")
    print("5. Check File in Project")
    print("6. Get User ID")
    print("q. Quit")

def run_module(module_name, function_name):
    try:
        module = importlib.import_module(f'apis.{module_name}')
        func = getattr(module, function_name)
        print(f"\n🔄 Running {module_name}.{function_name}()")
        func()  # Call the function
    except Exception as e:
        print(f"[ERROR] Could not run {module_name}.{function_name}: {e}")

def get_project_id_from_cli():
    parser = argparse.ArgumentParser(description="Run GitLab automation tasks")
    parser.add_argument('--project-id', type=int, help='Project ID for GitLab operations')
    args = parser.parse_args()
    return args.project_id

def main():
    project_id = get_project_id_from_cli()

    if project_id:
        print(f"✅ Using Project ID from CLI: {project_id}")
        # Example: Run issue summary by default or any other logic
        from apis.issues_api import run_issues
        run_issues()
    else:
        # Interactive mode
        while True:
            show_menu()
            choice = input("Enter your choice: ").strip().lower()
            if choice == 'q':
                print("👋 Exiting... Goodbye!")
                break
            elif choice in MODE_MAP:
                module_name, function_name = MODE_MAP[choice]
                run_module(module_name, function_name)
            else:
                print("❌ Invalid choice. Please try again.")

if __name__ == "__main__":
    main()