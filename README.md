# 📊 GitLab Analytics Dashboard

A comprehensive Streamlit-based dashboard designed to analyze GitLab activity across projects and groups on Swecha's self-hosted GitLab instance ([code.swecha.org](https://code.swecha.org)).  
The dashboard provides insightful GitLab metrics with secured access and interactive data exploration tools.

---

**## 📁 Project Structure**

```

gitlab-analytics-dashboard/
├── main.py                      # Main Streamlit app (dashboard UI & logic)
├── utils/
│   └── validate_gitlab_token.py  # GitLab token validation utility
├── users.json                   # Stores registered users and hashed credentials
├── Collegedetails.csv           # CSV file containing enrollment numbers and faculty mentors
└── .streamlit/
    └── secrets.toml             # (Optional) Stores GitLab token securely
```

---

****## 🚀 Features****


- 🔑 Secure login with predefined and dynamically managed user roles  
- 📊 Real-time GitLab contribution analytics (commits, MRs, issues)  
- 📘 Profile README availability checker integrated into reports  
- 🏷️ Intern mapping through external CSV for enhanced traceability  
- 🖥️ Custom faculty-wise filtering and role-based visibility  
- 📥 Export activity reports and project stats as downloadable CSVs  
- 📈 Interactive charts powered by Plotly for data-driven insights

---

## 📦 Installation

### 🔧 Requirements

- Python 3.8+
- pip packages listed in `requirements.txt`

### 🛠️ Steps

```bash
git clone https://code.swecha.org/your-username/gitlab-analytics-dashboard.git
cd gitlab-analytics-dashboard
pip install -r requirements.txt
```

Optionally, create a `.streamlit/secrets.toml` file for development tokens:

```toml
GITLAB_TOKEN = "your_gitlab_token"
```

---

## 🔐 Authentication

This dashboard uses a simple and secure login system. Credentials can be managed by administrators.  
Each user is assigned a type (e.g., admin, faculty), which determines their access privileges on the dashboard.

- Admins can manage users and view all group data.  
- Faculty have access only to user-level dashboards and filtered reports.  

Authentication ensures controlled access to group-specific data and insights.

---

## 👥 User Management

****Admins can:****

- Manage user status (activate/deactivate)  
- Reset passwords and GitLab access tokens  
- Edit user details through a clean interface  
- View a full list of currently registered dashboard users  

User data is persistently stored and token-safe when exporting or syncing.

---

## 🧠 Dashboard Capabilities

- 📂 View all accessible projects and filter them  
- 👥 Analyze group members and their contributions  
- 🧾 Automatically check for README files in profile repos  
- 🔢 Map students using enrollment number and mentor (from `Collegedetails.csv`)  
- 📉 Filter results by faculty mentor, activity level, or custom thresholds  
- 📤 Download structured reports in `.csv` format

---

## 🧪 Testing

Run the dashboard locally:

```bash
streamlit run main.py
```

If GitLab token is not available, you'll be prompted for one during login.

---

## 🌐 Live Deployment

**Access the live GitLab Analytics Dashboard here:**  
🔗 [https://progress4icfai-jbim9jeznzjxunlmzvnjts.streamlit.app/](https://progress4icfai-jbim9jeznzjxunlmzvnjts.streamlit.app/)

---

## 💬 Support

- 💡 Have feedback or feature suggestions?  
  [Open an issue](https://code.swecha.org/your-username/gitlab-analytics-dashboard/-/issues)

- ❓ Setup or usage doubts?  
  Email: **yaraakshaykumar23@ifheindia.org**.

---

## 🤝 Contributing

We welcome community contributions!

- Fork the repo on [code.swecha.org](https://code.swecha.org)  
- Submit merge requests for new features or improvements  
- Add unit tests and documentation where applicable

---

## 📝 License

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for details.
