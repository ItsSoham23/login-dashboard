
# Contributing to gitlab-wrapper

🙏 Thank you for your interest in contributing to `gitlab-wrapper`!  
This project is built to simplify GitLab automation and developer environment validation for [code.swecha.org](https://code.swecha.org), and we welcome your ideas, feedback, and code.



## 🧰 Prerequisites

Before contributing, please make sure you have:

- Python 3.8 or later installed  
- A GitLab account on [code.swecha.org](https://code.swecha.org)  
- Git installed and configured  
- A GitLab **Access Token** with `api` scope  
- Your token stored in a `.env` file:

```env
ACCESS_TOKEN=your_token_here
```


## 🛠 Project Setup

1. **Fork** this repository from `code.swecha.org/ranjithraj/gitlab-wrapper` 

2. **Clone your fork**:

```bash
git clone https://code.swecha.org/your-username/gitlab-wrapper.git
cd gitlab-wrapper
```


3. *(Optional)* **Create and activate a virtual environment**:

```bash
python3 -m venv venv
source venv/bin/activate
```

4. **Install the project dependencies** using `uv`:

```bash
uv pip install -r requirements.txt
```

<br>

> 🔁 If `uv` is not installed, install it first:

<br>


```bash
curl -Ls https://astral.sh/uv/install.sh | bash
```

<br>

> Then add it to your `PATH` (if needed):

<br>

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

<br>

> Then run again:

<br>

```bash
uv pip install -r requirements.txt
```


<br>


### 🧠 Why use `uv` instead of `pip`?

`uv` is a modern Python package manager built in Rust by Astral (the makers of Ruff).  
It’s a drop-in replacement for pip, pip-tools, and virtualenv — and it's **way faster**.

**Key benefits of `uv`:**

- ⚡ Blazing fast (written in Rust)  
- 🧹 Handles virtual environments and dependencies in one place  
- 📦 Safer and reproducible installs (lockfiles like pip-tools)  
- 🔧 Compatible with existing pip and requirements.txt  