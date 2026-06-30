# GitHub Repository Setup

The workspace is a git repository ready for GitHub push. The `gh` CLI
is not available in the Docker container (no root access for apt-get).

## Manual Setup Steps

### 1. Install gh CLI on the host

```bash
# Debian/Ubuntu
(type -p wget >/dev/null || sudo apt-get install -y wget) && \
sudo mkdir -p -m 755 /etc/apt/keyrings && \
wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg | \
    sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null && \
sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg && \
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | \
    sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null && \
sudo apt-get update && \
sudo apt-get install -y gh
```

### 2. Authenticate

```bash
gh auth login
# Or with a token:
export GH_TOKEN="<your-github-token>"
```

### 3. Create repo and push

From the workspace directory:

```bash
cd /ductor/agents/serveradmin/workspace

# Option A: Create new repo via gh
gh repo create server-admin-agent \
    --description "Secure remote server management agent with TOTP-guarded command execution" \
    --public \
    --source=. \
    --remote=origin \
    --push

# Option B: Manual remote setup
git remote add origin git@github.com:YOUR_USER/server-admin-agent.git
git push -u origin main
```

### 4. Verify

```bash
gh repo view --json name,url,defaultBranch
```
