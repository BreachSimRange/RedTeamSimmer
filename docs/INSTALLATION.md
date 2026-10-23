[← Back to README](../README.md)

# Installation

### Prerequisites

- **Git**
- **Atomic Red Team library** - cloned from [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) during setup (see [Download the Atomic Red Team library](#download-the-atomic-red-team-library) below). The server cannot list any techniques until this is in place.
- **Windows target systems** (for agent deployment)
- **Docker + Docker Compose** (for Docker setup)
- **Python 3.9+** (for direct setup)
- **Go 1.20+** (for building agents - see [installation steps below](#installing-go-for-building-agents))

---

### Option 1: Docker (Recommended)

The fastest way to get the server running. Docker handles all Python dependencies and environment isolation automatically.

#### Step 1: Clone the repository and download the Atomic Red Team library

```bash
git clone https://github.com/breachsimrange/RedTeamSimmer.git
cd RedTeamSimmer

# Download the Atomic Red Team library directly into server/atomic.
# This is REQUIRED before starting the container - without it the server
# has no techniques to list. It produces server/atomic/atomics/.
git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git server/atomic
```

> **Note:** `--depth 1` skips the repository history, which downloads far less. To update the library later, run `git -C server/atomic pull`.

#### Step 2: Configure environment

Open `docker-compose.yml` and set your values:

```yaml
environment:
  - ATOMICC2_ADMIN_TOKEN=YourSecureTokenHere
  - FLASK_SECRET_KEY=YourRandomSecretKeyHere
```

#### Step 3: Build and start

> **Important:** complete Step 1 (download the Atomic Red Team library into `server/atomic/`) before starting the container. The directory is mounted read-only into the container, and the server reads the technique catalog from it at startup.

```bash
docker compose up -d
```

The server will be available at `http://localhost:5000`.

#### Useful Docker commands

```bash
docker compose logs -f          # stream logs
docker compose restart          # restart after config changes
docker compose down             # stop and remove container
docker compose up -d --build    # rebuild image after code changes
```

> **Note:** The `server/atomic/`, `server/uploads/`, and `server/data/` paths are bind-mounted from your host so data persists across container restarts. The SQLite database is created at `server/data/data_store.sqlite3` on first run.

---

### Option 2: Direct Setup

The server can run on Windows, Linux, or macOS.

```bash
# Clone the repository
git clone https://github.com/breachsimrange/RedTeamSimmer.git
cd RedTeamSimmer
```

#### Python Virtual Environment (Recommended)

Always run RedTeamSimmer inside a Python virtual environment. This isolates dependencies from the system Python and avoids conflicts with other tools on the host.

```bash
# Create the virtual environment
python3 -m venv venv

# Activate (Linux / macOS)
source venv/bin/activate

# Activate (Windows PowerShell)
venv\Scripts\Activate.ps1

# Activate (Windows CMD)
venv\Scripts\activate.bat
```

When the venv is active your shell prompt will be prefixed with `(venv)`. Run every subsequent server command - `pip install`, `python app.py`, etc. - inside the activated venv. To deactivate when finished:

```bash
deactivate
```

> **Tip:** If you redeploy the server on another host, recreate the venv on that host rather than copying it - venvs contain absolute paths.

#### Install Server Dependencies

The server lives in the `server/` directory, so run these commands from there. The venv created above stays active regardless of the current directory.

```bash
# With the venv activated, move into the server directory:
cd server

pip install --upgrade pip
pip install -r requirements.txt
```

#### Download the Atomic Red Team library

The application reads atomic tests from `server/atomic/atomics/`. Clone the library directly into `server/atomic` (from inside the `server/` directory, so `atomic` resolves to `server/atomic`):

```bash
# From the server/ directory:
git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git atomic
```

This produces `server/atomic/atomics/`. To update the library later, run `git -C atomic pull`.

> **Important:** Download the Atomic Red Team library **before** launching the app for the first time. The server reads techniques from `server/atomic/atomics/` at startup, and without it the technique catalog is empty.

#### Initialize the Database

> **Before you run this:** make sure the Atomic Red Team library has been downloaded (previous step). The app loads the atomic test catalog on launch.

```bash
# From the server/ directory, with the venv activated:
python3 app.py
```

This creates the database and the default admin user on first run.

### Installing Go (for building agents)

Go is required to compile the Windows agent binary. The agent can be cross-compiled from any host with Go installed - you do not need Go on the target Windows machine, only on the system you build the binary on.

**Linux (Ubuntu/Debian/RHEL):**

```bash
# Check https://go.dev/dl/ for the latest stable version
GO_VERSION=1.22.5
wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz

# Remove any previous Go install and extract
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz

# Add Go to PATH (persisted across shells)
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
go version
# Expected: go version go1.22.5 linux/amd64
```

**macOS:**

```bash
# Option 1: Homebrew
brew install go

# Option 2: Download the .pkg installer from https://go.dev/dl/ and run it

# Verify
go version
```

**Windows:**

1. Download the MSI installer from <https://go.dev/dl/>.
2. Run the installer - it adds Go to the system `PATH` automatically.
3. Open a new PowerShell or CMD window and confirm:

   ```powershell
   go version
   ```

> **Distro package managers:** `apt install golang-go` and `dnf install golang` work but often ship outdated versions. Prefer the official tarball or installer for current toolchain features.

### Agent Setup (Windows Only)

> **Important:** Currently only Windows agents are fully functional. Linux and macOS agent support is under development.

```bash
# Navigate to agent directory
cd agent

# Edit agent.go and update the ServerURL
# Find this line and change the IP/hostname:
# ServerURL = "http://YOUR_SERVER_IP:5000"

# Build Windows agent (from any OS with Go installed)
GOOS=windows GOARCH=amd64 go build -o agent.exe .

# Or on Windows directly:
go build -o agent.exe .
```

**Agent Configuration Options (in agent.go):**

```go
const (
    ServerURL              = "http://192.168.1.100:5000"  // Your server address
    AdminToken             = "ChangeThisAdminToken!"       // Must match server token
    PollInterval           = 7 * time.Second              // How often to check for tasks
    FiledropPoll           = 5 * time.Second              // How often to check for files
)
```

### Downloading Detection Rules

RedTeamSimmer integrates with external detection rule sources. Use the provided scripts to download and generate the rule mappings.

#### Quick Setup (Recommended)

The easiest way to download all detection rules is to use the provided shell script:

```bash
# Navigate to the detection folder (inside server/)
cd server/detection

# Make script executable
chmod +x download-detection-rules.sh

# Run the downloader
./download-detection-rules.sh
```

This script will:
1. Download **AttackRuleMap** (Sigma + Splunk rules mapped to Atomic tests) into `server/detection/attack_rule_map.json`
2. Fetch and parse **Elastic Detection Rules** using the Python script into `server/detection/elastic_rules.json`

Both files are written next to the script, which is where the server loads them from.

#### Manual Setup

If you prefer to run the scripts manually:

**Step 1: Download AttackRuleMap (Sigma + Splunk Rules)**

[AttackRuleMap](https://github.com/krdmnbrk/AttackRuleMap) provides Sigma and Splunk detection rules mapped to Atomic Red Team tests.

```bash
# Run from the repository root. Download the mapping file directly
curl -sL https://raw.githubusercontent.com/krdmnbrk/AttackRuleMap/main/attack_rule_map.json \
  -o server/detection/attack_rule_map.json

# Verify download
python3 -c "import json; print(f'Loaded {len(json.load(open(\"server/detection/attack_rule_map.json\")))} entries')"
```

**Step 2: Fetch Elastic Detection Rules**

The `fetch_elastic_rules.py` script clones the Elastic detection-rules repository, parses TOML rule files, and extracts MITRE ATT&CK technique mappings.

```bash
# Navigate to the detection folder (inside server/)
cd server/detection

# Run the fetcher script (writes elastic_rules.json into this folder)
python3 fetch_elastic_rules.py
```


**Requirements for fetch_elastic_rules.py:**
- Git installed and in PATH
- Python 3.6+
- `toml` module (auto-installed if missing)

#### Detection Rules Directory Structure

After running the scripts, the relevant paths should look like:

```
RedTeamSimmer/
├── server/
│   ├── app.py
│   ├── detection/
│   │   ├── download-detection-rules.sh    # Main download script
│   │   ├── fetch_elastic_rules.py         # Elastic rules fetcher
│   │   ├── attack_rule_map.json           # Sigma + Splunk rules (downloaded)
│   │   └── elastic_rules.json             # Elastic rules (generated)
│   └── atomic/
│       └── atomics/                       # Atomic Red Team library (downloaded)
├── agent/
└── ...
```

#### Updating Detection Rules

To refresh the detection rules with the latest from upstream:

```bash
# Re-run the download script
cd server/detection
./download-detection-rules.sh
```

Or update individually:

```bash
# Update AttackRuleMap only (from the repository root)
curl -sL https://raw.githubusercontent.com/krdmnbrk/AttackRuleMap/main/attack_rule_map.json \
  -o server/detection/attack_rule_map.json

# Update Elastic rules only
cd server/detection && python3 fetch_elastic_rules.py
```

After updating rules, restart the Flask server to reload the detection database.

### PowerShell Modules (Required for Agent)

The agent needs three PowerShell modules for test execution, which it downloads from the server (`/modules/<name>.zip`) on first run and caches locally. **These are already bundled in `server/modules/`, so no action is required for a standard setup:**

| File (in `server/modules/`) | Source project |
|-----------------------------|----------------|
| `Invoke-AtomicRedTeam.zip`  | [redcanaryco/invoke-atomicredteam](https://github.com/redcanaryco/invoke-atomicredteam) |
| `powershell-yaml.zip`       | [cloudbase/powershell-yaml](https://github.com/cloudbase/powershell-yaml) |
| `AtomicTestHarnesses.zip`   | [redcanaryco/AtomicTestHarnesses](https://github.com/redcanaryco/AtomicTestHarnesses) |

Only if a module is missing or you want to refresh it: download the module from its source, zip it with the exact filename above, and place it in `server/modules/`. The filenames must match exactly - the agent requests them by name.
