[← Back to README](../README.md)

# Quick Start

### 1. Start the Server

> **Prerequisite:** the Atomic Red Team library must already be downloaded into `server/atomic/` (see [Download the Atomic Red Team library](INSTALLATION.md#download-the-atomic-red-team-library)). The server loads the technique catalog from `server/atomic/atomics/` on startup, so launching without it leaves the catalog empty.

```bash
# From the server/ directory, activate the venv first if not already
source venv/bin/activate

# Development mode
python app.py

# The server starts on http://localhost:5000
```

### 2. Login

Navigate to `http://localhost:5000` and login with default credentials:

| Username | Password |
|----------|----------|
| `redteamsimmer`  | `redteamsimmer`  |

> **Change the default password immediately after first login!**

### 3. Deploy Agent (Windows Only)

Copy the compiled `agent.exe` to your Windows target system and run:

```powershell
# Run as Administrator for full capability
.\agent.exe
```

The agent will:
1. Register with the server
2. Download required PowerShell modules
3. Begin polling for tasks

Verify the agent appears in the **Agents** section of the web UI.

### 4. Execute Tests

1. Go to **Execute Technique** in the sidebar
2. Expand tactic accordions to see available techniques
3. Check the boxes next to techniques you want to execute
4. Select your target agent(s) in the agent table
5. Optionally check **Get Prerequisites** to auto-install dependencies
6. Click **Execute Selected Tests**
7. Watch live output in the console below

### 5. View Results

- **Live Output** - Streams in real-time during execution
- **Test Results Table** - Shows pass/fail status for each technique
- **View Details** - Click to see full command output, arguments, and detection rules
- **Operations** - View historical operations and their results
