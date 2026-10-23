[← Back to README](../README.md)

# Deployment

### Running as a Service (systemd)

For Linux production deployments, run RedTeamSimmer as a systemd service so it starts on boot, restarts on failure, and writes structured logs to the journal. The service runs against a venv installed at `/opt/redteamsimmer/venv` - adjust the paths if you deploy elsewhere.

#### Step 1: Stage the Application

The runnable application (`app.py`, `requirements.txt`, `modules/`, `mitre/`, and the downloaded `atomic/` library) lives in the repo's `server/` directory, so copy the **contents of `server/`** into the deploy directory - not the repo root. This puts `app.py` at `/opt/redteamsimmer/app.py`, matching the service file below.

```bash
# Create the deploy directory and copy the server application into it
sudo mkdir -p /opt/redteamsimmer
sudo cp -r server/. /opt/redteamsimmer/
cd /opt/redteamsimmer
```

> **Important:** Download the Atomic Red Team library **before** staging (see [Installation](INSTALLATION.md#download-the-atomic-red-team-library)) so `server/atomic/` is copied along with the rest. If you staged first, clone it now with `sudo git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git /opt/redteamsimmer/atomic`. The server reads techniques from `/opt/redteamsimmer/atomic/atomics/` at startup.

#### Step 2: Create a Service User

A dedicated unprivileged user limits blast radius if the process is compromised.

```bash
sudo useradd --system --shell /bin/false --home-dir /opt/redteamsimmer redteamsimmer
sudo chown -R redteamsimmer:redteamsimmer /opt/redteamsimmer
```

#### Step 3: Create the venv and Install Dependencies

```bash
# Run as the service user so file ownership is correct
sudo -u redteamsimmer python3 -m venv /opt/redteamsimmer/venv
sudo -u redteamsimmer /opt/redteamsimmer/venv/bin/pip install --upgrade pip
sudo -u redteamsimmer /opt/redteamsimmer/venv/bin/pip install -r /opt/redteamsimmer/requirements.txt
```

#### Step 4: Create the Service File

Create `/etc/systemd/system/redteamsimmer.service`:

```ini
[Unit]
Description=RedTeamSimmer Adversary Emulation Platform
After=network.target

[Service]
Type=simple
User=redteamsimmer
Group=redteamsimmer
WorkingDirectory=/opt/redteamsimmer
Environment="PATH=/opt/redteamsimmer/venv/bin"
ExecStart=/opt/redteamsimmer/venv/bin/python app.py
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

> **Note:** `ExecStart` points directly at the venv's Python interpreter, so the service runs in the venv without needing explicit activation. Setting `Environment="PATH=..."` ensures any subprocesses (e.g., `git`, `python3`) also resolve to venv binaries first. The server binds `0.0.0.0:5000` from its built-in configuration - `app.py` takes no command-line flags, so change the port by editing `CONFIG["PORT"]` in `app.py` if needed.

#### Step 5: Enable and Start

```bash
# Reload systemd to pick up the new unit file
sudo systemctl daemon-reload

# Enable on boot and start now
sudo systemctl enable --now redteamsimmer

# Verify it's running
sudo systemctl status redteamsimmer

# Tail logs in real time
sudo journalctl -u redteamsimmer -f
```

#### Common service commands

```bash
sudo systemctl restart redteamsimmer   # restart after config/code changes
sudo systemctl stop redteamsimmer      # stop the service
sudo systemctl disable redteamsimmer   # don't start on boot
```
