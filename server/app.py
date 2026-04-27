# ========================
# Server for RedTeamSimmer
# Greetings from Abx
# breachsimrange.io
# ========================
import os, datetime, threading, uuid, re, sqlite3, yaml
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for, g
import time
import tempfile
import zipfile
import requests
import json
import shutil

import hashlib
import secrets
from functools import wraps

# ========================
# CONFIG
# ========================

CONFIG = {
    "ADMIN_TOKEN": os.environ.get("ATOMICC2_ADMIN_TOKEN", "ChangeThisAdminToken!"),
    "ATOMIC_ROOT": str(Path(__file__).resolve().parent / "atomic" / "atomics"),
    "DB_FILE": str(Path(__file__).resolve().parent / "data_store.sqlite3"),
    "UPLOAD_DIR": str(Path(__file__).resolve().parent / "uploads"),
    "HOST": "0.0.0.0",
    "PORT": 5000,
    "SECRET_KEY": os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32)),
    "SESSION_TIMEOUT_MINUTES": 60,
}

INDEX_YAML_WINDOWS = Path(CONFIG["ATOMIC_ROOT"]) / "Indexes" / "windows-index.yaml"
INDEX_MD_WINDOWS = Path(CONFIG["ATOMIC_ROOT"]) / "Indexes" / "Indexes-Markdown" / "windows-index.md"

DETECTION_DIR = Path(__file__).resolve().parent / "detection"
ATTACK_RULE_MAP_FILE = DETECTION_DIR / "attack_rule_map.json"
ELASTIC_RULES_FILE = DETECTION_DIR / "elastic_rules.json"

# ========================
# EMULATION PLANS CONFIG
# ========================
EMULATION_PLANS_DIR = Path(__file__).resolve().parent / "emulation_plans"
THREAT_ACTOR_IMAGES_DIR = Path(__file__).resolve().parent / "static" / "images" / "threat_actors"

# Mapping of MITRE Group ID to image filename
THREAT_ACTOR_IMAGES = {
    "G0007": "apt28.jpg",
    "G0022": "apt3.jpeg",
    "G0096": "apt41.jpeg",
    "G0046": "fin7.jpeg",
    "G0032": "lazarus.jpg",
    "G0102": "wizard_spider.jpeg",
}

app = Flask(__name__, static_folder="static", static_url_path="/static")
os.makedirs(CONFIG["UPLOAD_DIR"], exist_ok=True)
os.makedirs(EMULATION_PLANS_DIR, exist_ok=True)
os.makedirs(THREAT_ACTOR_IMAGES_DIR, exist_ok=True)

app.secret_key = CONFIG["SECRET_KEY"]
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=CONFIG["SESSION_TIMEOUT_MINUTES"])

# ========================
# DATABASE INIT/HELPERS
# ========================

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(CONFIG["DB_FILE"], check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def column_exists(db, table, column):
    cur = db.execute(f'PRAGMA table_info({table})')
    return any(row[1] == column for row in cur.fetchall())

def init_db():
    db = get_db()
    with db:
        db.execute('''CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY, info TEXT, last_seen TEXT)''')
        db.execute('''CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY, agent TEXT, plan TEXT, params TEXT,
            techniques TEXT, commands TEXT, type TEXT, status TEXT, created TEXT,
            file TEXT, path TEXT)''')
        db.execute('''CREATE TABLE IF NOT EXISTS outputs (
            agent TEXT, task_id TEXT, output TEXT, status TEXT, finished TEXT,
            PRIMARY KEY (agent, task_id))''')
        db.execute('''CREATE TABLE IF NOT EXISTS live_logs (
            task_id TEXT, line TEXT, ts TEXT, output_type TEXT, agent_comment INTEGER)''')
        db.execute('''CREATE TABLE IF NOT EXISTS confirmations (
            agent TEXT, task TEXT, confirmed INTEGER, PRIMARY KEY(agent, task))''')
        db.execute('''CREATE TABLE IF NOT EXISTS operations (
            id TEXT PRIMARY KEY, agent TEXT, plan TEXT, params TEXT, status TEXT,
            created TEXT, zipfile TEXT, techniques TEXT, agents TEXT, 
            progress INTEGER DEFAULT 0, timeline TEXT
        )''')
        
        # NEW TABLES for enhanced output
        db.execute('''CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT,
            technique_id TEXT,
            test_number TEXT,
            test_name TEXT,
            status TEXT,
            duration REAL,
            start_time INTEGER,
            end_time INTEGER,
            exit_code INTEGER,
            stdout_lines INTEGER,
            stderr_lines INTEGER,
            has_errors INTEGER,
            prerequisites_count INTEGER,
            errors TEXT
        )''')
        
        db.execute('''CREATE TABLE IF NOT EXISTS command_outputs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT,
            technique_id TEXT,
            command_type TEXT,
            command TEXT,
            exit_code INTEGER,
            execution_time REAL,
            stdout TEXT,
            stderr TEXT,
            stdout_line_count INTEGER,
            stderr_line_count INTEGER,
            timestamp INTEGER
        )''')
# Users table for authentication
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            created TEXT,
            last_login TEXT
        )''')

        # App settings table
        db.execute('''CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated TEXT
        )''')

# Create default admin user if none exists
        existing_admin = db.execute('SELECT id FROM users WHERE username=?', ('redteamsimmer',)).fetchone()
        if not existing_admin:
            default_password = hash_password("redteamsimmer")
            now = datetime.datetime.utcnow().isoformat()
            db.execute('''
                INSERT INTO users (username, password_hash, role, created)
                VALUES (?, ?, ?, ?)
            ''', ('redteamsimmer', default_password, 'redteamsimmer', now))
            db.commit()
            print("[*] Created default admin user (username: redteamsimmer, password: redteamsimmer)")
        # Auto-migrate missing columns
        ops_new_columns = [
            ("agents", "TEXT"),
            ("progress", "INTEGER DEFAULT 0"),
            ("timeline", "TEXT"),
        ]
        for col, typ in ops_new_columns:
            try:
                if not column_exists(db, "operations", col):
                    db.execute(f'ALTER TABLE operations ADD COLUMN {col} {typ}')
            except Exception:
                pass
        
        # Migrate live_logs table
        try:
            if not column_exists(db, "live_logs", "output_type"):
                db.execute('ALTER TABLE live_logs ADD COLUMN output_type TEXT')
            if not column_exists(db, "live_logs", "agent_comment"):
                db.execute('ALTER TABLE live_logs ADD COLUMN agent_comment INTEGER DEFAULT 0')
        except Exception:
            pass

        # Migrate command_outputs table - add timestamp column
        try:
            if not column_exists(db, "command_outputs", "timestamp"):
                db.execute('ALTER TABLE command_outputs ADD COLUMN timestamp INTEGER')
        except Exception:
            pass
        try:
            if not column_exists(db, "command_outputs", "test_number"):
                db.execute('ALTER TABLE command_outputs ADD COLUMN test_number TEXT')
        except Exception:
            pass    


@app.before_request
def before_request():
    if not hasattr(app, '_db_initialized'):
        init_db()
        app._db_initialized = True

# ========================
# AUTHENTICATION HELPERS
# ========================

def hash_password(password, salt=None):
    """Hash a password with salt using SHA-256"""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{hashed}"

def verify_password(password, stored_hash):
    """Verify a password against stored hash"""
    try:
        salt, hashed = stored_hash.split(':')
        return hash_password(password, salt) == stored_hash
    except:
        return False

def login_required(f):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for('login_page'))
        
        # Check session timeout
        last_activity = session.get('last_activity')
        if last_activity:
            last_time = datetime.datetime.fromisoformat(last_activity)
            if datetime.datetime.utcnow() - last_time > datetime.timedelta(minutes=CONFIG["SESSION_TIMEOUT_MINUTES"]):
                session.clear()
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({"error": "Session expired"}), 401
                return redirect(url_for('login_page'))
        
        session['last_activity'] = datetime.datetime.utcnow().isoformat()
        return f(*args, **kwargs)
    return decorated_function

# ========================
# STORE LAYER
# ========================

class Store:
    def register(self, agent_id, info):
        if isinstance(info, dict):
            info = json.dumps(info)
        now = datetime.datetime.utcnow().isoformat()
        db = get_db()
        with db:
            db.execute(
                'INSERT OR REPLACE INTO agents (id, info, last_seen) VALUES (?, ?, ?)',
                (agent_id, info, now)
            )

    def rename_agent(self, old_id, new_id):
        db = get_db()
        cur = db.execute('SELECT id FROM agents WHERE id=?', (old_id,))
        if not cur.fetchone():
            return False
        with db:
            db.execute('UPDATE agents SET id=? WHERE id=?', (new_id, old_id))
            db.execute('UPDATE tasks SET agent=? WHERE agent=?', (new_id, old_id))
            db.execute('UPDATE outputs SET agent=? WHERE agent=?', (new_id, old_id))
        return True

    def delete_agent(self, agent_id):
        db = get_db()
        with db:
            db.execute('DELETE FROM agents WHERE id=?', (agent_id,))
            db.execute('DELETE FROM tasks WHERE agent=?', (agent_id,))
            db.execute('DELETE FROM outputs WHERE agent=?', (agent_id,))

    def list_agents(self):
        db = get_db()
        rows = db.execute('SELECT * FROM agents').fetchall()
        return [dict(r) for r in rows]

    # NEW: Update agent info method
    def update_agent_info(self, agent_id, info):
        """Update agent info in database"""
        if isinstance(info, dict):
            info = json.dumps(info)
        db = get_db()
        with db:
            db.execute('UPDATE agents SET info=? WHERE id=?', (info, agent_id))

    def add_task(self, agent_id, task):
        task_id = task.get("id") or f"task-{uuid.uuid4().hex}"
        now = datetime.datetime.utcnow().isoformat()
        db = get_db()
        db.execute('''
            INSERT INTO tasks (
                id, agent, plan, params, techniques, commands, type, status, created, file, path
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            task_id, agent_id,
            task.get("plan"), task.get("params", ""),
            json.dumps(task.get("techniques", []), ensure_ascii=False),
            json.dumps(task.get("commands", []), ensure_ascii=False),
            task.get("type", "execute"),
            "queued", now,
            task.get("file"), task.get("path")
        ))
        db.commit()
        return {"id": task_id, "status": "queued"}

    def next_task(self, agent_id):
        db = get_db()
        task = db.execute('SELECT * FROM tasks WHERE agent=? AND status="queued" ORDER BY created LIMIT 1', (agent_id,)).fetchone()
        if not task:
            return None
        with db:
            db.execute('UPDATE tasks SET status="in-progress" WHERE id=?', (task["id"],))
        d = dict(task)
        d['techniques'] = json.loads(d.get('techniques') or '[]')
        d['commands'] = json.loads(d.get('commands') or '[]')
        return d


    
    def set_output(self, agent_id, task_id, text, status="completed"):
        db = get_db()
        now = datetime.datetime.utcnow().isoformat()
        with db:
            db.execute('''
                INSERT OR REPLACE INTO outputs (agent, task_id, output, status, finished)
                VALUES (?, ?, ?, ?, ?)
            ''', (agent_id, task_id, text, status, now))
            db.execute('UPDATE tasks SET status=? WHERE id=?', (status, task_id))

    def latest_output(self, agent_id):
        db = get_db()
        row = db.execute('SELECT * FROM outputs WHERE agent=? ORDER BY finished DESC LIMIT 1', (agent_id,)).fetchone()
        if not row:
            return {}
        d = dict(row)
        d['task_id'] = d.pop('task_id')
        return d

    def tasks_history(self):
        db = get_db()
        rows = db.execute('SELECT * FROM tasks ORDER BY created DESC').fetchall()
        result = []
        for t in rows:
            d = dict(t)
            d['techniques'] = json.loads(d['techniques']) if d['techniques'] else []
            d['commands'] = json.loads(d['commands']) if d['commands'] else []
            result.append(d)
        return result

    def get_task(self, task_id):
        db = get_db()
        t = db.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
        if not t: return None
        d = dict(t)
        d['techniques'] = json.loads(d['techniques']) if d['techniques'] else []
        d['commands'] = json.loads(d['commands']) if d['commands'] else []
        return d

    def add_operation(self, agent_list, plan, params, status, zipfile, techniques):
        op_id = f"op-{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.utcnow().isoformat()
        db = get_db()
        db.execute('''
            INSERT INTO operations (
                id, agent, plan, params, status, created, zipfile, techniques, agents, progress, timeline
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            op_id, agent_list[0] if agent_list else None, plan, params, status, now, zipfile,
            json.dumps(techniques or [], ensure_ascii=False),
            json.dumps(agent_list or [], ensure_ascii=False),
            0,
            json.dumps([{"step": "queued", "ts": now}], ensure_ascii=False)
        ))
        db.commit()
        return op_id

    def get_operations(self, status=None):
        db = get_db()
        query = "SELECT * FROM operations"
        params = []
        if status == "active":
            query += ' WHERE status NOT IN ("completed", "failed")'
        elif status == "history":
            query += ' WHERE status IN ("completed", "failed")'
        query += " ORDER BY created DESC"
        rows = db.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_operation(self, op_id):
        db = get_db()
        row = db.execute("SELECT * FROM operations WHERE id=?", (op_id,)).fetchone()
        return dict(row) if row else None

    def update_operation_status(self, op_id, new_status):
        db = get_db()
        db.execute("UPDATE operations SET status=? WHERE id=?", (new_status, op_id))
        db.commit()

    def update_operation_progress(self, op_id, progress, timeline_step=None):
        db = get_db()
        now = datetime.datetime.utcnow().isoformat()
        if timeline_step:
            op = self.get_operation(op_id)
            timeline = json.loads(op.get("timeline") or "[]")
            timeline.append({"step": timeline_step, "ts": now})
            db.execute("UPDATE operations SET progress=?, timeline=? WHERE id=?",
                       (progress, json.dumps(timeline, ensure_ascii=False), op_id))
        else:
            db.execute("UPDATE operations SET progress=? WHERE id=?", (progress, op_id))
        db.commit()

    def delete_operation(self, op_id):
        """Delete an operation from database"""
        db = get_db()
        with db:
            db.execute("DELETE FROM operations WHERE id=?", (op_id,))

def set_agent_confirmation(agent_id, task_id):
    db = get_db()
    with db:
        db.execute("INSERT OR REPLACE INTO confirmations (agent, task, confirmed) VALUES (?, ?, ?)", 
                   (agent_id, task_id, 1))

def agent_confirmed(agent_id, task_id):
    db = get_db()
    row = db.execute("SELECT confirmed FROM confirmations WHERE agent=? AND task=?", 
                     (agent_id, task_id)).fetchone()
    return bool(row and row["confirmed"] == 1)

def get_agent_status_list(agents, offline_minutes=10):
    now = datetime.datetime.utcnow()
    for ag in agents:
        try:
            last_seen = datetime.datetime.fromisoformat(ag["last_seen"])
            delta = now - last_seen
            ag["status"] = "online" if delta.total_seconds() < offline_minutes * 60 else "offline"
        except Exception:
            ag["status"] = "unknown"
    return agents

store = Store()


def update_operation_from_task(task_id, task_status):
    """Update operation status and progress when a task completes"""
    try:
        db = get_db()
        
        # Get the task to find its plan
        task = store.get_task(task_id)
        if not task:
            print(f"[DEBUG] Task {task_id} not found")
            return
        
        plan = task.get("plan")
        if not plan or plan == "file-drop":
            return
        
        print(f"[DEBUG] Updating operation for task {task_id}, plan={plan}, status={task_status}")
        
        # Find the operation with this plan
        op = db.execute("SELECT * FROM operations WHERE plan=?", (plan,)).fetchone()
        if not op:
            print(f"[DEBUG] No operation found for plan: {plan}")
            return
        
        op_id = op["id"]
        agents_str = op["agents"]
        
        # Parse agents list
        if isinstance(agents_str, str):
            try:
                agents = json.loads(agents_str)
            except:
                agents = []
        else:
            agents = agents_str or []
        
        # Count task statuses for all agents in this operation
        total_tasks = 0
        completed_tasks = 0
        failed_tasks = 0
        in_progress_tasks = 0
        
        for ag in agents:
            tasks = db.execute(
                "SELECT id, status FROM tasks WHERE agent=? AND plan=? AND type IN ('execute', 'get_prereqs')",
                (ag, plan)
            ).fetchall()
            
            for t in tasks:
                total_tasks += 1
                t_status = t["status"]
                
                # FIX: If this is the current task, use the passed status
                # (DB may not be updated yet due to race condition)
                if t["id"] == task_id:
                    t_status = task_status
                
                if t_status == "completed":
                    completed_tasks += 1
                elif t_status == "failed":
                    failed_tasks += 1
                elif t_status == "in-progress":
                    in_progress_tasks += 1
        
        print(f"[DEBUG] Tasks: total={total_tasks}, completed={completed_tasks}, failed={failed_tasks}, in_progress={in_progress_tasks}")
        
        # Calculate progress
        if total_tasks > 0:
            progress = int((completed_tasks + failed_tasks) / total_tasks * 100)
        else:
            progress = 0
        
        # Determine operation status
        finished_tasks = completed_tasks + failed_tasks
        if finished_tasks >= total_tasks and total_tasks > 0:
            if failed_tasks > 0 and completed_tasks == 0:
                new_status = "failed"
            elif failed_tasks > 0:
                new_status = "partial"
            else:
                new_status = "completed"
        elif in_progress_tasks > 0 or finished_tasks > 0:
            new_status = "running"
        else:
            new_status = "queued"
        
        # Update operation
        store.update_operation_progress(op_id, progress, f"task_{task_status}")
        store.update_operation_status(op_id, new_status)
        
        print(f"[DEBUG] ✓ Updated operation {op_id}: status={new_status}, progress={progress}%")
        
    except Exception as e:
        print(f"[ERROR] Failed to update operation from task: {e}")
        import traceback
        traceback.print_exc()
        
def json_dumps(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False)

def json_loads(txt):
    try:
        return json.loads(txt)
    except Exception:
        return []

# ========================
# EMULATION PLANS HELPERS
# ========================

def get_threat_actor_image(mitre_group_id):
    """Get the image URL for a threat actor by MITRE Group ID"""
    filename = THREAT_ACTOR_IMAGES.get(mitre_group_id, "placeholder.jpeg")
    image_path = THREAT_ACTOR_IMAGES_DIR / filename
    if image_path.exists():
        return f"/static/images/threat_actors/{filename}"
    return "/static/images/threat_actors/placeholder.jpeg"

def load_emulation_plans_from_disk():
    """Load all emulation plans from JSON files in the emulation_plans directory"""
    plans = []
    if not EMULATION_PLANS_DIR.exists():
        return plans
    
    for json_file in EMULATION_PLANS_DIR.glob("*.json"):
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                plan_data = json.load(f)
            
            # Add metadata
            plan_data["_filename"] = json_file.name
            plan_data["_filepath"] = str(json_file)
            plan_data["id"] = plan_data.get("mitre_group_id") or json_file.stem
            plan_data["image_url"] = get_threat_actor_image(plan_data.get("mitre_group_id"))
            
            plans.append(plan_data)
        except Exception as e:
            print(f"[ERROR] Failed to load emulation plan {json_file}: {e}")
    
    # Sort by name
    plans.sort(key=lambda x: x.get("name", ""))
    return plans

def get_emulation_plan_by_id(plan_id):
    """Get a specific emulation plan by ID or MITRE group ID"""
    plans = load_emulation_plans_from_disk()
    for plan in plans:
        if plan.get("id") == plan_id or plan.get("mitre_group_id") == plan_id:
            return plan
    return None

# ========================
# ATOMIC TEST RESOLVER (for emulation plans)
# ========================
# Problem this solves:
#   Emulation plan JSONs identify tests via technique_id + an
#   Invoke-AtomicTest command string like:
#       "Invoke-AtomicTest T1087.001 -TestNumbers 1,2"
#   The agent needs (yaml_file, 0-based test_index) to execute the right test.
#   Previously api_emulation_plan_execute hardcoded test_index=0 and guessed
#   the yaml path from the parent technique folder, so:
#     - Sub-techniques in nested folders (e.g. T1550.002/T1550.002.yaml)
#       were never found.
#     - Tests other than #0 were silently replaced with #0.
#     - "-TestNumbers 1,2" ran only one test instead of two.
#   The resolver below fixes all three by parsing the Invoke-AtomicTest
#   command and cross-referencing the on-disk YAML.

# Cache of parsed on-disk YAMLs. Key: absolute yaml path. Value: parsed dict.
_atomic_yaml_cache = {}

# Regex for: "Invoke-AtomicTest <TID> -TestNumbers <n>,<n>,..."
# Tolerates extra whitespace and optional -Tests/-TestNumbers variants.
_INVOKE_ATOMIC_RE = re.compile(
    r"Invoke-AtomicTest\s+(T\d+(?:\.\d+)?)\s+-TestNumbers?\s+([\d,\s]+)",
    re.IGNORECASE,
)


def _load_yaml_cached(yaml_path):
    """Load and parse a YAML file with caching. Returns parsed dict or None."""
    key = str(yaml_path)
    if key in _atomic_yaml_cache:
        return _atomic_yaml_cache[key]
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        _atomic_yaml_cache[key] = data
        return data
    except Exception as e:
        print(f"[WARN] Failed to parse YAML {yaml_path}: {e}")
        _atomic_yaml_cache[key] = None
        return None


def find_atomic_yaml(technique_id):
    """
    Find the on-disk atomic YAML for a technique ID.

    Tries in order:
      1. atomics/<tid>/<tid>.yaml  (nested sub-tech layout, e.g. T1550.002/T1550.002.yaml)
      2. atomics/<base_tid>/<base_tid>.yaml  (parent layout, e.g. T1550/T1550.yaml)
      3. atomics/<base_tid>/<tid>.yaml  (parent folder holding sub-tech yaml)

    Returns (yaml_path_str, actual_technique_id_of_yaml) or (None, None).

    actual_technique_id_of_yaml tells the caller whether the yaml found is
    for the exact technique requested or its parent (matters for sub-technique
    resolution - a parent yaml may contain tests for multiple sub-techniques).
    """
    atomic_root = Path(CONFIG["ATOMIC_ROOT"])
    base_tid = technique_id.split(".")[0]

    candidates = [
        (atomic_root / technique_id / f"{technique_id}.yaml", technique_id),
        (atomic_root / base_tid / f"{base_tid}.yaml", base_tid),
        (atomic_root / base_tid / f"{technique_id}.yaml", technique_id),
    ]

    for path, tid in candidates:
        if path.exists():
            return str(path), tid

    return None, None


def parse_invoke_atomic_command(command_str):
    """
    Parse an Invoke-AtomicTest command string from an emulation plan.

    Returns (technique_id, [1-based test numbers]) or (None, []).
    """
    if not command_str:
        return None, []
    m = _INVOKE_ATOMIC_RE.search(command_str)
    if not m:
        return None, []
    tid = m.group(1)
    nums_str = m.group(2)
    nums = []
    for part in nums_str.split(","):
        part = part.strip()
        if part.isdigit():
            nums.append(int(part))
    return tid, nums


def resolve_emulation_plan_test(plan_test):
    """
    Resolve a single emulation-plan AtomicTests entry into one or more
    concrete agent task specs.

    Input: dict with keys like Technique, TechniqueName, Command,
           MitreReference, atomic_validated.

    Returns: (resolved_list, skipped_reason)
      resolved_list: list of dicts, each ready to be appended to the
        agent's "techniques" payload. One dict per test number in the
        plan's -TestNumbers. Each dict has id, name, test_name,
        test_index (0-based), file, guid, command, mitre_reference,
        atomic_validated, plan_command.
      skipped_reason: None if at least one test resolved; otherwise a
        short human-readable string describing why nothing resolved.

    Note: it's possible for some test numbers in the plan to resolve and
    others to be skipped (e.g. out of range, non-Windows). In that case
    resolved_list contains the successful ones and skipped_reason is None.
    """
    technique_id = plan_test.get("Technique", "").strip()
    if not technique_id:
        return [], "plan entry has no Technique field"

    plan_command = plan_test.get("Command", "")
    technique_name = plan_test.get("TechniqueName", "")
    mitre_ref = plan_test.get("MitreReference", "")
    atomic_validated = plan_test.get("atomic_validated", False)

    # Parse the Invoke-AtomicTest command to get the test numbers
    parsed_tid, test_numbers = parse_invoke_atomic_command(plan_command)

    # Sanity check: parsed technique ID from command should match the Technique field
    if parsed_tid and parsed_tid.upper() != technique_id.upper():
        print(f"[WARN] Plan entry Technique={technique_id} but Command references {parsed_tid}; trusting Technique field")

    # If no test numbers specified, default to test 1 (common convention)
    if not test_numbers:
        test_numbers = [1]

    # Find the on-disk YAML
    yaml_path, yaml_tid = find_atomic_yaml(technique_id)
    if not yaml_path:
        return [], f"no atomic YAML found on disk for {technique_id}"

    doc = _load_yaml_cached(yaml_path)
    if not doc:
        return [], f"YAML at {yaml_path} could not be parsed"

    atomic_tests = doc.get("atomic_tests", []) or []
    if not atomic_tests:
        return [], f"YAML at {yaml_path} has no atomic_tests"

    resolved = []
    for test_num in test_numbers:
        # Invoke-AtomicTest uses 1-based numbering; internal index is 0-based.
        idx = test_num - 1
        if idx < 0 or idx >= len(atomic_tests):
            print(f"[WARN] {technique_id} test #{test_num} out of range "
                  f"(yaml has {len(atomic_tests)} tests) - skipping")
            continue

        test_obj = atomic_tests[idx]

        # Platform filter. If supported_platforms is absent, assume cross-platform.
        supported = test_obj.get("supported_platforms") or []
        if supported and "windows" not in [str(p).lower() for p in supported]:
            print(f"[WARN] {technique_id} test #{test_num} does not support windows "
                  f"(platforms={supported}) - skipping")
            continue

        # If yaml_tid is the parent (e.g. we loaded T1218.yaml but asked for T1218.011),
        # confirm this particular test actually belongs to the requested sub-technique.
        # The test carries no per-test technique ID in ART schema, so we rely on the
        # fact that if a nested yaml existed (yaml_tid == technique_id) we'd have
        # taken that path. When falling back to parent yaml, we trust -TestNumbers as
        # authoritative because that's what the plan author specified.

        resolved.append({
            "id": technique_id,
            "name": technique_name or test_obj.get("name", ""),
            "test_name": test_obj.get("name", "") or technique_name,
            "test_index": idx,
            "file": yaml_path,
            "guid": test_obj.get("auto_generated_guid", ""),
            "command": (test_obj.get("executor", {}) or {}).get("command", ""),
            "mitre_reference": mitre_ref,
            "atomic_validated": atomic_validated,
            "plan_command": plan_command,
            "yaml_attack_technique": yaml_tid,
        })

    if not resolved:
        return [], (f"none of the test numbers {test_numbers} in {technique_id} "
                    f"resolved (out of range or unsupported platform)")

    return resolved, None


def clear_atomic_yaml_cache():
    """Clear the YAML parse cache. Call if atomics folder contents change."""
    global _atomic_yaml_cache
    _atomic_yaml_cache = {}


# ========================
# ATOMIC INDEX PARSER
# ========================

def load_index_yaml():
    if not INDEX_YAML_WINDOWS.exists():
        return {}
    with open(INDEX_YAML_WINDOWS, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def parse_markdown_categories():
    if not INDEX_MD_WINDOWS.exists():
        print(f"[DEBUG] INDEX_MD_WINDOWS does not exist: {INDEX_MD_WINDOWS}")
        return []
    
    print(f"[DEBUG] Reading INDEX_MD_WINDOWS: {INDEX_MD_WINDOWS}")
    
    TACTIC_NAME_MAP = {
        "defense-evasion": "Defense Evasion",
        "defense evasion": "Defense Evasion",
        "privilege-escalation": "Privilege Escalation",
        "privilege escalation": "Privilege Escalation",
        "initial-access": "Initial Access",
        "initial access": "Initial Access",
        "credential-access": "Credential Access",
        "credential access": "Credential Access",
        "command-and-control": "Command and Control",
        "command and control": "Command and Control",
        "lateral-movement": "Lateral Movement",
        "lateral movement": "Lateral Movement",
        "execution": "Execution",
        "persistence": "Persistence",
        "discovery": "Discovery",
        "collection": "Collection",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
        "reconnaissance": "Reconnaissance",
        "resource-development": "Resource Development",
        "resource development": "Resource Development",
    }
    
    categories = []
    current = None
    with open(INDEX_MD_WINDOWS, "r", encoding="utf-8") as f:
        for raw_line in f:
            # Keep original line to check indentation
            stripped = raw_line.strip()
            
            # Skip empty lines
            if not stripped:
                continue
            
            # Skip techniques without tests (CONTRIBUTE A TEST placeholders)
            if "CONTRIBUTE" in stripped:
                continue
            
            # Skip indented lines (atomic test descriptions start with spaces)
            # Technique lines start at column 0 with "- ["
            if raw_line.startswith("  "):
                continue
            
            # Match tactic headers (# defense-evasion, # execution, etc.)
            if stripped.startswith("# ") and "Windows Atomic Tests" not in stripped and "ATT&CK" not in stripped:
                raw_name = stripped[2:].strip().lower()
                tactic_name = TACTIC_NAME_MAP.get(raw_name, raw_name.replace("-", " ").title())
                current = {"name": tactic_name, "techniques": []}
                categories.append(current)
                print(f"[DEBUG] New tactic: {tactic_name}")
                continue
            
            # Match techniques - lines starting with "- [" at column 0
            if stripped.startswith("- [") and current:
                # Extract technique ID (T followed by 4-5 digits, optionally .xxx)
                m_tid = re.search(r"(T\d{4,5}(?:\.\d{3})?)", stripped)
                if m_tid:
                    tid = m_tid.group(1)
                    # Extract name from [Name](link)
                    m_name = re.search(r"\[([^\]]+)\]", stripped)
                    if m_name:
                        name = m_name.group(1)
                    else:
                        name = tid
                    
                    current["techniques"].append({"id": tid, "name": name})
    
    # DEBUG - final summary
    print(f"[DEBUG] Total tactics found: {len(categories)}")
    for cat in categories:
        print(f"[DEBUG]   {cat['name']}: {len(cat['techniques'])} techniques")
    
    return categories

def attach_yaml_paths(categories, index_map):
    atomic_root = Path(CONFIG["ATOMIC_ROOT"])
    for cat in categories:
        for tech in cat["techniques"]:
            technique_id = tech["id"]
            meta = index_map.get(technique_id, {})

            # Build candidate paths in order of preference.
            # 1. Explicit folder hint from index_map (if any) - preserves old behaviour.
            # 2. Nested sub-technique layout: atomics/T1550.002/T1550.002.yaml
            # 3. Parent-flat layout: atomics/T1550/T1550.yaml
            # 4. Parent folder holding sub-tech file: atomics/T1550/T1550.002.yaml
            base_tid = technique_id.split(".")[0]
            candidates = []
            if meta.get("folder"):
                candidates.append(atomic_root / meta["folder"] / f"{technique_id}.yaml")
            candidates.extend([
                atomic_root / technique_id / f"{technique_id}.yaml",
                atomic_root / base_tid / f"{base_tid}.yaml",
                atomic_root / base_tid / f"{technique_id}.yaml",
            ])

            yfile = None
            for candidate in candidates:
                if candidate.exists():
                    yfile = candidate
                    break

            if yfile is not None:
                tech["file"] = str(yfile)
                try:
                    doc = yaml.safe_load(open(yfile, "r", encoding="utf-8"))
                    tests = []
                    for idx, t in enumerate(doc.get("atomic_tests", [])):
                        # Only include Windows-supported tests
                        supported_platforms = t.get("supported_platforms", [])
                        if supported_platforms:
                            platforms_lower = [p.lower() for p in supported_platforms]
                            if "windows" not in platforms_lower:
                                continue  # Skip non-Windows tests
                        
                        tests.append({
                            "name": t.get("name"),
                            "description": t.get("description", ""),
                            "executor": t.get("executor", {}).get("name"),
                            "command": t.get("executor", {}).get("command", ""),
                            "supported_platforms": supported_platforms,
                            "original_index": idx  # Keep track of original index in YAML
                        })
                    tech["tests"] = tests
                except Exception as e:
                    tech["tests"] = [{"name": "parse-error", "command": str(e)}]
            else:
                tech["file"] = None
                tech["tests"] = []
    return categories

def get_windows_tactics():
    categories = parse_markdown_categories()
    index_map = load_index_yaml()
    return {"tactics": attach_yaml_paths(categories, index_map)}

# ========================
# ROUTES
# ========================

# ========================
# AUTHENTICATION ROUTES
# ========================

@app.route("/login")
def login_page():
    if session.get('logged_in'):
        return redirect(url_for('index'))
    return app.send_static_file("login.html")

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    
    if not user or not verify_password(password, user['password_hash']):
        return jsonify({"error": "Invalid username or password"}), 401
    
    # Update last login
    now = datetime.datetime.utcnow().isoformat()
    db.execute('UPDATE users SET last_login=? WHERE id=?', (now, user['id']))
    db.commit()
    
    # Create session
    session.permanent = True
    session['logged_in'] = True
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    session['last_activity'] = now
    
    return jsonify({
        "status": "success",
        "user": {"id": user['id'], "username": user['username'], "role": user['role']}
    })

@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"status": "logged_out"})

@app.route("/api/auth/check")
def api_auth_check():
    if session.get('logged_in'):
        return jsonify({
            "authenticated": True,
            "user": {"username": session.get('username'), "role": session.get('role')}
        })
    return jsonify({"authenticated": False})

@app.route("/api/auth/change-password", methods=["POST"])
@login_required
def api_change_password():
    data = request.json or {}
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")
    
    if not current_password or not new_password:
        return jsonify({"error": "Current and new password required"}), 400
    
    if len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    
    if not verify_password(current_password, user['password_hash']):
        return jsonify({"error": "Current password is incorrect"}), 401
    
    new_hash = hash_password(new_password)
    db.execute('UPDATE users SET password_hash=? WHERE id=?', (new_hash, session['user_id']))
    db.commit()
    
    return jsonify({"status": "success", "message": "Password changed successfully"})

@app.route("/api/settings", methods=["GET"])
@login_required
def api_get_settings():
    db = get_db()
    rows = db.execute('SELECT key, value FROM app_settings').fetchall()
    settings = {row['key']: row['value'] for row in rows}
    return jsonify({"settings": settings})

@app.route("/api/settings", methods=["POST"])
@login_required
def api_update_settings():
    data = request.json or {}
    settings = data.get("settings", {})
    
    db = get_db()
    now = datetime.datetime.utcnow().isoformat()
    
    for key, value in settings.items():
        db.execute('INSERT OR REPLACE INTO app_settings (key, value, updated) VALUES (?, ?, ?)',
                  (key, str(value), now))
    db.commit()
    return jsonify({"status": "success"})

@app.route("/")
@login_required 
def index():
    return app.send_static_file("ui.html")

@app.route("/api/agent/confirm_file", methods=["POST"])
def api_agent_confirm_file():
    body = request.json or {}
    aid = body.get("agentId")
    task_id = body.get("taskId")
    if not aid or not task_id:
        return jsonify({"error": "missing parameters"}), 400

    print(f"[DEBUG] Received confirmation from agent {aid} for task {task_id}")
    set_agent_confirmation(aid, task_id)
    return jsonify({"status": "confirmed"})

@app.route("/api/techniques")
@login_required
def api_techniques():
    return jsonify(get_windows_tactics())

@app.route("/api/agents", methods=["GET", "POST", "DELETE"])
@login_required
def api_agents():
    if request.method == "GET":
        agents = store.list_agents()
        agents = get_agent_status_list(agents)
        return jsonify({"agents": agents})

    elif request.method == "POST":
        body = request.json or {}
        ok = store.rename_agent(body.get("agentId"), body.get("newId"))
        return jsonify({"status": "renamed" if ok else "notfound"})

    elif request.method == "DELETE":
        store.delete_agent(request.args.get("agentId"))
        return jsonify({"status": "deleted"})

@app.route("/api/execute", methods=["POST"])
@login_required
def api_execute():
    try:
        body = request.json or {}
        agentIds = body.get("agentIds") or []
        if not isinstance(agentIds, list):
            agentIds = [body.get("agentId")] if body.get("agentId") else []
        plan = body.get("planName") or f"plan-{datetime.datetime.utcnow().isoformat()}"
        params = body.get("params", "")
        techniques = body.get("techniques", [])
        incoming_commands = body.get("commands", [])
        task_type = body.get("type", "execute")

        print(f"[DEBUG] Execute request: agents={agentIds}, plan={plan}, techniques={len(techniques)}")

        if not agentIds or not techniques:
            return jsonify({"error": "missing agentIds or techniques"}), 400

        all_agents = get_agent_status_list(store.list_agents())
        online_ids = [a["id"] for a in all_agents if a["status"] == "online"]
        for agent in agentIds:
            if agent not in online_ids:
                return jsonify({"error": f"Agent {agent} offline or not found"}), 400

        folders_to_zip = set()
        yaml_files = []
        commands = []

        for t in techniques:
            file_path = t.get("file")
            try:
                test_index = int(t.get("test_index", 0))
            except Exception:
                test_index = 0

            if file_path and Path(file_path).exists():
                try:
                    with open(file_path, "r", encoding="utf-8") as yf:
                        doc = yaml.safe_load(yf)
                    atomic_tests = doc.get("atomic_tests", [])
                    if 0 <= test_index < len(atomic_tests):
                        atomic = atomic_tests[test_index]
                        
                        # Check if test supports Windows
                        supported_platforms = atomic.get("supported_platforms", [])
                        if supported_platforms and "windows" not in [p.lower() for p in supported_platforms]:
                            print(f"[DEBUG] Skipping non-Windows test: {t.get('id')} (platforms: {supported_platforms})")
                            continue
                        
                        yaml_files.append(file_path)
                        folder_path = str(Path(file_path).parent)
                        folders_to_zip.add(folder_path)
                        
                        executor = atomic.get("executor", {})
                        cmd = executor.get("command", "")
                        if cmd:
                            commands.append(cmd)
                except Exception as e:
                    print("YAML parse error:", e)

        # Generate a SINGLE main task ID for this operation
        main_task_id = f"task-{uuid.uuid4().hex}"
        tmp_zip_path = os.path.join(tempfile.gettempdir(), f"atomic_bundle_{main_task_id}.zip")

        print(f"[DEBUG] Main task ID: {main_task_id}")
        print(f"[DEBUG] Creating ZIP at: {tmp_zip_path}")
        print(f"[DEBUG] Folders to zip: {folders_to_zip}")

        with zipfile.ZipFile(tmp_zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for folder in folders_to_zip:
                for root, dirs, files in os.walk(folder):
                    for f in files:
                        abs_path = os.path.join(root, f)
                        rel_path = os.path.relpath(abs_path, CONFIG["ATOMIC_ROOT"])
                        zipf.write(abs_path, arcname=rel_path)

        print(f"[DEBUG] Created ZIP: {tmp_zip_path} ({os.path.getsize(tmp_zip_path)} bytes)")

        # Upload ZIP to each agent and create filedrop tasks
        filedrop_task_ids = []
        for agent in agentIds:
            try:
                agent_dir = os.path.join(CONFIG["UPLOAD_DIR"], agent)
                os.makedirs(agent_dir, exist_ok=True)
                
                # Copy the ZIP file to agent's directory
                dest_path = os.path.join(agent_dir, f"atomic_bundle_{main_task_id}.zip")
                shutil.copy(tmp_zip_path, dest_path)
                print(f"[DEBUG] Copied ZIP to: {dest_path} ({os.path.getsize(dest_path)} bytes)")
                
                # Create filedrop task with MAIN task ID so agent can confirm it
                task_obj = {
                    "id": main_task_id,
                    "plan": "file-drop",
                    "params": f"path:{dest_path}",
                    "file": f"atomic_bundle_{main_task_id}.zip",
                    "type": "filedrop",
                    "status": "queued"
                }
                store.add_task(agent, task_obj)
                filedrop_task_ids.append((agent, main_task_id))
                print(f"[DEBUG] Created filedrop task {main_task_id} for agent {agent}")
                
            except Exception as e:
                print(f"[ERROR] Failed to prepare filedrop for agent {agent}: {e}")
                import traceback
                traceback.print_exc()
                return jsonify({"error": f"filedrop preparation failed: {e}"}), 500

        # Wait for ALL agents to confirm ZIP extraction
        timeout = 60
        for agent in agentIds:
            start = time.time()
            print(f"[DEBUG] Waiting for agent '{agent}' to confirm ZIP extraction (task_id: {main_task_id})...")
            confirmed = False
            while time.time() - start < timeout:
                try:
                    if agent_confirmed(agent, main_task_id):
                        elapsed = time.time() - start
                        print(f"[DEBUG] Agent '{agent}' confirmed ZIP extraction after {elapsed:.1f}s")
                        confirmed = True
                        break
                except Exception as e:
                    print(f"[ERROR] Exception checking confirmation for {agent}: {e}")
                    import traceback
                    traceback.print_exc()
                time.sleep(1)
            
            if not confirmed:
                elapsed = time.time() - start
                print(f"[ERROR] Agent '{agent}' did not confirm after {elapsed:.1f}s")
                return jsonify({"error": f"Agent {agent} did not confirm ZIP extraction (timeout after {elapsed:.0f}s)"}), 500

        if incoming_commands:
            commands.extend(incoming_commands)

        if not commands and task_type == "execute":
            return jsonify({"error": "No commands to execute"}), 400

        # Ensure test_name is set for all techniques
        for t in techniques:
            if not t.get("test_name"):
                t["test_name"] = t.get("name", "")

        # Create operation
        op_id = store.add_operation(agentIds, plan, params, "running", 
                                     os.path.basename(tmp_zip_path), techniques)

        # Check if prerequisites should be fetched first
        get_prereqs_first = body.get("getPrereqsFirst", False)
        
        # If get_prereqs_first, create prereq tasks BEFORE execute tasks
        if get_prereqs_first:
            print(f"[DEBUG] Creating get_prereqs tasks for {len(agentIds)} agents")
            for agent in agentIds:
                prereq_task_id = f"prereq-{uuid.uuid4().hex}"
                store.add_task(agent, {
                    "id": prereq_task_id,
                    "plan": plan,
                    "params": params,
                    "techniques": techniques,
                    "commands": [],
                    "type": "get_prereqs",
                    "file": os.path.basename(tmp_zip_path),
                    "path": tmp_zip_path
                })
                print(f"[DEBUG] Created get_prereqs task {prereq_task_id} for agent {agent}")
        
        # Create EXECUTE tasks with UNIQUE IDs for each agent
        task_ids = []
        for agent in agentIds:
            execute_task_id = f"execute-{uuid.uuid4().hex}"
            task = store.add_task(agent, {
                "id": execute_task_id,
                "plan": plan,
                "params": params,
                "techniques": techniques,
                "commands": commands,
                "type": task_type,
                "file": os.path.basename(tmp_zip_path),
                "path": tmp_zip_path
            })
            task_ids.append(task)

        print(f"[DEBUG] Success! Created operation {op_id} with {len(task_ids)} tasks")

        return jsonify({
            "status": "queued",
            "operation": op_id,
            "operation_id": op_id,
            "tasks": task_ids,
            "zip": os.path.basename(tmp_zip_path)
        })
        
    except Exception as e:
        print(f"[ERROR] Exception in /api/execute: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/agent_files/<agent>")
def api_agent_files(agent):
    agent_dir = os.path.join(CONFIG["UPLOAD_DIR"], agent)
    files = []
    if os.path.exists(agent_dir):
        for f in os.listdir(agent_dir):
            fpath = os.path.join(agent_dir, f)
            if os.path.isfile(fpath):
                created = datetime.datetime.fromtimestamp(os.path.getctime(fpath)).isoformat()
                files.append({"file": f, "created": created})
    return jsonify({"files": files})

@app.route("/api/operations", methods=["GET"])
@login_required
def api_operations():
    status = request.args.get("status", None)
    operations = store.get_operations(status)
    for op in operations:
        if "agents" in op and isinstance(op["agents"], str):
            try:
                op["agents"] = json.loads(op["agents"])
            except Exception:
                op["agents"] = []
        if "techniques" in op and isinstance(op["techniques"], str):
            try:
                op["techniques"] = json.loads(op["techniques"])
            except Exception:
                op["techniques"] = []
    return jsonify({"operations": operations})

@app.route("/api/operations/<op_id>", methods=["GET", "DELETE"])
@login_required
def api_operation_detail(op_id):
    if request.method == "DELETE":
        store.delete_operation(op_id)
        return jsonify({"status": "deleted"})
    
    op = store.get_operation(op_id)
    if not op:
        return jsonify({"error": "Operation not found"}), 404
    if "agents" in op and isinstance(op["agents"], str):
        try:
            op["agents"] = json.loads(op["agents"])
        except Exception:
            op["agents"] = []
    if "techniques" in op and isinstance(op["techniques"], str):
        try:
            op["techniques"] = json.loads(op["techniques"])
        except Exception:
            op["techniques"] = []
    if "timeline" in op and isinstance(op["timeline"], str):
        try:
            op["timeline"] = json.loads(op["timeline"])
        except Exception:
            op["timeline"] = []
    return jsonify(op)

@app.route("/api/operations/<op_id>/logs", methods=["GET"])
def api_operations_logs(op_id):
    op = store.get_operation(op_id)
    if not op:
        return jsonify({"error": "not found"}), 404
    db = get_db()
    
    agents_str = op.get("agents", "[]")
    if isinstance(agents_str, str):
        try:
            agents = json.loads(agents_str)
        except:
            agents = []
    else:
        agents = agents_str or []
    
    plan = op["plan"]
    logs = []
    
    for agent in agents:
        task = db.execute("SELECT id FROM tasks WHERE agent=? AND plan=?", (agent, plan)).fetchone()
        if task:
            t_id = task["id"]
            rows = db.execute("SELECT line, ts, output_type FROM live_logs WHERE task_id=? ORDER BY ts ASC", (t_id,)).fetchall()
            for row in rows:
                logs.append({
                    "agent": agent, 
                    "line": row["line"], 
                    "ts": row["ts"],
                    "output_type": row["output_type"] if "output_type" in row.keys() else None
                })
    
    return jsonify({"logs": logs})

@app.route("/api/operations/<op_id>/pause", methods=["POST"])
def api_operations_pause(op_id):
    store.update_operation_status(op_id, "paused")
    return jsonify({"status": "paused"})

@app.route("/api/operations/<op_id>/resume", methods=["POST"])
def api_operations_resume(op_id):
    store.update_operation_status(op_id, "running")
    return jsonify({"status": "running"})

@app.route("/api/operations/<op_id>/stop", methods=["POST"])
def api_operations_stop(op_id):
    store.update_operation_status(op_id, "stopped")
    return jsonify({"status": "stopped"})

# ========================
# EMULATION PLANS ROUTES
# ========================

@app.route("/api/emulation_plans", methods=["GET"])
@login_required
def api_emulation_plans():
    """Get all emulation plans (summary only)"""
    plans = load_emulation_plans_from_disk()
    
    # Return summary info only (not full AtomicTests)
    summaries = []
    for plan in plans:
        summaries.append({
            "id": plan.get("id"),
            "name": plan.get("name"),
            "description": plan.get("description"),
            "mitre_group_id": plan.get("mitre_group_id"),
            "mitre_url": plan.get("mitre_url"),
            "aliases": plan.get("aliases", []),
            "attribution": plan.get("attribution"),
            "image_url": plan.get("image_url"),
            "coverage_stats": plan.get("coverage_stats", {}),
            "test_count": len(plan.get("AtomicTests", []))
        })
    
    return jsonify({"plans": summaries})

@app.route("/api/emulation_plans/<plan_id>", methods=["GET"])
@login_required
def api_emulation_plan_detail(plan_id):
    """Get full emulation plan details including all AtomicTests"""
    plan = get_emulation_plan_by_id(plan_id)
    if not plan:
        return jsonify({"error": "Emulation plan not found"}), 404
    return jsonify(plan)

@app.route("/api/emulation_plans/<plan_id>/execute", methods=["POST"])
@login_required
def api_emulation_plan_execute(plan_id):
    """Execute an emulation plan against selected agents"""
    try:
        body = request.json or {}
        agent_ids = body.get("agentIds", [])
        selected_test_indices = body.get("selectedTests", [])
        get_prereqs = body.get("getPrereqs", False)
        
        if not agent_ids:
            return jsonify({"error": "No agents selected"}), 400
        
        # Load the plan
        plan = get_emulation_plan_by_id(plan_id)
        if not plan:
            return jsonify({"error": "Emulation plan not found"}), 404
        
        atomic_tests = plan.get("AtomicTests", [])
        
        # Filter to selected tests if specified
        if selected_test_indices:
            selected_set = set(selected_test_indices)
            atomic_tests = [t for i, t in enumerate(atomic_tests) if i in selected_set]
        
        if not atomic_tests:
            return jsonify({"error": "No tests selected"}), 400
        
        # Validate agents are online
        all_agents = get_agent_status_list(store.list_agents())
        online_ids = [a["id"] for a in all_agents if a["status"] == "online"]
        for agent in agent_ids:
            if agent not in online_ids:
                return jsonify({"error": f"Agent {agent} offline or not found"}), 400
        
        # Build techniques list from atomic tests using the resolver.
        # Each plan entry may expand into 1..N agent tasks because
        # Invoke-AtomicTest commands like "-TestNumbers 1,2" request
        # multiple tests of the same technique.
        techniques = []
        folders_to_zip = set()
        skipped = []  # techniques that could not be resolved / were filtered

        # Clear the YAML cache so resolver picks up any recent atomics refresh.
        clear_atomic_yaml_cache()

        for test in atomic_tests:
            resolved, skip_reason = resolve_emulation_plan_test(test)

            if skip_reason and not resolved:
                skipped.append({
                    "technique": test.get("Technique", ""),
                    "technique_name": test.get("TechniqueName", ""),
                    "plan_command": test.get("Command", ""),
                    "reason": skip_reason,
                })
                print(f"[INFO] Skipped {test.get('Technique', '?')}: {skip_reason}")
                continue

            for item in resolved:
                techniques.append(item)
                yaml_path = item.get("file")
                if yaml_path:
                    folders_to_zip.add(str(Path(yaml_path).parent))

        print(f"[INFO] Emulation plan {plan_id}: resolved {len(techniques)} test(s), "
              f"skipped {len(skipped)}")
        
        if not techniques:
            return jsonify({
                "error": "No valid techniques could be resolved from the emulation plan",
                "skipped": skipped,
            }), 400

        # Create task ID and ZIP bundle
        main_task_id = f"emulation-{uuid.uuid4().hex}"
        plan_name = plan.get("name", plan_id)
        
        tmp_zip_path = os.path.join(tempfile.gettempdir(), f"emulation_bundle_{main_task_id}.zip")
        
        with zipfile.ZipFile(tmp_zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for folder in folders_to_zip:
                for root, dirs, files in os.walk(folder):
                    for f in files:
                        abs_path = os.path.join(root, f)
                        rel_path = os.path.relpath(abs_path, CONFIG["ATOMIC_ROOT"])
                        zipf.write(abs_path, arcname=rel_path)
        
        print(f"[DEBUG] Created emulation ZIP: {tmp_zip_path} ({os.path.getsize(tmp_zip_path)} bytes)")
        print(f"[DEBUG] Techniques to execute: {len(techniques)}")
        
        # Upload ZIP to each agent
        for agent in agent_ids:
            agent_dir = os.path.join(CONFIG["UPLOAD_DIR"], agent)
            os.makedirs(agent_dir, exist_ok=True)
            dest_path = os.path.join(agent_dir, f"emulation_bundle_{main_task_id}.zip")
            shutil.copy(tmp_zip_path, dest_path)
            
            task_obj = {
                "id": main_task_id,
                "plan": "file-drop",
                "params": f"path:{dest_path}",
                "file": f"emulation_bundle_{main_task_id}.zip",
                "type": "filedrop",
                "status": "queued"
            }
            store.add_task(agent, task_obj)
        
        # Wait for agent confirmations
        timeout = 60
        for agent in agent_ids:
            start = time.time()
            while time.time() - start < timeout:
                if agent_confirmed(agent, main_task_id):
                    print(f"[DEBUG] Agent {agent} confirmed ZIP extraction")
                    break
                time.sleep(1)
            else:
                return jsonify({"error": f"Agent {agent} did not confirm ZIP extraction (timeout)"}), 500
        
        # Create operation record
        op_id = store.add_operation(
            agent_ids,
            f"[EMULATION] {plan_name}",
            json.dumps({"emulation_plan_id": plan_id, "get_prereqs": get_prereqs}),
            "running",
            os.path.basename(tmp_zip_path),
            techniques
        )
        
        # Create execute tasks
        task_type = "get_prereqs" if get_prereqs else "execute"
        task_ids = []
        
        for agent in agent_ids:
            execute_task_id = f"emulation-exec-{uuid.uuid4().hex}"
            task = store.add_task(agent, {
                "id": execute_task_id,
                "plan": f"[EMULATION] {plan_name}",
                "params": json.dumps({"emulation_plan_id": plan_id}),
                "techniques": techniques,
                "commands": [],
                "type": task_type,
                "file": os.path.basename(tmp_zip_path),
                "path": tmp_zip_path
            })
            task_ids.append(task)
        
        print(f"[DEBUG] Created emulation operation {op_id} with {len(task_ids)} tasks")
        
        return jsonify({
            "status": "queued",
            "operation_id": op_id,
            "tasks": task_ids,
            "techniques_count": len(techniques),
            "skipped": skipped,
            "skipped_count": len(skipped),
            "plan_name": plan_name
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/api/emulation_plans/reload", methods=["POST"])
def api_emulation_plans_reload():
    """Force reload emulation plans from disk"""
    plans = load_emulation_plans_from_disk()
    return jsonify({"status": "reloaded", "count": len(plans)})

# ========================
# FILEDROP AND OTHER ROUTES
# ========================

@app.route("/api/filedrop", methods=["POST"])
def api_filedrop():
    agent_id = request.form.get("agentId")
    task_id = request.form.get("taskId")
    file = request.files.get("file")
    
    print(f"[DEBUG] Filedrop request: agentId={agent_id}, taskId={task_id}, file={file.filename if file else None}")
    
    if not agent_id or not file:
        return jsonify({"error": "missing agentId or file"}), 400

    agent_dir = os.path.join(CONFIG["UPLOAD_DIR"], agent_id)
    os.makedirs(agent_dir, exist_ok=True)
    
    # Use the EXACT filename from the request if it contains task ID
    if task_id and "atomic_bundle" in file.filename:
        fname = file.filename
    elif task_id:
        fname = f"atomic_bundle_{task_id}.zip"
    else:
        fname = f"{uuid.uuid4().hex}_{file.filename}"
    
    fpath = os.path.join(agent_dir, fname)
    print(f"[DEBUG] Saving file to: {fpath}")
    
    file.save(fpath)
    
    # Verify file was saved correctly
    if os.path.exists(fpath):
        file_size = os.path.getsize(fpath)
        print(f"[DEBUG] File saved successfully: {fpath} ({file_size} bytes)")
    else:
        print(f"[ERROR] File was not saved: {fpath}")
        return jsonify({"error": "Failed to save file"}), 500

    task = {
        "id": task_id if task_id else f"task-{uuid.uuid4().hex}",
        "plan": "file-drop",
        "params": f"path:{fpath}",
        "file": fname,
        "type": "filedrop",
        "status": "queued"
    }
    out = store.add_task(agent_id, task)
    
    print(f"[DEBUG] Created filedrop task: {out}")
    
    return jsonify({"status": "queued", "file": fname, "task": out})

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.json or {}
    if data.get("token") != CONFIG["ADMIN_TOKEN"]:
        return jsonify({"error": "bad token"}), 403
    info = data.get("info", "")
    if isinstance(info, dict):
        info = json.dumps(info)
    store.register(data.get("id"), info)
    return jsonify({"status": "registered", "id": data.get("id")})

@app.route("/api/poll/<aid>", methods=["GET"])
def api_poll(aid):
    if request.headers.get("X-AGENT-TOKEN") != CONFIG["ADMIN_TOKEN"]:
        return jsonify({"error": "unauthorized"}), 403
    db = get_db()
    now = datetime.datetime.utcnow().isoformat()
    db.execute('UPDATE agents SET last_seen=? WHERE id=?', (now, aid))
    db.commit()
    task = store.next_task(aid)
    return jsonify({"status": "task", "task": task}) if task else jsonify({"status": "idle"})

@app.route("/api/report/<aid>", methods=["POST"])
def api_report(aid):
    if request.headers.get("X-AGENT-TOKEN") != CONFIG["ADMIN_TOKEN"]:
        return jsonify({"error": "unauthorized"}), 403

    body = request.json or {}
    task_id = body.get("task_id")
    result_type = body.get("result_type")

    # Handle test execution results
    if result_type == "test_execution":
        db = get_db()
        main_cmd = body.get("main_command", {})
        with db:
            db.execute('''
                INSERT INTO test_results (
                    task_id, technique_id, test_number, test_name, status, duration,
                    start_time, end_time, exit_code, stdout_lines, stderr_lines,
                    has_errors, prerequisites_count, errors
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                task_id,
                body.get("technique_id"),
                body.get("test_number"),
                body.get("test_name"),
                body.get("status"),
                body.get("duration"),
                body.get("start_time"),
                body.get("end_time"),
                main_cmd.get("exit_code") if main_cmd else None,
                main_cmd.get("stdout_lines") if main_cmd else None,
                main_cmd.get("stderr_lines") if main_cmd else None,
                1 if (main_cmd.get("has_errors") if main_cmd else False) else 0,
                body.get("prerequisites_count"),
                json.dumps(body.get("errors", []))
            ))
        return jsonify({"status": "test_result_stored"})

    elif result_type == "command_output":
       db = get_db()
       with db:
           db.execute('''
               INSERT INTO command_outputs (
                   task_id, technique_id, test_number, command_type, command, exit_code,
                   execution_time, stdout, stderr, stdout_line_count, stderr_line_count,
                   timestamp
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ''', (
               task_id,
               body.get("technique_id"),
               body.get("test_number"),  # NEW
               body.get("command_type"),
               body.get("command"),
               body.get("exit_code"),
               body.get("execution_time"),
               body.get("stdout"),
               body.get("stderr"),
               body.get("stdout_line_count"),
               body.get("stderr_line_count"),
               body.get("timestamp")
           ))
       return jsonify({"status": "command_output_stored"})

    # Handle partial/live logs
    elif body.get("partial"):
        db = get_db()
        with db:
            db.execute("""
                INSERT INTO live_logs (task_id, line, ts, output_type, agent_comment)
                VALUES (?, ?, ?, ?, ?)
            """, (
                task_id, 
                body.get("output", ""), 
                datetime.datetime.utcnow().isoformat(),
                body.get("output_type", ""),
                1 if body.get("agent_comment") else 0
            ))
        return jsonify({"status": "logged"})

    # Handle final task completion
# Handle final task completion
    final_status = body.get("status", "completed")
    store.set_output(
        aid,
        task_id,
        body.get("output", ""),
        final_status
    )
    
    # UPDATE OPERATION STATUS AND PROGRESS
    update_operation_from_task(task_id, final_status)
    
    return jsonify({"status": "ok"})

@app.route("/api/task/status/<task_id>")
@login_required
def api_task_status(task_id):
    db = get_db()
    t = store.get_task(task_id)
    if not t:
        return jsonify({"error": "not found"}), 404

    logs = db.execute(
        "SELECT line FROM live_logs WHERE task_id=? ORDER BY ts ASC",
        (task_id,)
    ).fetchall()
    live_log = [row["line"] for row in logs]
    t["live_log"] = live_log
    return jsonify(t)

@app.route("/api/task/<task_id>/test_results")
@login_required
def api_task_test_results(task_id):
    """Get structured test results for a task"""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM test_results WHERE task_id=? ORDER BY start_time ASC",
        (task_id,)
    ).fetchall()
    results = [dict(row) for row in rows]
    return jsonify({"test_results": results})
@app.route("/api/task/<task_id>/command_output/<technique_id>")
@app.route("/api/task/<task_id>/command_output/<technique_id>/<test_number>")
@login_required
def api_task_command_output(task_id, technique_id, test_number=None):
    """Get detailed command outputs for a specific technique in a task"""
    db = get_db()
    
    if test_number is not None:
        rows = db.execute(
            "SELECT * FROM command_outputs WHERE task_id=? AND technique_id=? AND test_number=?",
            (task_id, technique_id, test_number)
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM command_outputs WHERE task_id=? AND technique_id=?",
            (task_id, technique_id)
        ).fetchall()
    
    outputs = {}
    for row in rows:
        cmd_type = row["command_type"]
        outputs[cmd_type] = dict(row)
    
    outputs["detection_rules"] = get_detection_rules_for_technique(technique_id)
    return jsonify(outputs)

@app.route("/api/tasks/history")
@login_required
def api_tasks_history():
    return jsonify({"tasks": store.tasks_history()})

@app.route("/api/modules")
def api_modules():
    modules_dir = Path(__file__).resolve().parent / "modules"
    files = []
    if modules_dir.exists():
        for f in modules_dir.iterdir():
            if f.is_file():
                files.append({"name": f.name, "size": f.stat().st_size})
    return jsonify({"files": files})

@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(CONFIG["UPLOAD_DIR"], filename)

@app.route("/uploads/<agent>/<filename>")
def uploads_agent(agent, filename):
    agent_dir = os.path.join(CONFIG["UPLOAD_DIR"], agent)
    return send_from_directory(agent_dir, filename)

@app.route("/modules/<filename>")
def serve_module(filename):
    modules_dir = Path(__file__).resolve().parent / "modules"
    return send_from_directory(modules_dir, filename)
    
@app.route("/api/agents/<agent_id>/config", methods=["GET", "POST"])
@login_required
def api_agent_config(agent_id):
    """Get or update agent configuration"""
    try:
        if request.method == "GET":
            agents = store.list_agents()
            agent = next((a for a in agents if a.get('id') == agent_id), None)
            if not agent:
                return jsonify({"error": "Agent not found"}), 404
            
            info = agent.get('info', {})
            if isinstance(info, str):
                try:
                    info = json.loads(info)
                except:
                    info = {}
            
            return jsonify({"config": info})
        
        elif request.method == "POST":
            body = request.json or {}
            config = body.get("config", {})
            
            # Get existing agent
            agents = store.list_agents()
            agent = next((a for a in agents if a.get('id') == agent_id), None)
            if not agent:
                return jsonify({"error": "Agent not found"}), 404
            
            # Merge config with existing info
            info = agent.get('info', {})
            if isinstance(info, str):
                try:
                    info = json.loads(info)
                except:
                    info = {}
            
            # Update with new config values
            info.update(config)
            
            # Save back to database using the new method
            store.update_agent_info(agent_id, info)
            
            return jsonify({"status": "updated", "config": info})
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
        
        
# =============================================================================
# DETECTION RULES LOADING FUNCTIONS
# =============================================================================

def load_attack_rule_map():
    """
    Load AttackRuleMap JSON file.
    Source: https://github.com/krdmnbrk/AttackRuleMap
    Format: List of objects with tech_id, atomic_attack_guid, sigma_rules, splunk_rules
    """
    if not ATTACK_RULE_MAP_FILE.exists():
        print(f"[WARN] AttackRuleMap not found: {ATTACK_RULE_MAP_FILE}")
        print(f"[WARN] Run: curl -o {ATTACK_RULE_MAP_FILE} https://raw.githubusercontent.com/krdmnbrk/AttackRuleMap/main/attack_rule_map.json")
        return []
    try:
        with open(ATTACK_RULE_MAP_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            print(f"[INFO] Loaded {len(data)} entries from AttackRuleMap")
            return data
    except Exception as e:
        print(f"[ERROR] Failed to load AttackRuleMap: {e}")
        return []


def load_elastic_rules():
    """
    Load Elastic Detection Rules parsed from TOML files.
    Source: https://github.com/elastic/detection-rules/tree/main/rules
    Generated by: fetch_elastic_rules.py
    
    Format:
    {
        "_info": {...},
        "techniques": {
            "T1003.001": [
                {"name": "...", "severity": "...", "url": "...", ...}
            ]
        }
    }
    """
    if not ELASTIC_RULES_FILE.exists():
        print(f"[INFO] Elastic rules file not found: {ELASTIC_RULES_FILE}")
        print(f"[INFO] Run fetch_elastic_rules.py to generate it")
        return {}
    try:
        with open(ELASTIC_RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            
            # New format from fetch_elastic_rules.py
            if "techniques" in data:
                techniques = data.get("techniques", {})
                info = data.get("_info", {})
                total_rules = info.get('total_rules', '?')
                print(f"[INFO] Loaded {len(techniques)} techniques from Elastic rules ({total_rules} rules)")
                return techniques
            
            # Legacy: array format
            elif isinstance(data, list):
                techniques = {}
                for entry in data:
                    tech_id = entry.get("technique_id", "")
                    if tech_id:
                        techniques[tech_id] = entry.get("rules", [])
                print(f"[INFO] Loaded {len(techniques)} techniques from Elastic rules (array format)")
                return techniques
            
            # Legacy: direct dict format
            else:
                techniques = {k: v for k, v in data.items() if not k.startswith("_")}
                if techniques:
                    print(f"[INFO] Loaded {len(techniques)} techniques from Elastic rules")
                return techniques
                
    except Exception as e:
        print(f"[ERROR] Failed to load Elastic rules: {e}")
        return {}


# =============================================================================
# CACHING
# =============================================================================

_attack_rule_map_cache = None
_elastic_rules_cache = None


def get_attack_rule_map():
    """Get cached AttackRuleMap data"""
    global _attack_rule_map_cache
    if _attack_rule_map_cache is None:
        _attack_rule_map_cache = load_attack_rule_map()
    return _attack_rule_map_cache


def get_elastic_rules():
    """Get cached Elastic rules data"""
    global _elastic_rules_cache
    if _elastic_rules_cache is None:
        _elastic_rules_cache = load_elastic_rules()
    return _elastic_rules_cache


def reload_detection_rules():
    """Force reload all detection rules from disk"""
    global _attack_rule_map_cache, _elastic_rules_cache
    _attack_rule_map_cache = None
    _elastic_rules_cache = None
    get_attack_rule_map()
    get_elastic_rules()


# =============================================================================
# MAIN LOOKUP FUNCTION
# =============================================================================

def get_detection_rules_for_technique(technique_id, atomic_guid=None):
    """
    Get all detection rules for a MITRE technique.
    
    Args:
        technique_id: MITRE technique ID (e.g., "T1003.001")
        atomic_guid: Optional specific Atomic test GUID to filter by
        
    Returns:
        Dict with sigma_rules, splunk_rules, elastic_rules, and metadata
    """
    attack_map = get_attack_rule_map()
    elastic_rules = get_elastic_rules()
    base_tech = technique_id.split(".")[0]
    
    result = {
        "technique_id": technique_id,
        "atomic_guid": atomic_guid,
        "sigma_rules": [],
        "splunk_rules": [],
        "elastic_rules": [],
        "atomic_tests": [],
        "references": {
            "mitre": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
            "sigma_search": f"https://github.com/SigmaHQ/sigma/search?q=attack.{technique_id.lower()}",
            "atomic": f"https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/{base_tech}",
            "elastic_explorer": f"https://elastic.github.io/detection-rules-explorer/?search={technique_id}",
            "car": f"https://car.mitre.org/analytics/?search={technique_id}"
        }
    }
    
    # Collect unique rules (avoid duplicates)
    sigma_seen = set()
    splunk_seen = set()
    
    # Search AttackRuleMap for matching technique
    for entry in attack_map:
        entry_tech = entry.get("tech_id", "")
        entry_guid = entry.get("atomic_attack_guid", "")
        
        # Match technique ID (exact or parent/child relationship)
        if entry_tech != technique_id and entry_tech != base_tech:
            if not (entry_tech.startswith(technique_id + ".") or technique_id.startswith(entry_tech + ".")):
                continue
            
        # If atomic_guid specified, filter to only that test
        if atomic_guid and entry_guid != atomic_guid:
            continue
        
        # Add atomic test info
        result["atomic_tests"].append({
            "guid": entry_guid,
            "name": entry.get("atomic_attack_name", ""),
            "platform": entry.get("platform", "")
        })
        
        # Collect Sigma rules
        for rule in entry.get("sigma_rules", []):
            rule_key = rule.get("rule_link", "")
            if rule_key and rule_key not in sigma_seen:
                sigma_seen.add(rule_key)
                result["sigma_rules"].append({
                    "name": rule.get("rule_name", ""),
                    "url": rule.get("rule_link", ""),
                    "atomic_test": entry.get("atomic_attack_name", ""),
                    "atomic_guid": entry_guid
                })
        
        # Collect Splunk rules
        for rule in entry.get("splunk_rules", []):
            rule_key = rule.get("rule_link", "")
            if rule_key and rule_key not in splunk_seen:
                splunk_seen.add(rule_key)
                result["splunk_rules"].append({
                    "name": rule.get("rule_name", ""),
                    "url": rule.get("rule_link", ""),
                    "atomic_test": entry.get("atomic_attack_name", ""),
                    "atomic_guid": entry_guid
                })
    
    # Add Elastic rules (from parsed TOML files)
    elastic_tech_rules = elastic_rules.get(technique_id, [])
    for rule in elastic_tech_rules:
        if isinstance(rule, dict):
            result["elastic_rules"].append({
                "name": rule.get("name", ""),
                "url": rule.get("url", ""),
                "description": rule.get("description", ""),
                "severity": rule.get("severity", ""),
                "risk_score": rule.get("risk_score", 0),
                "rule_id": rule.get("rule_id", ""),
                "tactic": rule.get("tactic", ""),
                "type": rule.get("type", "")
            })
    
    # Also check parent technique for Elastic rules
    if base_tech != technique_id:
        for rule in elastic_rules.get(base_tech, []):
            if isinstance(rule, dict):
                result["elastic_rules"].append({
                    "name": rule.get("name", ""),
                    "url": rule.get("url", ""),
                    "description": rule.get("description", ""),
                    "severity": rule.get("severity", ""),
                    "risk_score": rule.get("risk_score", 0),
                    "rule_id": rule.get("rule_id", ""),
                    "tactic": rule.get("tactic", ""),
                    "type": rule.get("type", ""),
                    "parent_technique": True
                })
    
    # Add summary counts
    result["summary"] = {
        "sigma_count": len(result["sigma_rules"]),
        "splunk_count": len(result["splunk_rules"]),
        "elastic_count": len(result["elastic_rules"]),
        "atomic_tests_count": len(result["atomic_tests"]),
        "total_rules": len(result["sigma_rules"]) + len(result["splunk_rules"]) + len(result["elastic_rules"])
    }
    
    return result


# =============================================================================
# API ROUTES
# =============================================================================

@app.route("/api/detection/<technique_id>")
def api_detection_rules(technique_id):
    """Get all detection rules for a MITRE technique"""
    rules = get_detection_rules_for_technique(technique_id)
    return jsonify(rules)


@app.route("/api/detection/<technique_id>/<atomic_guid>")
def api_detection_rules_for_atomic(technique_id, atomic_guid):
    """Get detection rules for a specific Atomic test"""
    rules = get_detection_rules_for_technique(technique_id, atomic_guid)
    return jsonify(rules)


@app.route("/api/detection/reload", methods=["POST"])
def api_detection_reload():
    """Reload detection rules from disk"""
    reload_detection_rules()
    attack_map = get_attack_rule_map()
    elastic_rules = get_elastic_rules()
    return jsonify({
        "status": "reloaded",
        "attack_rule_map_entries": len(attack_map),
        "elastic_techniques": len(elastic_rules)
    })


@app.route("/api/detection/stats")
def api_detection_stats():
    """Get detection rules statistics"""
    attack_map = get_attack_rule_map()
    elastic_rules = get_elastic_rules()
    
    # Count unique techniques and rules
    techniques = set()
    sigma_rules = set()
    splunk_rules = set()
    
    for entry in attack_map:
        techniques.add(entry.get("tech_id", ""))
        for rule in entry.get("sigma_rules", []):
            sigma_rules.add(rule.get("rule_link", ""))
        for rule in entry.get("splunk_rules", []):
            splunk_rules.add(rule.get("rule_link", ""))
    
    # Count Elastic rules
    elastic_rule_count = sum(len(rules) for rules in elastic_rules.values())
    
    return jsonify({
        "attack_rule_map": {
            "total_entries": len(attack_map),
            "unique_techniques": len(techniques),
            "unique_sigma_rules": len(sigma_rules),
            "unique_splunk_rules": len(splunk_rules)
        },
        "elastic_rules": {
            "unique_techniques": len(elastic_rules),
            "total_rules": elastic_rule_count
        }
    })
        

@app.route("/api/agents/<agent_id>/shutdown", methods=["POST"])
@login_required
def api_agent_shutdown(agent_id):
    """Send shutdown task to agent"""
    try:
        # Validate agent exists and is online
        agents = get_agent_status_list(store.list_agents())
        agent = next((a for a in agents if a.get('id') == agent_id), None)
        
        if not agent:
            return jsonify({"error": f"Agent {agent_id} not found"}), 404
        
        # Create shutdown task with all required fields
        task_id = f"shutdown-{uuid.uuid4().hex}"
        task = {
            "id": task_id,
            "type": "shutdown",
            "plan": "agent-shutdown",
            "params": "",
            "techniques": [],
            "commands": [],
            "file": None,
            "path": None
        }
        
        result = store.add_task(agent_id, task)
        
        print(f"[DEBUG] Shutdown task {task_id} queued for agent {agent_id}")
        
        return jsonify({"status": "queued", "task_id": task_id, "task": result})
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.run(host=CONFIG["HOST"], port=CONFIG["PORT"], debug=False, threaded=True)
