import uuid
import json
import threading
import time
import os
import base64
import re
import logging
from datetime import datetime, timedelta
from core.models import NeoC2DB
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

class AgentSession:
    def __init__(self, agent_id, ip_address, hostname, os_info, user, listener_id):
        self.id = agent_id
        self.ip_address = ip_address
        self.hostname = hostname
        self.os_info = os_info
        self.user = user
        self.listener_id = listener_id
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.checkin_interval = 30
        self.jitter = 5
        self.status = "active"
        self.tasks = []
        self.results = []
        self.lock = threading.Lock()
        
        self.interactive_mode = False
        self.interactive_task = None
        self.interactive_result = None
        self.interactive_event = threading.Event()
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'os_info': self.os_info,
            'user': self.user,
            'listener_id': self.listener_id,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'status': self.status,
            'pending_tasks': len(self.tasks),
            'interactive_mode': self.interactive_mode
        }

class AgentManager:
    def __init__(self, db, silent_mode=False, audit_logger=None):
        self.db = db
        self.agents = {}  # agent_id -> AgentSession
        self.running = False
        self.cleanup_thread = None
        self.result_monitor_thread = None
        self.silent_mode = silent_mode
        self.audit_logger = audit_logger  # Reference to audit logger
        self.logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.setup_db()
        
        self.agent_secret_keys = {}  # agent_id -> Fernet instance
        self._load_agent_secret_keys()
        
        self.interactive_result_callback = None
        
        self.interactive_agent_locks = {}  # agent_id -> {'operator': username, 'session_id': session_id, 'timestamp': datetime}
        
    
    def setup_db(self):
        self.db.execute('''
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                ip_address TEXT NOT NULL,
                hostname TEXT,
                os_info TEXT,
                user TEXT,
                listener_id TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active',
                checkin_interval INTEGER DEFAULT 30,
                jitter INTEGER DEFAULT 5,
                interactive_mode BOOLEAN DEFAULT 0,
                FOREIGN KEY (listener_id) REFERENCES listeners (id)
            )
        ''')
        
        self.db.execute('''
            CREATE TABLE IF NOT EXISTS agent_tasks (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                command TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                result TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                task_type TEXT DEFAULT 'queued',
                FOREIGN KEY (agent_id) REFERENCES agents (id)
            )
        ''')
        
        # Create indexes for better performance
        self.db.execute('CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)')
        self.db.execute('CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen)')
        self.db.execute('CREATE INDEX IF NOT EXISTS idx_agent_tasks_agent_id ON agent_tasks(agent_id)')
        self.db.execute('CREATE INDEX IF NOT EXISTS idx_agent_tasks_status ON agent_tasks(status)')
        
        try:
            self.db.execute("ALTER TABLE agents ADD COLUMN secret_key TEXT")
            self.logger.info("Database Migration: Added 'secret_key' column to agents table.")
        except Exception as e:
            if "duplicate column name" in str(e):
                pass  # Column already exists, which is fine
            else:
                self.logger.error(f"Error adding secret_key column: {str(e)}")
    
    def start(self):
        if self.running:
            return True
        
        try:
            self.logger.info("Starting Agent Manager...")
            self.running = True
            
            self._load_active_agents()
            
            self.cleanup_thread = threading.Thread(target=self._cleanup_worker)
            self.cleanup_thread.daemon = True
            self.cleanup_thread.start()
            
            self.result_monitor_thread = threading.Thread(target=self._result_monitor_worker)
            self.result_monitor_thread.daemon = True
            self.result_monitor_thread.start()
            
            self.logger.info("Agent Manager started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting Agent Manager: {str(e)}")
            return False
    
    def stop(self):
        if not self.running:
            return True
        
        try:
            self.logger.info("Stopping Agent Manager...")
            self.running = False
            
            # Stop cleanup thread
            if self.cleanup_thread and self.cleanup_thread.is_alive():
                self.cleanup_thread.join(timeout=5)
            
            # Stop result monitor thread
            if self.result_monitor_thread and self.result_monitor_thread.is_alive():
                self.result_monitor_thread.join(timeout=5)
            
            for agent_id, agent in self.agents.items():
                with agent.lock:
                    agent.status = "inactive"
                    self.db.execute('UPDATE agents SET status = ? WHERE id = ?', ('inactive', agent_id))
            
            self.logger.info("Agent Manager stopped successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping Agent Manager: {str(e)}")
            return False
    
    def _load_active_agents(self):
        try:
            agent_data = self.db.execute(
                "SELECT * FROM agents WHERE status = 'active'"
            ).fetchall()
        
            for data in agent_data:
                agent = AgentSession(
                    data['id'],
                    data['ip_address'],
                    data['hostname'],
                    data['os_info'],
                    data['user'],
                    data['listener_id']
                )
            
                # FIX: Use dictionary access instead of .get() for sqlite3.Row
                agent.interactive_mode = bool(data['interactive_mode']) if 'interactive_mode' in data.keys() else False
            
                task_data = self.db.execute(
                    "SELECT * FROM agent_tasks WHERE agent_id = ? AND status IN ('pending', 'sent')",
                    (data['id'],)
                ).fetchall()
            
                with agent.lock:
                    for task in task_data:
                        agent.tasks.append({
                            'id': task['id'],
                            'command': task['command'],
                            'status': task['status'],
                            'created_at': task['created_at']
                        })
            
                self.agents[data['id']] = agent
                
                secret_key = data['secret_key'] if data['secret_key'] else None
                if secret_key:
                    self.agent_secret_keys[data['id']] = Fernet(secret_key.encode())
        
            self.logger.info(f"Loaded {len(self.agents)} active agents from database")
        
        except Exception as e:
            self.logger.error(f"Error loading active agents: {str(e)}")
    
    def _cleanup_worker(self):
        while self.running:
            try:
                time.sleep(60)
                if self.running:
                    self._cleanup_inactive_agents()
            except Exception as e:
                self.logger.error(f"Error in agent cleanup worker: {str(e)}")
    
    def _result_monitor_worker(self):
        if not self.silent_mode:
            self.logger.info("Result monitor worker started")
        while self.running:
            try:
                time.sleep(30)
                if self.running:
                    self._check_agent_results()
            except Exception as e:
                if not self.silent_mode:
                    self.logger.error(f"Error in agent result monitor worker: {str(e)}")
    
    def _cleanup_inactive_agents(self):
        current_time = datetime.now()
        inactive_agents = []
        
        for agent_id, agent in self.agents.items():
            with agent.lock:
                if (current_time - agent.last_seen).total_seconds() > 300:
                    inactive_agents.append(agent_id)
                    agent.status = "inactive"
                    self.db.execute('UPDATE agents SET status = ? WHERE id = ?', ('inactive', agent_id))
        
        db_inactive_agents = self.db.execute(
            "SELECT id FROM agents WHERE status = 'active' AND last_seen < ?",
            (current_time - timedelta(minutes=5),)
        ).fetchall()
        
        for agent_data in db_inactive_agents:
            agent_id = agent_data['id']
            if agent_id in self.agents:
                with self.agents[agent_id].lock:
                    self.agents[agent_id].status = "inactive"
            self.db.execute('UPDATE agents SET status = ? WHERE id = ?', ('inactive', agent_id))
        
        if inactive_agents:
            self.logger.info(f"Cleaned up {len(inactive_agents)} inactive agents")
    
    def _check_agent_results(self):
        try:
            completed_tasks = self.db.execute('''
                SELECT * FROM agent_tasks 
                WHERE status = 'completed' AND result IS NOT NULL
                ORDER BY completed_at DESC
            ''').fetchall()
        
            if not completed_tasks:
                return

            if not self.silent_mode:
                self.logger.info(f"Found {len(completed_tasks)} completed task(s) with results")
        
            for task_row in completed_tasks:
                task_data = dict(task_row)

                agent_id = task_data.get('agent_id')
                task_id = task_data.get('id')
                
                if not agent_id or not task_id:
                    continue

                agent = self.agents.get(agent_id)
                if agent:
                    with agent.lock:
                        if not isinstance(agent.results, list):
                            agent.results = []
                        
                        result_exists = any(
                            isinstance(r, dict) and r.get('task_id') == task_id 
                            for r in agent.results
                        )
                        
                        if not result_exists:
                            agent.results.append({
                                'task_id': task_id,
                                'command': task_data.get('command'),
                                'result': task_data.get('result'),
                                'completed_at': task_data.get('completed_at')
                            })
                            if not self.silent_mode:
                                self.logger.info(f"Stored result for task {task_id} from agent {str(agent_id)[:8]}...")
                
        except Exception as e:
            if not self.silent_mode:
                self.logger.error(f"Error checking agent results: {str(e)}")

          
    def start_agent_result_monitor(self):
        # ignore
        # This method is called by the framework
        # The actual monitoring is handled by the _result_monitor_worker
        return True

    def _load_agent_secret_keys(self):
        try:
            agents_with_keys = self.db.execute(
                "SELECT id, secret_key FROM agents WHERE secret_key IS NOT NULL"
            ).fetchall()
            
            for agent_data in agents_with_keys:
                agent_id = agent_data['id']
                secret_key = agent_data['secret_key']
                if secret_key:
                    self.agent_secret_keys[agent_id] = Fernet(secret_key.encode())
                    
            self.logger.info(f"Loaded {len(self.agent_secret_keys)} agent secret keys into memory")
        except Exception as e:
            self.logger.error(f"Error loading agent secret keys: {str(e)}")

    def _generate_secret_key(self):
        return Fernet.generate_key().decode()

    def _encrypt_data(self, agent_id, data):
        try:
            if not isinstance(data, str):
                data = json.dumps(data)
            
            if agent_id not in self.agent_secret_keys:
                agent_data = self.db.execute(
                    "SELECT secret_key FROM agents WHERE id = ?", (agent_id,)
                ).fetchone()
                
                if agent_data and agent_data['secret_key']:
                    self.agent_secret_keys[agent_id] = Fernet(agent_data['secret_key'].encode())
                else:
                    self.logger.error(f"No secret key found for agent {agent_id}")
                    return None
            
            # Encrypt the data
            encrypted_data = self.agent_secret_keys[agent_id].encrypt(data.encode())
            return base64.b64encode(encrypted_data).decode()
            
        except Exception as e:
            self.logger.error(f"Encryption error for agent {agent_id}: {str(e)}")
            return None

    def _decrypt_data(self, agent_id, encrypted_data):
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            
            if agent_id not in self.agent_secret_keys:
                agent_data = self.db.execute(
                    "SELECT secret_key FROM agents WHERE id = ?", (agent_id,)
                ).fetchone()
                
                if agent_data and agent_data['secret_key']:
                    self.agent_secret_keys[agent_id] = Fernet(agent_data['secret_key'].encode())
                else:
                    self.logger.error(f"No secret key found for agent {agent_id}")
                    return None
            
            decrypted_data = self.agent_secret_keys[agent_id].decrypt(encrypted_bytes)
            return decrypted_data.decode()
            
        except Exception as e:
            self.logger.error(f"Decryption error for agent {agent_id}: {str(e)}")
            return None

    def _validate_agent_identity(self, agent_id, provided_secret_key):
        try:
            agent_data = self.db.execute(
                "SELECT secret_key FROM agents WHERE id = ?", (agent_id,)
            ).fetchone()
            
            if not agent_data or not agent_data['secret_key']:
                self.logger.warning(f"No secret key found in DB for agent {agent_id}")
                return False
            
            stored_secret_key = agent_data['secret_key']
            
            # Compare the keys securely
            return secrets.compare_digest(provided_secret_key, stored_secret_key)
            
        except Exception as e:
            self.logger.error(f"Error validating agent identity {agent_id}: {str(e)}")
            return False
    
    def register_agent(self, ip_address, hostname, os_info, user, listener_id, agent_id=None):
        # Use provided agent_id or generate new one
        if not agent_id:
            agent_id = str(uuid.uuid4())
    
        # FIX: Check if agent already exists in database (not just in memory)
        existing_agent = self.get_agent(agent_id)
        if existing_agent:
            self.logger.debug(f"Agent {agent_id} already exists, updating last_seen")
            # Update last_seen for existing agent
            with existing_agent.lock:
                existing_agent.last_seen = datetime.now()
                
                # Update in database
                self.db.execute('UPDATE agents SET ip_address = ?, hostname = ?, os_info = ?, user = ?, listener_id = ?, last_seen = ? WHERE id = ?',
                               (ip_address, hostname, os_info, user, listener_id, existing_agent.last_seen, agent_id))
                
                # Log agent reconnection event
                if self.audit_logger:
                    self.audit_logger.log_event(
                        user_id="system",  # System event
                        action="agent.reconnect",
                        resource_type="agent",
                        resource_id=agent_id,
                        details=json.dumps({
                            "ip_address": ip_address,
                            "hostname": hostname,
                            "os_info": os_info,
                            "user": user,
                            "listener_id": listener_id
                        }),
                        ip_address=ip_address
                    )
            return agent_id
    
        existing_agent_data = self.db.execute(
            "SELECT secret_key FROM agents WHERE id = ?", (agent_id,)
        ).fetchone()
        
        if existing_agent_data and existing_agent_data['secret_key']:
            secret_key = existing_agent_data['secret_key']
            self.logger.debug(f"Using existing secret key for agent {agent_id}")
        else:
            secret_key = self._generate_secret_key()
            self.logger.debug(f"Generated new secret key for agent {agent_id}")
        
        agent = AgentSession(agent_id, ip_address, hostname, os_info, user, listener_id)

        with agent.lock:
            self.agents[agent_id] = agent

            try:
                existing_check = self.db.execute(
                    "SELECT id FROM agents WHERE id = ?", (agent_id,)
                ).fetchone()

                if existing_check:
                    self.db.execute('''
                        UPDATE agents
                        SET ip_address = ?, hostname = ?, os_info = ?, user = ?, listener_id = ?,
                            last_seen = ?, secret_key = ?
                        WHERE id = ?
                    ''', (ip_address, hostname, os_info, user, listener_id, agent.last_seen, secret_key, agent_id))
                else:
                    self.db.execute('''
                        INSERT INTO agents (id, ip_address, hostname, os_info, user, listener_id, first_seen, last_seen, interactive_mode, secret_key)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (agent_id, ip_address, hostname, os_info, user, listener_id, agent.first_seen, agent.last_seen, 0, secret_key))

                self.logger.info(f"Agent registered: {agent_id} from {ip_address}")

                self.agent_secret_keys[agent_id] = Fernet(secret_key.encode())

                if self.audit_logger:
                    self.audit_logger.log_event(
                        user_id="system",  # System event
                        action="agent.register",
                        resource_type="agent",
                        resource_id=agent_id,
                        details=json.dumps({
                            "ip_address": ip_address,
                            "hostname": hostname,
                            "os_info": os_info,
                            "user": user,
                            "listener_id": listener_id
                        }),
                        ip_address=ip_address
                    )

                # Notify callbacks about the new agent registration (only for new agents, not reconnections)
                if not existing_check:
                    self._notify_agent_registration(agent_id, ip_address, hostname, os_info, user, listener_id)

            except Exception as e:
                self.logger.error(f"Error registering agent {agent_id}: {str(e)}")
                raise e

        return agent_id
        
    def get_agent(self, agent_id, update_ip=None):
        agent = self.agents.get(agent_id)

        if agent:
            with agent.lock:
                agent.last_seen = datetime.now()
                if update_ip and agent.ip_address != update_ip:
                    agent.ip_address = update_ip
                    self.db.execute('UPDATE agents SET last_seen = ?, ip_address = ? WHERE id = ?', (agent.last_seen, update_ip, agent_id))
                else:
                    self.db.execute('UPDATE agents SET last_seen = ? WHERE id = ?', (agent.last_seen, agent_id))
                    
                if agent_id not in self.agent_secret_keys:
                    agent_data = self.db.execute(
                        "SELECT secret_key FROM agents WHERE id = ?", (agent_id,)
                    ).fetchone()
                    if agent_data and agent_data['secret_key']:
                        self.agent_secret_keys[agent_id] = Fernet(agent_data['secret_key'].encode())
            return agent

        try:
            agent_data = self.db.execute(
                "SELECT * FROM agents WHERE id = ?",
                (agent_id,)
            ).fetchone()
    
            if agent_data:
                # Determine IP address to use - either from DB or provided update
                ip_address = agent_data['ip_address']
                if update_ip:
                    ip_address = update_ip  # Use the provided IP for this check-in if specified
                    # Update the database record with the new IP
                    self.db.execute('UPDATE agents SET ip_address = ? WHERE id = ?', (update_ip, agent_id))
                
                agent = AgentSession(
                    agent_data['id'],
                    ip_address,  # Use the potentially updated IP
                    agent_data['hostname'],
                    agent_data['os_info'],
                    agent_data['user'],
                    agent_data['listener_id']
                )
        
                agent.first_seen = datetime.fromisoformat(agent_data['first_seen']) if isinstance(agent_data['first_seen'], str) else agent_data['first_seen']
                agent.last_seen = datetime.now()
                agent.status = agent_data['status']
                agent.checkin_interval = agent_data['checkin_interval']
                agent.jitter = agent_data['jitter']
            
                # FIX: Use dictionary access instead of .get() for sqlite3.Row
                agent.interactive_mode = bool(agent_data['interactive_mode']) if 'interactive_mode' in agent_data.keys() else False
        
                # Load pending tasks
                task_data = self.db.execute(
                    "SELECT * FROM agent_tasks WHERE agent_id = ? AND status IN ('pending', 'sent') ORDER BY created_at ASC",
                    (agent_id,)
                ).fetchall()
        
                with agent.lock:
                    for task in task_data:
                        agent.tasks.append({
                            'id': task['id'],
                            'command': task['command'],
                            'status': task['status'],
                            'created_at': task['created_at']
                        })
        
                # Add to in-memory dictionary
                self.agents[agent_id] = agent
                
                # Load the agent's secret key into memory cache if it exists
                secret_key = agent_data['secret_key'] if agent_data['secret_key'] else None
                if secret_key:
                    self.agent_secret_keys[agent_id] = Fernet(secret_key.encode())
        
                if update_ip:
                    self.db.execute('UPDATE agents SET last_seen = ?, ip_address = ? WHERE id = ?', (agent.last_seen, update_ip, agent_id))
                else:
                    self.db.execute('UPDATE agents SET last_seen = ? WHERE id = ?', (agent.last_seen, agent_id))
        
                self.logger.debug(f"Loaded agent {agent_id[:8]}... from database")
                return agent
        except Exception as e:
            self.logger.error(f"Error loading agent {agent_id}: {str(e)}")
        return None
    
    def _is_script_command(self, command):
        powershell_patterns = [
            r'\$[a-zA-Z_]\w*',  # PowerShell variables
            r'Set-ItemProperty',  # Registry operations
            r'New-Object\s+-ComObject',  # COM object creation
            r'Invoke-RestMethod',  # PowerShell web requests
            r'Invoke-Expression',  # PowerShell execution
            r'Get-Service',  # Windows service operations
            r'New-ScheduledTask',  # Scheduled task operations
            r'Copy-Item',  # File operations
            r'Test-Path',  # Path checking
            r'Get-Random',  # Random functions
            r'Write-Output',  # Output functions
            r'Add-Type',  # Type definitions
            r'Start-Process',  # Process operations
        ]
        
        bash_patterns = [
            r'\${?\w+\}?',  # Shell variables
            r'crontab',  # Cron operations
            r'chmod',  # File permissions
            r'launchctl',  # macOS launch services
            r'systemctl',  # Linux system control
            r'ps aux',  # Process listing
            r'grep',  # Text filtering
            r'cat\s+<<',  # Here documents
            r'^#!/',  # Shebang lines
        ]
        
        python_patterns = [
            r'^import\s+\w+',  # Import statements at start of line
            r'^from\s+\w+\s+import',  # From import statements at start of line
            r'def\s+\w+\s*\(',  # Function definitions
            r'class\s+\w+\s*:',  # Class definitions
            r'if\s+__name__\s*==\s*[\'\"]__main__[\'\"]',  # Main guard
            r'print\s*\(',  # Print function calls
            r'if\s+.*:',  # If statements
            r'for\s+.*:',  # For loops
            r'while\s+.*:',  # While loops
            r'with\s+.*:',  # With statements
            r'try\s*:',  # Try blocks
            r'[\'\"]\s*%\s*',  # String formatting
            r'f[\'\"].*{.*}.*[\'\"]',  # f-strings
        ]
        
        command_lower = command.lower()
        for pattern in powershell_patterns + bash_patterns + python_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        
        if ('{' in command and '}' in command and 
            ('#' in command or '//' in command or '#' in command.split('\n')[0] if command.split('\n') else False)):
            return True
            
        return False

    def add_task(self, agent_id, command):
        agent = self.get_agent(agent_id)
        if not agent:
            self.logger.warning(f"Agent {agent_id} not found")
            return {'success': False, 'error': f"Agent {agent_id} not found"}
    
        processed_command = command
        if self._is_script_command(command):
            encoded_script = base64.b64encode(command.encode('utf-8')).decode('utf-8')
            processed_command = f"module {encoded_script}"
            self.logger.info(f"Detected script command, encoded as module: {command[:50]}...")

        try:
            cursor = self.db.execute('''
                INSERT INTO agent_tasks (agent_id, command, status, created_at, task_type)
                VALUES (?, ?, ?, ?, ?)
            ''', (agent_id, processed_command, 'pending', datetime.now(), 'queued'))
            
            new_task_id = cursor.lastrowid
            self.logger.info(f"Task {new_task_id} added for agent {agent_id}: {processed_command[:50]}...")
            
            with agent.lock:
                agent.tasks.append({
                    'id': new_task_id,
                    'command': processed_command,
                    'status': 'pending',
                    'created_at': datetime.now()
                })
            
            if self.audit_logger:
                self.audit_logger.log_event(
                    user_id="system",  # System event
                    action="task.created",
                    resource_type="agent_task",
                    resource_id=new_task_id,
                    details=json.dumps({
                        "agent_id": agent_id,
                        "command": processed_command,
                        "task_type": "queued"
                    }),
                    ip_address=agent.ip_address if agent else "unknown"
                )
            
            # Return a dictionary instead of just the number
            return {'success': True, 'task_id': new_task_id}
        except Exception as e:
            self.logger.error(f"Failed to add task to DB: {e}")
            return {'success': False, 'error': str(e)}
        
    def get_tasks(self, agent_id):
        agent = self.get_agent(agent_id)
        if not agent:
            return []

        db_tasks = self.db.execute('''
            SELECT * FROM agent_tasks 
            WHERE agent_id = ? AND status = 'pending'
            ORDER BY created_at ASC
        ''', (agent_id,)).fetchall()
    
        pending_tasks = []
    
        with agent.lock:
            for task_row in db_tasks:
                db_task_status = self.db.execute(
                    "SELECT status FROM agent_tasks WHERE id = ?", (task_row['id'],)
                ).fetchone()
                
                if db_task_status and db_task_status['status'] == 'sent':
                    continue  # Task was already sent, skip it
                
                encrypted_command = self._encrypt_data(agent_id, task_row['command'])
                if encrypted_command is None:
                    self.logger.error(f"Failed to encrypt task {task_row['id']} for agent {agent_id}")
                    continue
                    
                task = {
                    'id': task_row['id'],
                    'command': encrypted_command,  # Now encrypted
                    'status': 'sent',  # Mark as sent when retrieved
                    'created_at': task_row['created_at']
                }
                pending_tasks.append(task)
            
                # Mark as sent in database
                self.db.execute('UPDATE agent_tasks SET status = ? WHERE id = ?', ('sent', task['id']))
            
                # Update in-memory list if task exists there
                found = False
                for mem_task in agent.tasks:
                    if mem_task['id'] == task['id']:
                        mem_task['status'] = 'sent'
                        found = True
                        break
            
                # Add to memory if not there
                if not found:
                    agent.tasks.append(task)
        
            return pending_tasks
    
    
    
    def add_result(self, agent_id, task_id, result):
        import os
        import base64
        import time
        from datetime import datetime
        agent = self.get_agent(agent_id)  # Changed from self.agents.get()
        if not agent:
            self.logger.warning(f"Agent {agent_id} not found")
            return False

        decrypted_result = self._decrypt_data(agent_id, result)
        if decrypted_result is not None:
            processed_result = decrypted_result
            self.logger.debug(f"Successfully decrypted result for task {task_id} from agent {agent_id}")
        else:
            processed_result = result
            self.logger.debug(f"Result for task {task_id} from agent {agent_id} appears to be unencrypted, using as-is")

        # Check the original task type to determine if this is a download task
        original_task = self.db.execute(
            "SELECT command, task_type FROM agent_tasks WHERE id = ?", (task_id,)
        ).fetchone()

        # Check if this is a download task
        is_download_task = False
        original_command = None
        if original_task:
            original_command = original_task['command']
            if original_task['task_type'] == 'download' or (original_task['command'] and original_task['command'].startswith('download ')):
                is_download_task = True

        # If it's a download task, process the base64 result and save to loot directory
        if is_download_task and processed_result:
            try:
                # Create loot directory if it doesn't exist
                loot_dir = os.path.join(os.getcwd(), "loot")
                os.makedirs(loot_dir, exist_ok=True)

                # Extract original file path to create a meaningful filename
                original_file_path = "unknown_file"
                if original_command and original_command.startswith('download '):
                    original_file_path = original_command[9:]  # Remove 'download ' prefix
                    # Sanitize the path for use in filename
                    original_file_path = os.path.basename(original_file_path).replace('/', '_').replace('\\', '_')

                # Generate a timestamp-based filename
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                file_extension = os.path.splitext(original_file_path)[1] if os.path.splitext(original_file_path)[1] else ".dat"

                # If the result looks like base64, try to decode it
                if processed_result.startswith('[ERROR]') or processed_result.startswith('[ERROR'):
                    # This is an error message, not base64 content
                    loot_filename = f"download_error_{timestamp}_{original_file_path.replace('.', '_')}.txt"
                    loot_path = os.path.join(loot_dir, loot_filename)
                    with open(loot_path, 'w') as f:
                        f.write(processed_result)
                    loot_result_msg = f"Download error saved to: {loot_path}"
                else:
                    # Try to decode as base64
                    try:
                        decoded_data = base64.b64decode(processed_result)
                        loot_filename = f"download_{timestamp}_{original_file_path}"
                        loot_path = os.path.join(loot_dir, loot_filename)

                        with open(loot_path, 'wb') as f:
                            f.write(decoded_data)

                        loot_result_msg = f"Downloaded file saved to: {loot_path} ({len(decoded_data)} bytes)"
                    except Exception:
                        # If decoding fails, save as-is
                        loot_filename = f"download_raw_{timestamp}_{original_file_path.replace('.', '_')}.txt"
                        loot_path = os.path.join(loot_dir, loot_filename)
                        with open(loot_path, 'w') as f:
                            f.write(processed_result)
                        loot_result_msg = f"Raw download content saved to: {loot_path}"

                # Update the result to indicate where the file was saved
                processed_result = f"[DOWNLOAD COMPLETED] {loot_result_msg}\nOriginal remote path: {original_file_path}\nResult was automatically saved to prevent base64 display in results."

            except Exception as e:
                self.logger.error(f"Error processing download task result: {str(e)}")
                # Keep original behavior if there's an error processing the download

        existing_task = self.db.execute(
            "SELECT status FROM agent_tasks WHERE id = ?", (task_id,)
        ).fetchone()

        if existing_task and existing_task['status'] == 'completed':
            self.logger.info(f"[!] Task {task_id} is already marked as completed, skipping duplicate processing")
            return True  # Return True to indicate it's handled (even if duplicate)

        with agent.lock:
            for task in agent.tasks:
                if task['id'] == task_id:
                    task['status'] = 'completed'
                    task['result'] = processed_result
                    task['completed_at'] = datetime.now()

                    self.db.execute('''
                        UPDATE agent_tasks SET status = ?, result = ?, completed_at = ?
                        WHERE id = ?
                    ''', ('completed', processed_result, task['completed_at'], task_id))

                    if self.audit_logger:
                        self.audit_logger.log_event(
                            user_id="system",  # System event
                            action="task.completed",
                            resource_type="agent_task",
                            resource_id=task_id,
                            details=json.dumps({
                                "agent_id": agent_id,
                                "command": task['command'],
                                "result_summary": f"Result length: {len(str(processed_result))} chars"
                            }),
                            ip_address=agent.ip_address if agent else "unknown"
                        )

                    self.logger.info(f"Result received from agent {agent_id} for task {task_id}")
                    return True

            try:
                self.db.execute('''
                    UPDATE agent_tasks SET status = ?, result = ?, completed_at = ?
                    WHERE id = ? AND agent_id = ?
                ''', ('completed', processed_result, datetime.now(), task_id, agent_id))

                if self.audit_logger:
                    self.audit_logger.log_event(
                        user_id="system",  # System event
                        action="task.completed",
                        resource_type="agent_task",
                        resource_id=task_id,
                        details=json.dumps({
                            "agent_id": agent_id,
                            "result_summary": f"Result length: {len(str(processed_result))} chars",
                            "source": "database_only"
                        }),
                        ip_address="unknown"  # We don't have agent object here
                    )

                self.logger.info(f"Result received from agent {agent_id} for task {task_id} (DB only)")
                return True
            except Exception as e:
                self.logger.error(f"Error updating task result: {str(e)}")
                return False

    def add_upload_task(self, agent_id, local_path, remote_path):
        agent = self.get_agent(agent_id)
        if not agent:
            error_msg = f"Agent {agent_id} not found"
            self.logger.error(f"{error_msg}")
            return {'success': False, 'error': error_msg}

        if not os.path.exists(local_path):
            error_msg = f"Local file not found on server: {local_path}"
            self.logger.error(f"{error_msg}")
            return {'success': False, 'error': error_msg}

        try:
            with open(local_path, "rb") as f:
                file_content = f.read()
            encoded_content = base64.b64encode(file_content).decode('utf-8')
            command = f"upload {remote_path} {encoded_content}"
        
            with agent.lock:
                cursor = self.db.execute('''
                    INSERT INTO agent_tasks (agent_id, command, status, created_at, task_type)
                    VALUES (?, ?, ?, ?, ?)
                ''', (agent_id, command, 'pending', datetime.now(), 'upload'))
                new_task_id = cursor.lastrowid
                agent.tasks.append({
                    'id': new_task_id,
                    'command': command,
                    'status': 'pending',
                    'created_at': datetime.now()
                })
    
            self.logger.info(f"Upload task {new_task_id} for '{os.path.basename(local_path)}' -> '{remote_path}' added for agent {agent_id[:8]}...")
            return {'success': True, 'task_id': new_task_id}

        except Exception as e:
            error_msg = f"An error occurred during upload task preparation: {e}"
            self.logger.info(f"[-] {error_msg}")
            return {'success': False, 'error': error_msg}


    def add_download_task(self, agent_id, remote_path):
        agent = self.get_agent(agent_id)
        if not agent:
            error_msg = f"Agent {agent_id} not found"
            self.logger.info(f"[-] {error_msg}")
            return {'success': False, 'error': error_msg}

        command = f"download {remote_path}"
        try:
            with agent.lock:
                cursor = self.db.execute('''
                    INSERT INTO agent_tasks (agent_id, command, status, created_at, task_type)
                    VALUES (?, ?, ?, ?, ?)
                ''', (agent_id, command, 'pending', datetime.now(), 'download'))
                new_task_id = cursor.lastrowid
                agent.tasks.append({
                    'id': new_task_id,
                    'command': command,
                    'status': 'pending',
                    'created_at': datetime.now()
                })
            self.logger.info(f"[+] Download task {new_task_id} for '{remote_path}' added for agent {agent_id[:8]}...")
            return {'success': True, 'task_id': new_task_id}
        except Exception as e:
            error_msg = f"An error occurred during download task preparation: {e}"
            self.logger.info(f"[-] {error_msg}")
            return {'success': False, 'error': error_msg}
    
    # ===== INTERACTIVE MODE METHODS =====
    def try_acquire_interactive_lock(self, agent_id, username, session_id):
        if self.is_agent_locked_interactively(agent_id):
            lock_info = self.get_interactive_lock_info(agent_id)
            if lock_info and lock_info['operator'] != username:
                return {
                    'success': False, 
                    'error': f"Agent {agent_id} is currently in interactive mode with operator: {lock_info['operator']}",
                    'locked_by': lock_info['operator'],
                    'session_id': lock_info['session_id']
                }
        
        lock_result = self.acquire_interactive_lock(agent_id, username, session_id)
        if not lock_result['success']:
            return lock_result
        
        enter_result = self.enter_interactive_mode(agent_id)
        if not enter_result:
            self.release_interactive_lock(agent_id)
            return {'success': False, 'error': 'Failed to enter interactive mode with agent'}
        
        return {'success': True}

    def enter_interactive_mode(self, agent_id):
        """Enter interactive mode with an agent"""
        agent = self.get_agent(agent_id)
        if not agent:
            self.logger.info(f"[-] Agent {agent_id} not found")
            return False

        with agent.lock:
            agent.interactive_mode = True
            agent.interactive_task = None
            agent.interactive_result = None
            agent.interactive_event.clear()
        
            # PERSIST TO DATABASE
            self.db.execute(
                'UPDATE agents SET interactive_mode = ? WHERE id = ?', 
                (1, agent_id)  # 1 for True, 0 for False
            )

        if self.audit_logger:
            self.audit_logger.log_event(
                user_id="system",  # System event
                action="interactive_mode.entered",
                resource_type="agent",
                resource_id=agent_id,
                details=json.dumps({
                    "agent_id": agent_id,
                    "ip_address": agent.ip_address if agent else "unknown"
                }),
                ip_address=agent.ip_address if agent else "unknown"
            )

        self.logger.info(f"[+] Entered interactive mode with agent {agent_id}")
        return True

    def exit_interactive_mode(self, agent_id):
        """Exit interactive mode with an agent"""
        agent = self.get_agent(agent_id)
        if not agent:
            self.logger.info(f"[-] Agent {agent_id} not found")
            return False

        with agent.lock:
            agent.interactive_mode = False
            agent.interactive_task = None
            agent.interactive_result = None
            agent.interactive_event.set()  # Unblock any waiting commands
        
            self.db.execute(
                'UPDATE agents SET interactive_mode = ? WHERE id = ?', 
                (0, agent_id)  # 1 for True, 0 for False
            )

        self.release_interactive_lock(agent_id)
        
        if self.audit_logger:
            self.audit_logger.log_event(
                user_id="system",  # System event
                action="interactive_mode.exited",
                resource_type="agent",
                resource_id=agent_id,
                details=json.dumps({
                    "agent_id": agent_id,
                    "ip_address": agent.ip_address if agent else "unknown"
                }),
                ip_address=agent.ip_address if agent else "unknown"
            )

        self.logger.info(f"[+] Exited interactive mode with agent {agent_id}")
        return True

    def send_interactive_command(self, agent_id, command, timeout=120):
        """Send a command in interactive mode and wait for result"""
        agent = self.get_agent(agent_id)
        if not agent:
            return None, "Agent not found"

        if not agent.interactive_mode:
            return None, "Agent not in interactive mode"

        try:
            cursor = self.db.execute('''
                INSERT INTO agent_tasks (agent_id, command, status, created_at, task_type)
                VALUES (?, ?, ?, ?, ?)
            ''', (agent_id, command, 'pending', datetime.now(), 'interactive'))
            
            task_id = cursor.lastrowid # Get the real, numeric ID from the database
            self.logger.info(f"[+] Interactive task {task_id} written to DB")

        except Exception as e:
            self.logger.info(f"[-] Failed to write interactive task to DB: {e}")
            return None, f"Failed to create task: {e}"

        if self.audit_logger:
            self.audit_logger.log_event(
                user_id="system",  # System event
                action="interactive_task.created",
                resource_type="agent_task",
                resource_id=task_id,
                details=json.dumps({
                    "agent_id": agent_id,
                    "command": command,
                    "task_type": "interactive"
                }),
                ip_address=agent.ip_address if agent else "unknown"
            )

        with agent.lock:
            agent.interactive_task = {
                'id': task_id, # Use the real ID
                'command': command,
                'created_at': datetime.now()
            }
            agent.interactive_result = None
            agent.interactive_event.clear()

        import time
        start_time = time.time()
        poll_interval = 2  # Poll every 2 seconds
    
        while time.time() - start_time < timeout:
            if agent.interactive_event.wait(timeout=poll_interval):
                with agent.lock:
                    result = agent.interactive_result
                    agent.interactive_task = None
                    agent.interactive_result = None
                return result, None
        
            try:
                task_row = self.db.execute(
                    "SELECT status, result FROM agent_tasks WHERE id = ? AND agent_id = ?",
                    (task_id, agent_id)
                ).fetchone()
            
                if task_row and task_row['status'] == 'completed':
                    result = task_row['result']
                    with agent.lock:
                        agent.interactive_task = None
                        agent.interactive_result = None
                    self.logger.info(f"[+] Got interactive result from DB polling")
                    return result, None
            except Exception as e:
                self.logger.info(f"[-] Error polling DB for result: {e}")
    
        with agent.lock:
            agent.interactive_task = None
        return None, f"Timeout waiting for agent response ({timeout}s)"

    def get_interactive_task(self, agent_id):
        agent = self.get_agent(agent_id)
        if not agent or not agent.interactive_mode:
            return None

        with agent.lock:
            if agent.interactive_task:
                return agent.interactive_task
    
        try:
            interactive_task_row = self.db.execute('''
                SELECT * FROM agent_tasks 
                WHERE agent_id = ? 
                  AND task_type = 'interactive' 
                  AND status IN ('pending', 'sent')
                ORDER BY created_at ASC
                LIMIT 1
            ''', (agent_id,)).fetchone()
        
            if interactive_task_row:
                if hasattr(interactive_task_row, 'keys'):  # sqlite3.Row object
                    task_data = dict(interactive_task_row)
                else:
                    task_data = interactive_task_row
                
                task = {
                    'id': task_data['id'],
                    'command': task_data['command'],
                    'created_at': task_data['created_at']
                }
            
                with agent.lock:
                    agent.interactive_task = task
            
                self.logger.info(f"[+] Loaded interactive task from DB for agent {agent_id}: {task['command'][:50]}...")
                return task
        except Exception as e:
            self.logger.info(f"[-] Error checking DB for interactive task: {e}")
    
        return None

    def set_interactive_result(self, agent_id, task_id, result):
        agent = self.get_agent(agent_id)
        if not agent:
            self.logger.info(f"[-] Agent {agent_id} not found")
            return False

        decrypted_result = self._decrypt_data(agent_id, result)
        if decrypted_result is not None:
            processed_result = decrypted_result
            self.logger.debug(f"Successfully decrypted interactive result for task {task_id} from agent {agent_id}")
        else:
            processed_result = result
            self.logger.debug(f"Interactive result for task {task_id} from agent {agent_id} appears to be unencrypted, using as-is")

        existing_task = self.db.execute(
            "SELECT status FROM agent_tasks WHERE id = ?", (task_id,)
        ).fetchone()
        
        if existing_task and existing_task['status'] == 'completed':
            self.logger.info(f"[!] Task {task_id} is already marked as completed, skipping duplicate processing")
            return True  # Return True to indicate it's handled (even if duplicate)

        try:
            cursor = self.db.execute('''
                UPDATE agent_tasks SET status = ?, result = ?, completed_at = ?
                WHERE id = ?
            ''', ('completed', processed_result, datetime.now(), task_id))
            
            if cursor.rowcount > 0:
                self.logger.info(f"[+] Interactive result for task {str(task_id)[:8]}... saved to DB")
            else:
                self.logger.info(f"[-] No task found with id {str(task_id)[:8]}... to update")
                return False
        except Exception as e:
            self.logger.info(f"[-] Failed to save interactive result to DB: {e}")
            return False

        if self.audit_logger:
            task_command = self.db.execute(
                "SELECT command FROM agent_tasks WHERE id = ?", (task_id,)
            ).fetchone()
            command = task_command['command'] if task_command else "unknown"
            
            self.audit_logger.log_event(
                user_id="system",  # System event
                action="interactive_task.completed",
                resource_type="agent_task",
                resource_id=task_id,
                details=json.dumps({
                    "agent_id": agent_id,
                    "command": command,
                    "result_summary": f"Result length: {len(str(processed_result))} chars",
                    "task_type": "interactive"
                }),
                ip_address=agent.ip_address if agent else "unknown"
            )

        # Broadcast the result to remote CLI if callback is registered
        if self.interactive_result_callback:
            try:
                self.interactive_result_callback(agent_id, task_id, processed_result)
                self.logger.info(f"[+] Interactive result broadcasted via callback for agent {agent_id}, task {task_id}")
            except Exception as e:
                self.logger.error(f"[-] Error broadcasting interactive result: {str(e)}")

        with agent.lock:
            if agent.interactive_task and agent.interactive_task['id'] == task_id:
                agent.interactive_result = processed_result
                agent.interactive_event.set()
                self.logger.info(f"[+] Interactive result received and signaled for agent {agent_id}")
                return True
            else:
                self.logger.info(f"[+] Interactive result saved to DB (no in-memory task to signal)")
                return True

    def is_interactive_task(self, agent_id, task_id):
        agent = self.get_agent(agent_id)
        if not agent:
            return False

        with agent.lock:
            if agent.interactive_task and agent.interactive_task['id'] == task_id:
                return True
    
        try:
            task_row = self.db.execute(
                "SELECT task_type FROM agent_tasks WHERE id = ? AND agent_id = ?",
                (task_id, agent_id)
            ).fetchone()
        
            if task_row:
                if hasattr(task_row, 'keys'):  # sqlite3.Row object
                    task_data = dict(task_row)
                    task_type = task_data.get('task_type')
                else:
                    # Handle case where fetchone returns an int or other type
                    task_type = task_row if isinstance(task_row, str) else task_row[0] if hasattr(task_row, '__getitem__') else None
                
                if task_type == 'interactive':
                    self.logger.info(f"[DEBUG] Task {str(task_id)[:8]}... identified as interactive from DB")
                    return True
        except Exception as e:
            self.logger.info(f"[-] Error checking task type in DB: {e}")
    
        return False
    
    # ===== END INTERACTIVE MODE METHODS =====
    
    def get_agent_results(self, agent_id, limit=50):
        """Get results for a specific agent from database"""
        try:
            results = self.db.execute('''
                SELECT * FROM agent_tasks 
                WHERE agent_id = ? AND status = 'completed' AND result IS NOT NULL
                ORDER BY completed_at DESC
                LIMIT ?
            ''', (agent_id, limit)).fetchall()
        
            result_list = []
            for r in results:
                # Convert sqlite3.Row to dict for proper access
                row_dict = dict(r)
                result_list.append({
                    'task_id': row_dict['id'],
                    'command': row_dict['command'],
                    'result': row_dict['result'],
                    'created_at': row_dict['created_at'],
                    'completed_at': row_dict['completed_at'],
                    'task_type': row_dict.get('task_type', 'queued')
                })
        
            return result_list
        except Exception as e:
            self.logger.info(f"[-] Error getting agent results: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    def get_all_results(self, limit=100):
        try:
            results = self.db.execute('''
                SELECT agent_tasks.*, agents.hostname, agents.user 
                FROM agent_tasks 
                LEFT JOIN agents ON agent_tasks.agent_id = agents.id
                WHERE agent_tasks.status = 'completed' AND agent_tasks.result IS NOT NULL
                ORDER BY agent_tasks.completed_at DESC
                LIMIT ?
            ''', (limit,)).fetchall()
        
            result_list = []
            for r in results:
                row_dict = dict(r)
                result_list.append({
                    'task_id': row_dict['id'],
                    'agent_id': row_dict['agent_id'],
                    'hostname': row_dict.get('hostname', 'unknown'),
                    'user': row_dict.get('user', 'unknown'),
                    'command': row_dict['command'],
                    'result': row_dict['result'],
                    'created_at': row_dict['created_at'],
                    'completed_at': row_dict['completed_at'],
                    'task_type': row_dict.get('task_type', 'queued')
                })
        
            return result_list
        except Exception as e:
            self.logger.info(f"[-] Error getting all results: {str(e)}")
            import traceback
            traceback.print_exc()
            return []
    
    def list_agents(self, include_inactive=False):
        try:
            if include_inactive:
                query = "SELECT * FROM agents ORDER BY last_seen DESC"
                agents_data = self.db.execute(query).fetchall()
            else:
                query = "SELECT * FROM agents WHERE status = 'active' ORDER BY last_seen DESC"
                agents_data = self.db.execute(query).fetchall()
    
            agent_list = []
            for data in agents_data:
                agent_dict = {
                    'id': data['id'],
                    'ip_address': data['ip_address'],
                    'hostname': data['hostname'],
                    'os_info': data['os_info'],
                    'user': data['user'],
                    'listener_id': data['listener_id'],
                    'first_seen': data['first_seen'],
                    'last_seen': data['last_seen'],
                    'status': data['status'],
                    'pending_tasks': 0,  # Will be calculated below
                    'interactive_mode': bool(data['interactive_mode']) if 'interactive_mode' in data.keys() else False
                }
        
                # Check if agent is in memory and get additional info
                if data['id'] in self.agents:
                    in_memory_agent = self.agents[data['id']]
                    with in_memory_agent.lock:
                        agent_dict['pending_tasks'] = len([t for t in in_memory_agent.tasks if t['status'] == 'pending'])
                        agent_dict['interactive_mode'] = in_memory_agent.interactive_mode
                else:
                    task_count = self.db.execute(
                        "SELECT COUNT(*) as count FROM agent_tasks WHERE agent_id = ? AND status IN ('pending', 'sent')",
                        (data['id'],)
                    ).fetchone()
                    agent_dict['pending_tasks'] = task_count['count'] if task_count else 0
        
                agent_list.append(agent_dict)
    
            return agent_list
    
        except Exception as e:
            self.logger.info(f"[-] Error listing agents: {str(e)}")
            # Fallback to in-memory agents
            return [agent.to_dict() for agent in self.agents.values()]
    
    def get_agent_stats(self):
        """Get agent statistics"""
        stats = {
            'total_agents': len(self.agents),
            'active_agents': len([a for a in self.agents.values() if a.status == 'active']),
            'total_tasks': sum(len(agent.tasks) for agent in self.agents.values()),
            'pending_tasks': sum(len([t for t in agent.tasks if t['status'] == 'pending']) for agent in self.agents.values())
        }
        
        db_stats = self.db.execute('''
            SELECT 
                COUNT(*) as total_agents,
                COUNT(CASE WHEN status = 'active' THEN 1 END) as active_agents,
                COUNT(CASE WHEN status = 'inactive' THEN 1 END) as inactive_agents
            FROM agents
        ''').fetchone()
        
        stats['db_total_agents'] = db_stats['total_agents']
        stats['db_active_agents'] = db_stats['active_agents']
        stats['db_inactive_agents'] = db_stats['inactive_agents']
        
        return stats
    
    def remove_agent(self, agent_id):
        agent = self.get_agent(agent_id)  # Changed from checking self.agents directly
        if agent:
            with agent.lock:
                agent.status = "removed"
        
            if agent_id in self.agents:
                del self.agents[agent_id]
        
            self.db.execute('UPDATE agents SET status = ? WHERE id = ?', ('removed', agent_id))
        
            self.logger.info(f"[+] Agent {agent_id} removed")
            return True
    
        try:
            result = self.db.execute('UPDATE agents SET status = ? WHERE id = ?', ('removed', agent_id))
            if result.rowcount > 0:
                self.logger.info(f"[+] Agent {agent_id} removed from database")
                return True
        except Exception as e:
            self.logger.info(f"[-] Error removing agent: {str(e)}")
    
        self.logger.info(f"[-] Agent {agent_id} not found")
        return False

    def acquire_interactive_lock(self, agent_id, username, session_id):
        if agent_id in self.interactive_agent_locks:
            # Agent is already locked by another user
            lock_info = self.interactive_agent_locks[agent_id]
            return {
                'success': False, 
                'error': f"Agent {agent_id} is currently in interactive mode with operator: {lock_info['operator']}",
                'locked_by': lock_info['operator'],
                'session_id': lock_info['session_id']
            }
        
        # Acquire the lock
        self.interactive_agent_locks[agent_id] = {
            'operator': username,
            'session_id': session_id,
            'timestamp': datetime.now()
        }
        
        return {'success': True}

    def release_interactive_lock(self, agent_id):
        if agent_id in self.interactive_agent_locks:
            del self.interactive_agent_locks[agent_id]
            return {'success': True}
        return {'success': False, 'error': 'Agent not locked'}

    def get_interactive_lock_info(self, agent_id):
        return self.interactive_agent_locks.get(agent_id, None)

    def is_agent_locked_interactively(self, agent_id):
        return agent_id in self.interactive_agent_locks

    def register_interactive_result_callback(self, callback):
        self.interactive_result_callback = callback

    def register_agent_callback(self, callback):
        """Register a callback for agent registration events"""
        self.agent_callback = callback

    def _notify_agent_registration(self, agent_id, ip_address, hostname, os_info, user, listener_id):
        """Notify registered callbacks about a new agent registration"""
        if hasattr(self, 'agent_callback') and self.agent_callback:
            try:
                agent_data = {
                    'id': agent_id,
                    'ip_address': ip_address,
                    'hostname': hostname,
                    'os_info': os_info,
                    'user': user,
                    'listener_id': listener_id,
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                    'status': 'active'
                }
                self.agent_callback(agent_data)
            except Exception as e:
                self.logger.error(f"Error in agent registration callback: {str(e)}")
