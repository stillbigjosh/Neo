"""
The Neo C2 Framework is a post-exploitation command and control framework.

This file is part of Neo C2 Framework.
Copyright (C) 2025 @stillbigjosh

The Neo C2 Framework of this edition is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

The Neo C2 Framework is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Neo.  If not, see <http://www.gnu.org/licenses/>
"""

import sqlite3
import uuid
import json
import logging
from datetime import datetime
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
import os
import threading
from contextlib import contextmanager
import time # Added for retry logic

class DatabaseConfig:
    @staticmethod
    def get_db_path():
        """Get the appropriate database path for the environment"""
        if os.getenv('RAILWAY_ENVIRONMENT') or os.getenv('DOCKER_ENV'):
            volume_path = '/data'
            db_path = os.path.join(volume_path, 'neoc2.db')

            os.makedirs(volume_path, exist_ok=True)

            try:
                os.chmod(volume_path, 0o755)
            except:
                pass

        else:
            db_path = 'neoc2.db'

        return db_path
    
    @staticmethod
    def ensure_db_permissions(db_path):
        try:
            if os.path.exists(db_path):
                os.chmod(db_path, 0o664)
            
            db_dir = os.path.dirname(db_path)
            if db_dir and os.path.exists(db_dir):
                os.chmod(db_dir, 0o755)
        except Exception as e:
            self.logger.warning(f"Could not set database permissions: {e}")

class NeoC2DB:
    def __init__(self, db_path=None, timeout=30):
        if db_path is None:
            db_path = DatabaseConfig.get_db_path()
        
        self.db_path = db_path
        self.timeout = timeout
        self._local = threading.local()
        
        self.logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')

        DatabaseConfig.ensure_db_permissions(self.db_path)

        self._setup_database()
    
    def _setup_database(self):
        try:
            conn = sqlite3.connect(self.db_path, timeout=self.timeout)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=10000")
            conn.execute("PRAGMA temp_store=memory")
            conn.execute("PRAGMA mmap_size=268435456")
            conn.row_factory = sqlite3.Row
            conn.close()
        except Exception as e:
            self.logger.error(f"Database setup error: {e}")
    
    def get_connection(self):
        """Get a thread-local database connection"""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            self._local.connection = sqlite3.connect(
                self.db_path, 
                timeout=self.timeout,
                check_same_thread=False
            )
            self._local.connection.row_factory = sqlite3.Row
            self._local.connection.execute("PRAGMA busy_timeout=30000")  # 30 second timeout
        return self._local.connection
    
    @contextmanager
    def get_cursor(self):
        max_retries = 3
        retry_delay = 0.1
        conn = self.get_connection()

        for attempt in range(max_retries):
            try:
                cursor = conn.cursor()
                yield cursor
                conn.commit()
                return
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                    conn.rollback()
                    time.sleep(retry_delay * (2 ** attempt))
                    continue
                else:
                    conn.rollback()
                    raise
            except Exception as e:
                if conn:
                    conn.rollback()
                raise
    
    def execute(self, query, params=None):
        with self.get_cursor() as cursor:
            if params:
                return cursor.execute(query, params)
            else:
                return cursor.execute(query)
    
    def executemany(self, query, params_list):
        with self.get_cursor() as cursor:
            return cursor.executemany(query, params_list)
    
    def fetchone(self, query, params=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        return cursor.fetchone()

    def fetchall(self, query, params=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        return cursor.fetchall()
            
    def close_connection(self):
        if hasattr(self._local, 'connection') and self._local.connection:
            self._local.connection.close()
            self._local.connection = None
            
    def init_db(self):
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=self.timeout)
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS roles (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    permissions TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT,
                    role_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active INTEGER DEFAULT 1,
                    registration_status TEXT DEFAULT 'approved',
                    FOREIGN KEY (role_id) REFERENCES roles (id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    last_activity TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT,
                    is_active INTEGER DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    action TEXT NOT NULL,
                    resource_type TEXT,
                    resource_id TEXT,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS listeners (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    type TEXT NOT NULL,
                    host TEXT,
                    port INTEGER,
                    profile_name TEXT,
                    agent_id TEXT,
                    remote_host TEXT,
                    remote_port INTEGER,
                    config TEXT,
                    status TEXT DEFAULT 'stopped',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
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
                    active INTEGER DEFAULT 1,
                    interactive_mode INTEGER NOT NULL DEFAULT 0,
                    checkin_interval INTEGER DEFAULT 30,
                    jitter INTEGER DEFAULT 5,
                    communication_protocol TEXT,
                    persistence_methods TEXT,
                    secret_key TEXT,  -- Secret key for encrypted communication
                    FOREIGN KEY (listener_id) REFERENCES listeners (id)
                )
            ''')
            try:
                cursor.execute("ALTER TABLE agents ADD COLUMN interactive_mode INTEGER NOT NULL DEFAULT 0")
                self.logger.info("Database Migration: Added 'interactive_mode' column to agents table.")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    pass
                else:
                    raise e

            try:
                cursor.execute("ALTER TABLE users ADD COLUMN registration_status TEXT DEFAULT 'approved'")
                self.logger.info("Database Migration: Added 'registration_status' column to users table.")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    pass
                else:
                    raise e

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    command TEXT NOT NULL,
                    module_id TEXT,
                    status TEXT DEFAULT 'pending',
                    result TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS agent_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    command TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    result TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    task_type TEXT NOT NULL DEFAULT 'queued',
                    FOREIGN KEY (agent_id) REFERENCES agents (id)
                )
            ''')
            try:
                cursor.execute("ALTER TABLE agent_tasks ADD COLUMN task_type TEXT NOT NULL DEFAULT 'queued'")
                self.logger.info("Database Migration: Added 'task_type' column to agent_tasks table.")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    pass
                else:
                    raise e

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS modules (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    type TEXT,
                    code TEXT,
                    technique_id TEXT,
                    mitre_tactics TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS results (
                    id TEXT PRIMARY KEY,
                    task_id TEXT,
                    agent_id TEXT,
                    data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (task_id) REFERENCES tasks (id),
                    FOREIGN KEY (agent_id) REFERENCES agents (id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS profiles (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    config TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.commit()
            self.logger.info("Database tables checked/created successfully.")
            
        except Exception as e:
            self.logger.error(f"FATAL: Error initializing database: {str(e)}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close() # Always close the temporary connection

   
    


    def get_modules(self, module_type=None):
        try:
            with self.get_cursor() as cursor:
                if module_type:
                    cursor.execute('SELECT * FROM modules WHERE type = ?', (module_type,))
                else:
                    cursor.execute('SELECT * FROM modules')
                rows = cursor.fetchall()
                return [self._dict_from_module_row(row) for row in rows]
        except Exception as e:
            self.logger.error(f"Error getting modules: {str(e)}")
            return []

    def get_all_modules(self):
        return self.get_modules()
        

    def add_module(self, name, description, module_type, code, technique_id='', mitre_tactics=None):
        module_id = str(uuid.uuid4())
        try:
            with self.get_cursor() as cursor:
                cursor.execute('''
                INSERT INTO modules (id, name, description, type, code, technique_id, mitre_tactics)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (module_id, name, description, module_type, code, technique_id, 
                      json.dumps(mitre_tactics) if mitre_tactics else None))
            return module_id
        except Exception as e:
            self.logger.error(f"Error adding module: {str(e)}")
            raise


    def get_module(self, module_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM modules WHERE id = ?', (module_id,))
                row = cursor.fetchone()

                if row:
                    return dict(row)  # Convert sqlite3.Row to regular dict
                return None
            
        except Exception as e:
            import logging
            logging.error(f"Error in get_module for ID {module_id}: {e}")
            return None






    def delete_module(self, module_id):
        """Delete a module from the database"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute('DELETE FROM modules WHERE id = ?', (module_id,))
        except Exception as e:
            self.logger.error(f"Error deleting module: {str(e)}")

    def _dict_from_module_row(self, row):
        module = dict(row)

        if module.get('mitre_tactics'):
            try:
                module['mitre_tactics'] = json.loads(module['mitre_tactics'])
            except (json.JSONDecodeError, TypeError):
                module['mitre_tactics'] = []

        return module

    def create_result(self, result_id, task_id, agent_id, data):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('''
                INSERT INTO results (id, task_id, agent_id, data)
                VALUES (?, ?, ?, ?)
                ''', (result_id, task_id, agent_id, data))
        except Exception as e:
            self.logger.error(f"Error creating result: {str(e)}")
            raise

    def get_results(self, task_id=None, agent_id=None):
        try:
            with self.get_cursor() as cursor:
                query = "SELECT * FROM results"
                params = []
                
                conditions = []
                if task_id:
                    conditions.append("task_id = ?")
                    params.append(task_id)
                if agent_id:
                    conditions.append("agent_id = ?")
                    params.append(agent_id)
                    
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
                    
                cursor.execute(query, tuple(params))
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            self.logger.error(f"Error getting results: {str(e)}")
            return []

    def create_profile(self, profile_id, name, description, config):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('''
                INSERT INTO profiles (id, name, description, config)
                VALUES (?, ?, ?, ?)
                ''', (profile_id, name, description, json.dumps(config)))
        except Exception as e:
            self.logger.error(f"Error creating profile: {str(e)}")
            raise

    def get_profile_by_name(self, name):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('SELECT * FROM profiles WHERE name = ?', (name,))
                row = cursor.fetchone()
                if row:
                    return self._dict_from_profile_row(row)
                return None
        except Exception as e:
            self.logger.error(f"Error getting profile by name: {str(e)}")
            return None


    def update_profile_by_name(self, name, description, config_str):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('''
                    UPDATE profiles
                    SET description = ?, config = ?
                    WHERE name = ?
                ''', (description, config_str, name))

            if cursor.rowcount == 0:
                raise ValueError(f"Profile with name '{name}' not found")
        except Exception as e:
            self.logger.error(f"Error updating profile by name: {str(e)}")
            raise


    def add_profile(self, name, description, config_str):
        profile_id = str(uuid.uuid4())
        try:
            self.execute('''
                INSERT INTO profiles (id, name, description, config, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (profile_id, name, description, config_str, datetime.now().isoformat()))
            return profile_id
        except sqlite3.IntegrityError:
            raise ValueError(f"A profile with the name '{name}' already exists.")
        except Exception as e:
            self.logger.error(f"Error adding profile: {str(e)}")
            raise

    def get_all_profiles(self):
        try:
            rows = self.fetchall('SELECT * FROM profiles ORDER BY created_at DESC')
            return [self._dict_from_profile_row(row) for row in rows]
        except Exception as e:
            self.logger.error(f"Error getting all profiles: {str(e)}")
            return []

    def update_profile(self, profile_id, name, description, config_str):
        try:
            self.execute('''
                UPDATE profiles
                SET name = ?, description = ?, config = ?
                WHERE id = ?
            ''', (name, description, config_str, profile_id))
        except Exception as e:
            self.logger.error(f"Error updating profile: {str(e)}")
            raise

    def delete_profile(self, profile_id):
        try:
            self.execute('DELETE FROM profiles WHERE id = ?', (profile_id,))
        except Exception as e:
            self.logger.error(f"Error deleting profile: {str(e)}")
            raise

    def get_profile(self, profile_id):
        try:
            row = self.fetchone('SELECT * FROM profiles WHERE id = ?', (profile_id,))
            if row:
                return self._dict_from_profile_row(row)
            return None
        except Exception as e:
            self.logger.error(f"Error getting profile: {str(e)}")
            return None

    def _dict_from_profile_row(self, row):
        profile = dict(row)
        if profile.get('config'):
            try:
                profile['config'] = json.loads(profile['config'])
            except (json.JSONDecodeError, TypeError):
                profile['config'] = {}
        return profile

    

    def create_listener(self, listener_id, name, listener_type, host=None, port=None, 
                      profile_name=None, agent_id=None, remote_host=None, 
                      remote_port=None, config=None):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('''
                INSERT INTO listeners (id, name, type, host, port, profile_name, 
                                      agent_id, remote_host, remote_port, config)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (listener_id, name, listener_type, host, port, profile_name, 
                      agent_id, remote_host, remote_port, json.dumps(config) if config else None))
        except Exception as e:
            self.logger.error(f"Error creating listener: {str(e)}")
            raise

    def get_listener(self, listener_id):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('SELECT * FROM listeners WHERE id = ?', (listener_id,))
                row = cursor.fetchone()
                if row:
                    return self._dict_from_listener_row(row)
                return None
        except Exception as e:
            self.logger.error(f"Error getting listener: {str(e)}")
            return None

    def get_listeners(self, status=None):
        try:
            with self.get_cursor() as cursor:
                if status:
                    cursor.execute('SELECT * FROM listeners WHERE status = ?', (status,))
                else:
                    cursor.execute('SELECT * FROM listeners')
                rows = cursor.fetchall()
                return [self._dict_from_listener_row(row) for row in rows]
        except Exception as e:
            self.logger.error(f"Error getting listeners: {str(e)}")
            return []

    def update_listener(self, listener_id, status=None, config=None):
        try:
            updates = []
            values = []
            
            if status is not None:
                updates.append("status = ?")
                values.append(status)
            if config is not None:
                updates.append("config = ?")
                values.append(json.dumps(config))
                
            if updates:
                values.append(listener_id)
                query = f"UPDATE listeners SET {', '.join(updates)} WHERE id = ?"
                with self.get_cursor() as cursor:
                    cursor.execute(query, tuple(values))
        except Exception as e:
            self.logger.error(f"Error updating listener: {str(e)}")

    def _dict_from_listener_row(self, row):
        listener = dict(row)

        if listener.get('config'):
            try:
                listener['config'] = json.loads(listener['config'])
            except (json.JSONDecodeError, TypeError):
                listener['config'] = {}

        return listener

    def get_listener_by_name(self, name):
        try:
            row = self.fetchone('SELECT * FROM listeners WHERE name = ?', (name,))
            if row:
                return self._dict_from_listener_row(row)
            return None
        except Exception as e:
            self.logger.error(f"Error getting listener by name: {str(e)}")
            return None

    def update_listener_status(self, listener_id, status):
        try:
            self.execute(
                "UPDATE listeners SET status = ? WHERE id = ?",
                (status, listener_id)
            )
        except Exception as e:
            self.logger.error(f"Error updating listener status: {str(e)}")
            raise

    def delete_listener(self, listener_id):
        try:
            result = self.execute('DELETE FROM listeners WHERE id = ?', (listener_id,))
            if result.rowcount == 0:
                raise ValueError("Listener not found")
        except Exception as e:
            self.logger.error(f"Error deleting listener: {str(e)}")
            raise

    def get_listeners(self, status=None):
        try:
            if status:
                rows = self.fetchall('SELECT * FROM listeners WHERE status = ? ORDER BY created_at DESC', (status,))
            else:
                rows = self.fetchall('SELECT * FROM listeners ORDER BY created_at DESC')
            listeners = [self._dict_from_listener_row(row) for row in rows]
            return listeners
        except Exception as e:
            self.logger.error(f"Error getting listeners: {str(e)}")
            return []
            

    def create_audit_log(self, log_id, user_id, action, resource_type=None, 
                       resource_id=None, details=None, ip_address=None):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('''
                INSERT INTO audit_log (id, user_id, action, resource_type, 
                                      resource_id, details, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (log_id, user_id, action, resource_type, resource_id, 
                      json.dumps(details) if details else None, ip_address))
        except Exception as e:
            self.logger.error(f"Error creating audit log: {str(e)}")
            raise

    def get_audit_logs(self, user_id=None, action=None, resource_type=None, 
                      resource_id=None, limit=100):
        try:
            with self.get_cursor() as cursor:
                query = "SELECT * FROM audit_log"
                params = []
                
                conditions = []
                if user_id:
                    conditions.append("user_id = ?")
                    params.append(user_id)
                if action:
                    conditions.append("action = ?")
                    params.append(action)
                if resource_type:
                    conditions.append("resource_type = ?")
                    params.append(resource_type)
                if resource_id:
                    conditions.append("resource_id = ?")
                    params.append(resource_id)
                    
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
                    
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                    
                cursor.execute(query, tuple(params))
                rows = cursor.fetchall()
                return [self._dict_from_audit_log_row(row) for row in rows]
        except Exception as e:
            self.logger.error(f"Error getting audit logs: {str(e)}")
            return []

    def _dict_from_audit_log_row(self, row):
        log = dict(row)

        if log.get('details'):
            try:
                log['details'] = json.loads(log['details'])
            except (json.JSONDecodeError, TypeError):
                log['details'] = {}

        return log

    def create_session(self, session_id, user_id, token, expires_at=None, 
                     ip_address=None, user_agent=None):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('''
                INSERT INTO sessions (id, user_id, token, expires_at, 
                                     ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (session_id, user_id, token, expires_at, ip_address, user_agent))
        except Exception as e:
            self.logger.error(f"Error creating session: {str(e)}")
            raise

    def get_session(self, session_id):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('SELECT * FROM sessions WHERE id = ?', (session_id,))
                row = cursor.fetchone()
                if row:
                    return dict(row)
                return None
        except Exception as e:
            self.logger.error(f"Error getting session: {str(e)}")
            return None

    def get_session_by_token(self, token):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('SELECT * FROM sessions WHERE token = ?', (token,))
                row = cursor.fetchone()
                if row:
                    return dict(row)
                return None
        except Exception as e:
            self.logger.error(f"Error getting session by token: {str(e)}")
            return None

    def update_session_activity(self, session_id):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('''
                UPDATE sessions SET last_activity = CURRENT_TIMESTAMP 
                WHERE id = ?
                ''', (session_id,))
        except Exception as e:
            self.logger.error(f"Error updating session activity: {str(e)}")

    def create_user(self, user_id, username, password, email=None, role_id=None):
        try:
            hashed_password = generate_password_hash(password)
            with self.get_cursor() as cursor:
                cursor.execute('''
                INSERT INTO users (id, username, password_hash, email, role_id, created_at, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (user_id, username, hashed_password, email, role_id, datetime.now(), 1))
            self.logger.debug(f"Database: Created user {username} with hashed password")
        except Exception as e:
            self.logger.error(f"Error creating user in database: {str(e)}")
            raise

    def get_user(self, user_id):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
                row = cursor.fetchone()
                if row:
                    return dict(row)
                return None
        except Exception as e:
            self.logger.error(f"Error getting user: {str(e)}")
            return None

    def get_user_by_username(self, username):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('SELECT * FROM users WHERE username = ? AND is_active = 1 AND registration_status = \'approved\'', (username,))
                row = cursor.fetchone()
                if row:
                    user_dict = dict(row)
                    self.logger.debug(f"Database: Found user {username} with password: {user_dict.get('password_hash')}")
                    return user_dict
                self.logger.debug(f"Database: User {username} not found")
                return None
        except Exception as e:
            self.logger.error(f"Error getting user by username: {str(e)}")
            return None
    
    def get_user_by_username_all_status(self, username):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
                row = cursor.fetchone()
                if row:
                    user_dict = dict(row)
                    return user_dict
                return None
        except Exception as e:
            self.logger.error(f"Error getting user by username (all status): {str(e)}")
            return None

    def update_user_last_login(self, user_id):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('''
                    UPDATE users SET last_login = ?
                    WHERE id = ?
                ''', (datetime.now(), user_id))
        except Exception as e:
            self.logger.error(f"Error updating user last login: {str(e)}")

    def authenticate_user(self, username, password):
        try:
            user = self.get_user_by_username(username)
            if user and check_password_hash(user.get('password_hash'), password):
                self.update_user_last_login(user['id'])
                return user
            return None
        except Exception as e:
            self.logger.error(f"Error authenticating user: {str(e)}")
            return None

    def create_role(self, role_id, name, description=None, permissions=None):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('''
                INSERT INTO roles (id, name, description, permissions, created_at)
                VALUES (?, ?, ?, ?, ?)
                ''', (role_id, name, description, json.dumps(permissions) if permissions else None, datetime.now()))
        except Exception as e:
            self.logger.error(f"Error creating role: {str(e)}")
            raise

    def get_role(self, role_id):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('SELECT * FROM roles WHERE id = ?', (role_id,))
                row = cursor.fetchone()
                if row:
                    role = dict(row)
                    if role.get('permissions'):
                        try:
                            role['permissions'] = json.loads(role['permissions'])
                        except (json.JSONDecodeError, TypeError):
                            role['permissions'] = []
                    return role
                return None
        except Exception as e:
            self.logger.error(f"Error getting role: {str(e)}")
            return None

    def get_role_by_name(self, name):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('SELECT * FROM roles WHERE name = ?', (name,))
                row = cursor.fetchone()
                if row:
                    role = dict(row)
                    if role.get('permissions'):
                        try:
                            role['permissions'] = json.loads(role['permissions'])
                        except (json.JSONDecodeError, TypeError):
                            role['permissions'] = []
                    return role
                return None
        except Exception as e:
            self.logger.error(f"Error getting role by name: {str(e)}")
            return None

    def get_all_roles(self):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('SELECT * FROM roles')
                rows = cursor.fetchall()
                roles = []
                for row in rows:
                    role = dict(row)
                    if role.get('permissions'):
                        try:
                            role['permissions'] = json.loads(role['permissions'])
                        except (json.JSONDecodeError, TypeError):
                            role['permissions'] = []
                    roles.append(role)
                return roles
        except Exception as e:
            self.logger.error(f"Error getting all roles: {str(e)}")
            return []

    def get_table_info(self, table_name):
        try:
            with self.get_cursor() as cursor:
                cursor.execute(f"PRAGMA table_info({table_name})")
                return cursor.fetchall()
        except Exception as e:
            self.logger.error(f"Error getting table info: {str(e)}")
            return []

    def get_all_tables(self):
        try:
            with self.get_cursor() as cursor:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                return [row['name'] for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Error getting all tables: {str(e)}")
            return []

    def debug_database_contents(self):
        try:
            self.logger.debug("=== DATABASE CONTENTS ===")

            tables = self.get_all_tables()
            self.logger.debug(f"Tables: {tables}")

            with self.get_cursor() as cursor:
                cursor.execute("SELECT id, username, password_hash, role_id, is_active FROM users")
                users = cursor.fetchall()
                self.logger.debug(f"Users: {[dict(u) for u in users]}")

                cursor.execute("SELECT id, name, permissions FROM roles")
                roles = cursor.fetchall()
                self.logger.debug(f"Roles: {[dict(r) for r in roles]}")

            self.logger.debug("=== END DATABASE CONTENTS ===")

        except Exception as e:
            self.logger.error(f"Error debugging database contents: {str(e)}")

    def vacuum_database(self):
        try:
            with self.get_cursor() as cursor:
                cursor.execute("VACUUM")
            self.logger.info("Database vacuumed successfully")
        except Exception as e:
            self.logger.error(f"Error vacuuming database: {str(e)}")

    def backup_database(self, backup_path):
        try:
            import shutil
            shutil.copy2(self.db_path, backup_path)
            self.logger.info(f"Database backed up to: {backup_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error backing up database: {str(e)}")
            return False

    def get_inactive_agents(self, max_inactive_time=300):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(f'''
            SELECT * FROM agents
            WHERE status = 'active'
            AND (last_seen IS NULL OR datetime(last_seen) < datetime('now', '-{max_inactive_time} seconds'))
            ''')
            rows = cursor.fetchall()
            return [self._dict_from_agent_row(row) for row in rows]


    def get_all_agents(self):
        try:
            rows = self.fetchall('SELECT * FROM agents ORDER BY last_seen DESC')
            return [self._dict_from_agent_row(row) for row in rows]
        except Exception as e:
            self.logger.error(f"Error getting all agents: {str(e)}")
            return []

    def get_agent(self, agent_id):
        try:
            row = self.fetchone('SELECT * FROM agents WHERE id = ?', (agent_id,))
            if row:
                return self._dict_from_agent_row(row)
            return None
        except Exception as e:
            self.logger.error(f"Error getting agent: {str(e)}")
            return None
            
    def get_agent_tasks(self, agent_id):
        try:
            rows = self.fetchall('SELECT * FROM tasks WHERE agent_id = ? ORDER BY created_at DESC', (agent_id,))
            return [self._dict_from_task_row(row) for row in rows]
        except Exception as e:
            self.logger.error(f"Error getting agent tasks: {str(e)}")
            return []
            
    def add_task(self, agent_id, command, task_type='queued'):
        try:
            with self.get_cursor() as cursor:
                cursor.execute('''
                    INSERT INTO agent_tasks (agent_id, command, status, created_at, task_type)
                    VALUES (?, ?, ?, ?, ?)
                ''', (agent_id, command, 'pending', datetime.now(), task_type))

                new_task_id = cursor.lastrowid
                self.logger.info(f"Task {new_task_id} added for agent {agent_id}: {command[:50]}...")
                return new_task_id
        except Exception as e:
            self.logger.error(f"Error adding task to DB: {e}")
            return None

    def _dict_from_agent_row(self, row):
        if not row:
            return None
        if hasattr(row, 'keys'):
            return {key: row[key] for key in row.keys()}
        else:
            return dict(row)

    def _dict_from_task_row(self, row):
        if not row:
            return None
        if hasattr(row, 'keys'):
            return {key: row[key] for key in row.keys()}
        else:
            return dict(row)
        
    def get_tasks(self, agent_id):
        agent = self.agents.get(agent_id)
        if not agent:
            return []
        with agent.lock:
            pending_tasks = [task for task in agent.tasks if task['status'] == 'pending']
            for task in pending_tasks:
                task['status'] = 'sent'
                self.db.execute('UPDATE agent_tasks SET status = ? WHERE id = ?', ('sent', task['id']))
            return pending_tasks
            
    def get_agent_results(self, agent_id, limit=50):
        try:
            results = self.fetchall('''
                SELECT * FROM agent_tasks
                WHERE agent_id = ? AND status = 'completed' AND result IS NOT NULL
                ORDER BY completed_at DESC
                LIMIT ?
            ''', (agent_id, limit))

            result_list = []
            for r in results:
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
            self.logger.error(f"Error getting agent results: {str(e)}")
            return []
            
    def add_result(self, agent_id, task_id, result):
        agent = self.agents.get(agent_id)
        if not agent:
            return False

        with agent.lock:
            for task in agent.tasks:
                if task['id'] == task_id:
                    task['status'] = 'completed'
                    task['result'] = result
                    task['completed_at'] = datetime.now()

                    self.db.execute('''
                        UPDATE agent_tasks SET status = ?, result = ?, completed_at = ?
                        WHERE id = ?
                    ''', ('completed', result, task['completed_at'], task_id))

                    self.logger.info(f"Result received from agent {agent_id} for task {task_id}")
                    break

        return True
    
    def get_all_tasks(self):
        try:
            rows = self.fetchall('SELECT * FROM agent_tasks ORDER BY created_at DESC')
            result_list = []
            for row in rows:
                row_dict = dict(row) if hasattr(row, '_mapping') else row
                result_list.append({
                    'id': row_dict['id'],
                    'agent_id': row_dict['agent_id'],
                    'command': row_dict['command'],
                    'status': row_dict['status'],
                    'result': row_dict['result'],
                    'task_type': row_dict.get('task_type', 'queued'),
                    'created_at': row_dict['created_at'],
                    'completed_at': row_dict['completed_at']
                })
            
            return result_list
        except Exception as e:
            self.logger.error(f"Error getting all tasks: {str(e)}")
            return []
        
    

















