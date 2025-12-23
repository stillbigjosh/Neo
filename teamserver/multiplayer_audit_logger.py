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

import os
import json
import uuid
import threading
import time
import logging
from datetime import datetime
from core.models import NeoC2DB


class MultiplayerAuditLogger:
    def __init__(self, db):
        self.db = db
        self.logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.running = False
        self.log_thread = None
        self.log_queue = []
        self.log_lock = threading.Lock()
        self.setup_db()
    
    def setup_db(self):
        self.db.execute('''
            CREATE TABLE IF NOT EXISTS multiplayer_audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                session_id TEXT,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                session_type TEXT DEFAULT 'web'  -- web, cli
            )
        ''')
        
        self.db.execute('''
            CREATE INDEX IF NOT EXISTS idx_multiplayer_audit_timestamp 
            ON multiplayer_audit_events (timestamp)
        ''')
        self.db.execute('''
            CREATE INDEX IF NOT EXISTS idx_multiplayer_audit_user 
            ON multiplayer_audit_events (user_id)
        ''')
        self.db.execute('''
            CREATE INDEX IF NOT EXISTS idx_multiplayer_audit_action 
            ON multiplayer_audit_events (action)
        ''')
    
    def start(self):
        """Start the audit logger"""
        if self.running:
            return True
            
        try:
            self.logger.info("Starting Multiplayer Audit Logger...")
            self.running = True
            
            self.log_thread = threading.Thread(target=self._process_logs)
            self.log_thread.daemon = True
            self.log_thread.start()
            
            self.logger.info("Multiplayer Audit Logger started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting Multiplayer Audit Logger: {str(e)}")
            return False
    
    def stop(self):
        """Stop the audit logger"""
        if not self.running:
            return True
            
        try:
            self.logger.info("Stopping Multiplayer Audit Logger...")
            self.running = False
            
            if self.log_thread and self.log_thread.is_alive():
                self.log_thread.join(timeout=2)
            
            self._flush_logs()
            
            self.logger.info("Multiplayer Audit Logger stopped successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping Multiplayer Audit Logger: {str(e)}")
            return False
    
    def log_event(self, user_id, action, resource_type=None, resource_id=None, 
                  details=None, ip_address=None, session_id=None, session_type='web'):
        try:
            event = {
                'user_id': user_id,
                'username': self._get_username(user_id),
                'session_id': session_id,
                'action': action,
                'resource_type': resource_type,
                'resource_id': resource_id,
                'details': details,
                'ip_address': ip_address,
                'timestamp': datetime.now(),
                'session_type': session_type
            }
            
            with self.log_lock:
                self.log_queue.append(event)
            
            self._insert_event_to_db(event)
            
        except Exception as e:
            self.logger.error(f"Error logging multiplayer event: {str(e)}")
    
    def _insert_event_to_db(self, event):
        try:
            self.db.execute('''
                INSERT INTO multiplayer_audit_events 
                (user_id, username, session_id, action, resource_type, resource_id, details, ip_address, session_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event['user_id'],
                event['username'],
                event['session_id'],
                event['action'],
                event['resource_type'],
                event['resource_id'],
                event['details'],
                event['ip_address'],
                event['session_type']
            ))
        except Exception as e:
            self.logger.error(f"Error inserting multiplayer audit event to DB: {str(e)}")
    
    def _get_username(self, user_id):
        try:
            user_data = self.db.execute(
                "SELECT username FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()
            return user_data['username'] if user_id and user_data else 'unknown'
        except Exception:
            return 'unknown'
    
    def _process_logs(self):
        """Process logs in background thread"""
        while self.running:
            try:
                time.sleep(1)  # Process other events
            except Exception as e:
                self.logger.error(f"Error in log processing: {str(e)}")
    
    def _flush_logs(self):
        pass
    
    def get_user_activity(self, user_id, limit=50):
        try:
            events = self.db.execute('''
                SELECT * FROM multiplayer_audit_events 
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (user_id, limit)).fetchall()
            
            return events
        except Exception as e:
            self.logger.error(f"Error getting user activity: {str(e)}")
            return []
    
    def get_agent_activity(self, agent_id, limit=50):
        try:
            events = self.db.execute('''
                SELECT * FROM multiplayer_audit_events 
                WHERE resource_type = 'agent' AND resource_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (agent_id, limit)).fetchall()
            
            return events
        except Exception as e:
            self.logger.error(f"Error getting agent activity: {str(e)}")
            return []
    
    def get_session_activity(self, session_id, limit=50):
        try:
            events = self.db.execute('''
                SELECT * FROM multiplayer_audit_events 
                WHERE session_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (session_id, limit)).fetchall()
            
            return events
        except Exception as e:
            self.logger.error(f"Error getting session activity: {str(e)}")
            return []
    
    def get_collaboration_events(self, limit=50):
        try:
            events = self.db.execute('''
                SELECT * FROM multiplayer_audit_events 
                WHERE action LIKE '%agent_monitor%' 
                   OR action LIKE '%interactive%'
                   OR action LIKE '%multiplayer%'
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,)).fetchall()
            
            return events
        except Exception as e:
            self.logger.error(f"Error getting collaboration events: {str(e)}")
            return []
