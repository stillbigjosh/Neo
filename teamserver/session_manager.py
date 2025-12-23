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
import time
import threading
import logging
from datetime import datetime, timedelta
from core.models import NeoC2DB

class Session:
    def __init__(self, id, user_id, ip_address, user_agent, created_at, expires_at):
        self.id = id
        self.user_id = user_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.created_at = created_at
        self.expires_at = expires_at
        self.last_activity = created_at
        self.is_active = True
    
    def is_expired(self):
        return datetime.now() > self.expires_at
    
    def update_activity(self):
        self.last_activity = datetime.now()
    
    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "is_active": self.is_active
        }

class SessionManager:
    def __init__(self, db):
        self.db = db
        self.session_duration = 24 * 60 * 60  # 24 hours in seconds
        self.active_sessions = {}
        self.running = False
        self.cleanup_thread = None
        self.logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.setup_db()
    
    def setup_db(self):
        self.db.execute('''
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
    
    def start(self):
        """Start the session manager"""
        if self.running:
            return True
        
        try:
            self.logger.info("Starting Session Manager...")
            self.running = True
            
            self._load_active_sessions()
            
            self.cleanup_thread = threading.Thread(target=self._cleanup_worker)
            self.cleanup_thread.daemon = True
            self.cleanup_thread.start()
            
            self.logger.info("Session Manager started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting Session Manager: {str(e)}")
            return False
    
    def stop(self):
        if not self.running:
            return True
        
        try:
            self.logger.info("Stopping Session Manager...")
            self.running = False
            
            if self.cleanup_thread and self.cleanup_thread.is_alive():
                self.cleanup_thread.join(timeout=5)
            
            self.cleanup_inactive_sessions()
            
            self.active_sessions.clear()
            
            self.logger.info("Session Manager stopped successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping Session Manager: {str(e)}")
            return False
    
    def _load_active_sessions(self):
        try:
            session_data = self.db.execute(
                "SELECT * FROM sessions WHERE is_active = 1 AND expires_at > ?",
                (datetime.now(),)
            ).fetchall()
            
            for data in session_data:
                session = Session(
                    data['id'],
                    data['user_id'],
                    data['ip_address'],
                    data['user_agent'],
                    data['created_at'],
                    data['expires_at']
                )
                
                if not session.is_expired():
                    self.active_sessions[session.id] = session
            
            self.logger.info(f"Loaded {len(self.active_sessions)} active sessions from database")
            
        except Exception as e:
            self.logger.error(f"Error loading active sessions: {str(e)}")
    
    def _cleanup_worker(self):
        while self.running:
            try:
                time.sleep(300)  # 5 minutes
                if self.running:
                    self.cleanup_inactive_sessions()
            except Exception as e:
                self.logger.error(f"Error in session cleanup worker: {str(e)}")
    
    def create_session(self, user_id, ip_address, user_agent=None):
        session_id = str(uuid.uuid4())
        created_at = datetime.now()
        expires_at = created_at + timedelta(seconds=self.session_duration)
        
        session = Session(
            session_id,
            user_id,
            ip_address,
            user_agent,
            created_at,
            expires_at
        )
        
        self.db.execute(
            "INSERT INTO sessions (id, user_id, token, created_at, expires_at, last_activity, ip_address, user_agent, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, user_id, session_id, created_at, expires_at, created_at, ip_address, user_agent, True)
        )
        
        self.active_sessions[session_id] = session
        
        return session
    
    def get_session(self, session_id):
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            if session.is_expired():
                self.deactivate_session(session_id)
                return None
            return session
        
        session_data = self.db.execute(
            "SELECT * FROM sessions WHERE id = ? AND is_active = 1",
            (session_id,)
        ).fetchone()
        
        if not session_data:
            return None
        
        session = Session(
            session_data['id'],
            session_data['user_id'],
            session_data['ip_address'],
            session_data['user_agent'],
            session_data['created_at'],
            session_data['expires_at']
        )
        
        if session.is_expired():
            self.deactivate_session(session_id)
            return None
        
        self.active_sessions[session_id] = session
        return session
    
    def update_activity(self, session_id):
        session = self.get_session(session_id)
        if session:
            session.update_activity()
            # Update in database
            self.db.execute(
                "UPDATE sessions SET last_activity = ? WHERE id = ?",
                (session.last_activity, session_id)
            )
    
    def deactivate_session(self, session_id):
        """Deactivate a session"""
        # Remove from active sessions
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
        
        # Update in database
        self.db.execute(
            "UPDATE sessions SET is_active = 0 WHERE id = ?",
            (session_id,)
        )
    
    def cleanup_inactive_sessions(self):
        expired_sessions = []
        for session_id, session in self.active_sessions.items():
            if session.is_expired():
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.deactivate_session(session_id)
        
        expired_sessions = self.db.execute(
            "SELECT id FROM sessions WHERE expires_at < ? AND is_active = 1",
            (datetime.now(),)
        ).fetchall()
        
        for session_data in expired_sessions:
            self.deactivate_session(session_data['id'])
    
    def get_user_sessions(self, user_id):
        sessions = []
        
        for session_id, session in self.active_sessions.items():
            if session.user_id == user_id:
                sessions.append(session.to_dict())
        
        session_data = self.db.execute(
            "SELECT * FROM sessions WHERE user_id = ? AND is_active = 1",
            (user_id,)
        ).fetchall()
        
        for data in session_data:
            session = Session(
                data['id'],
                data['user_id'],
                data['ip_address'],
                data['user_agent'],
                data['created_at'],
                data['expires_at']
            )
            if not session.is_expired():
                sessions.append(session.to_dict())
        
        return sessions
    
    def terminate_all_user_sessions(self, user_id):
        sessions = self.get_user_sessions(user_id)
        
        for session in sessions:
            self.deactivate_session(session['id'])
    
    def get_active_session_count(self):
        return len(self.active_sessions)
    
    def get_session_stats(self):
        return {
            'active_sessions': len(self.active_sessions),
            'total_sessions_created': self.db.execute(
                "SELECT COUNT(*) FROM sessions"
            ).fetchone()[0],
            'expired_sessions_cleaned': len([
                s for s in self.active_sessions.values() if s.is_expired()
            ])
        }
