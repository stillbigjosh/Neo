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
from teamserver.session_manager import Session, SessionManager
from flask_socketio import SocketIO
import gevent
from gevent import queue


class MultiplayerSession(Session):
    def __init__(self, id, user_id, username, ip_address, user_agent, created_at, expires_at, session_type='web'):
        super().__init__(id, user_id, ip_address, user_agent, created_at, expires_at)
        self.username = username
        self.session_type = session_type  # 'web' or 'cli'
        self.interactive_agent = None
        self.accessible_agents = set()  # Set of agent IDs this user can access
        self.current_view = 'dashboard'  # Current UI view
        self.notifications = queue.Queue()  # Notification queue for this session
        self.presence_status = 'available'  # available, busy, away, offline
        self.last_activity = datetime.now()
        
    def update_presence_status(self, status):
        self.presence_status = status
        self.last_activity = datetime.now()
        
    def to_dict(self):
        base_dict = super().to_dict()
        base_dict.update({
            'username': self.username,
            'session_type': self.session_type,
            'interactive_agent': self.interactive_agent,
            'accessible_agents': list(self.accessible_agents),
            'current_view': self.current_view,
            'presence_status': self.presence_status,
            'last_activity': self.last_activity.isoformat()
        })
        return base_dict


class MultiplayerSessionManager:
    
    def __init__(self, db, socketio=None):
        self.db = db
        self.socketio = socketio
        self.session_duration = 24 * 60 * 60  # 24 hours
        self.active_sessions = {}
        self.user_sessions = {}  # Maps user_id to [session_ids]
        self.agent_sessions = {}  # Maps agent_id to [session_ids] - sessions viewing this agent
        self.interactive_locks = {}  # Maps agent_id to session_id holding the interactive lock
        self.running = False
        self.cleanup_thread = None
        self.logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.setup_db()
        
    def setup_db(self):
        self.db.execute('''
            CREATE TABLE IF NOT EXISTS multiplayer_sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                session_type TEXT DEFAULT 'web',
                token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                last_activity TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                interactive_agent TEXT,
                current_view TEXT DEFAULT 'dashboard',
                presence_status TEXT DEFAULT 'available',
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        self.db.execute('''
            CREATE TABLE IF NOT EXISTS agent_session_presence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                presence_status TEXT DEFAULT 'viewing',
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES multiplayer_sessions (id)
            )
        ''')
        
        self.db.execute('''
            CREATE TABLE IF NOT EXISTS user_presence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                session_id TEXT NOT NULL,
                session_type TEXT DEFAULT 'web',
                presence_status TEXT DEFAULT 'available',
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES multiplayer_sessions (id)
            )
        ''')
    
    def start(self):
        if self.running:
            return True
            
        try:
            self.logger.info("Starting Multiplayer Session Manager...")
            self.running = True
            
            self._load_active_sessions()
            
            self.cleanup_thread = threading.Thread(target=self._cleanup_worker)
            self.cleanup_thread.daemon = True
            self.cleanup_thread.start()
            
            if hasattr(self, 'audit_logger') and self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        user_id=None,
                        action='multiplayer_session_manager_start',
                        resource_type='service',
                        resource_id='multiplayer_session_manager',
                        details="Multiplayer Session Manager service started",
                        ip_address=None
                    )
                except Exception as e:
                    self.logger.error(f"Error logging multiplayer session manager start event: {str(e)}")
            
            self.logger.info("Multiplayer Session Manager started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting Multiplayer Session Manager: {str(e)}")
            return False
    
    def stop(self):
        if not self.running:
            return True
            
        try:
            self.logger.info("Stopping Multiplayer Session Manager...")
            self.running = False
            
            if hasattr(self, 'audit_logger') and self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        user_id=None,
                        action='multiplayer_session_manager_stop',
                        resource_type='service',
                        resource_id='multiplayer_session_manager',
                        details="Multiplayer Session Manager service stopped",
                        ip_address=None
                    )
                except Exception as e:
                    self.logger.error(f"Error logging multiplayer session manager stop event: {str(e)}")
            
            if self.cleanup_thread and self.cleanup_thread.is_alive():
                self.cleanup_thread.join(timeout=5)
            
            self.cleanup_inactive_sessions()
            
            self.active_sessions.clear()
            
            self.logger.info("Multiplayer Session Manager stopped successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping Multiplayer Session Manager: {str(e)}")
            return False
    
    def _load_active_sessions(self):
        try:
            session_data = self.db.execute(
                "SELECT * FROM multiplayer_sessions WHERE is_active = 1 AND expires_at > ?",
                (datetime.now(),)
            ).fetchall()
            
            for data in session_data:
                session = MultiplayerSession(
                    data['id'],
                    data['user_id'],
                    data['username'],
                    data['ip_address'],
                    data['user_agent'],
                    data['created_at'],
                    data['expires_at']
                )
                session.session_type = data['session_type']
                session.interactive_agent = data['interactive_agent']
                session.current_view = data['current_view']
                session.presence_status = data['presence_status']
                
                if not session.is_expired():
                    self.active_sessions[session.id] = session
            
            self.logger.info(f"Loaded {len(self.active_sessions)} active multiplayer sessions from database")
            
        except Exception as e:
            self.logger.error(f"Error loading active multiplayer sessions: {str(e)}")
    
    def _cleanup_worker(self):
        while self.running:
            try:
                time.sleep(300)  # 5 minutes
                if self.running:
                    self.cleanup_inactive_sessions()
            except Exception as e:
                self.logger.error(f"Error in multiplayer session cleanup worker: {str(e)}")
    
    def create_session(self, user_id, username, ip_address, user_agent=None, session_type='web'):
        session_id = str(uuid.uuid4())
        created_at = datetime.now()
        expires_at = created_at + timedelta(seconds=self.session_duration)
        
        session = MultiplayerSession(
            session_id,
            user_id,
            username,
            ip_address,
            user_agent,
            created_at,
            expires_at,
            session_type
        )
        
        self.db.execute(
            "INSERT INTO multiplayer_sessions (id, user_id, username, session_type, token, created_at, expires_at, last_activity, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, user_id, username, session_type, session_id, created_at, expires_at, created_at, ip_address, user_agent)
        )
        
        self.active_sessions[session_id] = session
        
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = []
        self.user_sessions[user_id].append(session_id)
        
        self._update_user_presence(user_id, username, session_id, session_type, 'available')
        
        self._broadcast_user_event('user_joined', {
            'session_id': session_id,
            'user_id': user_id,
            'username': username,
            'session_type': session_type,
            'timestamp': created_at.isoformat()
        })
        
        if hasattr(self, 'audit_logger') and self.audit_logger:
            try:
                self.audit_logger.log_event(
                    user_id=user_id,
                    action='multiplayer_session_create',
                    resource_type='session',
                    resource_id=session_id,
                    details=f"Multiplayer session created for user {username}",
                    ip_address=ip_address
                )
            except Exception as e:
                self.logger.error(f"Error logging multiplayer session create event: {str(e)}")
        
        return session
    
    def get_session(self, session_id):
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            if session.is_expired():
                self.deactivate_session(session_id)
                return None
            return session
        
        session_data = self.db.execute(
            "SELECT * FROM multiplayer_sessions WHERE id = ? AND is_active = 1",
            (session_id,)
        ).fetchone()
        
        if not session_data:
            return None
        
        session = MultiplayerSession(
            session_data['id'],
            session_data['user_id'],
            session_data['username'],
            session_data['ip_address'],
            session_data['user_agent'],
            session_data['created_at'],
            session_data['expires_at'],
            session_data['session_type']
        )
        session.interactive_agent = session_data['interactive_agent']
        session.current_view = session_data['current_view']
        session.presence_status = session_data['presence_status']
        
        if session.is_expired():
            self.deactivate_session(session_id)
            return None
        
        self.active_sessions[session_id] = session
        return session
    
    def update_activity(self, session_id):
        session = self.get_session(session_id)
        if session:
            session.update_activity()
            self.db.execute(
                "UPDATE multiplayer_sessions SET last_activity = ? WHERE id = ?",
                (session.last_activity, session_id)
            )
    
    def deactivate_session(self, session_id):
        if session_id not in self.active_sessions:
            return
            
        session = self.active_sessions[session_id]
        user_id = session.user_id
        username = session.username
        ip_address = session.ip_address
        
        for agent_id, lock_session_id in list(self.interactive_locks.items()):
            if lock_session_id == session_id:
                del self.interactive_locks[agent_id]
                self._broadcast_agent_event('interactive_lock_released', {
                    'agent_id': agent_id,
                    'session_id': session_id,
                    'username': username
                })
        
        for agent_id, session_list in list(self.agent_sessions.items()):
            if session_id in session_list:
                session_list.remove(session_id)
                self.db.execute(
                    "DELETE FROM agent_session_presence WHERE session_id = ? AND agent_id = ?",
                    (session_id, agent_id)
                )
                self._broadcast_agent_event('agent_presence_changed', {
                    'agent_id': agent_id,
                    'user_left': username,
                    'current_viewers': self.get_agent_presence(agent_id)
                })
        
        if user_id in self.user_sessions:
            if session_id in self.user_sessions[user_id]:
                self.user_sessions[user_id].remove(session_id)
        
        del self.active_sessions[session_id]
        
        self.db.execute(
            "UPDATE multiplayer_sessions SET is_active = 0 WHERE id = ?",
            (session_id,)
        )
        
        self._update_user_presence(user_id, username, session_id, session.session_type, 'offline')
        
        self._broadcast_user_event('user_left', {
            'session_id': session_id,
            'user_id': user_id,
            'username': username,
            'timestamp': datetime.now().isoformat()
        })
        
        try:
            from flask import current_app
            if hasattr(current_app, 'audit_logger'):
                current_app.audit_logger.log_event(
                    user_id=user_id,
                    action='multiplayer_session_deactivate',
                    resource_type='session',
                    resource_id=session_id,
                    details=f"Multiplayer session deactivated for user {username}",
                    ip_address=ip_address
                )
        except:
            pass
    
    def set_agent_presence(self, session_id, agent_id, presence_status='viewing'):
        session = self.get_session(session_id)
        if not session:
            return False
        
        if agent_id not in self.agent_sessions:
            self.agent_sessions[agent_id] = []
        
        if session_id not in self.agent_sessions[agent_id]:
            self.agent_sessions[agent_id].append(session_id)
            
            self.db.execute(
                "INSERT INTO agent_session_presence (agent_id, session_id, user_id, username, presence_status) VALUES (?, ?, ?, ?, ?)",
                (agent_id, session_id, session.user_id, session.username, presence_status)
            )
            
            self._broadcast_agent_event('agent_presence_changed', {
                'agent_id': agent_id,
                'user_joined': session.username,
                'current_viewers': self.get_agent_presence(agent_id)
            })
            
            if hasattr(self, 'audit_logger') and self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        user_id=session.user_id,
                        action='multiplayer_agent_presence_set',
                        resource_type='agent',
                        resource_id=agent_id,
                        details=f"User {session.username} set presence for agent {agent_id}",
                        ip_address=session.ip_address
                    )
                except Exception as e:
                    self.logger.error(f"Error logging multiplayer agent presence set event: {str(e)}")
        
        return True
    
    def remove_agent_presence(self, session_id, agent_id):
        if agent_id in self.agent_sessions and session_id in self.agent_sessions[agent_id]:
            self.agent_sessions[agent_id].remove(session_id)
            
            self.db.execute(
                "DELETE FROM agent_session_presence WHERE session_id = ? AND agent_id = ?",
                (session_id, agent_id)
            )
            
            self._broadcast_agent_event('agent_presence_changed', {
                'agent_id': agent_id,
                'user_left': self.get_session(session_id).username if self.get_session(session_id) else 'unknown',
                'current_viewers': self.get_agent_presence(agent_id)
            })
            
            session = self.get_session(session_id)
            if hasattr(self, 'audit_logger') and self.audit_logger and session:
                try:
                    self.audit_logger.log_event(
                        user_id=session.user_id,
                        action='multiplayer_agent_presence_remove',
                        resource_type='agent',
                        resource_id=agent_id,
                        details=f"User {session.username} removed presence for agent {agent_id}",
                        ip_address=session.ip_address
                    )
                except Exception as e:
                    self.logger.error(f"Error logging multiplayer agent presence remove event: {str(e)}")
    
    def get_agent_presence(self, agent_id):
        if agent_id not in self.agent_sessions:
            return []
        
        viewers = []
        for session_id in self.agent_sessions[agent_id]:
            session = self.active_sessions.get(session_id)
            if session:
                viewers.append({
                    'username': session.username,
                    'session_id': session_id,
                    'session_type': session.session_type,
                    'presence_status': session.presence_status
                })
        
        return viewers
    
    def request_interactive_lock(self, session_id, agent_id):
        session = self.get_session(session_id)
        if not session:
            return {'success': False, 'message': 'Session not found'}
        
        if agent_id in self.interactive_locks:
            existing_lock_session_id = self.interactive_locks[agent_id]
            if existing_lock_session_id != session_id:
                existing_session = self.active_sessions.get(existing_lock_session_id)
                if existing_session:
                    return {
                        'success': False, 
                        'message': f'Agent {agent_id} is currently locked by {existing_session.username}'
                    }
        
        self.interactive_locks[agent_id] = session_id
        session.interactive_agent = agent_id
        
        self.db.execute(
            "UPDATE multiplayer_sessions SET interactive_agent = ? WHERE id = ?",
            (agent_id, session_id)
        )
        
        self._broadcast_agent_event('interactive_lock_acquired', {
            'agent_id': agent_id,
            'username': session.username,
            'session_id': session_id
        })
        
        if hasattr(self, 'audit_logger') and self.audit_logger:
            try:
                self.audit_logger.log_event(
                    user_id=session.user_id,
                    action='multiplayer_interactive_lock_acquire',
                    resource_type='agent',
                    resource_id=agent_id,
                    details=f"User {session.username} acquired interactive lock on agent {agent_id}",
                    ip_address=None
                )
            except Exception as e:
                self.logger.error(f"Error logging multiplayer interactive lock acquire event: {str(e)}")
        
        return {'success': True, 'message': f'Interactive lock acquired for agent {agent_id}'}
    
    def release_interactive_lock(self, session_id, agent_id):
        session = self.get_session(session_id)
        if not session:
            return {'success': False, 'message': 'Session not found'}
        
        if agent_id in self.interactive_locks and self.interactive_locks[agent_id] == session_id:
            del self.interactive_locks[agent_id]
            session.interactive_agent = None
            
            self.db.execute(
                "UPDATE multiplayer_sessions SET interactive_agent = NULL WHERE id = ?",
                (session_id,)
            )
            
            self._broadcast_agent_event('interactive_lock_released', {
                'agent_id': agent_id,
                'username': session.username,
                'session_id': session_id
            })
            
            if hasattr(self, 'audit_logger') and self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        user_id=session.user_id,
                        action='multiplayer_interactive_lock_release',
                        resource_type='agent',
                        resource_id=agent_id,
                        details=f"User {session.username} released interactive lock on agent {agent_id}",
                        ip_address=None
                    )
                except Exception as e:
                    self.logger.error(f"Error logging multiplayer interactive lock release event: {str(e)}")
            
            return {'success': True, 'message': f'Interactive lock released for agent {agent_id}'}
        
        return {'success': False, 'message': 'No interactive lock to release'}
    
    def get_session_stats(self):
        web_sessions = [s for s in self.active_sessions.values() if s.session_type == 'web']
        cli_sessions = [s for s in self.active_sessions.values() if s.session_type == 'cli']
        
        return {
            'total_sessions': len(self.active_sessions),
            'web_sessions': len(web_sessions),
            'cli_sessions': len(cli_sessions),
            'total_users': len(set(s.user_id for s in self.active_sessions.values())),
            'agent_interactions': len(self.interactive_locks),
            'agent_sessions': {aid: len(sessions) for aid, sessions in self.agent_sessions.items()}
        }
    
    def get_user_presence_list(self):
        users = []
        for session in self.active_sessions.values():
            users.append({
                'username': session.username,
                'user_id': session.user_id,
                'session_id': session.id,
                'session_type': session.session_type,
                'presence_status': session.presence_status,
                'last_activity': session.last_activity.isoformat(),
                'interactive_agent': session.interactive_agent
            })
        return users
    
    def _update_user_presence(self, user_id, username, session_id, session_type, status):
        if status == 'offline':
            self.db.execute(
                "DELETE FROM user_presence WHERE user_id = ? AND session_id = ?",
                (user_id, session_id)
            )
        else:
            self.db.execute('''
                INSERT OR REPLACE INTO user_presence 
                (user_id, username, session_id, session_type, presence_status, last_activity) 
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, username, session_id, session_type, status, datetime.now()))
    
    def _broadcast_user_event(self, event_type, data):
        if self.socketio:
            try:
                self.socketio.emit(event_type, data, namespace='/multiplayer')
            except Exception as e:
                self.logger.error(f"Error broadcasting user event {event_type}: {str(e)}")
    
    def _broadcast_agent_event(self, event_type, data):
        """Broadcast agent-related events"""
        if self.socketio:
            try:
                self.socketio.emit(event_type, data, namespace='/agents')
            except Exception as e:
                self.logger.error(f"Error broadcasting agent event {event_type}: {str(e)}")
    
    def cleanup_inactive_sessions(self):
        expired_sessions = []
        for session_id, session in self.active_sessions.items():
            if session.is_expired():
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.deactivate_session(session_id)
        
        expired_sessions = self.db.execute(
            "SELECT id FROM multiplayer_sessions WHERE expires_at < ? AND is_active = 1",
            (datetime.now(),)
        ).fetchall()
        
        for session_data in expired_sessions:
            self.deactivate_session(session_data['id'])
