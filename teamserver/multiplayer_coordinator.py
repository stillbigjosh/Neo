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
import threading
import logging
import time
from datetime import datetime
from gevent import queue
from core.models import NeoC2DB
from flask_socketio import SocketIO


class MultiplayerCoordinator:    
    def __init__(self, db, socketio=None):
        self.db = db
        self.socketio = socketio
        self.logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        
        self.agent_monitors = {}  # agent_id -> set of session_ids
        self.agent_command_queues = {}  # agent_id -> queue of commands
        self.agent_result_queues = {}  # agent_id -> queue of results
        
        self.session_user_map = {}  # session_id -> user info
        self.user_session_map = {}  # user_id -> set of session_ids
        
        self.command_broadcast_queue = queue.Queue()
        self.result_broadcast_queue = queue.Queue()
        
        self.audit_logger = None  # Will be set by framework if available
        
        self.running = False
        self.broadcast_thread = None
        self.command_thread = None
        self.result_thread = None
        
    def start(self):
        if self.running:
            return True
            
        try:
            self.logger.info("Starting Multiplayer Coordinator Service...")
            self.running = True
            
            if not self.audit_logger:
                try:
                    from teamserver.audit_logger import AuditLogger
                    self.audit_logger = AuditLogger(self.db)
                except ImportError:
                    self.audit_logger = None
                    self.logger.warning("Could not initialize audit logger")
            
            self.broadcast_thread = threading.Thread(target=self._process_broadcasts)
            self.broadcast_thread.daemon = True
            self.broadcast_thread.start()
            
            self.command_thread = threading.Thread(target=self._process_commands)
            self.command_thread.daemon = True
            self.command_thread.start()
            
            self.result_thread = threading.Thread(target=self._process_results)
            self.result_thread.daemon = True
            self.result_thread.start()
            
            if self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        user_id=None,
                        action='multiplayer_coordinator_start',
                        resource_type='service',
                        resource_id='multiplayer_coordinator',
                        details="Multiplayer Coordinator service started",
                        ip_address=None
                    )
                except Exception as e:
                    self.logger.error(f"Error logging multiplayer coordinator start event: {str(e)}")
            
            self.logger.info("Multiplayer Coordinator Service started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting Multiplayer Coordinator: {str(e)}")
            return False
    
    def stop(self):
        if not self.running:
            return True
            
        try:
            self.logger.info("Stopping Multiplayer Coordinator Service...")
            self.running = False
            
            if self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        user_id=None,
                        action='multiplayer_coordinator_stop',
                        resource_type='service',
                        resource_id='multiplayer_coordinator',
                        details="Multiplayer Coordinator service stopped",
                        ip_address=None
                    )
                except Exception as e:
                    self.logger.error(f"Error logging multiplayer coordinator stop event: {str(e)}")
            
            if self.broadcast_thread and self.broadcast_thread.is_alive():
                self.broadcast_thread.join(timeout=2)
            if self.command_thread and self.command_thread.is_alive():
                self.command_thread.join(timeout=2)
            if self.result_thread and self.result_thread.is_alive():
                self.result_thread.join(timeout=2)
            
            self.logger.info("Multiplayer Coordinator Service stopped successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping Multiplayer Coordinator: {str(e)}")
            return False
    
    def add_agent_monitor(self, session_id, agent_id, username):
        if agent_id not in self.agent_monitors:
            self.agent_monitors[agent_id] = set()
        
        self.agent_monitors[agent_id].add(session_id)
        
        self.session_user_map[session_id] = {
            'username': username,
            'joined_at': datetime.now().isoformat(),
            'session_id': session_id
        }
        
        user_info = self._get_user_info(username)
        if user_info:
            user_id = user_info['id']
            if user_id not in self.user_session_map:
                self.user_session_map[user_id] = set()
            self.user_session_map[user_id].add(session_id)
        
        self._broadcast_agent_event('agent_monitored', {
            'agent_id': agent_id,
            'username': username,
            'session_id': session_id,
            'action': 'start_monitoring'
        })
        
        if self.audit_logger:
            try:
                user_info = self._get_user_info(username)
                user_id = user_info['id'] if user_info else None
                self.audit_logger.log_event(
                    user_id=user_id,
                    action='multiplayer_agent_monitor_start',
                    resource_type='agent',
                    resource_id=agent_id,
                    details=f"User {username} started monitoring agent {agent_id}",
                    session_id=session_id
                )
            except Exception as e:
                self.logger.error(f"Error logging multiplayer agent monitor event: {str(e)}")
        
        self.logger.info(f"Session {session_id} ({username}) started monitoring agent {agent_id}")
        return True
    
    def remove_agent_monitor(self, session_id, agent_id):
        if agent_id in self.agent_monitors:
            if session_id in self.agent_monitors[agent_id]:
                self.agent_monitors[agent_id].remove(session_id)
                
                if session_id in self.session_user_map:
                    username = self.session_user_map[session_id]['username']
                    del self.session_user_map[session_id]
                    
                    user_info = self._get_user_info(username)
                    if user_info:
                        user_id = user_info['id']
                        if user_id in self.user_session_map and session_id in self.user_session_map[user_id]:
                            self.user_session_map[user_id].remove(session_id)
                
                if len(self.agent_monitors[agent_id]) == 0:
                    del self.agent_monitors[agent_id]
                    
                self._broadcast_agent_event('agent_monitored', {
                    'agent_id': agent_id,
                    'username': self.session_user_map.get(session_id, {}).get('username', 'unknown'),
                    'session_id': session_id,
                    'action': 'stop_monitoring'
                })
                
                if self.audit_logger:
                    try:
                        user_info = self._get_user_info(username)
                        user_id = user_info['id'] if user_info else None
                        self.audit_logger.log_event(
                            user_id=user_id,
                            action='multiplayer_agent_monitor_stop',
                            resource_type='agent',
                            resource_id=agent_id,
                            details=f"User {username} stopped monitoring agent {agent_id}",
                            session_id=session_id
                        )
                    except Exception as e:
                        self.logger.error(f"Error logging multiplayer agent unmonitor event: {str(e)}")
                
                self.logger.info(f"Session {session_id} stopped monitoring agent {agent_id}")
                return True
        
        return False
    
    def broadcast_command(self, command_data):
        agent_id = command_data.get('agent_id')
        username = command_data.get('username', 'system')
        command = command_data.get('command', 'unknown')
        
        if agent_id in self.agent_monitors:
            broadcast_data = {
                'type': 'command',
                'data': command_data,
                'timestamp': datetime.now().isoformat(),
                'source_user': username
            }
            self.command_broadcast_queue.put(broadcast_data)
        
        if self.audit_logger and agent_id in self.agent_monitors:
            try:
                # Get user_id from username
                user_info = self._get_user_info(username)
                user_id = user_info['id'] if user_info else None
                
                self.audit_logger.log_event(
                    user_id=user_id,
                    action='multiplayer_command_broadcast',
                    resource_type='agent',
                    resource_id=agent_id,
                    details=f"Command '{command}' broadcast to {len(self.agent_monitors.get(agent_id, []))} monitoring sessions",
                    ip_address=None
                )
            except Exception as e:
                self.logger.error(f"Error logging multiplayer command broadcast event: {str(e)}")
        
        return True
    
    def broadcast_result(self, result_data):
        agent_id = result_data.get('agent_id')
        task_id = result_data.get('task_id', 'unknown')
        result_short = str(result_data.get('result', ''))[:100]  # Take first 100 chars of result
        
        if agent_id in self.agent_monitors:
            broadcast_data = {
                'type': 'result',
                'data': result_data,
                'timestamp': datetime.now().isoformat()
            }
            self.result_broadcast_queue.put(broadcast_data)
        
        if self.audit_logger and agent_id in self.agent_monitors:
            try:
                self.audit_logger.log_event(
                    user_id=None,  # Results typically come from agents, not users
                    action='multiplayer_result_broadcast',
                    resource_type='agent',
                    resource_id=agent_id,
                    details=f"Result for task {task_id} broadcast to {len(self.agent_monitors.get(agent_id, []))} monitoring sessions",
                    ip_address=None
                )
            except Exception as e:
                self.logger.error(f"Error logging multiplayer result broadcast event: {str(e)}")
        
        return True
    
    def get_agent_monitors(self, agent_id):
        if agent_id not in self.agent_monitors:
            return []
        
        monitors = []
        for session_id in self.agent_monitors[agent_id]:
            if session_id in self.session_user_map:
                monitors.append(self.session_user_map[session_id])
        
        return monitors
    
    def get_user_sessions(self, user_id):
        if user_id in self.user_session_map:
            return list(self.user_session_map[user_id])
        return []
    
    def _process_broadcasts(self):
        while self.running:
            try:
                try:
                    cmd_broadcast = self.command_broadcast_queue.get(timeout=0.1)
                    self._emit_to_agent_monitors(cmd_broadcast['data']['agent_id'], 'command_broadcast', cmd_broadcast)
                except queue.Empty:
                    pass
                
                try:
                    result_broadcast = self.result_broadcast_queue.get(timeout=0.1)
                    self._emit_to_agent_monitors(result_broadcast['data']['agent_id'], 'result_broadcast', result_broadcast)
                except queue.Empty:
                    pass
                
            except Exception as e:
                self.logger.error(f"Error in broadcast processing: {str(e)}")
                time.sleep(0.1)  # Prevent tight loop on error
    
    def _process_commands(self):
        while self.running:
            try:
                time.sleep(0.1)  # Small delay to prevent tight loop
            except Exception as e:
                self.logger.error(f"Error in command processing: {str(e)}")
                break
    
    def _process_results(self):
        while self.running:
            try:
                time.sleep(0.1)  # Small delay to prevent tight loop
            except Exception as e:
                self.logger.error(f"Error in result processing: {str(e)}")
                break
    
    def _emit_to_agent_monitors(self, agent_id, event_type, data):
        if self.socketio and agent_id in self.agent_monitors:
            for session_id in self.agent_monitors[agent_id]:
                try:
                    self.socketio.emit(event_type, data, room=session_id, namespace='/multiplayer')
                except Exception as e:
                    self.logger.error(f"Error emitting to session {session_id}: {str(e)}")
    
    def _get_user_info(self, username):
        try:
            user_data = self.db.execute(
                "SELECT id, username, role_id FROM users WHERE username = ? AND is_active = 1",
                (username,)
            ).fetchone()
            
            if user_data:
                role_data = self.db.execute(
                    "SELECT name, permissions FROM roles WHERE id = ?",
                    (user_data['role_id'],)
                ).fetchone()
                
                return {
                    'id': user_data['id'],
                    'username': user_data['username'],
                    'role_id': user_data['role_id'],
                    'role_name': role_data['name'] if role_data else 'unknown',
                    'permissions': json.loads(role_data['permissions']) if role_data and role_data['permissions'] else []
                }
        except Exception as e:
            self.logger.error(f"Error getting user info for {username}: {str(e)}")
        
        return None
    
    def _broadcast_agent_event(self, event_type, data):
        if self.socketio:
            try:
                self.socketio.emit(event_type, data, namespace='/agents')
            except Exception as e:
                self.logger.error(f"Error broadcasting agent event {event_type}: {str(e)}")
    
    def add_user_session(self, session_id, user_id, username, ip_address, session_type='remote_cli'):
        self.session_user_map[session_id] = {
            'user_id': user_id,
            'username': username,
            'ip_address': ip_address,
            'session_type': session_type,
            'joined_at': datetime.now().isoformat(),
            'session_id': session_id
        }
        
        if user_id not in self.user_session_map:
            self.user_session_map[user_id] = set()
        self.user_session_map[user_id].add(session_id)
        
        if self.audit_logger:
            try:
                self.audit_logger.log_event(
                    user_id=user_id,
                    action='multiplayer_coordinator_user_session_add',
                    resource_type='session',
                    resource_id=session_id,
                    details=f"User {username} added to multiplayer coordinator",
                    ip_address=ip_address
                )
            except Exception as e:
                self.logger.error(f"Error logging multiplayer coordinator user session add event: {str(e)}")
        
        self.logger.info(f"Added user session {session_id} for user {username}")
        return True

    def remove_user_session(self, session_id):
        """Remove a user session from the coordinator - for remote CLI integration"""
        if session_id in self.session_user_map:
            session_info = self.session_user_map[session_id]
            username = session_info['username']
            user_id = session_info['user_id']
            ip_address = session_info.get('ip_address', None)
            
            del self.session_user_map[session_id]
            
            if user_id in self.user_session_map and session_id in self.user_session_map[user_id]:
                self.user_session_map[user_id].remove(session_id)
                if len(self.user_session_map[user_id]) == 0:
                    del self.user_session_map[user_id]
            
            for agent_id, session_set in list(self.agent_monitors.items()):
                if session_id in session_set:
                    session_set.remove(session_id)
                    if len(session_set) == 0:
                        del self.agent_monitors[agent_id]
            
            if self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        user_id=user_id,
                        action='multiplayer_coordinator_user_session_remove',
                        resource_type='session',
                        resource_id=session_id,
                        details=f"User {username} removed from multiplayer coordinator",
                        ip_address=ip_address
                    )
                except Exception as e:
                    self.logger.error(f"Error logging multiplayer coordinator user session remove event: {str(e)}")
            
            self.logger.info(f"Removed user session {session_id} for user {username}")
            return True
        
        return False

    def get_coordinator_stats(self):
        total_monitors = sum(len(sessions) for sessions in self.agent_monitors.values())
        total_users = len(self.user_session_map)
        
        return {
            'agent_monitors': len(self.agent_monitors),
            'total_monitors': total_monitors,
            'total_users': total_users,
            'command_queue_size': self.command_broadcast_queue.qsize(),
            'result_queue_size': self.result_broadcast_queue.qsize()
        }
