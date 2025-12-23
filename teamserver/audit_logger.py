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

class AuditLogger:
    def __init__(self, db):
        self.db = db
        self.running = False
        self.log_buffer = []
        self.buffer_size = 100  # Buffer logs before writing to database
        self.flush_interval = 30  # Flush buffer every 30 seconds
        self.flush_thread = None
        self.logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.lock = threading.Lock()
        self.setup_db()
    
    def setup_db(self):
        self.db.execute('''
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
        
        self.db.execute('''
            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp 
            ON audit_log(timestamp)
        ''')
        
        self.db.execute('''
            CREATE INDEX IF NOT EXISTS idx_audit_log_user_id 
            ON audit_log(user_id)
        ''')
        
        self.db.execute('''
            CREATE INDEX IF NOT EXISTS idx_audit_log_action 
            ON audit_log(action)
        ''')
    
    def start(self):
        if self.running:
            return True
        
        try:
            self.logger.info("Starting Audit Logger...")
            self.running = True
            
            self.flush_thread = threading.Thread(target=self._buffer_worker)
            self.flush_thread.daemon = True
            self.flush_thread.start()
            
            self.logger.info("Audit Logger started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting Audit Logger: {str(e)}")
            return False
    
    def stop(self):
        if not self.running:
            return True
        
        try:
            self.logger.info("Stopping Audit Logger...")
            self.running = False
            
            if self.flush_thread and self.flush_thread.is_alive():
                self.flush_thread.join(timeout=5)
            
            self._flush_buffer()
            
            self.logger.info("Audit Logger stopped successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping Audit Logger: {str(e)}")
            return False
    
    def _buffer_worker(self):
        while self.running:
            try:
                time.sleep(self.flush_interval)
                if self.running:
                    self._flush_buffer()
            except Exception as e:
                self.logger.error(f"Error in audit log buffer worker: {str(e)}")
    
    def _flush_buffer(self):
        with self.lock:
            if not self.log_buffer:
                return
            
            try:
                logs_to_flush = self.log_buffer.copy()
                self.log_buffer.clear()
                
                with self.db.get_cursor() as cursor:
                    for log in logs_to_flush:
                        cursor.execute('''
                            INSERT INTO audit_log 
                            (id, user_id, action, resource_type, resource_id, details, ip_address, timestamp) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            log['id'],
                            log['user_id'],
                            log['action'],
                            log['resource_type'],
                            log['resource_id'],
                            log['details'],
                            log['ip_address'],
                            log['timestamp']
                        ))
                
                if logs_to_flush:
                    self.logger.info(f"Flushed {len(logs_to_flush)} audit logs to database")
                
            except Exception as e:
                self.logger.error(f"Error flushing audit log buffer: {str(e)}")
                self.log_buffer.extend(logs_to_flush)
    
    def log_event(self, user_id, action, resource_type, resource_id, details, ip_address):
        event_id = str(uuid.uuid4())
        timestamp = datetime.now()
        
        log_entry = {
            'id': event_id,
            'user_id': user_id,
            'action': action,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'details': details,
            'ip_address': ip_address,
            'timestamp': timestamp
        }
        
        with self.lock:
            self.log_buffer.append(log_entry)
            
            if len(self.log_buffer) >= self.buffer_size:
                self._flush_buffer()
    
    def get_logs(self, limit=100, offset=0):
        self._flush_buffer()
        
        logs = []
        log_data = self.db.execute(
            "SELECT al.*, u.username FROM audit_log al LEFT JOIN users u ON al.user_id = u.id ORDER BY al.timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ).fetchall()
        
        for data in log_data:
            username = data['username']
            display_username = username if username is not None else 'misc'
            
            if data['resource_type'] == 'agent' and data['resource_id']:
                display_username = data['resource_id'][:6] if len(data['resource_id']) >= 6 else data['resource_id']
            elif data['resource_type'] == 'agent_task' and data['details']:
                try:
                    details_dict = json.loads(data['details'])
                    agent_id = details_dict.get('agent_id')
                    if agent_id:
                        display_username = agent_id[:6] if len(agent_id) >= 6 else agent_id
                except (json.JSONDecodeError, TypeError):
                    pass
            
            logs.append({
                "id": data['id'],
                "user_id": data['user_id'],
                "username": display_username,
                "action": data['action'],
                "resource_type": data['resource_type'],
                "resource_id": data['resource_id'],
                "details": data['details'],
                "ip_address": data['ip_address'],
                "timestamp": str(data['timestamp'])
            })
        
        return logs
    
    def get_user_logs(self, user_id, limit=100, offset=0):
        self._flush_buffer()
        
        logs = []
        log_data = self.db.execute(
            "SELECT * FROM audit_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (user_id, limit, offset)
        ).fetchall()
        
        for data in log_data:
            logs.append({
                "id": data['id'],
                "user_id": data['user_id'],
                "action": data['action'],
                "resource_type": data['resource_type'],
                "resource_id": data['resource_id'],
                "details": data['details'],
                "ip_address": data['ip_address'],
                "timestamp": str(data['timestamp'])
            })
        
        return logs
    
    def get_resource_logs(self, resource_type, resource_id, limit=100, offset=0):
        self._flush_buffer()
        
        logs = []
        log_data = self.db.execute(
            "SELECT al.*, u.username FROM audit_log al LEFT JOIN users u ON al.user_id = u.id WHERE al.resource_type = ? AND al.resource_id = ? ORDER BY al.timestamp DESC LIMIT ? OFFSET ?",
            (resource_type, resource_id, limit, offset)
        ).fetchall()
        
        for data in log_data:
            username = data['username']
            display_username = username if username is not None else 'misc'
            
            if data['resource_type'] == 'agent' and data['resource_id']:
                display_username = data['resource_id'][:6] if len(data['resource_id']) >= 6 else data['resource_id']
            elif data['resource_type'] == 'agent_task' and data['details']:
                try:
                    details_dict = json.loads(data['details'])
                    agent_id = details_dict.get('agent_id')
                    if agent_id:
                        display_username = agent_id[:6] if len(agent_id) >= 6 else agent_id
                except (json.JSONDecodeError, TypeError):
                    pass
            
            logs.append({
                "id": data['id'],
                "user_id": data['user_id'],
                "username": display_username,
                "action": data['action'],
                "resource_type": data['resource_type'],
                "resource_id": data['resource_id'],
                "details": data['details'],
                "ip_address": data['ip_address'],
                "timestamp": str(data['timestamp'])
            })
        
        return logs
    
    def search_logs(self, query, limit=100, offset=0):
        self._flush_buffer()
        
        logs = []
        search_query = "%"
        for term in query.split():
            search_query += f"%{term}%"
        
        log_data = self.db.execute(
            "SELECT al.*, u.username FROM audit_log al LEFT JOIN users u ON al.user_id = u.id WHERE al.action LIKE ? OR al.details LIKE ? OR u.username LIKE ? ORDER BY al.timestamp DESC LIMIT ? OFFSET ?",
            (search_query, search_query, search_query, limit, offset)
        ).fetchall()
        
        for data in log_data:
            username = data['username']
            display_username = username if username is not None else 'misc'
            
            if data['resource_type'] == 'agent' and data['resource_id']:
                display_username = data['resource_id'][:6] if len(data['resource_id']) >= 6 else data['resource_id']
            elif data['resource_type'] == 'agent_task' and data['details']:
                try:
                    details_dict = json.loads(data['details'])
                    agent_id = details_dict.get('agent_id')
                    if agent_id:
                        display_username = agent_id[:6] if len(agent_id) >= 6 else agent_id
                except (json.JSONDecodeError, TypeError):
                    pass
            
            logs.append({
                "id": data['id'],
                "user_id": data['user_id'],
                "username": display_username,
                "action": data['action'],
                "resource_type": data['resource_type'],
                "resource_id": data['resource_id'],
                "details": data['details'],
                "ip_address": data['ip_address'],
                "timestamp": str(data['timestamp'])
            })
        
        return logs
    
    def get_log_stats(self):
        self._flush_buffer()
        
        stats = {}
        
        total_logs = self.db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        stats['total_logs'] = total_logs
        
        action_stats = self.db.execute(
            "SELECT action, COUNT(*) as count FROM audit_log GROUP BY action ORDER BY count DESC"
        ).fetchall()
        stats['by_action'] = {row['action']: row['count'] for row in action_stats}
        
        log_data = self.db.execute(
            "SELECT al.user_id, u.username, al.resource_type, al.resource_id, al.details FROM audit_log al LEFT JOIN users u ON al.user_id = u.id"
        ).fetchall()
        
        stats['by_user'] = {}
        for row in log_data:
            username = row['username']
            key = username if username is not None else 'misc'
            
            if row['resource_type'] == 'agent' and row['resource_id']:
                key = row['resource_id'][:6] if len(row['resource_id']) >= 6 else row['resource_id']
            elif row['resource_type'] == 'agent_task' and row['details']:
                try:
                    details_dict = json.loads(row['details'])
                    agent_id = details_dict.get('agent_id')
                    if agent_id:
                        key = agent_id[:6] if len(agent_id) >= 6 else agent_id
                except (json.JSONDecodeError, TypeError):
                    pass
            
            stats['by_user'][key] = stats['by_user'].get(key, 0) + 1
        
        recent_logs = self.db.execute(
            "SELECT COUNT(*) FROM audit_log WHERE timestamp >= datetime('now', '-1 day')"
        ).fetchone()[0]
        stats['recent_24h'] = recent_logs
        
        return stats
    
    def cleanup_old_logs(self, days_to_keep=90):
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        with self.db.get_cursor() as cursor:
            deleted_count = cursor.execute(
                "DELETE FROM audit_log WHERE timestamp < ?",
                (cutoff_date,)
            ).rowcount
        
        self.logger.info(f"Cleaned up {deleted_count} old audit log entries (older than {days_to_keep} days)")
        return deleted_count
