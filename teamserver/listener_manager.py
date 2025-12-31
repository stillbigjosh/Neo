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

import uuid
import threading
import sqlite3
from datetime import datetime
from core.models import NeoC2DB
from listeners.listener import TCPListener, BaseListener
from listeners.http_listener_process import HTTPListenerProcessManager

class ListenerManager:
    def __init__(self, config, db):
        self.config = config
        self.db = db  # This is the NeoC2DB instance
        self.listeners = {}  # In-memory dictionary for RUNNING non-HTTP listener instances
        self.http_listener_manager = HTTPListenerProcessManager(config, db)  # Separate manager for HTTP listeners

    def create_listener(self, listener_type, **kwargs):
        try:
            name = kwargs.get('name')
            if not name:
                return {"success": False, "error": "Listener name is required."}

            if self.db.get_listener_by_name(name):
                return {"success": False, "error": f"Listener with name '{name}' already exists."}

            listener_id = str(uuid.uuid4())
            
            self.db.create_listener(
                listener_id=listener_id,
                name=name,
                listener_type=listener_type,
                host=kwargs.get('host', '0.0.0.0'),
                port=kwargs.get('port'),
                profile_name=kwargs.get('profile_name', 'default'),
                config=None
            )
            
            if listener_type in ['http', 'https']:
                return {
                    "success": True, 
                    "listener_id": listener_id,
                    "message": f"HTTP listener '{name}' created. Start it to activate on its own port."
                }
            else:
                return {
                    "success": True, 
                    "listener_id": listener_id,
                    "message": f"Listener '{name}' created. Start it to activate."
                }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def start_listener(self, listener_id):
        try:
            listener_data = self.db.get_listener(listener_id)
            if not listener_data:
                return {"success": False, "error": f"Listener {listener_id} not found"}

            listener_type = listener_data['type']

            if listener_type in ['http', 'https']:
                return self.http_listener_manager.start_listener(listener_id)
            
            if listener_data['status'] == 'running' and listener_id in self.listeners:
                return {"success": True, "message": "Listener is already running."}

            listener_class_map = {
                'tcp': TCPListener, 'smb': TCPListener
            }

            if listener_type not in listener_class_map:
                return {"success": False, "error": f"Unsupported listener type: {listener_type}"}
        
            listener_class = listener_class_map[listener_type]
            listener = listener_class(
                config=self.config, db=self.db, id=listener_data['id'],
                name=listener_data['name'], host=listener_data['host'],
                port=listener_data['port'], profile_name=listener_data['profile_name'],
                use_https=(listener_type == 'https')
            )
        
            self.listeners[listener_id] = listener
        
            listener.start()
            status_message = f"Listener {listener_data['name']} started on port {listener_data['port']}"
        
            self.db.update_listener_status(listener_id, 'running')
        
            return {"success": True, "message": status_message}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def stop_listener(self, listener_id):
        try:
            listener_data = self.db.get_listener(listener_id)
            if not listener_data:
                return {"success": False, "error": f"Listener {listener_id} not found."}

            listener_type = listener_data['type']

            if listener_type in ['http', 'https']:
                return self.http_listener_manager.stop_listener(listener_id)
            
            if listener_id in self.listeners:
                self.listeners[listener_id].stop()
                del self.listeners[listener_id]
            
            self.db.update_listener_status(listener_id, 'stopped')
            
            return {"success": True, "message": f"Listener {listener_data['name']} stopped."}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_listeners(self):
        try:
            listeners = self.db.get_listeners()
            return {"success": True, "listeners": listeners}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_listener(self, listener_id):
        try:
            listener_data = self.db.get_listener(listener_id)
            if not listener_data:
                return {"success": False, "error": "Listener not found."}
            
            listener_type = listener_data['type']

            if listener_type in ['http', 'https']:
                return self.http_listener_manager.get_listener(listener_id)
            else:
                listener = self.db.get_listener(listener_id)
                if not listener:
                    return {"success": False, "error": "Listener not found."}
                return {"success": True, "listener": listener}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def delete_listener(self, listener_id):
        try:
            listener_data = self.db.get_listener(listener_id)
            if not listener_data:
                return {"success": False, "error": "Listener not found."}

            listener_type = listener_data['type']

            if listener_type in ['http', 'https']:
                if listener_id in self.http_listener_manager.listeners:
                    self.http_listener_manager.stop_listener(listener_id)
            else:
                if listener_id in self.listeners:
                    self.listeners[listener_id].stop()
                    del self.listeners[listener_id]

            self.db.delete_listener(listener_id)
            
            return {"success": True, "message": "Listener deleted successfully."}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def start_all(self):
        try:
            http_result = self.http_listener_manager.start_all()
            http_started = 0
            if http_result.get('success'):
                if "started" in http_result.get('message', ''):
                    try:
                        http_started = int(http_result['message'].split()[1])
                    except:
                        http_started = 0
            
            non_http_listeners = [
                l for l in self.db.get_listeners(status='running') 
                if l['type'] not in ['http', 'https']
            ]
            
            started_count = 0
            for listener in non_http_listeners:
                result = self.start_listener(listener['id'])
                if result.get('success'):
                    started_count += 1
            
            total_started = http_started + started_count
            return {
                "success": True, 
                "message": f"Started {total_started} listeners ({http_started} HTTP, {started_count} non-HTTP)."
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def stop_all(self):
        try:
            http_result = self.http_listener_manager.stop_all()
            http_stopped = 0
            if http_result.get('success'):
                if "stopped" in http_result.get('message', ''):
                    try:
                        http_stopped = int(http_result['message'].split()[1])
                    except:
                        http_stopped = 0
            
            stopped_count = 0
            for listener_id in list(self.listeners.keys()):
                result = self.stop_listener(listener_id)
                if result.get('success'):
                    stopped_count += 1
            
            total_stopped = http_stopped + stopped_count
            return {
                "success": True, 
                "message": f"Stopped {total_stopped} listeners ({http_stopped} HTTP, {stopped_count} non-HTTP)."
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    def create_http_listener_for_web_app(self, name, profile_name='default'):
        try:
            existing = self.db.get_listener_by_name(name)
            if existing:
                return {"success": True, "listener_id": existing['id'], "message": "Listener already exists"}
        
            listener_id = str(uuid.uuid4())
        
            web_host = self.config.get('web.host', '0.0.0.0')
            web_port = self.config.get('web.port', 443)
        
            self.db.create_listener(
                listener_id=listener_id,
                name=name,
                listener_type='http', 
                host=web_host,
                port=web_port,
                profile_name=profile_name,
                config={'integrated_with_web_app': True}  # Mark as integrated
            )
        
        
            return {
                "success": True, 
                "listener_id": listener_id,
                "message": f"HTTP listener '{name}' created and integrated with web app"
            }
        
        except Exception as e:
            return {"success": False, "error": str(e)}


