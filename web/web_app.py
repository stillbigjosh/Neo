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
import base64
import uuid
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory, flash
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import threading  

from core.config import NeoC2Config
from core.models import NeoC2DB
from teamserver.module_manager import ModuleManager


from core.payload_storage import get_uploaded_payload, set_uploaded_payload, clear_uploaded_payload

# Import new separated blueprints
from web.routes_auth import bp as auth_bp
from web.routes_registration import bp as registration_bp
from web.routes_user_management import bp as user_management_bp
from web.routes_dashboard import bp as dashboard_bp

from teamserver.session_manager import SessionManager
from teamserver.user_manager import UserManager
from teamserver.role_manager import RoleManager
from teamserver.audit_logger import AuditLogger
from teamserver.listener_manager import ListenerManager
from teamserver.agent_manager import AgentManager

from web.multi_port_endpoint_discovery import MultiPortEndpointDiscovery

from web.routes_agent_comms import bp as agent_comms_bp, init_agent_comms

from flask_socketio import SocketIO



class User(UserMixin):
    def __init__(self, id, username, role_name='viewer'):
        self.id = id
        self.username = username
        self.role_name = role_name
class NeoC2Web:
    def __init__(self, config, db, module_manager,
                 session_manager=None, user_manager=None, role_manager=None, agent_manager=None, task_orchestrator=None):
        self.app = Flask(__name__,
                        template_folder='templates',
                        static_folder='static')
        self.app.secret_key = config.get("web.secret_key")

        self.agent_manager = agent_manager
        self.task_orchestrator = task_orchestrator
        
        self.app.agent_manager = agent_manager
        self.app.config['AGENT_MANAGER'] = agent_manager
        
        self.listener_manager = None
        
        CORS(self.app)
        
        self.app.register_blueprint(auth_bp)  # Auth routes (login, logout)
        self.app.register_blueprint(dashboard_bp)  # Dashboard for non-admin users

        self.app.register_blueprint(agent_comms_bp)
        self.app.register_blueprint(registration_bp)
        self.app.register_blueprint(user_management_bp)

        init_agent_comms(self.agent_manager)  # Pass the shared instance instead of db
        
        from web.routes_agent_comms import init_endpoint_discovery, endpoint_discovery
        init_endpoint_discovery(self.app)
        
        self.db = db
        self.config = config
        self.module_manager = module_manager
        self.session_manager = session_manager
        self.user_manager = user_manager
        self.role_manager = role_manager
        
        self.listener_manager = ListenerManager(config, db)
        self.audit_logger = AuditLogger(db)
        
        self.multi_port_discovery = MultiPortEndpointDiscovery(self.app, self.listener_manager)
        
        self.multi_port_discovery.start()
        
        self.app.multi_port_discovery = self.multi_port_discovery
        
        self.protocol_multiplexer = None
        self.protocol_negotiator = None
        
        try:
            self.module_manager.add_default_modules()
        except Exception as e:
            print(f"Warning: Could not load default modules: {str(e)}")
        
        self.app.db = db
        self.app.config_obj = config
        self.app.config['task_orchestrator'] = task_orchestrator
        self.app.module_manager = module_manager
        
        self.app.listener_manager = self.listener_manager
        self.app.audit_logger = self.audit_logger
        self.app.session_manager = session_manager
        self.app.user_manager = user_manager
        self.app.role_manager = role_manager
        self.app.protocol_multiplexer = None
        self.app.protocol_negotiator = None
        self.app.multi_port_discovery = self.multi_port_discovery
        
        self.app.config['PROTOCOL_MULTIPLEXER'] = None
        self.app.config['PROTOCOL_NEGOTIATOR'] = None
        
        
        self.memory_users = {}
        self.app.memory_users = self.memory_users  # Make accessible to blueprints
        
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)
        self.login_manager.login_view = 'auth.login'  # Updated to use auth blueprint
        
        self.setup_routes()

        self.socketio = SocketIO(self.app, cors_allowed_origins="*", async_mode='gevent',
                                 logger=False, engineio_logger=False)


    def register_listener_blueprints(self, listener_manager):
        self.listener_manager = listener_manager
        print(f"[+] HTTP listeners now run on separate processes/ports - no blueprints registered with main app")
        print(f"[+] Main web interface runs on port {self.config.get('web.port', 443)} only")

    def start(self):
        if hasattr(self, 'listener_manager') and self.listener_manager:
            self.register_listener_blueprints(self.listener_manager)

        self.app.debug = True
        import os
        web_port = int(os.environ.get('MULTI', self.config.get('web.port', 7443)))
        print(f"[+] NeoC2Web starting on port {web_port}")
        return True
    
    def setup_routes(self):
        @self.login_manager.user_loader
        def load_user(user_id):
            if user_id in self.memory_users:
                user_data = self.memory_users[user_id]
                user_role = 'viewer'  # Default
                if self.user_manager:
                    db_user = self.user_manager.get_user(user_id)
                    if db_user and 'role_name' in db_user:
                        user_role = db_user['role_name']
                return User(user_data['id'], user_data['username'], user_role)
            
            if self.user_manager:
                user = self.user_manager.get_user(user_id)
                if user:
                    user_role = user.get('role_name', 'viewer')
                    return User(user['id'], user['username'], user_role)
            
            return None
        
        @self.app.route('/api/agents')
        @login_required
        def api_agents():
            agents = self.db.get_all_agents()
            return jsonify({"agents": agents})
        
        @self.app.route('/api/agents/<agent_id>')
        @login_required
        def api_agent(agent_id):
            agent = self.db.get_agent(agent_id)
            if not agent:
                return jsonify({"error": "Agent not found"}), 404
            return jsonify(agent)
        
        @self.app.route('/api/tasks', methods=['GET'])
        @login_required
        def api_tasks():
            tasks = self.db.get_all_tasks()
            return jsonify({"tasks": tasks})
        
        @self.app.route('/api/tasks', methods=['POST'])
        @login_required
        def api_create_task():
            data = request.get_json()
            if not data or 'agent_id' not in data or 'command' not in data:
                return jsonify({"error": "Missing required fields"}), 400
            
            task_id = self.db.add_task(data['agent_id'], data['command'])
            self.app.audit_logger.log_event(
                current_user.id,
                "tasks.create",
                "task",
                task_id,
                json.dumps({"agent_id": data['agent_id'], "command": data['command']}),
                request.remote_addr
            )
            return jsonify({"task_id": task_id})
        
        @self.app.route('/api/tasks/<task_id>')
        @login_required
        def api_task(task_id):
            task = self.db.get_task(task_id)
            if not task:
                return jsonify({"error": "Task not found"}), 404
            return jsonify(task)
        
        @self.app.route('/api/modules')
        @login_required
        def api_modules():
            modules = self.db.get_all_modules()
            return jsonify({"modules": modules})
        
        @self.app.route('/api/modules/<module_id>')
        @login_required
        def api_module(module_id):
            module = self.db.get_module(module_id)
            if not module:
                return jsonify({"error": "Module not found"}), 404
            return jsonify(module)
        
        @self.app.route('/api/results/<agent_id>')
        @login_required
        def api_results(agent_id):
            results = self.db.get_agent_results(agent_id)
            return jsonify({"results": results})
        
        @self.app.route('/api/run_module', methods=['POST'])
        @login_required
        def api_run_module():
            data = request.get_json()
            if not data or 'module_name' not in data or 'agent_id' not in data:
                return jsonify({"error": "Missing required fields"}), 400
            
            module_name = data['module_name']
            args = data.get('args', {})
            agent_id = data['agent_id']
            
            result = self.module_manager.execute_module(module_name, args, agent_id)
            if isinstance(result, str):
                return jsonify({"error": result}), 400
            
            self.app.audit_logger.log_event(
                current_user.id,
                "modules.execute",
                "module",
                module_name,
                json.dumps({"args": args, "agent_id": agent_id}),
                request.remote_addr
            )
            return jsonify({"task_id": result.get('task_id'), "result": result.get('result')})
        
        @self.app.route('/api/chain_modules', methods=['POST'])
        @login_required
        def api_chain_modules():
            data = request.get_json()
            if not data or 'module_names' not in data or 'args_list' not in data or 'agent_id' not in data:
                return jsonify({"error": "Missing required fields"}), 400
            
            module_names = data['module_names']
            args_list = data['args_list']
            agent_id = data['agent_id']
            
            result = self.module_manager.chain_modules(module_names, args_list, agent_id)
            if isinstance(result, str):
                return jsonify({"error": result}), 400
            
            self.app.audit_logger.log_event(
                current_user.id,
                "modules.chain",
                "module_chain",
                str(uuid.uuid4()),
                json.dumps({"module_names": module_names, "args_list": args_list, "agent_id": agent_id}),
                request.remote_addr
            )
            return jsonify({"task_id": result.get('task_id'), "result": result.get('result')})
        
        @self.app.route('/health')
        def health_check():
            return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})
        
        @self.app.route('/api/info')
        def api_info():
            auth_header = request.headers.get('Authorization')
            expected_token = self.config.get('web.internal_api_token')

            if expected_token:
                if auth_header and auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
                    if token == expected_token:
                        pass
                    else:
                        return jsonify({"error": "Unauthorized"}), 403
                elif request.remote_addr in ['127.0.0.1', '::1']:
                    pass
                else:
                    return jsonify({"error": "Unauthorized"}), 403
            else:
                if request.remote_addr not in ['127.0.0.1', '::1']:
                    return jsonify({"error": "Unauthorized"}), 403

            return jsonify({
                "name": "NeoC2",
                "version": "1.0.0",
                "description": "Command and Control Framework",
                "endpoints": {
                    "agents": "/api/agents",
                    "tasks": "/api/tasks",
                    "modules": "/api/modules"
                }
            })
        
        @self.app.route('/api/profiles/<profile_name>')
        def api_get_profile(profile_name):
            auth_header = request.headers.get('Authorization')
            expected_token = self.config.get('web.internal_api_token')

            if expected_token:
                if auth_header and auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
                    if token == expected_token:
                        pass
                    else:
                        return jsonify({"error": "Unauthorized"}), 403
                elif request.remote_addr in ['127.0.0.1', '::1']:
                    pass
                else:
                    return jsonify({"error": "Unauthorized"}), 403
            else:
                if request.remote_addr not in ['127.0.0.1', '::1']:
                    return jsonify({"error": "Unauthorized"}), 403

            try:
                profile = self.db.get_profile_by_name(profile_name)
                if not profile:
                    return jsonify({"error": "Profile not found"}), 404

                return jsonify({
                    "id": profile['id'],
                    "name": profile['name'],
                    "description": profile['description'],
                    "config": profile['config']
                })
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @self.app.route('/api/notifications', methods=['GET'])
        @login_required
        def api_notifications():
            try:
                multiplayer_session_manager = getattr(self.app, 'multiplayer_session_manager', None)
                
                if not multiplayer_session_manager:
                    return jsonify({"notifications": [], "count": 0})

                notifications = []
                
                if hasattr(multiplayer_session_manager, 'user_sessions'):
                    user_sessions = multiplayer_session_manager.user_sessions.get(current_user.id, [])
                    
                    for user_session_id in user_sessions:
                        user_session = multiplayer_session_manager.get_session(user_session_id)
                        if user_session and hasattr(user_session, 'notifications'):
                            import queue  # Use standard queue for compatibility
                            while not user_session.notifications.empty():
                                try:
                                    notification = user_session.notifications.get_nowait()
                                    if isinstance(notification, dict):
                                        notifications.append(notification)
                                    else:
                                        notifications.append({
                                            "message": str(notification),
                                            "type": "info",
                                            "timestamp": datetime.now().isoformat()
                                        })
                                except queue.Empty:
                                    break

                return jsonify({
                    "notifications": notifications,
                    "count": len(notifications)
                })

            except Exception as e:
                import traceback
                traceback.print_exc()
                return jsonify({
                    "notifications": [],
                    "count": 0,
                    "error": str(e)
                }), 500
        
        @self.app.errorhandler(403)
        def forbidden(error):
            return render_template('error.html', 
                                 error_code=403, 
                                 error_message="Access Denied", 
                                 error_details="You don't have permission to access this resource."), 403
        
        @self.app.errorhandler(401)
        def unauthorized(error):
            return render_template('error.html', 
                                 error_code=401, 
                                 error_message="Unauthorized", 
                                 error_details="Please log in to access this resource."), 401

        return self.app
    
    def register_distributed_routes(self):
        print("[-] Distributed routes have been deprecated and removed")
