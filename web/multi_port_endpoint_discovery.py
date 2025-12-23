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

import gevent
import time
import logging
import json
import requests
from flask import request, jsonify, current_app
import uuid
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
import urllib3

urllib3.disable_warnings(InsecureRequestWarning)


logger = logging.getLogger(__name__)

agent_manager = None


class MultiPortEndpointDiscovery:
    def __init__(self, app, listener_manager):
        self.app = app
        self.listener_manager = listener_manager
        self.known_endpoints = {}  # Endpoint -> {handler, port, listener_id}
        self.listener_ports = {}   # listener_id -> port
        self.logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        self.running = False
        self.thread = None
        self.scan_interval = 30  # seconds
    
    def start(self):
        if self.running:
            return
        
        self.running = True
        self.thread = gevent.spawn(self._discovery_worker)
        self.logger.info("Multi-port endpoint discovery service started")
        
        self.scan_all_listeners()
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.kill()
        self.logger.info("Multi-port endpoint discovery service stopped")
    
    def _discovery_worker(self):
        while self.running:
            try:
                self.scan_all_listeners()
                gevent.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"Error in discovery worker: {str(e)}")
                gevent.sleep(self.scan_interval)
    
    def scan_all_listeners(self):
        try:
            all_listeners = self.listener_manager.db.get_listeners()
            
            discovered_count = 0
            for listener in all_listeners:
                listener_id = listener['id']
                listener_type = listener['type']
                
                if listener_type in ['http', 'https']:
                    if hasattr(self.listener_manager, 'http_listener_manager'):
                        http_manager = self.listener_manager.http_listener_manager
                        if listener_id in http_manager.listeners:
                            http_listener = http_manager.listeners[listener_id]
                            if http_listener.is_running():
                                port = http_listener.port
                                try:
                                    base_url = f"http://{http_listener.host}:{port}"
                                    response = requests.get(f"{base_url}/api/listener-info", timeout=5)
                                    if response.status_code == 200:
                                        listener_info = response.json()
                                        listener_endpoints = listener_info.get('endpoints', {})
                                        
                                        # Store endpoints for this specific listener/port
                                        for endpoint_name, endpoint_path in listener_endpoints.items():
                                            if endpoint_name == 'register':
                                                endpoint_key = f"http://{http_listener.host}:{port}{endpoint_path}"
                                                self.known_endpoints[endpoint_key] = {
                                                    'handler': self._handle_agent_register_wrapper,
                                                    'port': port,
                                                    'listener_id': listener_id,
                                                    'source': f'listener_{listener_id[:8]}'
                                                }
                                                discovered_count += 1
                                            elif endpoint_name == 'tasks':
                                                endpoint_key = f"http://{http_listener.host}:{port}{endpoint_path}"
                                                self.known_endpoints[endpoint_key] = {
                                                    'handler': self._handle_agent_tasks_wrapper,
                                                    'port': port,
                                                    'listener_id': listener_id,
                                                    'has_agent_id': True,
                                                    'source': f'listener_{listener_id[:8]}'
                                                }
                                                discovered_count += 1
                                            elif endpoint_name == 'results':
                                                endpoint_key = f"http://{http_listener.host}:{port}{endpoint_path}"
                                                self.known_endpoints[endpoint_key] = {
                                                    'handler': self._handle_agent_results_wrapper,
                                                    'port': port,
                                                    'listener_id': listener_id,
                                                    'has_agent_id': True,
                                                    'source': f'listener_{listener_id[:8]}'
                                                }
                                                discovered_count += 1
                                            elif endpoint_name == 'interactive':
                                                endpoint_key = f"http://{http_listener.host}:{port}{endpoint_path}"
                                                self.known_endpoints[endpoint_key] = {
                                                    'handler': self._handle_interactive_wrapper,
                                                    'port': port,
                                                    'listener_id': listener_id,
                                                    'has_agent_id': True,
                                                    'source': f'listener_{listener_id[:8]}'
                                                }
                                                discovered_count += 1
                                            elif endpoint_name == 'interactive_status':
                                                endpoint_key = f"http://{http_listener.host}:{port}{endpoint_path}"
                                                self.known_endpoints[endpoint_key] = {
                                                    'handler': self._handle_interactive_status_wrapper,
                                                    'port': port,
                                                    'listener_id': listener_id,
                                                    'has_agent_id': True,
                                                    'source': f'listener_{listener_id[:8]}'
                                                }
                                                discovered_count += 1

                                except Exception as e:
                                    self.logger.warning(f"Could not query listener {listener_id} at port {port}: {str(e)}")
            
            if discovered_count > 0:
                self.logger.info(f"Discovered {discovered_count} endpoints from running listeners")
        
        except Exception as e:
            self.logger.error(f"Error scanning all listeners: {str(e)}")
    
    def _handle_agent_register_wrapper(self, from_port=None, listener_id=None):
        return handle_agent_register_common(from_port, listener_id)
    
    def _handle_agent_tasks_wrapper(self, agent_id=None, from_port=None, listener_id=None):
        return handle_agent_tasks_common(agent_id, from_port, listener_id)
    
    def _handle_agent_results_wrapper(self, agent_id=None, from_port=None, listener_id=None):
        return handle_agent_results_common(agent_id, from_port, listener_id)
    
    def _handle_interactive_wrapper(self, agent_id=None, from_port=None, listener_id=None):
        return handle_interactive_communication(agent_id, from_port, listener_id)

    def _handle_interactive_status_wrapper(self, agent_id=None, from_port=None, listener_id=None):
        return handle_interactive_status(agent_id, from_port, listener_id)
    
    def get_known_endpoints(self):
        endpoints_copy = {}
        for endpoint, endpoint_info in self.known_endpoints.items():
            endpoint_copy = {k: v for k, v in endpoint_info.items() if k != 'handler'}
            endpoint_copy['has_handler'] = 'handler' in endpoint_info
            endpoints_copy[endpoint] = endpoint_copy
        return endpoints_copy


def handle_agent_register_common(from_port=None, listener_id=None):
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400
        
        actual_listener_id = listener_id or data.get('listener_id', 'web_app_default')
        
        if actual_listener_id == 'web_app_default':
            from flask import request
            pass
        
        logger.debug(f"Registration request received for listener: {actual_listener_id}")
        
        hostname = data.get('hostname', 'unknown')
        os_info = data.get('os_info', 'unknown')
        user = data.get('user', 'unknown')
        ip_address = request.remote_addr
        agent_id = data.get('agent_id')  # Get agent's pre-assigned ID
        
        logger.debug(f"Agent info - Hostname: {hostname}, Listener: {actual_listener_id}, Agent ID: {agent_id}")
        
        profile_config = get_profile_config_for_listener(actual_listener_id)
        
        provided_secret_key = data.get('secret_key')
        logger.debug(f"Agent info - Hostname: {hostname}, Listener: {actual_listener_id}, Agent ID: {agent_id}, Secret Key Provided: {bool(provided_secret_key)}")
        
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
                    listener_id=actual_listener_id,
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
            listener_id=actual_listener_id,
            agent_id=agent_id  # Pass the agent's pre-assigned ID
        )
        
        agent_data = agent_manager.db.fetchone("SELECT secret_key FROM agents WHERE id = ?", (registered_agent_id,))
        secret_key = agent_data['secret_key'] if agent_data else None
        
        heartbeat_interval = profile_config.get('heartbeat_interval', 30)
        jitter = profile_config.get('jitter', 5)
        
        logger.info(f"Agent registered: {registered_agent_id} with listener: {actual_listener_id}")
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

def handle_agent_tasks_common(agent_id, from_port=None, listener_id=None):
    try:
        logger.debug(f"Task request for agent {agent_id}")
        
        agent = agent_manager.get_agent(agent_id)
        if not agent:
            logger.debug(f"Agent {agent_id} not found")
            return jsonify({"status": "error", "message": "Agent not found"}), 404
        
        actual_listener_id = listener_id or agent.listener_id
        profile_config = get_profile_config_for_listener(actual_listener_id)
        
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
        
        # Format tasks for agent
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

def handle_agent_results_common(agent_id, from_port=None, listener_id=None):
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400
        
        logger.debug(f"Result submission for agent {agent_id}")
        
        task_id = data.get('task_id')
        result = data.get('result', '')
        
        if not task_id:
            return jsonify({
                'status': 'error',
                'message': 'Task ID is required'
            }), 400
        
        agent = agent_manager.get_agent(agent_id)
        actual_listener_id = listener_id or (agent.listener_id if agent else 'web_app_default')
        
        if agent:
            profile_config = get_profile_config_for_listener(actual_listener_id)
            logger.debug(f"Agent {agent_id} belongs to listener: {actual_listener_id}")
        
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

def handle_interactive_communication(agent_id, from_port=None, listener_id=None):
    try:
        if request.method == 'GET':
            return handle_interactive_get(agent_id)
        else:  # POST
            return handle_interactive_post(agent_id)
            
    except Exception as e:
        logger.error(f"Interactive communication error for agent {agent_id}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Interactive communication failed: {str(e)}'
        }), 500


def get_profile_config_for_listener(listener_id):
    try:
        if not listener_id:
            return {}
            
        from flask import current_app
        if not hasattr(current_app, 'db'):
            logger.error("Database not available in app context")
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
        
    except RuntimeError:
        logger.debug("Not in Flask app context, skipping profile config lookup")
        return {}
    except Exception as e:
        logger.error(f"Error getting profile config: {str(e)}")
        return {}


def get_listener_port(listener_id):
    try:
        if not listener_id:
            return None
            
        from flask import current_app
        if not hasattr(current_app, 'db'):
            logger.error("Database not available in app context")
            return None
            
        listener = current_app.db.get_listener(listener_id)
        if not listener:
            logger.debug(f"Listener {listener_id} not found")
            return None
        
        return listener.get('port')
        
    except RuntimeError:
        logger.debug("Not in Flask app context, skipping listener port lookup")
        return None
    except Exception as e:
        logger.error(f"Error getting listener port: {str(e)}")
        return None


def handle_interactive_get(agent_id):
    try:
        logger.debug(f"Interactive poll from agent {agent_id}")
        
        agent = agent_manager.get_agent(agent_id)
        if not agent:
            return jsonify({"status": "error", "message": "Agent not found"}), 404
        
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
    except Exception as e:
        logger.error(f"Error in interactive get for agent {agent_id}: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': f'Interactive get failed: {str(e)}'
        }), 500


def handle_interactive_post(agent_id):
    try:
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
    except Exception as e:
        logger.error(f"Error in interactive post for agent {agent_id}: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': f'Interactive post failed: {str(e)}'
        }), 500


def handle_interactive_status(agent_id, from_port=None, listener_id=None):
    try:
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            client_ip = forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.headers.get('X-Real-IP') or request.remote_addr

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
        logger.error(f"Interactive status check failed for agent {agent_id}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Interactive status check failed: {str(e)}'
        }), 500
