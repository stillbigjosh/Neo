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
import argparse
import secrets
from pathlib import Path

class NeoC2Config:
    def __init__(self, config_file=None):
        self.config_file = config_file or "config.json"
        self.default_config = {
            "server": {
                "host": os.environ.get('IP', '0.0.0.0'),  # Use IP environment variable or default
                "port": 443,
                "ssl_cert": "server.crt",
                "ssl_key": "server.key"
            },
            "database": {
                "path": "neoc2.db"
            },
            "agents": {
                "default_checkin": 30,
                "default_jitter": 5,
                "max_inactive_time": 300
            },
            "web": {
                "enabled": True,
                "port": int(os.environ.get('MULTI', 7443)),
                "host": os.environ.get('IP', '0.0.0.0'),
                "secret_key": self._generate_secret_key(),
                "internal_api_token": self._generate_api_token()
            },
            "cli": {
                "history_file": "~/.neoc2_history",
                "max_history": 1000
            },
            "remote_cli": {
                "enabled": True,
                "host": os.environ.get('IP', '0.0.0.0'),  # Use IP environment variable or default
                "port": 8444,
                "ssl_enabled": True,
                "cert_file": "server.crt",
                "key_file": "server.key"
            }
        }
        
        self.config = self.load_config()
    
    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r") as f:
                    config = json.load(f)

                # Generate a new secret key if one doesn't exist or is empty/default
                if not config.get('web', {}).get('secret_key') or config.get('web', {}).get('secret_key') == "change_me_in_production":
                    config.setdefault('web', {})['secret_key'] = self._generate_secret_key()

                # Generate a new API token if one doesn't exist or is the default
                if not config.get('web', {}).get('internal_api_token') or config.get('web', {}).get('internal_api_token') == "secret_internal_token_change_me":
                    config.setdefault('web', {})['internal_api_token'] = self._generate_api_token()

                return self.merge_configs(self.default_config, config)
            except json.JSONDecodeError:
                print(f"Error parsing config file {self.config_file}, using defaults")
                return self.default_config
        else:
            # Generate new security credentials for fresh installations
            self.default_config['web']['secret_key'] = self._generate_secret_key()
            self.default_config['web']['internal_api_token'] = self._generate_api_token()
            with open(self.config_file, "w") as f:
                json.dump(self.default_config, f, indent=4)
            return self.default_config
    
    def merge_configs(self, default, user):
        result = default.copy()
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self.merge_configs(result[key], value)
            else:
                result[key] = value
        return result
    
    def save_config(self):
        with open(self.config_file, "w") as f:
            json.dump(self.config, f, indent=4)

    def _generate_secret_key(self):
        """Generate a random secret key for Flask applications"""
        return secrets.token_hex(32)

    def _generate_api_token(self):
        """Generate a random API token for internal communications"""
        return secrets.token_urlsafe(32)

    def get(self, key, default=None):
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key, value):
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self.save_config()
    
    
    def parse_args(self):
        parser = argparse.ArgumentParser(description="NeoC2 Framework")
        parser.add_argument("--host", help="Server host to bind to")
        parser.add_argument("--port", type=int, help="Server port to bind to")
        parser.add_argument("--ssl-cert", help="Path to SSL certificate file")
        parser.add_argument("--ssl-key", help="Path to SSL private key file")
        parser.add_argument("--db-path", help="Path to database file")
        parser.add_argument("--web-only", action="store_true", help="Run only web interface")
        parser.add_argument("--cli-only", action="store_true", help="Run only CLI interface")
        parser.add_argument("--profile", help="Configuration profile to use")
        
        args = parser.parse_args()
        
        if args.host:
            self.set("server.host", args.host)
        if args.port:
            self.set("server.port", args.port)
        if args.ssl_cert:
            self.set("server.ssl_cert", args.ssl_cert)
        if args.ssl_key:
            self.set("server.ssl_key", args.ssl_key)
        if args.db_path:
            self.set("database.path", args.db_path)
        if args.profile:
            print("Warning: Profiles feature has been removed from config")
        
        return args
