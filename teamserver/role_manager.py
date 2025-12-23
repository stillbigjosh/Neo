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
from core.models import NeoC2DB

class RoleManager:
    def __init__(self, db):
        self.db = db

    def create_role(self, name, description, permissions):
        existing_role = self.db.execute(
            "SELECT id FROM roles WHERE name = ?",
            (name,)
        ).fetchone()
        if existing_role:
            return {
                "success": False,
                "message": "Role already exists"
            }
        
        role_id = str(uuid.uuid4())
        created_at = str(uuid.uuid4())  # Convert UUID to string
        self.db.execute(
            "INSERT INTO roles (id, name, description, permissions, created_at) VALUES (?, ?, ?, ?, ?)",
            (role_id, name, description, json.dumps(permissions), created_at)
        )
        return {
            "success": True,
            "role_id": role_id,
            "message": "Role created successfully"
        }

    def get_role(self, role_id):
        role_data = self.db.execute(
            "SELECT id, name, description, permissions FROM roles WHERE id = ?",
            (role_id,)
        ).fetchone()
        if not role_data:
            return None
        return {
            "id": role_data['id'],
            "name": role_data['name'],
            "description": role_data['description'],
            "permissions": json.loads(role_data['permissions'])
        }

    def get_role_by_name(self, name):
        role_data = self.db.execute(
            "SELECT id, name, description, permissions FROM roles WHERE name = ?",
            (name,)
        ).fetchone()
        if not role_data:
            return None
        return {
            "id": role_data['id'],
            "name": role_data['name'],
            "description": role_data['description'],
            "permissions": json.loads(role_data['permissions'])
        }

    def update_role(self, role_id, updates):
        set_clauses = []
        params = []
        if 'name' in updates:
            set_clauses.append("name = ?")
            params.append(updates['name'])
        if 'description' in updates:
            set_clauses.append("description = ?")
            params.append(updates['description'])
        if 'permissions' in updates:
            set_clauses.append("permissions = ?")
            params.append(json.dumps(updates['permissions']))
        
        if not set_clauses:
            return {
                "success": False,
                "message": "No updates provided"
            }
        
        # Add role_id to params
        params.append(role_id)
        
        self.db.execute(
            f"UPDATE roles SET {', '.join(set_clauses)} WHERE id = ?",
            tuple(params)
        )
        return {
            "success": True,
            "message": "Role updated successfully"
        }

    def list_roles(self):
        roles_data = self.db.execute("SELECT id, name, description FROM roles").fetchall()
        roles = []
        for role_data in roles_data:
            roles.append({
                "id": role_data['id'],
                "name": role_data['name'],
                "description": role_data['description']
            })
        return roles

    def has_permission(self, role_id, action):
        """
        Check if a role has permission to perform an action.

        Args:
            role_id (str): The ID of the role to check
            action (str): The action to check permission for

        Returns:
            bool: True if the role has permission, False otherwise
        """
        role_data = self.db.execute(
            "SELECT permissions FROM roles WHERE id = ?",
            (role_id,)
        ).fetchone()

        if not role_data:
            return False

        permissions = json.loads(role_data['permissions']) if role_data['permissions'] else []

        # Check if the role has wildcard permission (*)
        if '*' in permissions:
            return True

        # Check if the role has the specific permission
        if action in permissions:
            return True

        # Check for wildcard permissions in the same category (e.g., 'agents.*')
        for perm in permissions:
            if perm.endswith('.*'):
                category = perm[:-2]  # Remove the '.*' suffix
                if action.startswith(category + '.'):
                    return True

        return False
