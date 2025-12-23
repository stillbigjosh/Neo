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
import logging
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from core.models import NeoC2DB

class UserManager:
    def __init__(self, db):
        self.db = db
        self.logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
    
    def create_user(self, username, email, password, role_id="operator"):
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute(
                    "SELECT id FROM users WHERE username = ?",
                    (username,)
                )
                existing_user = cursor.fetchone()
                
                if existing_user:
                    return {
                        "success": False,
                        "message": "Username already exists"
                    }
                
                hashed_password = generate_password_hash(password)
                user_id = str(uuid.uuid4())
                cursor.execute(
                    "INSERT INTO users (id, username, password_hash, email, role_id, created_at, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (user_id, username, hashed_password, email, role_id, datetime.now(), 1)
                )
                
                
                return {
                    "success": True,
                    "user_id": user_id,
                    "message": "User created successfully"
                }
        except Exception as e:
            self.logger.info(f"Error creating user: {str(e)}")
            import traceback
            return {
                "success": False,
                "message": f"Error creating user: {str(e)}"
            }
    
    def authenticate(self, username, password):
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute(
                    "SELECT id, username, password_hash, role_id, is_active, registration_status FROM users WHERE username = ? AND is_active = 1 AND registration_status = 'approved'",
                    (username,)
                )
                user_data = cursor.fetchone()
                
                if not user_data:
                    self.logger.info(f"User not found: {username}")
                    cursor.execute("SELECT username, is_active, registration_status FROM users")
                    all_users = cursor.fetchall()
                    return None
                
                
                if not check_password_hash(user_data['password_hash'], password):
                    self.logger.info(f"Password mismatch for user: {username}")
                    return None
                
                self.logger.info(f"Password match for user: {username}")
                
                cursor.execute(
                    "SELECT name, permissions FROM roles WHERE id = ?",
                    (user_data['role_id'],)
                )
                role_data = cursor.fetchone()
                
                if not role_data:
                    self.logger.info(f"Role not found for user: {username}, role_id: {user_data['role_id']}")
                    cursor.execute("SELECT id, name FROM roles")
                    all_roles = cursor.fetchall()
                    
                    return {
                        "id": user_data['id'],
                        "username": user_data['username'],
                        "role_id": user_data['role_id'],
                        "role_name": "unknown",
                        "role_permissions": []
                    }
                
                
                cursor.execute(
                    "UPDATE users SET last_login = ? WHERE id = ?",
                    (datetime.now(), user_data['id'])
                )
                
                self.logger.info(f"Authentication successful for user: {username}")
                
                return {
                    "id": user_data['id'],
                    "username": user_data['username'],
                    "role_id": user_data['role_id'],
                    "role_name": role_data['name'],
                    "role_permissions": json.loads(role_data['permissions']) if role_data['permissions'] else []
                }
                
        except Exception as e:
            self.logger.info(f"Error authenticating user: {str(e)}")
            import traceback
            return None
    
    def get_user(self, user_id):
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute(
                    "SELECT u.id, u.username, u.role_id, u.email, u.created_at, u.last_login, u.is_active, r.name as role_name, r.permissions as role_permissions FROM users u LEFT JOIN roles r ON u.role_id = r.id WHERE u.id = ?",
                    (user_id,)
                )
                user_data = cursor.fetchone()
                
                if not user_data:
                    return None
                
                return {
                    "id": user_data['id'],
                    "username": user_data['username'],
                    "email": user_data['email'],
                    "role_id": user_data['role_id'],
                    "role_name": user_data['role_name'] or "unknown",
                    "role_permissions": json.loads(user_data['role_permissions']) if user_data['role_permissions'] else [],
                    "created_at": user_data['created_at'],
                    "last_login": user_data['last_login'],
                    "is_active": user_data['is_active']
                }
        except Exception as e:
            self.logger.info(f"Error getting user: {str(e)}")
            return None
    
    def get_user_by_username(self, username):
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute(
                    "SELECT u.id, u.username, u.role_id, u.email, u.created_at, u.last_login, u.is_active, u.registration_status, r.name as role_name, r.permissions as role_permissions FROM users u LEFT JOIN roles r ON u.role_id = r.id WHERE u.username = ? AND u.is_active = 1 AND u.registration_status = 'approved'",
                    (username,)
                )
                user_data = cursor.fetchone()
                
                if not user_data:
                    return None
                
                return {
                    "id": user_data['id'],
                    "username": user_data['username'],
                    "email": user_data['email'],
                    "role_id": user_data['role_id'],
                    "role_name": user_data['role_name'] or "unknown",
                    "role_permissions": json.loads(user_data['role_permissions']) if user_data['role_permissions'] else [],
                    "created_at": user_data['created_at'],
                    "last_login": user_data['last_login'],
                    "is_active": user_data['is_active'],
                    "registration_status": user_data['registration_status']
                }
        except Exception as e:
            self.logger.info(f"Error getting user by username: {str(e)}")
            return None
    
    def update_user(self, user_id, updates):
        try:
            set_clauses = []
            params = []
            
            if 'username' in updates:
                set_clauses.append("username = ?")
                params.append(updates['username'])
            
            if 'password' in updates:
                hashed_password = generate_password_hash(updates['password'])
                set_clauses.append("password_hash = ?")
                params.append(hashed_password)
            
            if 'email' in updates:
                set_clauses.append("email = ?")
                params.append(updates['email'])
            
            if 'role_id' in updates:
                set_clauses.append("role_id = ?")
                params.append(updates['role_id'])
            
            if 'is_active' in updates:
                set_clauses.append("is_active = ?")
                params.append(updates['is_active'])
            
            if not set_clauses:
                return {
                    "success": False,
                    "message": "No updates provided"
                }
            
            params.append(user_id)
            
            with self.db.get_cursor() as cursor:
                cursor.execute(
                    f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?",
                    tuple(params)
                )
            
            return {
                "success": True,
                "message": "User updated successfully"
            }
        except Exception as e:
            self.logger.info(f"Error updating user: {str(e)}")
            return {
                "success": False,
                "message": f"Error updating user: {str(e)}"
            }
    
    def delete_user(self, user_id):
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute(
                    "UPDATE users SET is_active = 0 WHERE id = ?",
                    (user_id,)
                )
            
            return {
                "success": True,
                "message": "User deactivated successfully"
            }
        except Exception as e:
            self.logger.info(f"Error deleting user: {str(e)}")
            return {
                "success": False,
                "message": f"Error deleting user: {str(e)}"
            }
    
    def list_users(self):
        try:
            users = []
            
            with self.db.get_cursor() as cursor:
                cursor.execute(
                    "SELECT u.id, u.username, u.email, u.role_id, r.name as role_name, u.created_at, u.last_login FROM users u LEFT JOIN roles r ON u.role_id = r.id WHERE u.is_active = 1"
                )
                user_data = cursor.fetchall()
            
            for data in user_data:
                users.append({
                    "id": data['id'],
                    "username": data['username'],
                    "email": data['email'],
                    "role_id": data['role_id'],
                    "role_name": data['role_name'] or "unknown",
                    "created_at": data['created_at'],
                    "last_login": data['last_login'] if data['last_login'] else None
                })
            
            return users
        except Exception as e:
            self.logger.info(f"Error listing users: {str(e)}")
            return []
    
    def change_password(self, user_id, old_password, new_password):
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute(
                    "SELECT password_hash FROM users WHERE id = ? AND is_active = 1",
                    (user_id,)
                )
                user_data = cursor.fetchone()
                
                if not user_data:
                    return {
                        "success": False,
                        "message": "User not found"
                    }
                
                if not check_password_hash(user_data['password_hash'], old_password):
                    return {
                        "success": False,
                        "message": "Incorrect old password"
                    }
                
                hashed_new_password = generate_password_hash(new_password)
                cursor.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (hashed_new_password, user_id)
                )
                
                return {
                    "success": True,
                    "message": "Password changed successfully"
                }
        except Exception as e:
            return {
                "success": False,
                "message": f"Error changing password: {str(e)}"
            }
    
    def reset_password(self, user_id, new_password):
        try:
            with self.db.get_cursor() as cursor:
                hashed_new_password = generate_password_hash(new_password)
                cursor.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (hashed_new_password, user_id)
                )
            
            return {
                "success": True,
                "message": "Password reset successfully"
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Error resetting password: {str(e)}"
            }

    def debug_user_creation(self):
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute("SELECT id, username, password_hash, role_id, is_active FROM users WHERE username = 'admin'")
                admin_user = cursor.fetchone()
                
                cursor.execute("SELECT id, name, permissions FROM roles")
                roles = cursor.fetchall()
                
                cursor.execute("SELECT id, username, password_hash, role_id, is_active FROM users")
                all_users = cursor.fetchall()
                
                
                if admin_user:
                    self.logger.debug(f"Username: {admin_user['username']}")
                    self.logger.debug(f"Role ID: {admin_user['role_id']}")
                    self.logger.debug(f"Is Active: {admin_user['is_active']}")
                    
                    cursor.execute("SELECT name FROM roles WHERE id = ?", (admin_user['role_id'],))
                    role = cursor.fetchone()
                    self.logger.debug(f"Role name: {role['name'] if role else 'ROLE NOT FOUND'}")
                
        except Exception as e:
            self.logger.info(f"Debug error: {str(e)}")
    
    def get_all_users_with_status(self):
        try:
            users = []
            
            with self.db.get_cursor() as cursor:
                cursor.execute(
                    "SELECT u.id, u.username, u.email, u.role_id, r.name as role_name, u.created_at, u.last_login, u.is_active, u.registration_status FROM users u LEFT JOIN roles r ON u.role_id = r.id ORDER BY u.created_at DESC"
                )
                user_data = cursor.fetchall()
            
            for data in user_data:
                users.append({
                    "id": data['id'],
                    "username": data['username'],
                    "email": data['email'],
                    "role_id": data['role_id'],
                    "role_name": data['role_name'] or "unknown",
                    "created_at": data['created_at'],
                    "last_login": data['last_login'] if data['last_login'] else None,
                    "is_active": data['is_active'],
                    "registration_status": data['registration_status']
                })
            
            return users
        except Exception as e:
            self.logger.info(f"Error getting all users with status: {str(e)}")
            return []
