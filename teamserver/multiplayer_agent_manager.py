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
import threading
import time
import logging
from datetime import datetime
from core.models import NeoC2DB
from teamserver.agent_manager import AgentManager


class MultiplayerAgentManager(AgentManager):
    
    def __init__(self, db, silent_mode=False, multiplayer_coordinator=None):
        super().__init__(db, silent_mode=silent_mode)
        self.multiplayer_coordinator = multiplayer_coordinator
        self.logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')
        
        if not hasattr(self, 'agents'):
            self.agents = {}
        if not hasattr(self, 'agent_tasks'):
            self.agent_tasks = {}
        if not hasattr(self, 'agent_results'):
            self.agent_results = {}
        
    def add_task(self, agent_id, command):
        result = super().add_task(agent_id, command)
        
        if self.multiplayer_coordinator and result and result.get('success'):
            command_data = {
                'agent_id': agent_id,
                'command': command,
                'task_id': result['task_id'],
                'timestamp': datetime.now().isoformat()
            }
            self.multiplayer_coordinator.broadcast_command(command_data)
        
        if hasattr(self.multiplayer_coordinator, 'audit_logger') and self.multiplayer_coordinator.audit_logger:
            try:
                user_id = getattr(self, 'current_user_id', None)  # This might not be set in all contexts
                self.multiplayer_coordinator.audit_logger.log_event(
                    user_id=user_id,
                    action='multiplayer_agent_task_add',
                    resource_type='agent',
                    resource_id=agent_id,
                    details=f"Task added for agent with command: {command[:50]}{'...' if len(command) > 50 else ''}",
                    ip_address=getattr(self, 'current_ip_address', None)
                )
            except Exception as e:
                self.logger.error(f"Error logging multiplayer agent task add event: {str(e)}")
        
        return result
    
    def add_download_task(self, agent_id, remote_path):
        result = super().add_download_task(agent_id, remote_path)
        
        if self.multiplayer_coordinator and result and result.get('success'):
            command_data = {
                'agent_id': agent_id,
                'command': f'download {remote_path}',
                'task_id': result['task_id'],
                'command_type': 'download',
                'timestamp': datetime.now().isoformat()
            }
            self.multiplayer_coordinator.broadcast_command(command_data)
        
        if hasattr(self.multiplayer_coordinator, 'audit_logger') and self.multiplayer_coordinator.audit_logger:
            try:
                user_id = getattr(self, 'current_user_id', None)  # This might not be set in all contexts
                self.multiplayer_coordinator.audit_logger.log_event(
                    user_id=user_id,
                    action='multiplayer_agent_download_task_add',
                    resource_type='agent',
                    resource_id=agent_id,
                    details=f"Download task added for agent with path: {remote_path}",
                    ip_address=getattr(self, 'current_ip_address', None)
                )
            except Exception as e:
                self.logger.error(f"Error logging multiplayer agent download task add event: {str(e)}")
        
        return result
    
    def add_upload_task(self, agent_id, agent_command):
        result = super().add_upload_task(agent_id, agent_command)
        
        if self.multiplayer_coordinator and result and result.get('success'):
            command_data = {
                'agent_id': agent_id,
                'command': f'upload {agent_command}',
                'task_id': result['task_id'],
                'command_type': 'upload',
                'timestamp': datetime.now().isoformat()
            }
            self.multiplayer_coordinator.broadcast_command(command_data)
        
        if hasattr(self.multiplayer_coordinator, 'audit_logger') and self.multiplayer_coordinator.audit_logger:
            try:
                user_id = getattr(self, 'current_user_id', None)  # This might not be set in all contexts
                self.multiplayer_coordinator.audit_logger.log_event(
                    user_id=user_id,
                    action='multiplayer_agent_upload_task_add',
                    resource_type='agent',
                    resource_id=agent_id,
                    details=f"Upload task added for agent with command: {agent_command}",
                    ip_address=getattr(self, 'current_ip_address', None)
                )
            except Exception as e:
                self.logger.error(f"Error logging multiplayer agent upload task add event: {str(e)}")
        
        return result
    
    def process_agent_results(self, agent_id, results):
        processed_results = super().process_agent_results(agent_id, results)
        
        if self.multiplayer_coordinator and results:
            for result in results:
                result_data = {
                    'agent_id': agent_id,
                    'task_id': result.get('task_id'),
                    'result': result.get('result', ''),
                    'command': result.get('command', ''),
                    'timestamp': datetime.now().isoformat()
                }
                self.multiplayer_coordinator.broadcast_result(result_data)
        
        if hasattr(self.multiplayer_coordinator, 'audit_logger') and self.multiplayer_coordinator.audit_logger and results:
            try:
                self.multiplayer_coordinator.audit_logger.log_event(
                    user_id=None,
                    action='multiplayer_agent_results_process',
                    resource_type='agent',
                    resource_id=agent_id,
                    details=f"Processed {len(results)} results from agent",
                    ip_address=None
                )
            except Exception as e:
                self.logger.error(f"Error logging multiplayer agent results process event: {str(e)}")
        
        return processed_results
