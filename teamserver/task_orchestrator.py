import uuid
import json
import time
from datetime import datetime
import logging

class TaskOrchestrator:
    
    def __init__(self, module_manager, agent_manager, db):
        self.module_manager = module_manager
        self.agent_manager = agent_manager
        self.db = db
        self.setup_logging()
        self.setup_db()
    
    def setup_logging(self):
        log_dir = "logs"
        import os
        os.makedirs(log_dir, exist_ok=True)
        logging.basicConfig(
            filename=os.path.join(log_dir, "task_orchestrator.log"),
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("TaskOrchestrator")
    
    def setup_db(self):
        self.db.execute('''
        CREATE TABLE IF NOT EXISTS task_chains (
            id TEXT PRIMARY KEY,
            name TEXT,
            agent_id TEXT,
            module_names TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (agent_id) REFERENCES agents(id)
        )
        ''')
        
        self.db.execute('''
        CREATE TABLE IF NOT EXISTS chain_tasks (
            id TEXT PRIMARY KEY,
            chain_id TEXT,
            module_name TEXT,
            module_id TEXT,
            sequence_order INTEGER,
            args TEXT,
            status TEXT DEFAULT 'pending',
            result TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            error TEXT,
            FOREIGN KEY (chain_id) REFERENCES task_chains(id),
            FOREIGN KEY (module_id) REFERENCES modules(id)
        )
        ''')
        
        self.db.get_connection().commit()
    
    def create_chain(self, agent_id, module_names, chain_name=None, args_list=None):
        try:
            agent = self.agent_manager.get_agent(agent_id)
            if not agent:
                return {
                    'success': False,
                    'error': f'Agent {agent_id} not found'
                }

            invalid_modules = []
            for module_name in module_names:
                module = self.module_manager.get_module(module_name)
                if not module:
                    invalid_modules.append(module_name)

            if invalid_modules:
                return {
                    'success': False,
                    'error': f'Invalid modules: {", ".join(invalid_modules)}'
                }

            chain_id = str(uuid.uuid4())

            if not chain_name:
                chain_name = f"Chain_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            self.db.execute('''
            INSERT INTO task_chains (id, name, agent_id, module_names, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                chain_id,
                chain_name,
                agent_id,
                json.dumps(module_names),
                'pending',
                datetime.now()
            ))

            if args_list is None:
                args_list = [{}] * len(module_names)

            for i, module_name in enumerate(module_names):
                module = self.module_manager.get_module(module_name)
                task_id = str(uuid.uuid4())

                self.db.execute('''
                INSERT INTO chain_tasks (id, chain_id, module_name, module_id, sequence_order, args, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    task_id,
                    chain_id,
                    module_name,
                    module['id'],
                    i,
                    json.dumps(args_list[i] if i < len(args_list) else {}),
                    'pending',
                    datetime.now()
                ))
            
            self.db.get_connection().commit()

            self.logger.info(f"Created task chain {chain_id} with {len(module_names)} modules for agent {agent_id}")

            return {
                'success': True,
                'chain_id': chain_id,
                'chain_name': chain_name,
                'module_count': len(module_names)
            }

        except Exception as e:
            self.logger.error(f"Error creating task chain: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def execute_chain(self, chain_id, execute_async=False):
        try:
            chain = self.db.fetchone(
                'SELECT * FROM task_chains WHERE id = ?',
                (chain_id,)
            )

            if not chain:
                return {
                    'success': False,
                    'error': 'Chain not found'
                }

            agent_id = chain['agent_id']

            self.db.execute(
                'UPDATE task_chains SET status = ?, started_at = ? WHERE id = ?',
                ('running', datetime.now(), chain_id)
            )
            self.db.get_connection().commit()

            tasks = self.db.fetchall(
                'SELECT * FROM chain_tasks WHERE chain_id = ? ORDER BY sequence_order',
                (chain_id,)
            )
            
            if not tasks:
                return {
                    'success': False,
                    'error': 'No tasks found in chain'
                }
            
            results = []
            previous_result = None

            for task in tasks:
                task_id = task['id']
                module_name = task['module_name']
                args = json.loads(task['args']) if task['args'] else {}

                self.db.execute(
                    'UPDATE chain_tasks SET status = ?, started_at = ? WHERE id = ?',
                    ('running', datetime.now(), task_id)
                )
                self.db.get_connection().commit()

                module = self.module_manager.get_module(module_name)
                if not module:
                    error_msg = f'Module {module_name} not found'
                    self.db.execute(
                        'UPDATE chain_tasks SET status = ?, error = ?, completed_at = ? WHERE id = ?',
                        ('failed', error_msg, datetime.now(), task_id)
                    )
                    self.db.get_connection().commit()

                    results.append({
                        'module': module_name,
                        'status': 'failed',
                        'error': error_msg
                    })

                    self._mark_chain_failed(chain_id, error_msg)
                    break

                try:
                    if execute_async:
                        class MinimalSession:
                            def __init__(self, agent_manager, agent_id):
                                self.agent_manager = agent_manager
                                self.current_agent = agent_id  # Set the current agent ID

                        session = MinimalSession(self.agent_manager, agent_id)

                        module_args = args.copy()  # Don't modify the original args
                        if 'agent_id' not in module_args:
                            module_args['agent_id'] = agent_id

                        try:
                            module_result = module['module'].execute(module_args, session)
                            if module_result.get('success') and 'task_id' in module_result:
                                result = {
                                    'module': module_name,
                                    'status': 'queued',
                                    'agent_task_id': module_result['task_id'],
                                    'output': module_result.get('output', '')
                                }
                            elif not module_result.get('success'):
                                result = {
                                    'module': module_name,
                                    'status': 'failed',
                                    'error': module_result.get('error', 'Module execution failed')
                                }
                            else:
                                result = {
                                    'module': module_name,
                                    'status': 'failed',
                                    'error': f'Unexpected result from module: {module_result}'
                                }
                        except Exception as e:
                            result = {
                                'module': module_name,
                                'status': 'failed',
                                'error': f'Error executing module: {str(e)}'
                            }
                    else:
                        result = self._execute_module_sync(module, args, previous_result, agent_id)

                    self.db.execute(
                        'UPDATE chain_tasks SET status = ?, result = ?, completed_at = ? WHERE id = ?',
                        (result['status'], json.dumps(result), datetime.now(), task_id)
                    )
                    self.db.get_connection().commit()

                    results.append(result)
                    previous_result = result.get('output')

                    if result['status'] == 'failed':
                        self._mark_chain_failed(chain_id, result.get('error', 'Task execution failed'))
                        break
                    
                except Exception as e:
                    error_msg = str(e)
                    self.logger.error(f"Error executing module {module_name}: {error_msg}")
                    
                    self.db.execute(
                        'UPDATE chain_tasks SET status = ?, error = ?, completed_at = ? WHERE id = ?',
                        ('failed', error_msg, datetime.now(), task_id)
                    )
                    self.db.get_connection().commit()
                    
                    results.append({
                        'module': module_name,
                        'status': 'failed',
                        'error': error_msg
                    })
                    
                    self._mark_chain_failed(chain_id, error_msg)
                    break
            
            all_succeeded = all(r.get('status') in ['completed', 'queued'] for r in results)
            if all_succeeded:
                self.db.execute(
                    'UPDATE task_chains SET status = ?, completed_at = ? WHERE id = ?',
                    ('completed', datetime.now(), chain_id)
                )
                self.db.get_connection().commit()

            return {
                'success': True,
                'chain_id': chain_id,
                'results': results,
                'status': 'completed' if all_succeeded else 'failed'
            }

        except Exception as e:
            self.logger.error(f"Error executing chain {chain_id}: {str(e)}")
            self._mark_chain_failed(chain_id, str(e))
            return {
                'success': False,
                'error': str(e)
            }

    def _build_module_command(self, module_name, args, previous_result=None):
        command = f"execute_module {module_name}"

        if previous_result:
            args['previous_result'] = previous_result

        if args:
            args_str = json.dumps(args)
            command += f" {args_str}"

        return command

    def _execute_module_sync(self, module, args, previous_result, agent_id):

        module_info = module['info']

        return {
            'module': module_info['name'],
            'status': 'completed',
            'output': f"Simulated execution of {module_info['name']}",
            'args': args
        }

    def _mark_chain_failed(self, chain_id, error):
        """Mark a chain as failed"""
        try:
            self.db.execute(
                'UPDATE task_chains SET status = ?, completed_at = ? WHERE id = ?',
                ('failed', datetime.now(), chain_id)
            )

            self.db.execute(
                'UPDATE chain_tasks SET status = ?, error = ? WHERE chain_id = ? AND status = ?',
                ('cancelled', 'Chain failed', chain_id, 'pending')
            )

            self.db.get_connection().commit()
        except Exception as e:
            self.logger.error(f"Error marking chain as failed: {str(e)}")
    
    def get_chain_status(self, chain_id):
        try:
            chain = self.db.fetchone(
                'SELECT * FROM task_chains WHERE id = ?',
                (chain_id,)
            )
            
            if not chain:
                return None
            
            tasks = self.db.fetchall(
                'SELECT * FROM chain_tasks WHERE chain_id = ? ORDER BY sequence_order',
                (chain_id,)
            )
            
            return {
                'chain_id': chain['id'],
                'name': chain['name'],
                'agent_id': chain['agent_id'],
                'status': chain['status'],
                'created_at': chain['created_at'],
                'started_at': chain['started_at'],
                'completed_at': chain['completed_at'],
                'tasks': [
                    {
                        'module_name': t['module_name'],
                        'status': t['status'],
                        'sequence_order': t['sequence_order'],
                        'result': json.loads(t['result']) if t['result'] else None,
                        'error': t['error']
                    }
                    for t in tasks
                ]
            }
        except Exception as e:
            self.logger.error(f"Error getting chain status: {str(e)}")
            return None
    
    def list_chains(self, agent_id=None, status=None, limit=50):
        try:
            query = 'SELECT * FROM task_chains'
            params = []
            conditions = []
            
            if agent_id:
                conditions.append('agent_id = ?')
                params.append(agent_id)
            
            if status:
                conditions.append('status = ?')
                params.append(status)
            
            if conditions:
                query += ' WHERE ' + ' AND '.join(conditions)
            
            query += ' ORDER BY created_at DESC LIMIT ?'
            params.append(limit)
            
            chains = self.db.fetchall(query, tuple(params))
            
            return [
                {
                    'chain_id': c['id'],
                    'name': c['name'],
                    'agent_id': c['agent_id'],
                    'module_names': json.loads(c['module_names']),
                    'status': c['status'],
                    'created_at': c['created_at'],
                    'completed_at': c['completed_at']
                }
                for c in chains
            ]
        except Exception as e:
            self.logger.error(f"Error listing chains: {str(e)}")
            return []



