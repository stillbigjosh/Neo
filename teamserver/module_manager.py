import os
import sys
import json
import importlib.util
import inspect
import uuid
import logging
from datetime import datetime
from core.config import NeoC2Config
from core.models import NeoC2DB

class Module:
    def __init__(self, id, name, path, description, type, technique_id, mitre_tactics, dependencies):
        self.id = id
        self.name = name
        self.path = path
        self.description = description
        self.type = type
        self.technique_id = technique_id
        self.mitre_tactics = mitre_tactics
        self.dependencies = dependencies
        self.module = None
    
    def load(self):
        spec = importlib.util.spec_from_file_location(self.name, self.path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)


class ModuleManager:
    def __init__(self, config, db):
        self.config = config
        self.db = db
        self.modules_dir = "modules"
        self.armory_dir = "armory"
        self.loaded_modules = {}
        
        self.setup_logging()
        self.setup_db()
        self.add_default_modules()
        self.load_all_modules()
        os.makedirs(self.modules_dir, exist_ok=True)
        os.makedirs(self.armory_dir, exist_ok=True)

    def setup_logging(self):
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        logging.basicConfig(
            filename=os.path.join(log_dir, "module_manager.log"),
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("ModuleManager")
        
    def setup_db(self):
        self.db.execute('''
        CREATE TABLE IF NOT EXISTS modules (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            type TEXT,
            code TEXT,
            technique_id TEXT,
            mitre_tactics TEXT,
            dependencies TEXT,
            path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        cursor = self.db.execute("PRAGMA table_info(modules)")
        existing_columns = [row[1] for row in cursor.fetchall()]

        if 'dependencies' not in existing_columns:
            self.logger.info("Migrating database: Adding 'dependencies' column")
            self.db.execute("ALTER TABLE modules ADD COLUMN dependencies TEXT")

        if 'path' not in existing_columns:
            self.logger.info("Migrating database: Adding 'path' column")
            self.db.execute("ALTER TABLE modules ADD COLUMN path TEXT")

        self.db.get_connection().commit()

        self.db.execute('''
        CREATE TABLE IF NOT EXISTS module_executions (
            id TEXT PRIMARY KEY,
            module_id TEXT,
            agent_id TEXT,
            task_id TEXT,
            args TEXT,
            result TEXT,
            status TEXT,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (module_id) REFERENCES modules(id)
        )
        ''')
    
    def load_module(self, module_path):
        try:
            module_name = os.path.basename(module_path).replace('.py', '')

            if module_name in self.loaded_modules:
                self.logger.warning(f"Module {module_name} already loaded")
                pass
                return False

            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            if not hasattr(module, 'get_info'):
                self.logger.error(f"Module {module_name} does not have a get_info function")
                return False

            info = module.get_info()

            required_keys = ['name', 'description', 'type']
            for key in required_keys:
                if key not in info:
                    self.logger.error(f"Module {module_name} missing required key: {key}")
                    return False

            with open(module_path, 'r') as f:
                code = f.read()

            existing = self.db.execute(
                "SELECT id FROM modules WHERE name = ?",
                (info['name'],)
            ).fetchone()

            if existing:
                self.logger.debug(f"Module with name '{info['name']}' already exists in database")
                return False

            id = str(uuid.uuid4())

            self.db.execute('''
            INSERT INTO modules (id, name, description, type, code, technique_id, mitre_tactics, dependencies, path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                id,
                info['name'],
                info.get('description', ''),
                info.get('type', ''),
                code,
                info.get('technique_id', ''),
                json.dumps(info.get('mitre_tactics', [])),
                json.dumps(info.get('dependencies', [])),
                module_path
            ))

            self.db.get_connection().commit()
        
            self.loaded_modules[module_name] = {
                'module': module,
                'info': info,
                'path': module_path,
                'id': id
            }
        
            self.logger.info(f"Loaded module {module_name} from {module_path}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error loading module {module_path}: {str(e)}")
            import traceback
            return False
    
    def load_all_modules(self):
        """Load all modules from modules directory"""
        for file in os.listdir(self.modules_dir):
            if file.endswith('.py') and file != '__init__.py':
                module_path = os.path.join(self.modules_dir, file)
                self.load_module(module_path)
    
    def get_module(self, module_name):
        return self.loaded_modules.get(module_name)
    
    def load_modules_from_db(self):
        rows = self.db.execute("SELECT id, name, path FROM modules").fetchall()
        for row in rows:
            module_id = row['id']
            module_name = row['name']
            module_path = row['path']
            
            if module_path and os.path.exists(module_path) and module_name not in self.loaded_modules:
                try:
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    if hasattr(module, 'get_info'):
                        info = module.get_info()

                        self.loaded_modules[module_name] = {
                            'module': module,
                            'info': info,
                            'path': module_path,
                            'id': module_id
                        }

                        self.logger.info(f"Loaded module {module_name} from database path {module_path}")
                except Exception as e:
                    self.logger.error(f"Error loading module {module_name} from DB path {module_path}: {str(e)}")
    
    def list_modules(self):
        rows = self.db.execute("SELECT name, description, type, technique_id, mitre_tactics FROM modules").fetchall()
        modules = []
        for row in rows:
            modules.append({
                'name': row['name'],
                'description': row['description'],
                'type': row['type'],
                'technique_id': row['technique_id'],
                'mitre_tactics': json.loads(row['mitre_tactics']) if row['mitre_tactics'] else []
            })
        return modules
    def add_default_modules(self):
        self.load_modules_from_db()
        self.load_all_modules()
        self.load_modules_from_db()
    
    
    
    def check_module_compatibility(self, module_path):
        try:

            spec = importlib.util.spec_from_file_location("module", module_path)
            if spec is None:
                return False, f"Could not load module from path: {module_path}"


            module = importlib.util.module_from_spec(spec)

            spec.loader.exec_module(module)

            required_functions = ['get_info', 'execute']

            for func_name in required_functions:
                has_func = hasattr(module, func_name)
                if not has_func:
                    return False, f"Missing required function: {func_name}"

            info = module.get_info()

            if info is None:
                return False, "get_info() returned None - must return a dictionary"

            if not isinstance(info, dict):
                return False, f"get_info() must return a dictionary, got {type(info).__name__}"

            required_keys = ['name', 'description', 'type']

            for key in required_keys:
                has_key = key in info
                if not has_key:
                    return False, f"Missing required key in get_info: {key}"

            execute_sig = inspect.signature(module.execute)
            param_count = len(execute_sig.parameters)

            if param_count < 1:
                return False, "execute function must accept at least one parameter"

            return True, "Module is compatible"

        except Exception as e:
            import traceback
            return False, f"Error checking module: {str(e)}"
    
    
