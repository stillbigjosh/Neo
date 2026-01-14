#!/usr/bin/env python3

import os
import sys
import signal
import logging
import argparse
from pathlib import Path

project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

from wsgi_framework import NeoC2Framework

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='[%(levelname)-8s] %(asctime)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger('NeoC2Service')

def main():
    parser = argparse.ArgumentParser(description="NeoC2 Service")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--init-db", action="store_true", help="Initialize database and exit")
    parser.add_argument("--generate-ssl", action="store_true", help="Generate SSL certificates and exit")
    parser.add_argument("--foreground", action="store_true", help="Run in foreground mode for debugging")
    args = parser.parse_args()
    
    logger = setup_logging()
    
    os.chdir(project_root)
    
    venv_path = project_root / ".venv"
    if venv_path.exists():
        venv_site_packages = venv_path / "lib" / "python3.*/" / "site-packages"
        import glob
        site_packages_paths = glob.glob(str(venv_site_packages))
        if site_packages_paths:
            sys.path.insert(0, site_packages_paths[0])
    
    logger.info("Initializing NeoC2 Framework...")
    framework = NeoC2Framework(args.config)

    if args.init_db:
        logger.info("Initializing database...")
        framework.db.init_db()
        logger.info("Database initialized")
        return

    if args.generate_ssl:
        logger.info("Generating SSL certificates...")
        # Generate certificates in the project root directory (parent directory of setup)
        if 'setup' in str(project_root):
            # We're running from setup directory, so generate in parent
            parent_dir = project_root.parent
            os.system(f"cd {parent_dir} && openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'")
            # Also copy to listeners directory
            import shutil
            if (parent_dir / "server.key").exists() and (parent_dir / "listeners").exists():
                shutil.copy2(parent_dir / "server.key", parent_dir / "listeners" / "server.key")
                shutil.copy2(parent_dir / "server.crt", parent_dir / "listeners" / "server.crt")
        else:
            # We're running from project root
            os.system("openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'")
            # Also copy to listeners directory
            import shutil
            if os.path.exists("server.key") and os.path.exists("listeners"):
                shutil.copy2("server.key", "listeners/server.key")
                shutil.copy2("server.crt", "listeners/server.crt")
        logger.info("SSL certificates generated and copied to listeners directory")
        return
    
    logger.info("Starting NeoC2 Framework as service...")
    try:
        if not framework.start():
            logger.error("Failed to start framework")
            sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\nReceived keyboard interrupt, shutting down...")
        framework.stop()
    except Exception as e:
        logger.error(f"Framework error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
