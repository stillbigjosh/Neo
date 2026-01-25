#!/bin/bash

echo "Setting environment variables..."
# If script is in setup directory, source .env from parent directory
if [[ "$(pwd)" == */setup ]]; then
    if [ -f "../.env" ]; then
        source ../.env
    else
        echo "Warning: .env file not found in parent directory"
    fi
else
    source .env
fi

# Determine the parent directory for file access
if [[ "$(pwd)" == */setup ]]; then
    PARENT_DIR="$(dirname "$(pwd)")"
    # Create virtual environment in parent directory if it doesn't exist
    if [ ! -d "$PARENT_DIR/.venv" ]; then
        echo "Creating Python virtual environment in parent directory..."
        python3 -m venv "$PARENT_DIR/.venv"
    fi
    echo "Activating Python virtual environment from parent directory..."
    source "$PARENT_DIR/.venv/bin/activate"
else
    if [ ! -d ".venv" ]; then
        echo "Creating Python virtual environment..."
        python3 -m venv .venv
    fi
    echo "Activating Python virtual environment..."
    source .venv/bin/activate
fi

# Generate SSL certificates in parent directory if running from setup directory
if [[ "$(pwd)" == */setup ]]; then
    PARENT_DIR="$(dirname "$(pwd)")"
    if [ ! -f "$PARENT_DIR/server.crt" ] || [ ! -f "$PARENT_DIR/server.key" ]; then
        echo "Generating SSL certificates in parent directory..."
        openssl req -x509 -newkey rsa:4096 -keyout "$PARENT_DIR/server.key" -out "$PARENT_DIR/server.crt" -days 365 -nodes -subj "/C=US/ST=YourState/L=YourCity/O=YourOrganization/OU=YourOU/CN=YourDomain"
        # Copy certificates to the existing listeners directory in the parent project
        cp "$PARENT_DIR/server.key" "$PARENT_DIR/listeners/"
        cp "$PARENT_DIR/server.crt" "$PARENT_DIR/listeners/"
    fi
else
    if [ ! -f server.crt ] || [ ! -f server.key ]; then
        echo "Generating SSL certificates..."
        openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=US/ST=YourState/L=YourCity/O=YourOrganization/OU=YourOU/CN=YourDomain"
        # Copy certificates to the existing listeners directory
        cp server.key listeners/
        cp server.crt listeners/
    fi
fi

if [[ "$(pwd)" == */setup ]]; then
    # Requirements.txt should be in parent directory (project root)
    if [ -f "../requirements.txt" ]; then
        echo "Installing requirements from requirements.txt in parent directory..."
        pip install --break-system-packages -r ../requirements.txt
    else
        echo "requirements.txt not found in parent directory. Cannot install dependencies."
        exit 1
    fi
else
    if [ -f requirements.txt ]; then
        echo "Installing requirements from requirements.txt..."
        pip install --break-system-packages -r requirements.txt
    else
        echo "requirements.txt not found. Cannot install dependencies."
        exit 1
    fi
fi

echo "Checking firewall status..."
if command -v ufw &> /dev/null; then
    UFW_STATUS=$(ufw status | grep -w "443/tcp")
    if [ -z "$UFW_STATUS" ]; then
        echo "Port 443 is not open. Allowing port 443/tcp in ufw..."
        ufw allow 443/tcp
    else
        echo "Port 443/tcp is already allowed in ufw."
    fi
elif command -v firewall-cmd &> /dev/null; then
    FIREWALLD_STATUS=$(firewall-cmd --list-ports | grep -w "443/tcp")
    if [ -z "$FIREWALLD_STATUS" ]; then
        echo "Port 443 is not open. Allowing port 443/tcp in firewalld..."
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --reload
    else
        echo "Port 443/tcp is already allowed in firewalld."
    fi
else
    echo "Could not detect ufw or firewalld. Please ensure port 443 is open manually."
fi

pip install --break-system-packages gevent-websocket
echo ""
echo "********************************************************************************"
echo "** IMPORTANT: Remember to allow port 443 on your VPS/cloud firewall as well! **"
echo "********************************************************************************"
echo ""

# Now continue with the service setup portion
set -e  # Exit on any error

echo "Setting up NeoC2 as a system service..."

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or with sudo"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="/opt/neoc2"
SERVICE_NAME="neoc2"
SERVICE_FILE="$SCRIPT_DIR/neoc2.service"
SYSTEMD_SERVICE="/etc/systemd/system/neoc2.service"

# Copy the project to system location if not already there
if [ ! -d "/opt/neoc2" ]; then
    echo "Copying NeoC2 to system location (/opt/neoc2)..."
    mkdir -p /opt/neoc2
    # If script is in setup directory, copy parent directory contents but exclude setup directory
    if [[ "$SCRIPT_DIR" == */setup ]]; then
        PARENT_DIR="$(dirname "$SCRIPT_DIR")"
        # Copy all contents from parent directory except the setup directory itself
        for item in "$PARENT_DIR"/*; do
            item_name=$(basename "$item")
            if [ "$item_name" != "setup" ]; then
                cp -r "$item" "/opt/neoc2/"
            fi
        done
        # Also copy the runtime scripts (neoc2 and neoc2-cli) from setup to root installation directory
        # These are needed for the systemd service and other operations
        cp "$PARENT_DIR/setup/neoc2" "/opt/neoc2/"
        cp "$PARENT_DIR/setup/neoc2-cli" "/opt/neoc2/"
        cp "$PARENT_DIR/setup/c2_service.py" "/opt/neoc2/"
        # Copy .env file from parent directory to installation directory
        if [ -f "$PARENT_DIR/.env" ]; then
            cp "$PARENT_DIR/.env" "/opt/neoc2/"
        fi
    else
        cp -r "$SCRIPT_DIR/." /opt/neoc2/
    fi
    chown -R root:root /opt/neoc2
    echo "NeoC2 copied to /opt/neoc2"

    # Copy SSL certificates if they exist in the parent directory
    if [ -f "$PARENT_DIR/server.crt" ] && [ -f "$PARENT_DIR/server.key" ]; then
        cp "$PARENT_DIR/server.crt" "/opt/neoc2/"
        cp "$PARENT_DIR/server.key" "/opt/neoc2/"
    fi

    # Copy the virtual environment from parent directory to installation directory
    if [ -d "$PARENT_DIR/.venv" ]; then
        echo "Copying Python virtual environment to installation directory..."
        cp -r "$PARENT_DIR/.venv" "/opt/neoc2/.venv"
    else
        # If no venv exists in parent, create one in installation
        echo "Creating Python virtual environment in installation directory..."
        /usr/bin/python3 -m venv /opt/neoc2/.venv
        # Install requirements using the virtual environment's pip directly
        /opt/neoc2/.venv/bin/pip install --break-system-packages -r /opt/neoc2/requirements.txt
    fi

    # Ensure listeners directory has proper permissions for the service to write to it
    if [ -d "/opt/neoc2/listeners" ]; then
        chown -R root:root /opt/neoc2/listeners
    fi

fi

echo "Step 1: Making service scripts executable..."
chmod +x "/opt/neoc2/c2_service.py"
chmod +x "/opt/neoc2/neoc2-cli"
chmod +x "/opt/neoc2/neoc2"

echo "Step 2: Installing systemd service file..."
cp "$SERVICE_FILE" "$SYSTEMD_SERVICE"

echo "Step 3: Installing neoc2 CLI command..."
cp "/opt/neoc2/neoc2-cli" "/usr/local/bin/neoc2-cli"
chmod +x "/usr/local/bin/neoc2-cli"

echo "Step 4: Installing neoc2 service manager command..."
cp "/opt/neoc2/neoc2" "/usr/local/bin/neoc2"
chmod +x "/usr/local/bin/neoc2"

echo "Step 5: Reloading systemd daemon..."
systemctl daemon-reload

echo "Step 6: Enabling the service to start on boot..."
systemctl enable neoc2.service

echo "SECURITY NOTICE: The service reads credentials from /opt/neoc2/.env file."
echo "For production use, edit /opt/neoc2/.env to set your own credentials."
echo "The service uses gevent via gunicorn with wsgi_framework.py as entry point."
echo "Then run: sudo systemctl restart neoc2"
echo ""

echo "Step 7: Starting the service..."
systemctl start neoc2.service

echo "Step 8: Checking service status..."
systemctl status neoc2.service --no-pager -l

echo ""
echo "NeoC2 service setup completed!"
echo ""
echo "Useful commands:"
echo "  Enable auto-start: sudo systemctl enable neoc2"
echo "  Disable auto-start: sudo systemctl disable neoc2"
echo ""
echo "Service management (after setup):"
echo "  neoc2 status        - Check service status"
echo "  neoc2 start         - Start the C2 service"
echo "  neoc2 stop          - Stop the C2 service"
echo "  neoc2 restart       - Restart the C2 service"
echo "  neoc2 logs          - View service logs in real-time"
echo ""
echo "IMPORTANT: Credentials are read from /opt/neoc2/.env file!"
echo "The C2 server should now be running as a background service using gevent."
echo "Check the status and logs to confirm it's working properly."


