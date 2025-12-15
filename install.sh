#!/bin/bash

echo "Setting environment variables..."
source .env

if [ ! -d ".venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi

echo "Activating Python virtual environment..."
source .venv/bin/activate

if [ ! -f server.crt ] || [ ! -f server.key ]; then
    echo "Generating SSL certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=US/ST=YourState/L=YourCity/O=YourOrganization/OU=YourOU/CN=YourDomain"
    cp server.key listeners
    cp server.crt listeners
fi

if [ -f requirements.txt ]; then
    echo "Installing requirements from requirements.txt..."
    pip install -r requirements.txt
else
    echo "requirements.txt not found. Cannot install dependencies."
    exit 1
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

pip install gevent-websocket
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
    cp -r "$SCRIPT_DIR/." /opt/neoc2/
    chown -R root:root /opt/neoc2
    echo "NeoC2 copied to /opt/neoc2"
fi

echo "Step 1: Making service scripts executable..."
chmod +x "/opt/neoc2/c2_service.py"
chmod +x "/opt/neoc2/neoc2-cli"

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
echo "  Start service:     sudo systemctl start neoc2"
echo "  Stop service:      sudo systemctl stop neoc2"
echo "  Restart service:   sudo systemctl restart neoc2"
echo "  Check status:      sudo systemctl status neoc2"
echo "  View logs:         sudo journalctl -u neoc2 -f"
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
echo "The C2 server should now be running as a background service on port 443 using gevent."
echo "Check the status and logs to confirm it's working properly."


