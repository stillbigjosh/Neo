#!/bin/bash

set -e  # Exit on any error

echo "NeoC2 Uninstall Script"
echo "======================"

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or with sudo"
    exit 1
fi

read -p "This will completely remove NeoC2 from your system. Are you sure? (yes/no): " -r
if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
    echo "Uninstallation cancelled."
    exit 0
fi

echo ""
echo "Starting NeoC2 uninstallation..."

echo "Step 1: Stopping and disabling the service..."
if systemctl is-active --quiet neoc2; then
    systemctl stop neoc2
    echo "  - Service stopped"
else
    echo "  - Service was not running"
fi

if systemctl is-enabled --quiet neoc2; then
    systemctl disable neoc2
    echo "  - Service disabled"
else
    echo "  - Service was not enabled"
fi

echo "Step 2: Removing systemd service configuration..."
if [ -f "/etc/systemd/system/neoc2.service" ]; then
    rm -f /etc/systemd/system/neoc2.service
    echo "  - Service file removed"
else
    echo "  - Service file not found"
fi

echo "Step 3: Reloading systemd daemon..."
systemctl daemon-reload
systemctl reset-failed

echo "Step 4: Removing NeoC2 installation directory..."
if [ -d "/opt/neoc2" ]; then
    rm -rf /opt/neoc2
    echo "  - /opt/neoc2 directory removed"
else
    echo "  - /opt/neoc2 directory not found"
fi

echo "Step 5: Removing any remaining database and SSL files..."
rm -f /opt/neoc2/neoc2.db /opt/neoc2/neoc2.db-shm /opt/neoc2/neoc2.db-wal 2>/dev/null || true
rm -f /opt/neoc2/server.crt /opt/neoc2/server.key 2>/dev/null || true

echo "Step 6: Checking for any remaining NeoC2 processes..."
pkill -f "neoc2" 2>/dev/null || true
pkill -f "NeoC2" 2>/dev/null || true
rm /usr/local/bin/neoc2
rm /usr/local/bin/neoc2-cli
echo ""
echo "Uninstallation completed!"
echo ""
echo "NeoC2 has been completely removed from your system."
echo ""
echo "Note: If you installed NeoC2 in a different location than /opt/neoc2,"
echo "      you may need to manually remove those directories."
echo ""
echo "If you opened firewall ports for NeoC2, you may want to remove them:"
echo "  sudo ufw delete allow 443/tcp (if using ufw)"
echo "  sudo ufw delete allow 444/tcp (if using ufw)"
echo ""
