# ===============================
# 🛡️ Port Stealth Module
# ===============================
# This module implements port hiding for nmap evasion using RST packets

import socket
import threading
import time
import json
import struct

# Constants
PORTS_DB = "ports.json"
# Track active stealth sockets
STEALTH_SOCKETS = {}

def load_ports():
    """Load port configuration from JSON file"""
    try:
        with open(PORTS_DB, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_ports(ports):
    """Save port configuration to JSON file"""
    with open(PORTS_DB, "w") as f:
        json.dump(ports, f, indent=4)

def setup_socket_listen(port, active):
    """Platform-independent method using raw sockets to handle port visibility"""
    # Stop any existing socket for this port
    if port in STEALTH_SOCKETS and STEALTH_SOCKETS[port]['thread'].is_alive():
        STEALTH_SOCKETS[port]['active'] = False
        # Give thread time to exit
        time.sleep(0.1)
        
    if active:
        # Don't need to do anything, server will handle active ports
        if port in STEALTH_SOCKETS:
            del STEALTH_SOCKETS[port]
        return True
    else:
        # For inactive ports, start a temporary socket that responds with RST packets
        try:
            # Run this in a separate thread to avoid blocking
            stealth_info = {'active': True}
            thread = threading.Thread(target=_handle_inactive_port, args=(port, stealth_info), daemon=True)
            stealth_info['thread'] = thread
            STEALTH_SOCKETS[port] = stealth_info
            thread.start()
            return True
        except Exception as e:
            print(f"Error setting up stealth socket for port {port}: {e}")
            return False

def _handle_inactive_port(port, stealth_info):
    """Thread function to handle an inactive port"""
    try:
        # Create a socket that responds with RST packets to connections
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            s.bind(('0.0.0.0', port))
            s.listen(5)
            
            # Keep accepting connections but immediately close them with RST
            while stealth_info['active']:
                try:
                    # Set a timeout so we can check if we should exit
                    s.settimeout(0.5)
                    try:
                        client, addr = s.accept()
                        
                        # Set linger option to send RST instead of normal FIN
                        client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 
                                        struct.pack('ii', 1, 0))
                        client.close()
                    except socket.timeout:
                        # Check if we should still be active
                        continue
                except Exception:
                    if stealth_info['active']:
                        time.sleep(0.1)
                
                # Check if port should still be inactive
                ports = load_ports()
                port_config = next((p for p in ports if p["port"] == port), None)
                if not port_config or port_config["status"] == "active":
                    break
        finally:
            s.close()
            
    except Exception:
        pass

def update_port_visibility(port, active):
    """Update port visibility using RST packet approach"""
    result = setup_socket_listen(port, active)
    return result

def sync_all_ports():
    """Sync stealth settings for all ports"""
    ports = load_ports()
    for port_config in ports:
        port = port_config["port"]
        active = port_config["status"] == "active"
        update_port_visibility(port, active)

# Run synchronization on import
if __name__ != "__main__":
    try:
        sync_all_ports()
    except Exception as e:
        print(f"Error syncing port visibility: {e}")