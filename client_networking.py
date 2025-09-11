#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client - Network and Tunneling
Tünel sunucusu ve network bağlantı yönetimi
"""

import os
import sys
import ssl
import json
import time
import socket
import threading
from typing import Dict, Any, Optional

# Import helper functions and config
from client_helpers import log, ClientHelpers

# Get config function - will be set by main application
_get_config_func = None

def set_config_function(config_func):
    """Set the config function from main application"""
    global _get_config_func
    _get_config_func = config_func

def get_from_config(key_path: str, fallback):
    """Get config value using the injected config function"""
    if _get_config_func:
        return _get_config_func(key_path, fallback)
    return fallback

# Network configuration - loaded from config when available
HONEYPOT_IP: str = "194.5.236.181"  # Default, will be overridden
HONEYPOT_TUNNEL_PORT: int = 4443     # Default, will be overridden
RECV_SIZE: int = 65536               # Default, will be overridden
CONNECT_TIMEOUT: int = 8             # Default, will be overridden
SERVER_NAME: str = socket.gethostname()  # Default, will be overridden

def load_network_config():
    """Load network configuration from config file"""
    global HONEYPOT_IP, HONEYPOT_TUNNEL_PORT, RECV_SIZE, CONNECT_TIMEOUT, SERVER_NAME
    HONEYPOT_IP = get_from_config("honeypot.server_ip", "194.5.236.181")
    HONEYPOT_TUNNEL_PORT = get_from_config("honeypot.tunnel_port", 4443)
    RECV_SIZE = get_from_config("honeypot.receive_buffer_size", 65536)
    CONNECT_TIMEOUT = get_from_config("honeypot.connect_timeout", 8)
    server_name_config = get_from_config("honeypot.server_name", None)
    SERVER_NAME = server_name_config if server_name_config else socket.gethostname()

def set_network_config(honeypot_ip: str = None, tunnel_port: int = None, recv_size: int = None, 
                      connect_timeout: int = None, server_name: str = None) -> None:
    """Set network configuration constants (override config values if needed)"""
    global HONEYPOT_IP, HONEYPOT_TUNNEL_PORT, RECV_SIZE, CONNECT_TIMEOUT, SERVER_NAME
    if honeypot_ip is not None:
        HONEYPOT_IP = honeypot_ip
    if tunnel_port is not None:
        HONEYPOT_TUNNEL_PORT = tunnel_port
    if recv_size is not None:
        RECV_SIZE = recv_size
    if connect_timeout is not None:
        CONNECT_TIMEOUT = connect_timeout
    if server_name is not None:
        SERVER_NAME = server_name

def get_network_config() -> Dict[str, Any]:
    """Get current network configuration"""
    return {
        "honeypot_ip": HONEYPOT_IP,
        "tunnel_port": HONEYPOT_TUNNEL_PORT,
        "recv_size": RECV_SIZE,
        "connect_timeout": CONNECT_TIMEOUT,
        "server_name": SERVER_NAME
    }

def update_honeypot_ip_from_api(api_client, token: str) -> bool:
    """Future: Update honeypot IP from API (not implemented yet)"""
    try:
        # TODO: API endpoint'i hazır olduğunda implement edilecek
        # response = api_client.get_honeypot_config(token)
        # if response and 'server_ip' in response:
        #     global HONEYPOT_IP
        #     HONEYPOT_IP = response['server_ip']
        #     log(f"Honeypot IP updated from API: {HONEYPOT_IP}")
        #     return True
        log("[FUTURE] Honeypot IP API integration not yet implemented")
        return False
    except Exception as e:
        log(f"Failed to update honeypot IP from API: {e}")
        return False

# ===================== TUNNEL SERVER IMPLEMENTATION ===================== #

class TunnelServerThread(threading.Thread):
    """High-performance tunnel server for forwarding honeypot traffic"""
    
    def __init__(self, app, listen_port: int, service_name: str):
        super().__init__(daemon=True)
        self.app, self.listen_port, self.service_name = app, int(listen_port), service_name
        self.stop_evt, self.sock = threading.Event(), None

    def run(self):
        """Main server loop with optimized connection handling"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("0.0.0.0", self.listen_port))
            self.sock.listen(200)
            log(f"[{self.service_name}] Listening on 0.0.0.0:{self.listen_port}")
        except Exception as e:
            log(f"[{self.service_name}] Failed to bind port {self.listen_port}: {e}")
            return

        # Main accept loop with timeout handling
        while not self.stop_evt.is_set():
            try:
                self.sock.settimeout(1.0)
                client_sock, _ = self.sock.accept()
                
                # Handle connection in separate thread
                threading.Thread(
                    target=NetworkingHelpers.handle_incoming_connection,
                    args=(self.app, client_sock, self.listen_port, self.service_name),
                    daemon=True
                ).start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if not self.stop_evt.is_set():
                    log(f"[{self.service_name}] Accept error: {e}")

    def stop(self):
        """Gracefully stop the tunnel server"""
        self.stop_evt.set()
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

# ===================== NETWORKING HELPER FUNCTIONS ===================== #

class NetworkingHelpers:
    """Container class for networking utility functions"""
    
    @staticmethod
    def create_tls_socket():
        """Create TLS connection to honeypot server"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        raw = socket.create_connection((HONEYPOT_IP, HONEYPOT_TUNNEL_PORT), timeout=CONNECT_TIMEOUT)
        return ctx.wrap_socket(raw, server_hostname=HONEYPOT_IP)

    @staticmethod
    def send_json(sock, obj: Dict):
        """Send JSON object over socket"""
        data = (json.dumps(obj, separators=(',', ':')) + "\n").encode("utf-8")
        sock.sendall(data)

    @staticmethod
    def pipe_streams(src, dst):
        """Pipe data between two sockets"""
        try:
            while True:
                data = src.recv(RECV_SIZE)
                if not data: 
                    break
                dst.sendall(data)
        except:
            pass
        finally:
            for s in (dst, src):
                try: 
                    s.shutdown(socket.SHUT_RDWR)
                except: 
                    pass
                try: 
                    s.close()
                except: 
                    pass

    @staticmethod
    def handle_incoming_connection(app, local_sock, listen_port: str, service_name: str):
        """Handle incoming connection and forward to honeypot"""
        try:
            peer = local_sock.getpeername()
            attacker_ip, attacker_port = peer[0], peer[1]
        except:
            attacker_ip, attacker_port = "0.0.0.0", 0

        try:
            remote = NetworkingHelpers.create_tls_socket()
        except Exception as e:
            log(f"[{service_name}:{listen_port}] TLS bağlanamadı: {e}")
            try: local_sock.close()
            except: pass
            return

        try:
            handshake = {
                "op": "open", "token": app.state.get("token"),
                "client_ip": app.state.get("public_ip") or ClientHelpers.get_public_ip(),
                "hostname": SERVER_NAME, "service": service_name,
                "listen_port": int(listen_port), "attacker_ip": attacker_ip,
                "attacker_port": attacker_port
            }
            log(f"[{service_name}:{listen_port}] Honeypot'a gönderilen handshake: {json.dumps(handshake, indent=2)}")
            NetworkingHelpers.send_json(remote, handshake)
            log(f"[{service_name}:{listen_port}] Handshake başarıyla gönderildi - Hedef: {HONEYPOT_IP}:{HONEYPOT_TUNNEL_PORT}")
        except Exception as e:
            log(f"Handshake hata: {e}")
            try: remote.close(); local_sock.close()
            except: pass
            return

        # Start bidirectional pipe threads
        t1 = threading.Thread(target=NetworkingHelpers.pipe_streams, args=(local_sock, remote), daemon=True)
        t2 = threading.Thread(target=NetworkingHelpers.pipe_streams, args=(remote, local_sock), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
        log(f"[{service_name}:{listen_port}] bağlantı kapandı ({attacker_ip}:{attacker_port})")

    @staticmethod
    def is_port_in_use(port: int) -> bool:
        """Check if a port is currently in use"""
        try:
            if os.name == 'nt':
                from client_helpers import run_cmd
                ps = (
                    f"$p={int(port)};"
                    "$l=Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue;"
                    "if ($l) { Write-Output 'FOUND'; exit 0 } else { exit 1 }"
                )
                res = run_cmd(['powershell','-NoProfile','-Command', ps], timeout=8, suppress_rc_log=True)
                if res and getattr(res, 'returncode', 1) == 0 and getattr(res, 'stdout', '').find('FOUND') >= 0:
                    return True
        except Exception as e:
            log(f"Port check exception: {e}")
        return False

# ===================== TUNNEL MANAGEMENT LOOPS ===================== #

class TunnelManager:
    """Container class for tunnel management functionality"""
    
    @staticmethod
    def tunnel_sync_loop(app):
        """Regularly synchronize tunnel states with API"""
        while True:
            try:
                current_time = time.time()
                last_sync = app.state.get("last_tunnel_sync", 0)
                sync_interval = app.state.get("tunnel_sync_interval", 30)
                
                if current_time - last_sync >= sync_interval:
                    TunnelManager.sync_tunnel_states(app)
                    app.state["last_tunnel_sync"] = current_time
                    
                time.sleep(10)  # Check every 10 seconds
            except Exception as e:
                log(f"Tunnel sync loop error: {e}")
                time.sleep(30)

    @staticmethod  
    def tunnel_watchdog_loop(app):
        """Monitor and restart dead tunnels"""
        while True:
            try:
                if app.state.get("running"):
                    desired = {(str(p[0]), str(p[2]).upper()) for p in app.state.get("selected_rows", [])}
                    
                    # Restart missing/dead tunnels
                    for (listen_port, new_port, service) in app.state.get("selected_rows", []):
                        lp = int(str(listen_port))
                        st = app.state["servers"].get(lp)
                        if (st is None) or (not st.is_alive()):
                            try:
                                st2 = TunnelServerThread(app, lp, str(service))
                                st2.start(); time.sleep(0.2)
                                if st2.is_alive():
                                    app.state["servers"][lp] = st2
                                    log(f"[watchdog] {service}:{lp} yeniden başlatıldı")
                            except Exception as e:
                                log(f"[watchdog] {service}:{lp} başlatılamadı: {e}")

                    # Stop excess tunnels
                    for lp, st in list(app.state["servers"].items()):
                        key = (str(lp), str(st.service_name).upper())
                        if key not in desired:
                            try: st.stop(); del app.state["servers"][lp]
                            except Exception: pass
            except Exception as e:
                log(f"watchdog loop err: {e}")
            time.sleep(10)

    @staticmethod
    def sync_tunnel_states(app):
        """Synchronize tunnel states with API"""
        if app.state.get("reconciliation_paused"):
            log("Senkronizasyon duraklatıldı, atlanıyor...")
            return
        try:
            remote = app.api_request("GET", "premium/tunnel-status") or {}
            local  = app.get_local_tunnel_state()

            for service, remote_cfg in remote.items():
                if service not in app.DEFAULT_TUNNELS: 
                    continue
                listen_port = str(app.DEFAULT_TUNNELS[service]["listen_port"])
                desired = (remote_cfg.get('desired') or 'stopped').lower()
                local_status = (local.get(service, {}).get('status') or 'stopped').lower()

                if desired == 'started' and local_status != 'started':
                    newp = str(remote_cfg.get('new_port') or listen_port)
                    app.start_single_row(listen_port, newp, service)
                    # UI güncelleme: listen_port ile
                    app._update_row_ui(listen_port, service, True)
                elif desired == 'stopped' and local_status != 'stopped':
                    newp = str(remote_cfg.get('new_port') or listen_port)
                    app.stop_single_row(listen_port, newp, service)

            app.report_tunnel_status_once()
        except Exception as e:
            log(f"Tünel durumları senkronize edilirken hata: {e}")
        finally:
            with app.reconciliation_lock:
                app.state["reconciliation_paused"] = False

    @staticmethod
    def get_tunnel_state(app) -> Dict[str, Any]:
        """Get tunnel state from API"""
        try:
            token = app.state.get("token")
            if not token:
                return {}
                
            response = app.api_request("GET", "premium/tunnel-status")
            if isinstance(response, dict):
                return response.get("tunnels", {})
            return {}
        except Exception as e:
            log(f"Failed to get tunnel state: {e}")
            return {}

    @staticmethod
    def is_service_running(app, service_name: str) -> bool:
        """Check if a service tunnel is currently running"""
        try:
            service_upper = str(service_name).upper()
            
            # Check if any server is running for this service
            for port, server_thread in app.state["servers"].items():
                if hasattr(server_thread, 'service_name'):
                    if server_thread.service_name.upper() == service_upper:
                        return server_thread.is_alive()
            
            # Check by port mapping
            for row in app.state.get("selected_rows", []):
                if row[2].upper() == service_upper:
                    listen_port = int(row[0])
                    return listen_port in app.state["servers"] and app.state["servers"][listen_port].is_alive()
                    
            return False
        except Exception:
            return False
