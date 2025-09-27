#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cloud Honeypot Client - RDP Management Module
This module handles RDP port security transitions.
"""

import subprocess
import time
import tkinter as tk
from tkinter import ttk
from client_helpers import log


class RDPManager:
    """RDP port security manager"""
    
    def __init__(self, log_func=None):
        self.log_func = log_func or log
    
    def _get_current_rdp_port(self):
        """Get current RDP port from registry"""
        try:
            registry_path = r"HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            ps_cmd = f'powershell -Command "Get-ItemProperty -Path \'{registry_path}\' -Name PortNumber | Select-Object -ExpandProperty PortNumber"'
            
            result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
            
            if result.returncode == 0:
                port = int(result.stdout.strip())
                self.log_func(f"Current RDP registry port: {port}")
                return port
            else:
                self.log_func(f"Registry read error: {result.stderr}")
                return 3389  # Default fallback
                
        except Exception as e:
            self.log_func(f"RDP port read exception: {e}")
            return 3389
    
    def _set_rdp_port_registry(self, new_port: int) -> bool:
        """Set RDP port in Windows registry"""
        try:
            registry_path = r"HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            ps_cmd = f'powershell -Command "Set-ItemProperty -Path \'{registry_path}\' -Name PortNumber -Value {new_port} -Type DWord"'
            
            result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
            
            if result.returncode == 0:
                self.log_func(f"RDP port written to registry: {new_port}")
                return True
            else:
                self.log_func(f"Registry write error: {result.stderr}")
                return False
                
        except Exception as e:
            self.log_func(f"Registry write exception: {e}")
            return False
    
    def secure_rdp_port(self, target_port: int = 53389) -> bool:
        """
        Move RDP port to secure port
        
        Args:
            target_port (int): Target port (default 53389)
            
        Returns:
            bool: True if successful
        """
        try:
            current_port = self._get_current_rdp_port()
            
            if current_port == target_port:
                self.log_func(f"RDP already on secure port: {target_port}")
                return True
            
            self.log_func(f"RDP port transition starting: {current_port} -> {target_port}")
            
            # Update registry
            if not self._set_rdp_port_registry(target_port):
                self.log_func(f"RDP port update failed")
                return False
            
            self.log_func(f"RDP port successfully updated: {target_port}")
            self.log_func(f"Terminal Services restart may be required")
            return True
            
        except Exception as e:
            self.log_func(f"RDP security exception: {e}")
            return False


class RDPPopupManager:
    """RDP security popup manager"""
    
    def __init__(self, parent=None, log_func=None):
        self.parent = parent
        self.log_func = log_func or log
        
    def show_rdp_security_popup(self, current_port: int, target_port: int, callback=None):
        """
        Show RDP security popup
        
        Args:
            current_port (int): Current RDP port
            target_port (int): Target RDP port
            callback (callable): Function to call when completed
        """
        try:
            popup = tk.Toplevel(self.parent)
            popup.title("RDP Security Transition")
            popup.geometry("500x300")
            popup.resizable(False, False)
            popup.transient(self.parent)
            popup.grab_set()
            
            # Center window
            popup.update_idletasks()
            x = (popup.winfo_screenwidth() // 2) - (popup.winfo_width() // 2)
            y = (popup.winfo_screenheight() // 2) - (popup.winfo_height() // 2)
            popup.geometry(f"+{x}+{y}")
            
            # Content
            main_frame = ttk.Frame(popup, padding="20")
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Title
            title_label = ttk.Label(main_frame, text="RDP Port Security Transition", 
                                   font=("Arial", 14, "bold"))
            title_label.pack(pady=(0, 20))
            
            # Info
            info_text = f"""RDP port will be moved for security:

Current Port: {current_port}
New Port: {target_port}

This may temporarily disconnect your Remote Desktop connection.
After completion, you will need to connect using the new port.

Do you want to continue?"""
            
            info_label = ttk.Label(main_frame, text=info_text, 
                                  font=("Arial", 10), justify=tk.LEFT)
            info_label.pack(pady=(0, 30))
            
            # Buttons
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill=tk.X)
            
            def on_confirm():
                popup.destroy()
                if callback:
                    callback(True)
            
            def on_cancel():
                popup.destroy()
                if callback:
                    callback(False)
            
            ttk.Button(button_frame, text="Confirm and Continue", 
                      command=on_confirm).pack(side=tk.RIGHT, padx=(10, 0))
            ttk.Button(button_frame, text="Cancel", 
                      command=on_cancel).pack(side=tk.RIGHT)
            
        except Exception as e:
            self.log_func(f"RDP popup exception: {e}")