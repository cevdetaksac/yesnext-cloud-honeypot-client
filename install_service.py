#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client - Service Installation Helper
Windows Service kurulumu için yardımcı script
"""

import os
import sys
import subprocess
import ctypes

def is_admin():
    """Admin yetkileri kontrolü"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Script'i admin yetkileriyle yeniden başlat"""
    if is_admin():
        return True
    else:
        print("Service installation requires administrator privileges.")
        print("Requesting elevated permissions...")
        
        try:
            # Admin olarak yeniden başlat
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, 
                f'"{__file__}" {" ".join(sys.argv[1:])}', 
                None, 1
            )
            return False
        except:
            print("Failed to elevate privileges. Please run as administrator.")
            return False

def main():
    """Ana fonksiyon"""
    if not run_as_admin():
        return
        
    print("=" * 60)
    print("Cloud Honeypot Client - Service Manager")
    print("=" * 60)
    
    service_script = os.path.join(os.path.dirname(__file__), 'service_wrapper.py')
    
    if not os.path.exists(service_script):
        print(f"Error: Service script not found at: {service_script}")
        input("Press Enter to exit...")
        return
    
    if len(sys.argv) < 2:
        print("Available commands:")
        print("  install   - Install and start the service")
        print("  uninstall - Stop and remove the service") 
        print("  status    - Show service status")
        print("  restart   - Restart the service")
        print("  start     - Start the service")
        print("  stop      - Stop the service")
        print()
        
        while True:
            command = input("Enter command (or 'exit' to quit): ").lower().strip()
            
            if command == 'exit':
                break
            elif command in ['install', 'uninstall', 'status', 'restart', 'start', 'stop']:
                run_service_command(service_script, command)
                break
            else:
                print("Invalid command. Please try again.")
    else:
        command = sys.argv[1].lower()
        run_service_command(service_script, command)
    
    print()
    input("Press Enter to exit...")

def run_service_command(service_script, command):
    """Service komutunu çalıştır"""
    try:
        print(f"\nExecuting: {command}")
        print("-" * 40)
        
        result = subprocess.run([
            sys.executable, service_script, command
        ], capture_output=True, text=True, timeout=30)
        
        if result.stdout:
            print("Output:")
            print(result.stdout)
            
        if result.stderr:
            print("Errors:")
            print(result.stderr)
            
        if result.returncode == 0:
            print(f"✅ Command '{command}' completed successfully")
        else:
            print(f"❌ Command '{command}' failed with return code: {result.returncode}")
            
    except subprocess.TimeoutExpired:
        print("❌ Command timed out")
    except Exception as e:
        print(f"❌ Error executing command: {e}")

if __name__ == "__main__":
    main()