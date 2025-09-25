#!/usr/bin/env python3
"""
Windows Auto-Start Setup Utility
===============================

Handles automatic startup configuration for production deployment.
Sets up application to start automatically without user intervention.
"""

import os
import sys
import winreg
import subprocess
from pathlib import Path

def setup_autostart(exe_path: str, silent: bool = True) -> bool:
    """Setup application autostart via multiple methods"""
    success = False
    
    # Method 1: Registry startup entry
    if setup_registry_autostart(exe_path):
        print("✅ Registry autostart configured")
        success = True
    
    # Method 2: Task scheduler (more reliable)
    if setup_task_scheduler_autostart(exe_path, silent):
        print("✅ Task Scheduler autostart configured")
        success = True
        
    # Method 3: Service autostart (handled by installer)
    print("✅ Service autostart handled by installer")
    
    return success

def setup_registry_autostart(exe_path: str) -> bool:
    """Add to Windows startup registry"""
    try:
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        app_name = "CloudHoneypotClient"
        
        # Open registry key
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, 
                           winreg.KEY_SET_VALUE) as key:
            # Set startup entry with minimized flag
            startup_cmd = f'"{exe_path}" --minimized true'
            winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, startup_cmd)
            
        print(f"Registry autostart: {startup_cmd}")
        return True
        
    except Exception as e:
        print(f"Registry autostart failed: {e}")
        return False

def setup_task_scheduler_autostart(exe_path: str, silent: bool = True) -> bool:
    """Setup Windows Task Scheduler for autostart"""
    try:
        task_name = "CloudHoneypotClient_AutoStart"
        
        # XML template for task
        task_xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Cloud Honeypot Client Auto-Start</Description>
    <Author>YesNext</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT30S</Delay>
    </LogonTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT1M</Delay>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe_path}</Command>
      <Arguments>--minimized true --silent</Arguments>
      <WorkingDirectory>{Path(exe_path).parent}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>'''

        # Create temporary XML file
        temp_xml = Path.cwd() / "temp_task.xml"
        with open(temp_xml, 'w', encoding='utf-16') as f:
            f.write(task_xml)
        
        try:
            # Delete existing task if present
            subprocess.run(['schtasks', '/delete', '/tn', task_name, '/f'], 
                         capture_output=True)
            
            # Create new task
            result = subprocess.run([
                'schtasks', '/create', '/tn', task_name, 
                '/xml', str(temp_xml), '/f'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"Task Scheduler autostart: {task_name}")
                return True
            else:
                print(f"Task creation failed: {result.stderr}")
                return False
                
        finally:
            # Clean up temp file
            if temp_xml.exists():
                temp_xml.unlink()
                
    except Exception as e:
        print(f"Task Scheduler autostart failed: {e}")
        return False

def remove_autostart() -> bool:
    """Remove all autostart configurations"""
    success = True
    
    # Remove registry entry
    try:
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, 
                           winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, "CloudHoneypotClient")
        print("✅ Registry autostart removed")
    except Exception as e:
        print(f"Registry removal failed: {e}")
        success = False
    
    # Remove task scheduler entry
    try:
        result = subprocess.run(['schtasks', '/delete', '/tn', 
                               'CloudHoneypotClient_AutoStart', '/f'], 
                              capture_output=True)
        if result.returncode == 0:
            print("✅ Task Scheduler autostart removed")
        else:
            print("Task Scheduler removal failed")
            success = False
    except Exception as e:
        print(f"Task removal failed: {e}")
        success = False
    
    return success

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "remove":
            print("Removing autostart configurations...")
            remove_autostart()
        elif sys.argv[1] == "setup":
            if len(sys.argv) > 2:
                exe_path = sys.argv[2]
                print(f"Setting up autostart for: {exe_path}")
                setup_autostart(exe_path)
            else:
                print("Usage: autostart_setup.py setup <exe_path>")
        else:
            print("Usage: autostart_setup.py [setup <exe_path> | remove]")
    else:
        # Setup for current directory
        current_exe = Path.cwd() / "client.exe"
        if current_exe.exists():
            setup_autostart(str(current_exe))
        else:
            print("No client.exe found in current directory")