#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🎯 CLOUD HONEYPOT CLIENT - TASK SCHEDULER MODULE
===============================================

📋 ARCHITECTURE IMPLEMENTATION:
┌─────────────────────────────────────────────────────────────────┐
│             WINDOWS TASK SCHEDULER CONFIGURATION               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  🟢 BACKGROUND TASK: CloudHoneypot-Background                  │
│  ├─ XML: Configured for system-level execution                │
│  ├─ Trigger: <BootTrigger> PT30S delay                        │
│  ├─ Security: S-1-5-18 (SYSTEM), HighestAvailable            │
│  ├─ Command: honeypot-client.exe --mode=daemon --silent       │
│  ├─ Restart: PT10S interval, 5 attempts                       │
│  └─ Purpose: Headless server environments                     │
│                                                                 │
│  🟡 TRAY TASK: CloudHoneypot-Tray                            │
│  ├─ XML: Configured for user session execution               │
│  ├─ Trigger: <LogonTrigger> PT15S delay                      │
│  ├─ Security: Users group, HighestAvailable                  │
│  ├─ Command: honeypot-client.exe --mode=tray --silent        │
│  ├─ Restart: PT10S interval, 3 attempts                      │
│  └─ Purpose: Interactive desktop environments                │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│ DEPLOYMENT WORKFLOW:                                            │
│ 1. Administrator privilege check                                │
│ 2. Client executable validation                                 │
│ 3. XML task definition generation                               │
│ 4. Task removal (cleanup existing)                             │
│ 5. Task installation via schtasks.exe                          │
│ 6. Task verification and status check                          │
├─────────────────────────────────────────────────────────────────┤
│ ADVANTAGES OVER WINDOWS SERVICE:                                │
│ ✅ No SYSTEM context GUI limitations                           │
│ ✅ Built-in Windows reliability features                       │
│ ✅ User-friendly management via Task Scheduler MMC            │
│ ✅ Better separation between system/user contexts             │
│ ✅ Automatic Windows Update compatibility                      │
│ ✅ Standard Windows troubleshooting tools                     │
└─────────────────────────────────────────────────────────────────┘

🔧 USAGE:
  python install_task_scheduler.py           # Install tasks
  python install_task_scheduler.py uninstall # Remove tasks

📝 XML FEATURES:
- MultipleInstancesPolicy: IgnoreNew (prevents conflicts)
- RestartPolicy: Automatic failure recovery
- Hidden: false (visible in Task Scheduler)
- ExecutionTimeLimit: PT0S (unlimited runtime)
- Priority: 7 (normal priority)

💡 INTEGRATION NOTES:
- Works with singleton mutex system in client.py
- Respects existing process detection logic
- Compatible with legacy service monitor (transition period)
- Generates clean XML for Windows Task Scheduler v1.4
"""

import os
import sys
import subprocess
import ctypes
import json
import time
import xml.etree.ElementTree as ET
from datetime import datetime

from client_constants import TASK_STATE_FILE

# Configuration
TASK_NAME_BACKGROUND = "CloudHoneypot-Background"
TASK_NAME_TRAY = "CloudHoneypot-Tray"

def get_client_exe_path():
    """Get the current executable path dynamically"""
    if hasattr(sys, '_MEIPASS'):
        # Running as PyInstaller bundle
        return sys.executable
    else:
        # Running as script, try to find honeypot-client.exe
        script_dir = os.path.dirname(os.path.abspath(__file__))
        exe_path = os.path.join(script_dir, "honeypot-client.exe")
        if os.path.exists(exe_path):
            return exe_path
        # Fallback to installed location
        return os.path.join(r"C:\Program Files\YesNext\Cloud Honeypot Client", "honeypot-client.exe")

CLIENT_EXE = get_client_exe_path()

TASK_CACHE_MAX_AGE = 1800  # seconds


"""Task state persistence helpers"""
def _log_or_print(log_func, message):
    if callable(log_func):
        try:
            log_func(message)
            return
        except Exception:
            pass
    print(message)


def load_task_state():
    return _load_raw_task_state()


def _load_raw_task_state():
    try:
        with open(TASK_STATE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as exc:
        print(f"[TaskState] load error: {exc}")
        return {}


def save_task_state(state):
    data = dict(state or {})
    data['updated_at'] = int(time.time())
    try:
        os.makedirs(os.path.dirname(TASK_STATE_FILE), exist_ok=True)
        with open(TASK_STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as exc:
        print(f"[TaskState] save error: {exc}")


def _should_trust_cache(state, max_age):
    if not state or not isinstance(state, dict):
        return False
    timestamp = state.get('updated_at') or state.get('last_verified')
    if not timestamp:
        return False
    try:
        timestamp = int(timestamp)
    except (TypeError, ValueError):
        return False
    return (time.time() - timestamp) <= max_age


def ensure_tasks_installed(log_func=None, force=False, max_age=TASK_CACHE_MAX_AGE):
    state = load_task_state()
    if not force and _should_trust_cache(state, max_age) and state.get('both_installed'):
        cached_status = check_tasks_status(update_cache=True)
        if cached_status.get('both_installed'):
            _log_or_print(log_func, "Task Scheduler cache indicates tasks installed; skipping reinstall")
            return {'success': True, 'action': 'cache', 'status': cached_status}

    status = check_tasks_status(update_cache=True)
    if status.get('both_installed') and not force:
        _log_or_print(log_func, "Task Scheduler tasks already configured (verified)")
        return {'success': True, 'action': 'verified', 'status': status}

    _log_or_print(log_func, "Task Scheduler tasks missing or stale - attempting reinstall")
    success = install_tasks()
    if not success:
        failure_status = check_tasks_status(update_cache=False)
        return {'success': False, 'action': 'install_failed', 'status': failure_status}

    status_after = check_tasks_status(update_cache=True)
    if status_after.get('both_installed'):
        return {'success': True, 'action': 'installed', 'status': status_after}
    return {'success': False, 'action': 'verification_failed', 'status': status_after}


def is_admin():
    """Check if script is running with admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def create_background_task_xml():
    """Create XML for background task (runs at startup)"""
    xml_content = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{datetime.now().isoformat()}</Date>
    <Author>Cloud Honeypot Client</Author>
    <Description>Cloud Honeypot Client - Background Service</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT30S</Delay>
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
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartPolicy>
      <Interval>PT10S</Interval>
      <Count>5</Count>
    </RestartPolicy>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{CLIENT_EXE}"</Command>
      <Arguments>--mode=daemon --silent</Arguments>
      <WorkingDirectory>{os.path.dirname(CLIENT_EXE)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>'''
    return xml_content

def create_tray_task_xml():
    """Create XML for tray task (runs at user logon)"""
    xml_content = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{datetime.now().isoformat()}</Date>
    <Author>Cloud Honeypot Client</Author>
    <Description>Cloud Honeypot Client - Interactive Tray</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT15S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <GroupId>Users</GroupId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartPolicy>
      <Interval>PT10S</Interval>
      <Count>3</Count>
    </RestartPolicy>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{CLIENT_EXE}"</Command>
      <Arguments>--mode=tray --silent</Arguments>
      <WorkingDirectory>{os.path.dirname(CLIENT_EXE)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>'''
    return xml_content

def install_task(task_name: str, xml_content: str) -> bool:
    """Install a scheduled task using schtasks command"""
    try:
        print(f"Installing task: {task_name}")
        
        # Create temporary XML file
        temp_xml = os.path.join(os.environ['TEMP'], f"{task_name}.xml")
        
        with open(temp_xml, 'w', encoding='utf-16') as f:
            f.write(xml_content)
        
        # Delete existing task if it exists
        try:
            subprocess.run([
                'schtasks', '/Delete', '/TN', task_name, '/F'
            ], capture_output=True, check=False)
        except:
            pass
        
        # Create new task
        result = subprocess.run([
            'schtasks', '/Create', '/TN', task_name, '/XML', temp_xml, '/F'
        ], capture_output=True, text=True)
        
        # Clean up temporary file
        try:
            os.remove(temp_xml)
        except:
            pass
        
        if result.returncode == 0:
            print(f"✓ Task {task_name} installed successfully")
            return True
        else:
            print(f"✗ Failed to install task {task_name}: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"✗ Error installing task {task_name}: {e}")
        return False

def uninstall_task(task_name: str) -> bool:
    """Uninstall a scheduled task"""
    try:
        print(f"Uninstalling task: {task_name}")
        
        result = subprocess.run([
            'schtasks', '/Delete', '/TN', task_name, '/F'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✓ Task {task_name} uninstalled successfully")
            return True
        else:
            print(f"✓ Task {task_name} was not found (already uninstalled)")
            return True  # Not found is OK for uninstall
            
    except Exception as e:
        print(f"✗ Error uninstalling task {task_name}: {e}")
        return False

def verify_task_exists(task_name):
    """Check if a specific task exists"""
    try:
        result = subprocess.run([
            'schtasks', '/Query', '/TN', task_name
        ], capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False

def verify_tasks():
    """Verify that tasks are installed and configured correctly"""
    print("\n=== Task Verification ===")
    
    for task_name in [TASK_NAME_BACKGROUND, TASK_NAME_TRAY]:
        try:
            result = subprocess.run([
                'schtasks', '/Query', '/TN', task_name, '/FO', 'LIST'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✓ Task {task_name} found and configured")
                # Parse status from output
                for line in result.stdout.split('\n'):
                    if 'Status:' in line:
                        status = line.split(':', 1)[1].strip()
                        print(f"  Status: {status}")
                        break
            else:
                print(f"✗ Task {task_name} not found")
                
        except Exception as e:
            print(f"✗ Error checking task {task_name}: {e}")

def main():
    print("Cloud Honeypot Client - Task Scheduler Setup")
    print("=" * 50)
    
    if len(sys.argv) > 1 and sys.argv[1] == "uninstall":
        # Uninstall mode
        print("UNINSTALL MODE")
        print("Removing scheduled tasks...")
        
        success = True
        success &= uninstall_task(TASK_NAME_BACKGROUND)
        success &= uninstall_task(TASK_NAME_TRAY)
        
        if success:
            print("\n✓ All tasks uninstalled successfully")
            sys.exit(0)
        else:
            print("\n✗ Some tasks could not be uninstalled")
            sys.exit(1)
    
    # Install mode (default)
    if not is_admin():
        print("ERROR: Administrator privileges required")
        print("Please run this script as Administrator")
        return False
    
    if not os.path.exists(CLIENT_EXE):
        print(f"ERROR: Client executable not found: {CLIENT_EXE}")
        print("Please ensure Cloud Honeypot Client is properly installed")
        return False
    
    print("Setting up scheduled tasks for Cloud Honeypot Client...")
    print(f"Client executable: {CLIENT_EXE}")
    
    success = True
    
    # Install background task
    background_xml = create_background_task_xml()
    success &= install_task(TASK_NAME_BACKGROUND, background_xml)
    
    # Install tray task
    tray_xml = create_tray_task_xml()
    success &= install_task(TASK_NAME_TRAY, tray_xml)
    
    if success:
        print("\n[OK] All tasks installed successfully")
        verify_tasks()
        status_summary = check_tasks_status(update_cache=True)
        
        print("\nTask Scheduler setup completed!")
        print("- Background task will start honeypot at boot time")
        print("- Tray task will start GUI when user logs in")
        print("- Both tasks have automatic restart on failure")
        print(f"- Verification summary: {status_summary}")
        
        return True
    else:
        print("\n[WARN] Some tasks could not be installed")
        check_tasks_status(update_cache=True)
        return False

def install_tasks():
    """Install Task Scheduler tasks - Main entry point for client.py"""
    return main()

def uninstall_tasks():
    """Uninstall Task Scheduler tasks"""
    if not is_admin():
        print("Please run as Administrator to uninstall tasks")
        return False
    
    print("Removing scheduled tasks...")
    
    success = True
    success &= uninstall_task(TASK_NAME_BACKGROUND)
    success &= uninstall_task(TASK_NAME_TRAY)
    
    if success:
        print("✓ All tasks removed successfully")
        return True
    else:
        print("✗ Some tasks could not be removed")
        return False

def check_tasks_status(update_cache=False):
    """Check if tasks are installed and running"""
    bg_status = verify_task_exists(TASK_NAME_BACKGROUND)
    tray_status = verify_task_exists(TASK_NAME_TRAY)

    status = {
        'background_task': bg_status,
        'tray_task': tray_status,
        'both_installed': bg_status and tray_status,
        'last_verified': int(time.time())
    }

    if update_cache:
        save_task_state(status)

    return status

# For backwards compatibility when run as standalone script
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "uninstall":
        success = uninstall_tasks()
    else:
        success = install_tasks()
    
    sys.exit(0 if success else 1)