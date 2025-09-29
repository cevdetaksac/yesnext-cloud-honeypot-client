#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🎯 CLOUD HONEYPOT CLIENT - TASK SCHEDULER MODULE v2.7.5
=======================================================

📋 5-TASK SYSTEM ARCHITECTURE - SEPTEMBER 2025:
┌─────────────────────────────────────────────────────────────────┐
│              COMPREHENSIVE TASK SCHEDULER SYSTEM               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  🟢 CloudHoneypot-Background  → Boot-time daemon service       │
│  ├─ Trigger: System boot (30s delay)                          │  
│  ├─ Context: SYSTEM account, highest privileges               │
│  ├─ Purpose: Headless server operation                        │
│  └─ Command: honeypot-client.exe --mode=daemon --silent       │
│                                                                 │
│  🟡 CloudHoneypot-Tray       → User session GUI               │
│  ├─ Trigger: User logon (15s delay)                          │
│  ├─ Context: User account, interactive desktop               │
│  ├─ Purpose: Desktop management interface                     │
│  └─ Command: honeypot-client.exe --mode=tray --silent        │
│                                                                 │
│  � CloudHoneypot-Watchdog   → System health monitoring       │
│  ├─ Trigger: Hourly schedule                                 │
│  ├─ Context: SYSTEM account, maintenance                     │
│  ├─ Purpose: Process recovery and health checks              │
│  └─ Command: honeypot-client.exe --watchdog --silent         │
│                                                                 │
│  📱 CloudHoneypot-Updater    → Weekly update checks           │
│  ├─ Trigger: Weekly schedule (Sunday 03:00)                  │
│  ├─ Context: User account, interactive updates               │
│  ├─ Purpose: Interactive update management                    │
│  └─ Command: honeypot-client.exe --silent-update-check       │
│                                                                 │
│  🔄 CloudHoneypot-SilentUpdater → Automatic updates (2h)      │
│  ├─ Trigger: Every 2 hours                                   │
│  ├─ Context: SYSTEM account, background                      │
│  ├─ Purpose: Unattended system maintenance                   │
│  └─ Command: honeypot-client.exe --silent-update-check       │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│ 🏗️ MODULAR MANAGEMENT FUNCTIONS:                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  📊 perform_comprehensive_task_management() → Auto mgmt        │
│  ├─ Check & install missing tasks (admin required)            │
│  ├─ Activate existing tasks (no admin needed)                 │
│  ├─ Report status to application state                        │
│  └─ Integrated with client.py __init__                        │
│                                                                 │
│  🔧 Task Control Functions:                                    │
│  ├─ get_task_status()    → Query task state                   │
│  ├─ enable_task()        → Activate task                      │
│  ├─ disable_task()       → Deactivate task                    │
│  ├─ run_task()           → Immediate execution                 │
│  └─ All work without admin privileges                         │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│ 🎯 INSTALLER INTEGRATION STRATEGY:                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Installer: Stop all CloudHoneypot-* tasks                 │
│  2. Installer: Delete all tasks for clean installation        │
│  3. Installer: Install new application files                  │
│  4. Installer: Launch application once                        │
│  5. Application: Check & install missing tasks                │
│  6. Application: Activate all available tasks                 │
│  7. Future runs: Only verify & activate existing tasks       │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│ ✅ ADVANTAGES OVER WINDOWS SERVICES:                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ▶ No SYSTEM context GUI limitations                          │
│  ▶ Built-in Windows reliability & restart features            │
│  ▶ User-friendly Task Scheduler MMC management               │
│  ▶ Clean separation: system vs user contexts                 │
│  ▶ Automatic Windows Update compatibility                     │
│  ▶ Standard troubleshooting with Windows tools               │
│  ▶ Modern XML-based configuration                             │
│  ▶ Granular scheduling and trigger control                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

💡 INTEGRATION STATUS: v2.7.5 (September 2025)
- ✅ Full modular integration with client.py
- ✅ Installer-aware task management lifecycle  
- ✅ Admin-optional task activation system
- ✅ Comprehensive 5-task coverage
- ✅ Production-ready deployment workflow
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
TASK_NAME_WATCHDOG = "CloudHoneypot-Watchdog"
TASK_NAME_UPDATER = "CloudHoneypot-Updater"
TASK_NAME_SILENT_UPDATER = "CloudHoneypot-SilentUpdater"

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
    # First check admin status
    admin_rights = is_admin()
    
    state = load_task_state()
    if not force and _should_trust_cache(state, max_age) and (state.get('all_installed') or state.get('both_installed')):
        cached_status = check_tasks_status(update_cache=True)
        if cached_status.get('all_installed') or cached_status.get('both_installed'):
            _log_or_print(log_func, "[OK] Task Scheduler tasks verified (cached)")
            return {'success': True, 'action': 'cache', 'status': cached_status}

    status = check_tasks_status(update_cache=True)
    if (status.get('all_installed') or status.get('both_installed')) and not force:
        _log_or_print(log_func, "[OK] Task Scheduler tasks verified (installed)")
        return {'success': True, 'action': 'verified', 'status': status}

    # Tasks missing - check admin rights
    if not admin_rights:
        _log_or_print(log_func, "[WARN] Task Scheduler tasks missing but no admin rights - will be installed when run as admin")
        return {'success': False, 'action': 'needs_admin', 'status': status, 'admin_required': True}
    
    _log_or_print(log_func, "[SETUP] Installing missing Task Scheduler tasks...")
    success = install_tasks()
    if not success:
        failure_status = check_tasks_status(update_cache=False)
        return {'success': False, 'action': 'install_failed', 'status': failure_status}

    status_after = check_tasks_status(update_cache=True)
    if status_after.get('all_installed') or status_after.get('both_installed'):
        _log_or_print(log_func, "[OK] Task Scheduler tasks successfully installed")
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
      <Interval>PT10M</Interval>
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

def create_watchdog_task_xml():
    """Create XML for watchdog task (runs hourly to check and restart services)"""
    xml_content = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{datetime.now().isoformat()}</Date>
    <Author>Cloud Honeypot Client</Author>
    <Description>Cloud Honeypot Client - Hourly Watchdog Process Recovery</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2025-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
      <Repetition>
        <Interval>PT15M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </CalendarTrigger>
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
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>true</WakeToRun>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{CLIENT_EXE}"</Command>
      <Arguments>--mode=watchdog</Arguments>
      <WorkingDirectory>{os.path.dirname(CLIENT_EXE)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>'''
    return xml_content

def create_updater_task_xml():
    """Create XML for updater task (runs weekly to check for updates)"""
    xml_content = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{datetime.now().isoformat()}</Date>
    <Author>Cloud Honeypot Client</Author>
    <Description>Cloud Honeypot Client - Weekly Update Check and Auto-Install</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2025-01-01T02:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByWeek>
        <DaysOfWeek>
          <Sunday />
        </DaysOfWeek>
        <WeeksInterval>1</WeeksInterval>
      </ScheduleByWeek>
    </CalendarTrigger>
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
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>true</WakeToRun>
    <ExecutionTimeLimit>PT30M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{CLIENT_EXE}"</Command>
      <Arguments>--mode=updater</Arguments>
      <WorkingDirectory>{os.path.dirname(CLIENT_EXE)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>'''
    return xml_content

def create_silent_updater_task_xml():
    """Create XML for silent updater task (runs every 2 hours for silent updates)"""
    xml_content = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{datetime.now().isoformat()}</Date>
    <Author>Cloud Honeypot Client</Author>
    <Description>Cloud Honeypot Client - Silent Update Check and Auto-Install (Every 2 hours)</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT2H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2025-01-01T01:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
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
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT45M</ExecutionTimeLimit>
    <Priority>6</Priority>
    <RestartPolicy>
      <Interval>PT5M</Interval>
      <Count>3</Count>
    </RestartPolicy>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{CLIENT_EXE}"</Command>
      <Arguments>--silent-update-check</Arguments>
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
            ], capture_output=True, check=False, encoding='utf-8', errors='ignore')
        except:
            pass
        
        # Create new task
        result = subprocess.run([
            'schtasks', '/Create', '/TN', task_name, '/XML', temp_xml, '/F'
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore')
        
        # Clean up temporary file
        try:
            os.remove(temp_xml)
        except:
            pass
        
        if result.returncode == 0:
            print(f"[OK] Task {task_name} installed successfully")
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
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore')
        
        if result.returncode == 0:
            print(f"[OK] Task {task_name} uninstalled successfully")
            return True
        else:
            print(f"[INFO] Task {task_name} was not found (already uninstalled)")
            return True  # Not found is OK for uninstall
            
    except Exception as e:
        print(f"✗ Error uninstalling task {task_name}: {e}")
        return False

def verify_task_exists(task_name):
    """Check if a specific task exists"""
    try:
        result = subprocess.run([
            'schtasks', '/Query', '/TN', task_name
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore')
        return result.returncode == 0
    except Exception:
        return False

def verify_tasks():
    """Verify that tasks are installed and configured correctly"""
    print("\n=== Task Verification ===")
    
    for task_name in [TASK_NAME_BACKGROUND, TASK_NAME_TRAY, TASK_NAME_WATCHDOG]:
        try:
            result = subprocess.run([
                'schtasks', '/Query', '/TN', task_name, '/FO', 'LIST'
            ], capture_output=True, text=True, encoding='utf-8', errors='ignore')
            
            if result.returncode == 0:
                print(f"[OK] Task {task_name} found and configured")
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

def install_all_tasks(include_silent_updater: bool = False) -> bool:
    """Install all Task Scheduler tasks - used by installer and updates"""
    try:
        print("Installing Task Scheduler tasks...")
        
        success = True
        
        # Install Background Task
        xml_content = create_background_task_xml()
        success &= install_task(TASK_NAME_BACKGROUND, xml_content)
        
        # Install Tray Task
        xml_content = create_tray_task_xml()
        success &= install_task(TASK_NAME_TRAY, xml_content)
        
        # Install Watchdog Task
        xml_content = create_watchdog_task_xml()
        success &= install_task(TASK_NAME_WATCHDOG, xml_content)
        
        # Install Weekly Updater Task
        xml_content = create_updater_task_xml()
        success &= install_task(TASK_NAME_UPDATER, xml_content)
        
        # Install Silent Updater Task (every 2 hours) if requested
        if include_silent_updater:
            xml_content = create_silent_updater_task_xml()
            success &= install_task(TASK_NAME_SILENT_UPDATER, xml_content)
            print(f"[INFO] Silent updater task {'installed' if success else 'failed'}")
        
        return success
        
    except Exception as e:
        print(f"✗ install_all_tasks error: {e}")
        return False

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
        success &= uninstall_task(TASK_NAME_WATCHDOG)
        
        if success:
            print("\n[OK] All tasks uninstalled successfully")
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
    
    # Install watchdog task
    watchdog_xml = create_watchdog_task_xml()
    success &= install_task(TASK_NAME_WATCHDOG, watchdog_xml)
    
    if success:
        print("\n[OK] All tasks installed successfully")
        verify_tasks()
        status_summary = check_tasks_status(update_cache=True)
        
        print("\nTask Scheduler setup completed!")
        print("- Background task will start honeypot at boot time")
        print("- Tray task will start GUI when user logs in")
        print("- Watchdog task will check and restart services hourly")
        print("- All tasks have automatic restart on failure")
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
    """Uninstall all CloudHoneypot Task Scheduler tasks using PowerShell wildcard"""
    if not is_admin():
        print("Please run as Administrator to uninstall tasks")
        return False
    
    print("Removing all CloudHoneypot scheduled tasks...")
    
    try:
        # Use PowerShell to remove all CloudHoneypot* tasks
        powershell_cmd = [
            'powershell', '-ExecutionPolicy', 'Bypass', '-Command',
            'Get-ScheduledTask | Where-Object { $_.TaskName -like "CloudHoneypot*" } | ForEach-Object { Write-Host "Removing task: $($_.TaskName)"; Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue }'
        ]
        
        result = subprocess.run(powershell_cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        
        if result.returncode == 0:
            print("[OK] All CloudHoneypot tasks removed successfully")
            
            # Also check if any tasks still exist
            remaining = check_remaining_tasks()
            if remaining:
                print(f"⚠ Some tasks may still exist: {remaining}")
                return False
            return True
        else:
            print(f"⚠ PowerShell removal had issues: {result.stderr}")
            # Fallback to individual removal
            return fallback_individual_removal()
            
    except Exception as e:
        print(f"✗ PowerShell removal failed: {e}")
        # Fallback to individual removal
        return fallback_individual_removal()

def fallback_individual_removal():
    """Fallback method - remove tasks individually"""
    print("Using fallback method - removing tasks individually...")
    success = True
    success &= uninstall_task(TASK_NAME_BACKGROUND)
    success &= uninstall_task(TASK_NAME_TRAY)
    success &= uninstall_task(TASK_NAME_WATCHDOG)
    
    if success:
        print("[OK] Individual task removal completed")
        return True
    else:
        print("✗ Some tasks could not be removed")
        return False

def check_remaining_tasks():
    """Check if any CloudHoneypot tasks still exist"""
    try:
        result = subprocess.run([
            'powershell', '-ExecutionPolicy', 'Bypass', '-Command',
            'Get-ScheduledTask | Where-Object { $_.TaskName -like "CloudHoneypot*" } | Select-Object -ExpandProperty TaskName'
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore')
        
        if result.returncode == 0 and result.stdout.strip():
            remaining_tasks = [task.strip() for task in result.stdout.strip().split('\n') if task.strip()]
            return remaining_tasks
        return []
    except:
        return []

def check_tasks_status(update_cache=False):
    """Check if tasks are installed and running"""
    bg_status = verify_task_exists(TASK_NAME_BACKGROUND)
    tray_status = verify_task_exists(TASK_NAME_TRAY)
    watchdog_status = verify_task_exists(TASK_NAME_WATCHDOG)

    status = {
        'background_task': bg_status,
        'tray_task': tray_status,
        'watchdog_task': watchdog_status,
        'all_installed': bg_status and tray_status and watchdog_status,
        'both_installed': bg_status and tray_status,  # backward compatibility
        'last_verified': int(time.time())
    }

    if update_cache:
        save_task_state(status)

    return status


def get_task_status(task_name: str) -> dict:
    """Get detailed status of a specific task"""
    try:
        # Check if task exists and get basic info
        result = subprocess.run([
            'schtasks', '/Query', '/TN', task_name, '/FO', 'LIST'
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore')
        
        if result.returncode != 0:
            return {'exists': False, 'enabled': False, 'status': 'Not Found'}
        
        # Parse task details from output
        task_info = {'exists': True, 'enabled': False, 'status': 'Unknown'}
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            if 'Status:' in line or 'Durum:' in line:  # Handle Turkish locale
                status = line.split(':', 1)[1].strip()
                task_info['status'] = status
                # Task is enabled if status is Ready, Running, or similar active states
                task_info['enabled'] = status.lower() not in ['disabled', 'devre dışı', 'could not start']
        
        return task_info
        
    except Exception as e:
        return {'exists': False, 'enabled': False, 'status': f'Error: {e}'}


def enable_task(task_name: str) -> bool:
    """Enable a task (activate it)"""
    try:
        # Use schtasks /Change to enable the task
        result = subprocess.run([
            'schtasks', '/Change', '/TN', task_name, '/ENABLE'
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore')
        
        return result.returncode == 0
        
    except Exception:
        return False


def disable_task(task_name: str) -> bool:
    """Disable a task (deactivate it)"""
    try:
        # Use schtasks /Change to disable the task  
        result = subprocess.run([
            'schtasks', '/Change', '/TN', task_name, '/DISABLE'
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore')
        
        return result.returncode == 0
        
    except Exception:
        return False


def run_task(task_name: str) -> bool:
    """Manually run a task"""
    try:
        # Use schtasks /Run to start the task immediately
        result = subprocess.run([
            'schtasks', '/Run', '/TN', task_name
        ], capture_output=True, text=True, encoding='utf-8', errors='ignore')
        
        return result.returncode == 0
        
    except Exception:
        return False


def perform_comprehensive_task_management(log_func=None, app_state=None):
    """
    Comprehensive Task Scheduler management for application startup
    
    This function handles the complete task lifecycle:
    1. Check and install missing tasks (requires admin for installation)
    2. Verify and activate existing tasks (works without admin)
    3. Update application state with task information
    
    Args:
        log_func: Logging function to use
        app_state: Application state dict to update with missing task info
        
    Returns:
        dict: Management results with success status and activated task count
    """
    if log_func is None:
        log_func = print
        
    try:
        log_func("🔧 Performing comprehensive Task Scheduler management...")
        
        # Step 1: Check and install missing tasks
        result = ensure_tasks_installed(log_func=log_func, force=False)
        
        if result.get('success'):
            log_func("✅ All Task Scheduler tasks are registered")
        elif result.get('admin_required'):
            # Detaylı durum bilgisi ver
            status = result.get('status', {})
            missing_tasks = []
            
            if not status.get('tray_task', False):
                missing_tasks.append("Tray (user startup)")
            if not status.get('background_task', False):
                missing_tasks.append("Background (system service)")
            if not status.get('watchdog_task', False):
                missing_tasks.append("Watchdog (monitoring)")
            if not status.get('updater_task', False):
                missing_tasks.append("Updater (maintenance)")
            if not status.get('silent_updater_task', False):
                missing_tasks.append("SilentUpdater (auto-update)")
            
            if missing_tasks:
                log_func(f"⚠️ Missing task(s): {', '.join(missing_tasks)} - requires admin installation")
                # Update application state if provided
                if app_state is not None:
                    app_state["missing_tasks"] = missing_tasks
            else:
                log_func("✅ All Task Scheduler tasks are registered")
        
        # Step 2: Verify and enable existing tasks (works without admin)
        log_func("🔧 Checking task activation status...")
        task_names = [
            TASK_NAME_BACKGROUND,
            TASK_NAME_TRAY, 
            TASK_NAME_WATCHDOG,
            TASK_NAME_UPDATER,
            TASK_NAME_SILENT_UPDATER
        ]
        
        activated_count = 0
        activation_results = {}
        
        for task_name in task_names:
            try:
                task_status = get_task_status(task_name)
                if task_status.get('exists', False):
                    if not task_status.get('enabled', False):
                        log_func(f"📋 Activating task: {task_name}")
                        if enable_task(task_name):
                            activated_count += 1
                            activation_results[task_name] = "activated"
                            log_func(f"✅ Task activated: {task_name}")
                        else:
                            activation_results[task_name] = "activation_failed"
                            log_func(f"⚠️ Could not activate task: {task_name}")
                    else:
                        activation_results[task_name] = "already_active"
                        log_func(f"✅ Task already active: {task_name}")
                        activated_count += 1
                else:
                    activation_results[task_name] = "not_found"
                    
            except Exception as task_error:
                activation_results[task_name] = f"error: {task_error}"
                log_func(f"⚠️ Task check error for {task_name}: {task_error}")
        
        if activated_count > 0:
            log_func(f"🎯 Task management complete - {activated_count} tasks active")
        else:
            log_func("⚠️ No tasks could be activated - may need admin privileges")
        
        return {
            'success': True,
            'activated_count': activated_count,
            'activation_results': activation_results,
            'installation_result': result
        }
        
    except Exception as e:
        log_func(f"Task Scheduler management error: {e}")
        return {
            'success': False,
            'error': str(e),
            'activated_count': 0,
            'activation_results': {},
            'installation_result': {}
        }


# For backwards compatibility when run as standalone script
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "uninstall":
        success = uninstall_tasks()
    else:
        success = install_tasks()
    
    sys.exit(0 if success else 1)