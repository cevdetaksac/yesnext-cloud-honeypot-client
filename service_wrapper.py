import win32serviceutil
import win32service
import win32event
import win32process
import servicemanager
import sys
import os
import subprocess
import time
import json
import logging
from datetime import datetime

# Logging setup
log_path = os.path.join(os.environ.get('PROGRAMDATA', ''), 'YesNext', 'CloudHoneypotClient', 'service.log')
os.makedirs(os.path.dirname(log_path), exist_ok=True)

logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_message(message, level=logging.INFO):
    # Log message both to file and Windows Event Log
    logging.log(level, message)
    servicemanager.LogInfoMsg(message)

class CloudHoneypotService(win32serviceutil.ServiceFramework):
    _svc_name_ = "CloudHoneypotClient"
    _svc_display_name_ = "Cloud Honeypot Client Monitor"
    _svc_description_ = "Monitors and ensures Cloud Honeypot Client application is running"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.process = None
        log_message("Service initialized")

    def SvcStop(self):
        # Servis durdurma isteği geldiğinde çağrılır
        log_message("Service stop requested")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)

    def is_client_running(self):
        # Ana uygulamanın çalışıp çalışmadığını kontrol eder
        try:
            # Çalışan tüm cloud-client.exe süreçlerini bul
            wmi = win32process.EnumProcesses()
            for pid in wmi:
                try:
                    handle = win32process.OpenProcess(0x0400, 0, pid)
                    exe_path = win32process.GetModuleFileNameEx(handle, 0)
                    if 'cloud-client.exe' in exe_path.lower():
                        return True
                except:
                    continue
            return False
        except Exception as e:
            log_message(f"Process check error: {e}", logging.ERROR)
            return False

    def should_start_client(self):
        # Ana uygulamanın başlatılıp başlatılmayacağına karar verir
        try:
            state_file = os.path.join(os.environ.get('APPDATA', ''), 
                                    'YesNext', 'CloudHoneypotClient', 'state.json')
            if os.path.exists(state_file):
                with open(state_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                    # Eğer aktif koruma varsa başlat
                    return bool(state.get("selected_rows", []))
            return False
        except Exception as e:
            log_message(f"State check error: {e}", logging.ERROR)
            return False

    def start_client(self):
        """Ana uygulamayı başlatır"""
        try:
            exe_path = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(sys.executable)), 'honeypot-client.exe'))
            if not os.path.exists(exe_path):
                exe_path = os.path.abspath(os.path.join(os.path.dirname(sys.executable), 'honeypot-client.exe'))
            
            if not os.path.exists(exe_path):
                log_message(f"Could not find executable at: {exe_path}", logging.ERROR)
                return False
                
            cmd = [exe_path]
            
            # SYSTEM hesabı altında çalıştığı için, interactive window oluşturabilmesi için
            # özel flagler ile başlat
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_NORMAL
            
            self.process = subprocess.Popen(
                cmd,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            log_message(f"Started client process with PID: {self.process.pid}")
            return True
        except Exception as e:
            log_message(f"Start client error: {e}", logging.ERROR)
            return False

    def SvcDoRun(self):
        # Servis ana döngüsü
        try:
            log_message("Service starting")
            check_interval = 30  # 30 saniye aralıklarla kontrol et
            
            while True:
                # Servis durdurma isteği var mı kontrol et
                rc = win32event.WaitForSingleObject(self.stop_event, check_interval * 1000)
                if rc == win32event.WAIT_OBJECT_0:
                    break

                # Ana uygulama çalışıyor mu kontrol et
                if not self.is_client_running():
                    log_message("Client not running, checking if it should be started")
                    if self.should_start_client():
                        log_message("Active protection detected, starting client")
                        if self.start_client():
                            log_message("Client started successfully")
                        else:
                            log_message("Failed to start client", logging.ERROR)
                
            log_message("Service stopped")
            
        except Exception as e:
            log_message(f"Service error: {e}", logging.ERROR)
            raise

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(CloudHoneypotService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(CloudHoneypotService)
