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
import psutil
import winreg
from datetime import datetime

# Logging setup with rotation
log_path = os.path.join(os.environ.get('PROGRAMDATA', ''), 'YesNext', 'CloudHoneypotClient', 'service.log')
os.makedirs(os.path.dirname(log_path), exist_ok=True)

# Rotating file handler to prevent huge log files
from logging.handlers import RotatingFileHandler
log_handler = RotatingFileHandler(log_path, maxBytes=10*1024*1024, backupCount=5)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

logger = logging.getLogger('CloudHoneypotService')
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

def log_message(message, level=logging.INFO):
    # Log message both to file and Windows Event Log
    logger.log(level, message)
    try:
        servicemanager.LogInfoMsg(str(message))
    except:
        pass  # Service manager may not be available during testing

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
        """Servis durdurma isteği geldiğinde çağrılır"""
        log_message("Service stop requested")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        
        # Eğer client process'i varsa temiz bir şekilde kapat
        if self.process and self.process.poll() is None:
            try:
                log_message(f"Terminating client process (PID: {self.process.pid})")
                self.process.terminate()
                
                # Process'in kapanması için 10 saniye bekle
                try:
                    self.process.wait(timeout=10)
                    log_message("Client process terminated gracefully")
                except subprocess.TimeoutExpired:
                    log_message("Client process did not terminate, force killing...")
                    self.process.kill()
                    self.process.wait()
                    log_message("Client process force killed")
                    
            except Exception as e:
                log_message(f"Error terminating client process: {e}", logging.ERROR)
        
        win32event.SetEvent(self.stop_event)
        log_message("Service stop event set")

    def is_client_running(self):
        """Ana uygulamanın çalışıp çalışmadığını kontrol eder"""
        try:
            # Method 1: psutil kullanarak kontrol (daha güvenilir)
            try:
                import psutil
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        if proc.info['name'] and 'honeypot-client.exe' in proc.info['name'].lower():
                            log_message(f"Found running client: PID {proc.info['pid']}")
                            return True
                        if proc.info['exe'] and 'honeypot-client.exe' in proc.info['exe'].lower():
                            log_message(f"Found running client: PID {proc.info['pid']}")
                            return True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except ImportError:
                # Fallback: tasklist kullanarak kontrol
                result = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq honeypot-client.exe'], 
                                      capture_output=True, text=True, timeout=10)
                if 'honeypot-client.exe' in result.stdout:
                    log_message("Found running client via tasklist")
                    return True
                
            return False
        except Exception as e:
            log_message(f"Process check error: {e}", logging.ERROR)
            return False

    def should_start_client(self):
        """Ana uygulamanın başlatılıp başlatılmayacağına karar verir"""
        try:
            # Birden fazla konumu kontrol et
            possible_paths = [
                os.path.join(os.environ.get('APPDATA', ''), 'YesNext', 'CloudHoneypotClient', 'status.json'),
                os.path.join(os.environ.get('PROGRAMDATA', ''), 'YesNext', 'CloudHoneypotClient', 'status.json'),
                os.path.join(os.path.dirname(sys.executable), 'status.json'),  # Service yanında
            ]
            
            for state_file in possible_paths:
                if os.path.exists(state_file):
                    try:
                        with open(state_file, 'r', encoding='utf-8') as f:
                            state = json.load(f)
                            # Eğer running=true veya aktif tunnel varsa başlat
                            if state.get("running", False) or state.get("selected_rows", []):
                                log_message(f"Active state found in: {state_file}")
                                return True
                    except Exception as e:
                        log_message(f"Error reading {state_file}: {e}")
                        continue
            
            # Config dosyasından autostart kontrolü
            config_paths = [
                os.path.join(os.path.dirname(sys.executable), 'client_config.json'),
                os.path.join(os.environ.get('PROGRAMDATA', ''), 'YesNext', 'CloudHoneypotClient', 'client_config.json')
            ]
            
            for config_file in config_paths:
                if os.path.exists(config_file):
                    try:
                        with open(config_file, 'r', encoding='utf-8') as f:
                            config = json.load(f)
                            if config.get("tunnels", {}).get("auto_start", False):
                                log_message(f"Auto-start enabled in config: {config_file}")
                                return True
                    except Exception as e:
                        log_message(f"Error reading config {config_file}: {e}")
                        continue
                        
            # Registry'den autostart kontrolü
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                   r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
                    try:
                        winreg.QueryValueEx(key, "CloudHoneypotClient")
                        log_message("Autostart found in registry")
                        return True
                    except FileNotFoundError:
                        pass
            except Exception:
                pass
                        
            log_message("No active state or autostart found - client will not be started")
            return False
            
        except Exception as e:
            log_message(f"State check error: {e}", logging.ERROR)
            return False

    def find_client_executable(self):
        """Client executable dosyasını bulur"""
        possible_paths = [
            # Service yanında
            os.path.join(os.path.dirname(sys.executable), 'honeypot-client.exe'),
            # Bir üst dizinde
            os.path.join(os.path.dirname(os.path.dirname(sys.executable)), 'honeypot-client.exe'),
            # Program Files'da
            os.path.join(os.environ.get('PROGRAMFILES', ''), 'YesNext', 'CloudHoneypotClient', 'honeypot-client.exe'),
            # Current working directory
            os.path.join(os.getcwd(), 'honeypot-client.exe'),
            # Build directory'de
            os.path.join(os.path.dirname(sys.executable), 'build', 'client-onedir', 'honeypot-client.exe')
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                log_message(f"Found executable at: {path}")
                return path
                
        log_message("Could not find honeypot-client.exe in any expected location", logging.ERROR)
        return None

    def start_client(self):
        """Ana uygulamayı başlatır"""
        try:
            exe_path = self.find_client_executable()
            if not exe_path:
                return False
                
            # Minimized olarak başlat (tray'de çalışsın)
            cmd = [exe_path, '--minimized']
            
            # Service context'inde GUI uygulamayı başlatmak için gerekli ayarlar
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags = subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE - gizli başlat
            
            # İnteractive session'da çalışması için
            creation_flags = (
                subprocess.CREATE_NEW_CONSOLE | 
                subprocess.CREATE_NEW_PROCESS_GROUP
            )
            
            self.process = subprocess.Popen(
                cmd,
                startupinfo=startupinfo,
                creationflags=creation_flags,
                cwd=os.path.dirname(exe_path)  # Working directory'yi executable'ın yanına ayarla
            )
            
            log_message(f"Started client process with PID: {self.process.pid}")
            
            # Process başarıyla başladı mı kısa bir süre bekleyip kontrol et
            time.sleep(2)
            if self.process.poll() is None:  # Hala çalışıyor
                log_message("Client process started successfully and is running")
                return True
            else:
                log_message(f"Client process exited immediately with code: {self.process.returncode}", logging.ERROR)
                return False
                
        except Exception as e:
            log_message(f"Start client error: {e}", logging.ERROR)
            return False

    def SvcDoRun(self):
        """Servis ana döngüsü"""
        try:
            log_message("Cloud Honeypot Client Monitor Service starting")
            
            check_interval = 30  # 30 saniye aralıklarla kontrol et
            startup_delay = 10   # Başlangıçta 10 saniye bekle
            restart_attempts = 0
            max_restart_attempts = 5
            last_restart_time = 0
            restart_cooldown = 300  # 5 dakika cooldown
            
            # Sistem başlangıcında biraz bekle
            log_message(f"Waiting {startup_delay} seconds for system to stabilize...")
            time.sleep(startup_delay)
            
            while True:
                try:
                    # Servis durdurma isteği var mı kontrol et
                    rc = win32event.WaitForSingleObject(self.stop_event, check_interval * 1000)
                    if rc == win32event.WAIT_OBJECT_0:
                        log_message("Service stop event received")
                        break

                    # Ana uygulama çalışıyor mu kontrol et
                    client_running = self.is_client_running()
                    current_time = time.time()
                    
                    if not client_running:
                        log_message("Client not running, checking if it should be started")
                        
                        # Çok sık restart denemelerini engelle
                        if current_time - last_restart_time < restart_cooldown:
                            remaining_cooldown = restart_cooldown - (current_time - last_restart_time)
                            log_message(f"Restart cooldown active, waiting {remaining_cooldown:.0f} more seconds")
                            continue
                            
                        if restart_attempts >= max_restart_attempts:
                            log_message(f"Max restart attempts ({max_restart_attempts}) reached, entering extended cooldown")
                            # 15 dakika bekle ve sayacı sıfırla
                            time.sleep(900)
                            restart_attempts = 0
                            continue
                        
                        if self.should_start_client():
                            log_message(f"Starting client (attempt {restart_attempts + 1}/{max_restart_attempts})")
                            
                            if self.start_client():
                                log_message("Client started successfully")
                                restart_attempts = 0  # Başarılı start'ta sayacı sıfırla
                                last_restart_time = current_time
                            else:
                                restart_attempts += 1
                                last_restart_time = current_time
                                log_message(f"Failed to start client (attempt {restart_attempts}/{max_restart_attempts})", logging.ERROR)
                        else:
                            log_message("Client should not be started based on current configuration")
                    else:
                        # Client çalışıyor, restart sayacını sıfırla
                        if restart_attempts > 0:
                            log_message("Client is running normally, resetting restart counter")
                            restart_attempts = 0
                            
                except Exception as inner_e:
                    log_message(f"Error in service loop iteration: {inner_e}", logging.ERROR)
                    time.sleep(5)  # Hata durumunda kısa bekle
                
            log_message("Service main loop ended")
            
        except Exception as e:
            log_message(f"Critical service error: {e}", logging.ERROR)
            # Service'i yeniden başlatmayı dene
            servicemanager.LogErrorMsg(f"Critical error: {e}")
            raise

def install_service():
    """Servisi kur ve başlat"""
    try:
        # Önce varsa durdur ve kaldır
        try:
            win32serviceutil.StopService(CloudHoneypotService._svc_name_)
            log_message("Stopped existing service")
        except:
            pass
            
        try:
            win32serviceutil.RemoveService(CloudHoneypotService._svc_name_)
            log_message("Removed existing service")
        except:
            pass
        
        # Yeni servisi kur
        win32serviceutil.InstallService(
            sys.executable,
            CloudHoneypotService._svc_name_,
            CloudHoneypotService._svc_display_name_,
            description=CloudHoneypotService._svc_description_,
            startType=win32service.SERVICE_AUTO_START  # Otomatik başlatma
        )
        log_message("Service installed successfully")
        
        # Servisi başlat
        win32serviceutil.StartService(CloudHoneypotService._svc_name_)
        log_message("Service started successfully")
        
        print("Cloud Honeypot Client Monitor Service installed and started successfully!")
        return True
        
    except Exception as e:
        error_msg = f"Failed to install service: {e}"
        log_message(error_msg, logging.ERROR)
        print(error_msg)
        return False

def uninstall_service():
    """Servisi durdur ve kaldır"""
    try:
        # Servisi durdur
        try:
            win32serviceutil.StopService(CloudHoneypotService._svc_name_)
            log_message("Service stopped")
            print("Service stopped")
        except Exception as e:
            print(f"Warning: Could not stop service: {e}")
        
        # Servisi kaldır
        win32serviceutil.RemoveService(CloudHoneypotService._svc_name_)
        log_message("Service uninstalled successfully")
        print("Cloud Honeypot Client Monitor Service uninstalled successfully!")
        return True
        
    except Exception as e:
        error_msg = f"Failed to uninstall service: {e}"
        log_message(error_msg, logging.ERROR)
        print(error_msg)
        return False

def service_status():
    """Servis durumunu kontrol et"""
    try:
        status = win32serviceutil.QueryServiceStatus(CloudHoneypotService._svc_name_)
        status_code = status[1]
        
        status_map = {
            1: ("DURDURULDU", "STOPPED"),
            2: "BAŞLATILIYOR...", 
            3: "DURDURULUYOR...",
            4: ("ÇALIŞIYOR", "RUNNING"),
            5: "DEVAM ETTİRİLİYOR...",
            6: "DURAKLATILIYOR...", 
            7: ("DURAKLATILDI", "PAUSED")
        }
        
        status_text = status_map.get(status_code, f"BİLİNMEYEN ({status_code})")
        
        # Turkish/English dual display for GUI
        if isinstance(status_text, tuple):
            tr_text, en_text = status_text
            print(f"🔍 Servis Durumu: {tr_text}")
            print(f"🔍 Service Status: {en_text}")
            
            # Additional info for running status
            if status_code == 4:  # RUNNING
                print("✅ Cloud Honeypot Monitor servisi aktif olarak çalışıyor")
                print("🔧 Client uygulaması otomatik olarak korunuyor")
            elif status_code == 1:  # STOPPED
                print("❌ Cloud Honeypot Monitor servisi durdurulmuş")
                print("⚠️  Client uygulaması korunmuyor - otomatik restart devre dışı")
        else:
            print(f"🔍 Servis Durumu: {status_text}")
        
        return status_code
        
    except Exception as e:
        print(f"Could not query service status: {e}")
        return None

if __name__ == '__main__':
    if len(sys.argv) == 1:
        # Normal service mode
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(CloudHoneypotService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Command line mode
        command = sys.argv[1].lower() if len(sys.argv) > 1 else ''
        
        if command == 'install':
            install_service()
        elif command == 'uninstall' or command == 'remove':
            uninstall_service()
        elif command == 'status':
            service_status()
        elif command == 'restart':
            print("Restarting service...")
            win32serviceutil.RestartService(CloudHoneypotService._svc_name_)
            print("Service restarted")
        elif command == 'start':
            print("Starting service...")
            win32serviceutil.StartService(CloudHoneypotService._svc_name_)
            print("Service started")
        elif command == 'stop':
            print("Stopping service...")
            win32serviceutil.StopService(CloudHoneypotService._svc_name_)
            print("Service stopped")
        else:
            # Default handler for other commands
            win32serviceutil.HandleCommandLine(CloudHoneypotService)
