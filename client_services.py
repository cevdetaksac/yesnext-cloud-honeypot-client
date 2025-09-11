"""
Cloud Honeypot Client - System Services Module
Sistem servis yönetimi ve RDP operasyonları modülü
"""

import os
import sys
import ctypes
import subprocess
import winreg
import time
import socket
from typing import Optional, Dict, List, Tuple
import logging

class WindowsServiceManager:
    """Windows servis yönetim sınıfı"""
    
    def __init__(self, log_func=None):
        self.log = log_func if log_func else print
    
    def is_admin(self) -> bool:
        """Yönetici yetkisi kontrolü"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def restart_as_admin(self, script_path: str) -> bool:
        """Yönetici olarak yeniden başlat"""
        try:
            if self.is_admin():
                return True
            
            # ShellExecuteW ile yönetici olarak çalıştır
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                script_path,
                None,
                1
            )
            return True
        except Exception as e:
            self.log(f"[ADMIN] Yönetici yeniden başlatma hatası: {e}")
            return False
    
    def run_command(self, command: str, shell: bool = True, timeout: int = 30) -> Tuple[bool, str]:
        """Komut çalıştır"""
        try:
            self.log(f"[CMD] Çalıştırılıyor: {command}")
            
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            
            output = result.stdout + result.stderr
            success = result.returncode == 0
            
            self.log(f"[CMD] Sonuç: {result.returncode}")
            if output:
                self.log(f"[CMD] Çıktı: {output[:500]}...")
            
            return success, output
            
        except subprocess.TimeoutExpired:
            self.log(f"[CMD] Zaman aşımı: {command}")
            return False, "Timeout"
        except Exception as e:
            self.log(f"[CMD] Komut hatası: {e}")
            return False, str(e)
    
    def get_service_status(self, service_name: str) -> Optional[str]:
        """Servis durumunu al"""
        try:
            success, output = self.run_command(f'sc query "{service_name}"')
            
            if success and 'STATE' in output:
                # STATE satırını bul
                for line in output.split('\n'):
                    if 'STATE' in line:
                        if 'RUNNING' in line:
                            return 'running'
                        elif 'STOPPED' in line:
                            return 'stopped'
                        elif 'PENDING' in line:
                            return 'pending'
            
            return None
        except Exception as e:
            self.log(f"[SERVICE] Durum alma hatası: {e}")
            return None
    
    def start_service(self, service_name: str) -> bool:
        """Servis başlat"""
        try:
            success, output = self.run_command(f'sc start "{service_name}"')
            return success or 'already running' in output.lower()
        except Exception as e:
            self.log(f"[SERVICE] Başlatma hatası: {e}")
            return False
    
    def stop_service(self, service_name: str) -> bool:
        """Servis durdur"""
        try:
            success, output = self.run_command(f'sc stop "{service_name}"')
            return success or 'already stopped' in output.lower()
        except Exception as e:
            self.log(f"[SERVICE] Durdurma hatası: {e}")
            return False
    
    def restart_service(self, service_name: str) -> bool:
        """Servis yeniden başlat"""
        try:
            # Önce durdur
            self.stop_service(service_name)
            time.sleep(2)
            
            # Sonra başlat
            return self.start_service(service_name)
        except Exception as e:
            self.log(f"[SERVICE] Yeniden başlatma hatası: {e}")
            return False

class RDPManager:
    """RDP port yönetim sınıfı"""
    
    def __init__(self, service_manager: WindowsServiceManager, log_func=None):
        self.service_manager = service_manager
        self.log = log_func if log_func else print
        self.registry_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        self.default_port = 3389
        self.secure_port = 53389
    
    def get_rdp_port_from_registry(self) -> Optional[int]:
        """Registry'den RDP portunu al"""
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.registry_path) as key:
                port_value, _ = winreg.QueryValueEx(key, "PortNumber")
                self.log(f"[RDP] Registry'den okunan port: {port_value}")
                return int(port_value)
        except Exception as e:
            self.log(f"[RDP] Registry okuma hatası: {e}")
            return None
    
    def set_rdp_port_in_registry(self, port: int) -> bool:
        """Registry'de RDP portunu ayarla"""
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, 
                self.registry_path, 
                0, 
                winreg.KEY_SET_VALUE
            ) as key:
                winreg.SetValueEx(key, "PortNumber", 0, winreg.REG_DWORD, port)
                self.log(f"[RDP] Port {port} registry'ye yazıldı")
                return True
        except Exception as e:
            self.log(f"[RDP] Registry yazma hatası: {e}")
            return False
    
    def get_terminal_service_status(self) -> Optional[int]:
        """Terminal Services durumunu al"""
        try:
            success, output = self.service_manager.run_command('sc query "TermService"')
            
            if success:
                for line in output.split('\n'):
                    if 'STATE' in line and ':' in line:
                        state_part = line.split(':')[1].strip()
                        # STATE kısmından sayıyı çıkar
                        state_num = ''.join(filter(str.isdigit, state_part.split()[0]))
                        if state_num:
                            status = int(state_num)
                            self.log(f"[RDP] Terminal Services durumu: {status}")
                            return status
            
            return None
        except Exception as e:
            self.log(f"[RDP] Terminal Services durum hatası: {e}")
            return None
    
    def check_port_status(self, port: int) -> List[str]:
        """Port durumunu kontrol et"""
        connections = []
        try:
            success, output = self.service_manager.run_command(f'netstat -an | findstr ":{port}"')
            
            if success and output.strip():
                for line in output.split('\n'):
                    line = line.strip()
                    if line and f':{port}' in line:
                        connections.append(line)
                        self.log(f"[RDP] Port {port} durumu: {line}")
            
            return connections
        except Exception as e:
            self.log(f"[RDP] Port durumu kontrol hatası: {e}")
            return []
    
    def is_rdp_secure(self) -> bool:
        """RDP'nin güvenli portda olup olmadığını kontrol et"""
        current_port = self.get_rdp_port_from_registry()
        return current_port == self.secure_port
    
    def secure_rdp_port(self) -> bool:
        """RDP portunu güvenli porta taşı"""
        try:
            self.log("[RDP] Port güvene alma işlemi başlatılıyor...")
            
            # Registry'de port değiştir
            if not self.set_rdp_port_in_registry(self.secure_port):
                return False
            
            # Terminal Services'i yeniden başlat
            self.log("[RDP] Terminal Services yeniden başlatılıyor...")
            if not self.service_manager.restart_service("TermService"):
                self.log("[RDP] Terminal Services yeniden başlatılamadı!")
                return False
            
            # Biraz bekle
            time.sleep(3)
            
            # Durum kontrol et
            new_port = self.get_rdp_port_from_registry()
            if new_port == self.secure_port:
                self.log(f"[RDP] Port başarıyla {self.secure_port}'a taşındı")
                return True
            else:
                self.log(f"[RDP] Port taşıma başarısız: {new_port}")
                return False
                
        except Exception as e:
            self.log(f"[RDP] Güvene alma hatası: {e}")
            return False
    
    def restore_rdp_port(self) -> bool:
        """RDP portunu varsayılan porta geri döndür"""
        try:
            self.log("[RDP] Port geri yükleme işlemi başlatılıyor...")
            
            # Registry'de port değiştir
            if not self.set_rdp_port_in_registry(self.default_port):
                return False
            
            # Terminal Services'i yeniden başlat
            self.log("[RDP] Terminal Services yeniden başlatılıyor...")
            if not self.service_manager.restart_service("TermService"):
                self.log("[RDP] Terminal Services yeniden başlatılamadı!")
                return False
            
            # Biraz bekle
            time.sleep(3)
            
            # Durum kontrol et
            new_port = self.get_rdp_port_from_registry()
            if new_port == self.default_port:
                self.log(f"[RDP] Port başarıyla {self.default_port}'a geri yüklendi")
                return True
            else:
                self.log(f"[RDP] Port geri yükleme başarısız: {new_port}")
                return False
                
        except Exception as e:
            self.log(f"[RDP] Geri yükleme hatası: {e}")
            return False

class FirewallManager:
    """Windows Firewall yönetim sınıfı"""
    
    def __init__(self, service_manager: WindowsServiceManager, log_func=None):
        self.service_manager = service_manager
        self.log = log_func if log_func else print
    
    def add_firewall_rule(self, rule_name: str, port: int, protocol: str = "TCP") -> bool:
        """Firewall kuralı ekle"""
        try:
            command = (
                f'netsh advfirewall firewall add rule '
                f'name="{rule_name}" '
                f'dir=in '
                f'action=allow '
                f'protocol={protocol} '
                f'localport={port}'
            )
            
            success, output = self.service_manager.run_command(command)
            if success:
                self.log(f"[FIREWALL] Kural eklendi: {rule_name} ({port}/{protocol})")
            else:
                self.log(f"[FIREWALL] Kural ekleme hatası: {output}")
            
            return success
        except Exception as e:
            self.log(f"[FIREWALL] Kural ekleme hatası: {e}")
            return False
    
    def remove_firewall_rule(self, rule_name: str) -> bool:
        """Firewall kuralını kaldır"""
        try:
            command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            
            success, output = self.service_manager.run_command(command)
            if success:
                self.log(f"[FIREWALL] Kural kaldırıldı: {rule_name}")
            else:
                self.log(f"[FIREWALL] Kural kaldırma hatası: {output}")
            
            return success
        except Exception as e:
            self.log(f"[FIREWALL] Kural kaldırma hatası: {e}")
            return False
    
    def check_firewall_rule_exists(self, rule_name: str) -> bool:
        """Firewall kuralının varlığını kontrol et"""
        try:
            command = f'netsh advfirewall firewall show rule name="{rule_name}"'
            success, output = self.service_manager.run_command(command)
            
            exists = success and "No rules match" not in output
            self.log(f"[FIREWALL] Kural kontrol: {rule_name} = {'var' if exists else 'yok'}")
            
            return exists
        except Exception as e:
            self.log(f"[FIREWALL] Kural kontrol hatası: {e}")
            return False

class PortManager:
    """Port dinleme ve yönlendirme sınıfı"""
    
    def __init__(self, log_func=None):
        self.log = log_func if log_func else print
        self.active_tunnels = {}
    
    def is_port_available(self, port: int) -> bool:
        """Port kullanılabilirlik kontrolü"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
                return True
        except OSError:
            return False
    
    def find_available_port(self, start_port: int = 50000, end_port: int = 60000) -> Optional[int]:
        """Kullanılabilir port bul"""
        for port in range(start_port, end_port):
            if self.is_port_available(port):
                return port
        return None
    
    def check_port_usage(self, port: int) -> List[str]:
        """Port kullanımını kontrol et"""
        connections = []
        try:
            import subprocess
            result = subprocess.run(
                f'netstat -an | findstr ":{port}"',
                shell=True,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and f':{port}' in line:
                        connections.append(line)
            
            return connections
        except Exception as e:
            self.log(f"[PORT] Port kullanım kontrol hatası: {e}")
            return []

class TaskSchedulerManager:
    """Görev Zamanlayıcı yönetimi"""
    
    def __init__(self, service_manager: WindowsServiceManager, log_func=None):
        self.service_manager = service_manager
        self.log = log_func if log_func else print
    
    def create_startup_task(self, task_name: str, executable_path: str, 
                          working_dir: str = None) -> bool:
        """Başlangıç görevi oluştur"""
        try:
            # Çalışma dizini ayarla
            if not working_dir:
                working_dir = os.path.dirname(executable_path)
            
            # Görev oluşturma komutu
            command = (
                f'schtasks /create /tn "{task_name}" '
                f'/tr "{executable_path}" '
                f'/sc onlogon '
                f'/ru "SYSTEM" '
                f'/rl highest '
                f'/f'
            )
            
            success, output = self.service_manager.run_command(command)
            
            if success:
                self.log(f"[TASK] Başlangıç görevi oluşturuldu: {task_name}")
            else:
                self.log(f"[TASK] Görev oluşturma hatası: {output}")
            
            return success
        except Exception as e:
            self.log(f"[TASK] Görev oluşturma hatası: {e}")
            return False
    
    def delete_startup_task(self, task_name: str) -> bool:
        """Başlangıç görevini sil"""
        try:
            command = f'schtasks /delete /tn "{task_name}" /f'
            success, output = self.service_manager.run_command(command)
            
            if success:
                self.log(f"[TASK] Görev silindi: {task_name}")
            else:
                self.log(f"[TASK] Görev silme hatası: {output}")
            
            return success
        except Exception as e:
            self.log(f"[TASK] Görev silme hatası: {e}")
            return False
    
    def check_task_exists(self, task_name: str) -> bool:
        """Görevin varlığını kontrol et"""
        try:
            command = f'schtasks /query /tn "{task_name}"'
            success, output = self.service_manager.run_command(command)
            
            exists = success and task_name in output
            self.log(f"[TASK] Görev kontrol: {task_name} = {'var' if exists else 'yok'}")
            
            return exists
        except Exception as e:
            self.log(f"[TASK] Görev kontrol hatası: {e}")
            return False

if __name__ == "__main__":
    # Test
    import logging
    logging.basicConfig(level=logging.INFO)
    
    def test_log(msg):
        print(f"[TEST] {msg}")
    
    # Test service manager
    service_mgr = WindowsServiceManager(test_log)
    print(f"Admin yetkisi: {service_mgr.is_admin()}")
    
    # Test RDP manager
    rdp_mgr = RDPManager(service_mgr, test_log)
    current_port = rdp_mgr.get_rdp_port_from_registry()
    print(f"Mevcut RDP port: {current_port}")
    
    # Test firewall manager
    fw_mgr = FirewallManager(service_mgr, test_log)
    print("Firewall manager oluşturuldu")
    
    print("Tüm sistem modülleri test edildi ✅")
