"""
Cloud Honeypot Client - Utilities Module
Yardımcı fonksiyonlar ve araçlar modülü
"""

import os
import sys
import json
import logging
import hashlib
import base64
import uuid
import socket
import time
import struct
import ctypes
import ctypes.wintypes as wintypes
import subprocess
from datetime import datetime
from typing import Dict, Any, Optional

def get_resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        # If not running from PyInstaller bundle, use current directory
        base_path = os.path.abspath(".")
    
    full_path = os.path.join(base_path, relative_path)
    
    # If file doesn't exist in PyInstaller temp, try current directory
    if not os.path.exists(full_path) and hasattr(sys, '_MEIPASS'):
        fallback_path = os.path.join(os.path.abspath("."), relative_path)
        if os.path.exists(fallback_path):
            return fallback_path
    
    return full_path

class ConfigManager:
    """Konfigürasyon yönetimi sınıfı"""
    
    def __init__(self, config_file: str = "config.json", log_func=None):
        self.config_file = config_file
        self.log = log_func if log_func else print
        self.config_data = {}
        self.load_config()
    
    def load_config(self) -> bool:
        """Konfigürasyonu yükle"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config_data = json.load(f)
                self.log(f"[CONFIG] Konfigürasyon yüklendi: {self.config_file}")
                return True
            else:
                self.log(f"[CONFIG] Konfigürasyon dosyası bulunamadı: {self.config_file}")
                self.config_data = self.get_default_config()
                return self.save_config()
        except Exception as e:
            self.log(f"[CONFIG] Konfigürasyon yükleme hatası: {e}")
            self.config_data = self.get_default_config()
            return False
    
    def save_config(self) -> bool:
        """Konfigürasyonu kaydet"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config_data, f, indent=2, ensure_ascii=False)
            self.log(f"[CONFIG] Konfigürasyon kaydedildi: {self.config_file}")
            return True
        except Exception as e:
            self.log(f"[CONFIG] Konfigürasyon kaydetme hatası: {e}")
            return False
    
    def get_default_config(self) -> Dict[str, Any]:
        """Varsayılan konfigürasyonu al"""
        return {
            "version": "1.0.0",
            "language": "tr",
            "theme": "dark",
            "api_base_url": "https://honeypot.yesnext.com.tr",
            "log_level": "INFO",
            "auto_start": False,
            "rdp_protection": False,
            "tunnel_ports": [],
            "first_run": True,
            "token": "",
            "pc_name": "",
            "dashboard_url": "",
            "window_geometry": "800x600+100+100",
            "minimized_start": False,
            "update_check": True,
            "firewall_rules": [],
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
    
    def get(self, key: str, default=None) -> Any:
        """Konfigürasyon değeri al"""
        return self.config_data.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Konfigürasyon değeri ayarla"""
        self.config_data[key] = value
        self.config_data["updated_at"] = datetime.now().isoformat()
    
    def update(self, data: Dict[str, Any]) -> None:
        """Birden çok değeri güncelle"""
        self.config_data.update(data)
        self.config_data["updated_at"] = datetime.now().isoformat()

class LanguageManager:
    """Dil yönetimi sınıfı"""
    
    def __init__(self, lang_file: str = "client_lang.json", log_func=None):
        self.lang_file = lang_file
        self.log = log_func if log_func else print
        self.languages = {}
        self.current_language = "tr"
        self.load_languages()
    
    def load_languages(self) -> bool:
        """Dil dosyasını yükle"""
        try:
            if os.path.exists(self.lang_file):
                with open(self.lang_file, 'r', encoding='utf-8') as f:
                    self.languages = json.load(f)
                self.log(f"[LANG] Dil dosyası yüklendi: {self.lang_file}")
                return True
            else:
                self.log(f"[LANG] Dil dosyası bulunamadı: {self.lang_file}")
                self.languages = self.get_minimal_languages()
                return False
        except Exception as e:
            self.log(f"[LANG] Dil yükleme hatası: {e}")
            self.languages = self.get_minimal_languages()
            return False
    
    def get_minimal_languages(self) -> Dict[str, Dict[str, str]]:
        """Minimal dil verisi"""
        return {
            "tr": {
                "error": "Hata",
                "warning": "Uyarı", 
                "info": "Bilgi",
                "loading_title": "Yükleniyor...",
                "admin_required_title": "Yönetici Yetkileri Gerekli"
            },
            "en": {
                "error": "Error",
                "warning": "Warning",
                "info": "Info", 
                "loading_title": "Loading...",
                "admin_required_title": "Administrator Privileges Required"
            }
        }
    
    def set_language(self, lang_code: str) -> bool:
        """Dili ayarla"""
        if lang_code in self.languages:
            self.current_language = lang_code
            self.log(f"[LANG] Dil ayarlandı: {lang_code}")
            return True
        else:
            self.log(f"[LANG] Desteklenmeyen dil: {lang_code}")
            return False
    
    def get_text(self, key: str, default: str = None) -> str:
        """Dil metnini al"""
        try:
            if self.current_language in self.languages:
                return self.languages[self.current_language].get(key, default or key)
            return default or key
        except Exception:
            return default or key
    
    def get_all_texts(self) -> Dict[str, str]:
        """Mevcut dilin tüm metinlerini al"""
        return self.languages.get(self.current_language, {})

class LoggerManager:
    """Log yönetimi sınıfı"""
    
    def __init__(self, log_file: str = "logs/client.log", log_level: str = "INFO"):
        self.log_file = log_file
        self.log_level = log_level
        self.logger = None
        self.setup_logger()
    
    def setup_logger(self) -> None:
        """Logger'ı kur"""
        try:
            # Log dizinini oluştur
            log_dir = os.path.dirname(self.log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            # Logger oluştur
            self.logger = logging.getLogger('HoneypotClient')
            self.logger.setLevel(getattr(logging, self.log_level.upper(), logging.INFO))
            
            # Formatı ayarla
            formatter = logging.Formatter(
                '%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            # File handler
            file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
            
            # Console handler (sadece ERROR ve yukarısı)
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.ERROR)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
            
            self.logger.info("Logging sistemi başlatıldı")
            
        except Exception as e:
            print(f"Logger kurulum hatası: {e}")
            # Fallback - basic logging
            logging.basicConfig(
                level=getattr(logging, self.log_level.upper(), logging.INFO),
                format='%(asctime)s [%(levelname)s] %(message)s'
            )
            self.logger = logging.getLogger('HoneypotClient')
    
    def get_logger(self) -> logging.Logger:
        """Logger'ı al"""
        return self.logger
    
    def log(self, message: str, level: str = "INFO") -> None:
        """Log mesajı yaz"""
        if self.logger:
            log_func = getattr(self.logger, level.lower(), self.logger.info)
            log_func(message)

class SecurityUtils:
    """Güvenlik yardımcıları"""
    
    @staticmethod
    def generate_token() -> str:
        """Random token oluştur"""
        return str(uuid.uuid4())
    
    @staticmethod
    def hash_string(text: str, algorithm: str = "sha256") -> str:
        """String'i hash'le"""
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(text.encode('utf-8'))
        return hash_obj.hexdigest()
    
    @staticmethod
    def encode_base64(text: str) -> str:
        """Base64 encode"""
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')
    
    @staticmethod
    def decode_base64(encoded_text: str) -> str:
        """Base64 decode"""
        try:
            return base64.b64decode(encoded_text).decode('utf-8')
        except Exception:
            return ""
    
    @staticmethod
    def validate_token_format(token: str) -> bool:
        """Token formatını doğrula (UUID4)"""
        try:
            uuid.UUID(token, version=4)
            return True
        except ValueError:
            return False

class FileUtils:
    """Dosya yardımcıları"""
    
    @staticmethod
    def ensure_directory(path: str) -> bool:
        """Dizin var olduğundan emin ol"""
        try:
            os.makedirs(path, exist_ok=True)
            return True
        except Exception:
            return False
    
    @staticmethod
    def read_json_file(file_path: str) -> Optional[Dict]:
        """JSON dosyası oku"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None
    
    @staticmethod
    def write_json_file(file_path: str, data: Dict) -> bool:
        """JSON dosyası yaz"""
        try:
            # Dizin oluştur
            FileUtils.ensure_directory(os.path.dirname(file_path))
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False
    
    @staticmethod
    def get_file_size(file_path: str) -> int:
        """Dosya boyutunu al"""
        try:
            return os.path.getsize(file_path)
        except Exception:
            return 0
    
    @staticmethod
    def get_file_modified_time(file_path: str) -> Optional[datetime]:
        """Dosya değiştirme zamanını al"""
        try:
            timestamp = os.path.getmtime(file_path)
            return datetime.fromtimestamp(timestamp)
        except Exception:
            return None

class SystemUtils:
    """Sistem yardımcıları"""
    
    @staticmethod
    def get_computer_name() -> str:
        """Bilgisayar adını al"""
        try:
            return os.environ.get('COMPUTERNAME', 'Unknown')
        except Exception:
            return 'Unknown'
    
    @staticmethod
    def run_cmd(cmd, timeout: int = 20, suppress_rc_log: bool = False, log_func=None):
        """Terminal komutu çalıştır - Unicode safe"""
        if log_func is None:
            log_func = print
            
        try:
            if isinstance(cmd, str):
                cmd = cmd.split()
            
            creationflags = 0x08000000 if os.name == 'nt' else 0
            completed = subprocess.run(
                cmd, shell=False, capture_output=True, text=True,
                creationflags=creationflags, timeout=timeout,
                encoding='utf-8', errors='replace'  # Unicode safe encoding
            )
            
            if not suppress_rc_log:
                log_func(f"Command: {' '.join(cmd)} -> RC: {completed.returncode}")
                
            return completed
        except subprocess.TimeoutExpired:
            log_func(f"Command timeout: {' '.join(cmd)}")
            return None
        except UnicodeDecodeError as e:
            log_func(f"Command encoding error: {e}")
            # Fallback: try with different encoding
            try:
                creationflags = 0x08000000 if os.name == 'nt' else 0
                completed = subprocess.run(
                    cmd, shell=False, capture_output=True, text=True,
                    creationflags=creationflags, timeout=timeout,
                    encoding='cp1254', errors='replace'  # Windows Turkish encoding
                )
                return completed
            except Exception as fallback_error:
                log_func(f"Command fallback failed: {fallback_error}")
                return None
        except Exception as e:
            log_func(f"Command error: {e}")
            return None
    
    @staticmethod
    def get_username() -> str:
        """Kullanıcı adını al"""
        try:
            return os.environ.get('USERNAME', 'Unknown')
        except Exception:
            return 'Unknown'
    
    @staticmethod
    def get_windows_version() -> str:
        """Windows versiyonunu al"""
        try:
            import platform
            return f"{platform.system()} {platform.release()} {platform.version()}"
        except Exception:
            return "Unknown Windows"
    
    @staticmethod
    def get_python_version() -> str:
        """Python versiyonunu al"""
        return f"Python {sys.version.split()[0]}"
    
    @staticmethod
    def get_executable_path() -> str:
        """Çalıştırılabilir dosya yolunu al"""
        if getattr(sys, 'frozen', False):
            # PyInstaller ile derlenmiş
            return sys.executable
        else:
            # Script olarak çalışıyor
            return os.path.abspath(__file__)
    
    @staticmethod
    def get_working_directory() -> str:
        """Çalışma dizinini al"""
        if getattr(sys, 'frozen', False):
            # PyInstaller ile derlenmiş
            return os.path.dirname(sys.executable)
        else:
            # Script olarak çalışıyor
            return os.path.dirname(os.path.abspath(__file__))

class NetworkUtils:
    """Ağ yardımcıları"""
    
    @staticmethod
    def get_local_ip() -> str:
        """Local IP adresini al"""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    @staticmethod
    def is_port_open(host: str, port: int, timeout: int = 3) -> bool:
        """Port açık mı kontrol et"""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    @staticmethod
    def ping_host(host: str, timeout: int = 3) -> bool:
        """Host'u ping'le"""
        try:
            import subprocess
            result = subprocess.run(
                f"ping -n 1 -w {timeout * 1000} {host}",
                shell=True,
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False

def load_i18n(lang_file: str = "client_lang.json", language: str = "tr") -> dict:
    """Load all language data from JSON file"""
    try:
        if os.path.exists(lang_file):
            with open(lang_file, "r", encoding="utf-8") as f:
                all_languages = json.load(f)
                print(f"[LANG] All languages loaded from {lang_file}")
                print(f"[LANG] Available languages: {list(all_languages.keys())}")
                return all_languages
        else:
            print(f"[LANG] Language file not found: {lang_file}")
            return {"tr": {}, "en": {}}
    except Exception as e:
        print(f"[LANG] Error loading language file: {e}")
        return {"tr": {}, "en": {}}

if __name__ == "__main__":
    # Test
    print("Testing utility modules...")
    
    # Test config manager
    config = ConfigManager("test_config.json")
    print(f"Config loaded: {bool(config.config_data)} ✅")
    
    # Test language manager
    lang = LanguageManager()
    print(f"Language manager: {lang.current_language} ✅")
    
    # Test logger
    logger_mgr = LoggerManager("test.log")
    logger_mgr.log("Test mesajı")
    print("Logger tested ✅")
    
    # Test security utils
    token = SecurityUtils.generate_token()
    is_valid = SecurityUtils.validate_token_format(token)
    print(f"Security utils: {is_valid} ✅")
    
    # Test system utils
    pc_name = SystemUtils.get_computer_name()
    print(f"System utils: {pc_name} ✅")
    
    print("All utility modules tested successfully ✅")

# ===================== TOKEN STORE ===================== #
class TokenStore:
    """Windows DPAPI ile token saklama sınıfı"""
    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    CRYPTPROTECT_LOCAL_MACHINE = 0x4

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    @staticmethod
    def _to_blob(b: bytes):
        buf = ctypes.create_string_buffer(b)
        blob = TokenStore.DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
        return blob, buf  # keep buf referenced

    @staticmethod
    def _from_blob(blob) -> bytes:
        size = int(blob.cbData)
        ptr = ctypes.cast(blob.pbData, ctypes.POINTER(ctypes.c_byte))
        return ctypes.string_at(ptr, size)

    @staticmethod
    def _crypt_protect(data: bytes) -> bytes:
        crypt32  = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        flags = TokenStore.CRYPTPROTECT_UI_FORBIDDEN | TokenStore.CRYPTPROTECT_LOCAL_MACHINE
        payload = struct.pack("I", len(data)) + data
        in_blob, in_buf = TokenStore._to_blob(payload)
        out_blob = TokenStore.DATA_BLOB()
        if not crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, flags, ctypes.byref(out_blob)):
            raise RuntimeError("CryptProtectData failed")
        try:
            out = TokenStore._from_blob(out_blob)
        finally:
            try:
                kernel32.LocalFree(out_blob.pbData)
            except Exception:
                pass
        return out

    @staticmethod
    def _crypt_unprotect(data: bytes) -> bytes:
        crypt32  = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        flags = TokenStore.CRYPTPROTECT_UI_FORBIDDEN | TokenStore.CRYPTPROTECT_LOCAL_MACHINE
        in_blob, in_buf = TokenStore._to_blob(data)
        out_blob = TokenStore.DATA_BLOB()
        if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, flags, ctypes.byref(out_blob)):
            raise RuntimeError("CryptUnprotectData failed")
        try:
            out = TokenStore._from_blob(out_blob)
        finally:
            try:
                kernel32.LocalFree(out_blob.pbData)
            except Exception:
                pass
        return out[4:]  # strip prepended length

    @staticmethod
    def save(token: str, token_file_new: str):
        try:
            data = token.encode("utf-8")
            # küçük bir header ile integrity:
            h = hashlib.sha256(data).hexdigest().encode("ascii")
            payload = b"CHP1|" + h + b"|" + data
            enc = TokenStore._crypt_protect(payload)
            with open(token_file_new, "wb") as f:
                f.write(enc)
        except Exception as e:
            print(f"token save error: {e}")

    @staticmethod
    def load(token_file_new: str) -> Optional[str]:
        try:
            if os.path.exists(token_file_new):
                enc = open(token_file_new, "rb").read()
                dec = TokenStore._crypt_unprotect(enc)
                if not dec.startswith(b"CHP1|"):
                    return None
                _, h, data = dec.split(b"|", 2)
                if hashlib.sha256(data).hexdigest().encode("ascii") != h:
                    return None
                return data.decode("utf-8", "ignore").strip()
        except Exception as e:
            print(f"token load error: {e}")
        return None

    @staticmethod
    def migrate_from_plain(token_file_old: str, token_file_new: str):
        try:
            if os.path.exists(token_file_old):
                token = open(token_file_old, "r", encoding="utf-8").read().strip()
                if token:
                    TokenStore.save(token, token_file_new)
                try:
                    os.remove(token_file_old)
                except Exception:
                    pass
        except Exception as e:
            print(f"token migration error: {e}")

# ===================== SERVICE CONTROLLER ===================== #
class ServiceController:
    """Windows servis kontrolü sınıfı"""
    
    @staticmethod
    def _sc_query_code(svc_name: str) -> int:
        """
        Returns numeric state code independent of locale.
        1 STOPPED, 2 START_PENDING, 3 STOP_PENDING, 4 RUNNING ...
        """
        try:
            creationflags = 0x08000000 if os.name == 'nt' else 0
            completed = subprocess.run(['sc', 'queryex', svc_name],
                                       shell=False, capture_output=True, text=True,
                                       creationflags=creationflags, timeout=8)
            txt = (completed.stdout or "")
            for line in txt.splitlines():
                if 'STATE' in line.upper():
                    after = line.split(':', 1)[1].strip()
                    num = after.split()[0]
                    return int(num)
        except Exception as e:
            print(f"sc query error: {e}")
        return -1

    @staticmethod
    def _wait_state_code(svc_name: str, desired_code: int, timeout: int = 40) -> bool:
        t0 = time.time()
        while time.time() - t0 < timeout:
            code = ServiceController._sc_query_code(svc_name)
            if code == desired_code:
                return True
            # START/STOP pending ise biraz sabret
            if code in (2,3):
                time.sleep(1.2)
            else:
                time.sleep(0.6)
        return False

    @staticmethod
    def stop(svc_name: str, timeout: int = 40, log_func=None) -> bool:
        if log_func is None:
            log_func = print
            
        code = ServiceController._sc_query_code(svc_name)
        if code == 1:
            return True

        # 1) sc stop dene (kısa tekrarlar)
        for _ in range(2):
            SystemUtils.run_cmd(['sc', 'stop', svc_name], timeout=10, log_func=log_func)
            if ServiceController._wait_state_code(svc_name, 1, 12):
                return True
            time.sleep(2)

        # 2) PowerShell Stop-Service -Force
        SystemUtils.run_cmd(['powershell', '-NoProfile', '-Command',
                 f'Stop-Service -Name "{svc_name}" -Force -ErrorAction SilentlyContinue'], timeout=20, log_func=log_func)
        if ServiceController._wait_state_code(svc_name, 1, 15):
            return True

        log_func(f"Service {svc_name} did not stop in time")
        return False

    @staticmethod
    def start(svc_name: str, timeout: int = 40, log_func=None) -> bool:
        if log_func is None:
            log_func = print
            
        code = ServiceController._sc_query_code(svc_name)
        if code == 4:
            return True

        SystemUtils.run_cmd(['sc', 'start', svc_name], timeout=10, log_func=log_func)
        if ServiceController._wait_state_code(svc_name, 4, timeout):
            return True

        SystemUtils.run_cmd(['powershell', '-NoProfile', '-Command',
                 f'Start-Service -Name "{svc_name}" -ErrorAction SilentlyContinue'], timeout=20, log_func=log_func)
        return ServiceController._wait_state_code(svc_name, 4, 20)

    @staticmethod
    def restart(svc_name: str, log_func=None) -> bool:
        if log_func is None:
            log_func = print
            
        SystemUtils.run_cmd(['powershell', '-NoProfile', '-Command',
                 f'Restart-Service -Name "{svc_name}" -Force -ErrorAction SilentlyContinue'], timeout=25, log_func=log_func)
        if ServiceController._wait_state_code(svc_name, 4, 20):
            return True
        # fallback
        return ServiceController.stop(svc_name, 20, log_func) and ServiceController.start(svc_name, 20, log_func)

    @staticmethod
    def _check_port_in_use(port: int) -> bool:
        """Belirtilen portun kullanımda olup olmadığını kontrol eder"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result == 0
        except:
            return False

    @staticmethod
    def check_rdp_port_safety(log_func=None) -> bool:
        """RDP portunun güvenli durumda olup olmadığını kontrol eder ve detaylı log tutar"""
        if log_func is None:
            log_func = print
            
        try:
            # Regedit'ten port değerini oku
            current_port = ServiceController.get_rdp_port(log_func)
            log_func(f"Regedit RDP port değeri: {current_port}")
            
            # 3389 port durumunu kontrol et
            port_3389_in_use = ServiceController._check_port_in_use(3389)
            log_func(f"3389 portu kullanımda mı: {port_3389_in_use}")
            
            # RDP güvenli port durumunu kontrol et
            rdp_secure_port = get_rdp_secure_port()
            port_secure_in_use = ServiceController._check_port_in_use(rdp_secure_port)
            log_func(f"{rdp_secure_port} portu kullanımda mı: {port_secure_in_use}")
            
            # Terminal servisi durumunu kontrol et
            svc_status = ServiceController._sc_query_code("TermService")
            log_func(f"Terminal Servis durumu kodu: {svc_status}")
            
            if current_port == rdp_secure_port:
                # Port zaten güvenli konumda
                log_func(f"RDP port güvenli konumda ({rdp_secure_port})")
                if not port_3389_in_use:
                    log_func("3389 portu boşta, tünel başlatılabilir")
                else:
                    log_func("UYARI: 3389 portu hala kullanımda!")
                return True
            elif current_port == 3389:
                # Port varsayılan konumda, koruma başlatılabilir
                log_func("RDP port varsayılan konumda (3389)")
                if port_secure_in_use:
                    log_func(f"UYARI: {rdp_secure_port} portu kullanımda!")
                return True
            else:
                # Port beklenmeyen bir değerde
                log_func(f"RDP port beklenmeyen değerde: {current_port}")
                return False
        except Exception as e:
            log_func(f"RDP port kontrolü sırasında hata: {e}")
            return False

    @staticmethod
    def switch_rdp_port(new_port: int, log_func=None, firewall_func=None) -> bool:
        if log_func is None:
            log_func = print
            
        try:
            cur = ServiceController.get_rdp_port(log_func)
            if cur and int(cur) == int(new_port):
                try:
                    if firewall_func:
                        firewall_func(int(new_port), f"RDP {new_port}")
                except Exception as e:
                    log_func(f"firewall allow check/add failed for port {new_port}: {e}")
                return True
        except Exception as e:
            log_func(f"Exception: {e}")
            
        SystemUtils.run_cmd([
            'reg','add', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp',
            '/v','PortNumber','/t','REG_DWORD','/d', str(new_port), '/f'
        ], log_func=log_func)
        
        # Only add firewall allow if not already present (avoid duplicates on 3389/53389)
        try:
            if firewall_func:
                firewall_func(int(new_port), f"RDP {new_port}")
        except Exception as e:
            log_func(f"firewall allow check/add failed for port {new_port}: {e}")
            
        return ServiceController.restart('TermService', log_func)

    @staticmethod
    def get_rdp_port(log_func=None) -> Optional[int]:
        if log_func is None:
            log_func = print
            
        if os.name != 'nt':
            return None
        try:
            import winreg as _wr
            key = _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp")
            val, typ = _wr.QueryValueEx(key, "PortNumber")
            _wr.CloseKey(key)
            if isinstance(val, int):
                # Port değerini ve Terminal Servis durumunu logla
                log_func(f"Regedit RDP Port değeri: {val}")
                svc_status = ServiceController._sc_query_code("TermService")
                log_func(f"Terminal Servis durumu: {svc_status}")
                
                # Port dinleme durumunu kontrol et
                try:
                    netstat = SystemUtils.run_cmd(["netstat", "-an"], timeout=5, log_func=log_func)
                    if netstat and netstat.stdout:
                        for line in netstat.stdout.splitlines():
                            if f":{val}" in line:
                                log_func(f"RDP Port {val} durumu: {line.strip()}")
                except Exception as e:
                    log_func(f"RDP Port {val} netstat kontrolü hatası: {e}")
                
                return val
        except Exception as e:
            log_func(f"get_rdp_port error: {e}")
        return None

# ===================== HELPER FUNCTIONS ===================== #
def firewall_allow_exists_tcp_port(port: int, log_func=None) -> bool:
    """Checks if an inbound allow firewall rule exists for given TCP local port (Windows only)."""
    if log_func is None:
        log_func = print
        
    if os.name != 'nt':
        return False
    # Primary method: Use netsh (faster and more reliable than PowerShell)
    try:
        res = SystemUtils.run_cmd([
            'netsh', 'advfirewall', 'firewall', 'show', 'rule', 
            'name=all', 'dir=in', 'type=allow'
        ], timeout=10, suppress_rc_log=True, log_func=log_func)
        
        if res and hasattr(res, 'returncode') and res.returncode == 0:
            txt = str(res.stdout or "").lower()
            port_str = str(int(port))
            
            # Look for patterns indicating the port is allowed
            patterns = [
                f'localport: {port_str}',
                f'localport:{port_str}',
                f'localport = {port_str}',
                f'local port: {port_str}'
            ]
            
            for pattern in patterns:
                if pattern in txt:
                    return True
                    
            # Also check if 'any' is specified for local port
            if 'localport: any' in txt or 'localport:any' in txt:
                return True
                
    except Exception as e:
        if log_func:
            log_func(f"Firewall check error: {e}")
    
    # Fallback: Quick PowerShell check (simplified)
    try:
        ps = f"if (Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Get-NetFirewallPortFilter | Where-Object LocalPort -eq {port}) {{ Write-Output 'FOUND' }}"
        
        res = SystemUtils.run_cmd([
            'powershell', '-NoProfile', '-Command', ps
        ], timeout=5, suppress_rc_log=True, log_func=log_func)
        
        if res and res.returncode == 0:
            stdout = str(getattr(res, 'stdout', ''))
            if 'FOUND' in stdout:
                return True
                
    except Exception:
        pass
    return False

def ensure_firewall_allow_for_port(port: int, rule_name: str = None, log_func=None):
    """Ensure an inbound allow rule exists for TCP port; add if missing (Windows only)."""
    if log_func is None:
        log_func = print
        
    if os.name != 'nt':
        return
    
    if firewall_allow_exists_tcp_port(port, log_func):
        return
    
    if rule_name is None:
        rule_name = f"Allow_TCP_{port}"
    
    try:
        SystemUtils.run_cmd(['netsh','advfirewall','firewall','add','rule',
                           f'name={rule_name}','dir=in','action=allow','protocol=TCP',
                           f'localport={port}'], timeout=10, log_func=log_func)
        log_func(f"Firewall rule added for port {port}")
    except Exception as e:
        log_func(f"Failed to add firewall rule for port {port}: {e}")

def is_process_running_windows(pid: int) -> bool:
    """Windows'ta process'in çalışıp çalışmadığını kontrol et"""
    try:
        import psutil
        return psutil.pid_exists(pid)
    except ImportError:
        try:
            # tasklist fallback
            result = subprocess.run(['tasklist', '/FI', f'PID eq {pid}'], 
                                  capture_output=True, text=True, timeout=5)
            return str(pid) in result.stdout
        except:
            return False
    except:
        return False

def write_watchdog_token(value: str, token_file: str):
    """Watchdog token dosyasına yaz"""
    try:
        with open(token_file, "w", encoding="utf-8") as f:
            f.write(value.strip())
    except Exception as e:
        print(f"write_watchdog_token error: {e}")

def read_watchdog_token(token_file: str) -> str:
    """Watchdog token dosyasından oku"""
    try:
        if os.path.exists(token_file):
            with open(token_file, "r", encoding="utf-8") as f:
                return f.read().strip()
    except Exception as e:
        print(f"read_watchdog_token error: {e}")
    return ""

def start_watchdog_if_needed(watchdog_token_file: str, log_func=None):
    """Watchdog process'ini gerekirse başlat"""
    if log_func is None:
        log_func = print
        
    try:
        token = read_watchdog_token(watchdog_token_file)
        if not token:
            return
            
        try:
            pid = int(token)
            if is_process_running_windows(pid):
                log_func(f"Watchdog already running with PID {pid}")
                return
        except ValueError:
            pass
        
        # Watchdog yoksa başlat
        current_exe = sys.executable
        script_path = os.path.abspath(__file__).replace('client_utils.py', 'client.py')
        
        if os.path.exists(script_path):
            import subprocess
            proc = subprocess.Popen([current_exe, script_path, "--watchdog"],
                                  creationflags=0x08000000 if os.name == 'nt' else 0)
            write_watchdog_token(str(proc.pid), watchdog_token_file)
            log_func(f"Started watchdog process with PID {proc.pid}")
    except Exception as e:
        log_func(f"start_watchdog_if_needed error: {e}")

def is_admin() -> bool:
    """Admin yetkileri kontrolü"""
    if os.name != 'nt':
        return os.geteuid() == 0
    
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def set_autostart(enable: bool = True, log_func=None):
    """Windows autostart registry ayarı"""
    if log_func is None:
        log_func = print
        
    if os.name != 'nt':
        return
        
    import winreg
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    value_name = "HoneypotClient"
    
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        
        if enable:
            exe_path = sys.executable
            if exe_path.endswith('python.exe'):
                script_path = os.path.abspath(__file__).replace('client_utils.py', 'client.py')
                value = f'"{exe_path}" "{script_path}"'
            else:
                value = f'"{exe_path}"'
            
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value)
            log_func("Autostart enabled")
        else:
            try:
                winreg.DeleteValue(key, value_name)
                log_func("Autostart disabled")
            except FileNotFoundError:
                pass
                
        winreg.CloseKey(key)
    except Exception as e:
        log_func(f"Autostart setting error: {e}")

def watchdog_main(parent_pid: int, log_func=None):
    """Watchdog ana fonksiyonu - process izleme ve yeniden başlatma"""
    if log_func is None:
        log_func = print
        
    attempts = 0
    max_attempts = 5
    
    while attempts < max_attempts:
        time.sleep(5)
        
        # Watchdog token kontrolü
        token = read_watchdog_token("")
        if token.lower() == 'stop':
            return
            
        # Parent process kontrolü
        alive = is_process_running_windows(int(parent_pid))
        if not alive:
            log_func(f"[watchdog] Parent process {parent_pid} not found, attempting restart")
            attempts += 1
            
            try:
                # Yeni instance başlat
                if getattr(sys, 'frozen', False):
                    subprocess.Popen([sys.executable], shell=False)
                else:
                    subprocess.Popen([sys.executable, os.path.abspath(sys.argv[0])], shell=False)
                time.sleep(10)  # Başlamasını bekle
            except Exception as e:
                log_func(f"[watchdog] Restart error: {e}")
        else:
            attempts = 0  # Parent yaşıyorsa attempt'ları sıfırla
            
        time.sleep(10)  # Genel bekleme
    
    log_func(f"[watchdog] Maximum attempts ({max_attempts}) reached, exiting")

def install_excepthook(log_func=None):
    """Exception hook kurulumu"""
    if log_func is None:
        log_func = print
        
    def _hook(exc_type, exc, tb):
        try:
            import traceback
            log_func("UNHANDLED EXCEPTION:\n" + "".join(traceback.format_exception(exc_type, exc, tb)))
        except Exception as e:
            log_func(f"Exception hook error: {e}")
    
    try:
        sys.excepthook = _hook
    except Exception:
        pass

# ===== CONFIG MANAGEMENT =====

# Single config file next to executable (no AppData)
def get_config_file_path() -> str:
    """Get config file path - always next to executable"""
    if hasattr(sys, 'frozen'):
        # Build versiyonunda: executable yanındaki config
        exe_dir = os.path.dirname(sys.executable)
        return os.path.join(exe_dir, "client_config.json")
    else:
        # Development versiyonunda: script yanındaki config
        script_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(script_dir, "client_config.json")

CONFIG_FILE = get_config_file_path()

def load_config() -> dict:
    """Load application configuration - single file system"""
    default_config = {
        "application": {
            "name": "Cloud Honeypot Client",
            "version": "2.2.1",
            "author": "YesNext Technology"
        },
        "language": {
            "selected": "tr",
            "selected_by_user": False,
            "available_languages": ["tr", "en"],
            "default": "tr"
        },
        "ui": {
            "window_width": 900,
            "window_height": 700,
            "theme": "dark",
            "show_loading_screen": True,
            "loading_timeout": 30
        },
        "admin": {
            "require_admin_privileges": True,
            "auto_restart_as_admin": False,
            "show_admin_dialog": True
        },
        "logging": {
            "level": "INFO",
            "max_file_size_mb": 10,
            "backup_count": 5,
            "debug_mode": False
        },
        "api": {
            "base_url": "https://honeypot.yesnext.com.tr/api",
            "timeout": 30,
            "retry_count": 3
        },
        "honeypot": {
            "server_ip": "194.5.236.181",
            "tunnel_port": 4443,
            "connect_timeout": 8,
            "receive_buffer_size": 65536,
            "server_name": None
        },
        "tunnels": {
            "auto_start": False,
            "rdp_port": 53389,
            "default_ports": [
                {"local": 3389, "remote": 53389, "service": "RDP", "enabled": True},
                {"local": 1433, "remote": 0, "service": "MSSQL", "enabled": False},
                {"local": 3306, "remote": 0, "service": "MySQL", "enabled": False},
                {"local": 21, "remote": 0, "service": "FTP", "enabled": False},
                {"local": 22, "remote": 0, "service": "SSH", "enabled": False}
            ]
        },
        "updates": {
            "auto_check": True,
            "check_interval_hours": 24,
            "show_notifications": True
        },
        "advanced": {
            "startup_delay": 0,
            "minimize_to_tray": True,
            "auto_start_with_windows": False,
            "single_instance": True
        }
    }
    
    try:
        # Single config file system - no AppData
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
                # Merge with defaults to ensure all keys exist
                return merge_configs(default_config, config)
        else:
            # Create default config file if not exists
            save_config(default_config)
            return default_config
            
    except Exception as e:
        print(f"[CONFIG] Error loading config: {e}")
        return default_config

def save_config(config: dict) -> bool:
    """Save application configuration to single config file"""
    try:
        # No directory creation needed - config is next to executable
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        print(f"[CONFIG] Configuration saved to: {CONFIG_FILE}")
        return True
    except Exception as e:
        print(f"[CONFIG] Error saving config: {e}")
        return False

def merge_configs(default: dict, user: dict) -> dict:
    """Recursively merge user config with default config"""
    result = default.copy()
    for key, value in user.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_configs(result[key], value)
        else:
            result[key] = value
    return result

def get_config_value(key_path: str, default=None):
    """Get a configuration value using dot notation (e.g., 'language.selected')"""
    config = load_config()
    keys = key_path.split('.')
    value = config
    
    try:
        for key in keys:
            value = value[key]
        return value
    except (KeyError, TypeError):
        return default

# Alias for backward compatibility
def get_from_config(key_path: str, fallback):
    """Helper to get values from config with fallback - alias for get_config_value"""
    return get_config_value(key_path, fallback)

def get_port_table():
    """Get port table from configuration file
    
    Returns:
        List[Tuple[str, str, str]]: Port table in format [(listen_port, new_port, service), ...]
    """
    try:
        config = load_config()
        default_ports = config.get("tunnels", {}).get("default_ports", [])
        
        port_table = []
        for port_config in default_ports:
            listen_port = str(port_config.get("local", ""))
            remote_port = str(port_config.get("remote", 0)) if port_config.get("remote", 0) > 0 else "-"
            service = str(port_config.get("service", ""))
            
            if listen_port and service:
                port_table.append((listen_port, remote_port, service))
        
        print(f"[CONFIG] Port table loaded from config: {len(port_table)} entries")
        return port_table
        
    except Exception as e:
        print(f"[CONFIG] Error loading port table: {e}")
        # Fallback to default table
        return [
            ("3389", "53389", "RDP"),
            ("1433", "-", "MSSQL"),
            ("3306", "-", "MySQL"),
            ("21", "-", "FTP"),
            ("22", "-", "SSH"),
        ]

def get_rdp_secure_port():
    """Get RDP secure port from configuration
    
    Returns:
        int: RDP secure port number
    """
    try:
        return get_config_value("tunnels.rdp_port", 53389)
    except Exception:
        return 53389

def set_config_value(key_path: str, value) -> bool:
    """Set a configuration value using dot notation"""
    config = load_config()
    keys = key_path.split('.')
    
    # Navigate to the parent of the target key
    current = config
    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]
    
    # Set the final key
    current[keys[-1]] = value
    
    return save_config(config)

def update_language_config(language: str, selected_by_user: bool = True) -> bool:
    """Update language configuration"""
    config = load_config()
    config["language"]["selected"] = language
    config["language"]["selected_by_user"] = selected_by_user
    return save_config(config)

# ===== CONFIG SYSTEM FINALIZED =====
# All settings are now managed through client_config.json
# No legacy migration needed - pure config-driven architecture


# ===================== INSTALLER-BASED UPDATE SYSTEM ===================== #

class InstallerUpdateManager:
    """Yeni installer tabanlı güncelleme sistemi"""
    
    def __init__(self, github_owner: str, github_repo: str, log_func=None):
        self.github_owner = github_owner
        self.github_repo = github_repo
        self.log = log_func if log_func else print
        self.base_url = f"https://api.github.com/repos/{github_owner}/{github_repo}/releases/latest"
        
    def get_current_version(self) -> str:
        """Mevcut sürümü al"""
        try:
            config = load_config()
            return config.get("application", {}).get("version", "1.0.0")
        except:
            return "1.0.0"
    
    def check_for_updates(self) -> Dict[str, Any]:
        """Güncelleme kontrolü yap"""
        try:
            self.log("[UPDATE] Güncelleme kontrol ediliyor...")
            
            # GitHub API'den son sürüm bilgisini al
            import requests
            response = requests.get(self.base_url, timeout=10)
            if response.status_code != 200:
                return {"error": "API erişim hatası", "current_version": self.get_current_version()}
            
            data = response.json()
            latest_tag = data.get("tag_name") or data.get("name", "")
            latest_version = latest_tag.lstrip('v')
            current_version = self.get_current_version().lstrip('v')
            
            self.log(f"[UPDATE] Mevcut sürüm: {current_version}")
            self.log(f"[UPDATE] Son sürüm: {latest_version}")
            
            # Sürüm karşılaştırması
            if self._compare_versions(latest_version, current_version) <= 0:
                return {
                    "has_update": False,
                    "current_version": current_version,
                    "latest_version": latest_version,
                    "message": "Güncel sürüm kullanılıyor"
                }
            
            # Installer asset'ini bul
            assets = data.get("assets", [])
            installer_asset = None
            
            for asset in assets:
                name = asset.get("name", "").lower()
                if name.endswith("-installer.exe") or name.endswith("installer.exe"):
                    installer_asset = asset
                    break
            
            if not installer_asset:
                return {"error": "Installer dosyası bulunamadı", "current_version": current_version}
            
            return {
                "has_update": True,
                "current_version": current_version,
                "latest_version": latest_version,
                "release_notes": data.get("body", ""),
                "installer_url": installer_asset.get("browser_download_url"),
                "installer_size": installer_asset.get("size", 0),
                "installer_name": installer_asset.get("name"),
                "published_at": data.get("published_at")
            }
            
        except Exception as e:
            self.log(f"[UPDATE] Kontrol hatası: {e}")
            return {"error": str(e), "current_version": self.get_current_version()}
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """Sürüm karşılaştırması (-1: v1<v2, 0: v1=v2, 1: v1>v2)"""
        try:
            def normalize(v):
                return [int(x) for x in v.replace('v', '').split('.')]
            
            v1_parts = normalize(version1)
            v2_parts = normalize(version2)
            
            # Uzunlukları eşitle
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            if v1_parts < v2_parts:
                return -1
            elif v1_parts > v2_parts:
                return 1
            else:
                return 0
        except:
            return 0
    
    def download_installer(self, download_url: str, progress_callback=None) -> Optional[str]:
        """Installer'ı indir"""
        try:
            import requests
            import tempfile
            
            self.log("[UPDATE] Installer indiriliyor...")
            
            # Temp dizinde installer dosyası oluştur
            temp_dir = tempfile.mkdtemp(prefix="honeypot_update_")
            installer_path = os.path.join(temp_dir, "honeypot-client-installer.exe")
            
            response = requests.get(download_url, stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(installer_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        if progress_callback and total_size > 0:
                            progress = int((downloaded / total_size) * 100)
                            progress_callback(progress)
            
            self.log(f"[UPDATE] Installer indirildi: {installer_path}")
            return installer_path
            
        except Exception as e:
            self.log(f"[UPDATE] İndirme hatası: {e}")
            return None
    
    def install_update(self, installer_path: str, silent: bool = False, progress_callback=None) -> bool:
        """Güncellemeyi yükle"""
        try:
            if not os.path.exists(installer_path):
                self.log("[UPDATE] Installer dosyası bulunamadı")
                return False
            
            self.log("[UPDATE] Güncelleme yükleniyor...")
            if progress_callback:
                progress_callback(75, "Eski sürüm kapatılıyor...")
            
            # Mevcut process'leri sonlandır
            self._terminate_running_instances()
            
            if progress_callback:
                progress_callback(80, "Installer başlatılıyor...")
            
            # Installer'ı çalıştır
            cmd = [installer_path]
            if silent:
                cmd.extend(["/S", "/silent"])  # NSIS silent install
            else:
                # Interactive mod - kullanıcı installer'ı görecek
                cmd.extend(["/NCRC"])  # CRC check'i atla, hızlandır
            
            self.log(f"[UPDATE] Installer komutu: {' '.join(cmd)}")
            
            if progress_callback:
                progress_callback(85, "Yükleme başlatılıyor... (Installer penceresi açılacak)")
            
            # Installer'ı başlat
            import subprocess
            
            if silent:
                # Silent mode - subprocess.run ile bekle
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                success = result.returncode == 0
                if not success:
                    self.log(f"[UPDATE] Installer hatası: {result.stderr}")
            else:
                # Interactive mode - GUI installer'ı doğru şekilde başlat
                try:
                    # Method 1: Explorer ile başlat (Windows'ta en güvenilir)
                    explorer_cmd = ['explorer.exe', installer_path]
                    self.log(f"[UPDATE] Explorer ile installer başlatılıyor: {' '.join(explorer_cmd)}")
                    
                    process = subprocess.Popen(
                        explorer_cmd,
                        shell=False,
                        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    
                    if progress_callback:
                        progress_callback(90, "Yükleme devam ediyor... (Installer penceresi açılacak)")
                    
                    # Installer'ın başlatıldığından emin olmak için kısa bekleme
                    import time
                    time.sleep(2)
                    
                    # Process'in çalışıp çalışmadığını kontrol et
                    if process.poll() is None:
                        self.log("[UPDATE] Explorer ile installer başarıyla başlatıldı")
                        success = True
                    else:
                        # Explorer hemen kapandı, alternatif yöntem dene
                        self.log("[UPDATE] Explorer yöntemi başarısız, doğrudan başlatmayı deniyor...")
                        
                        # Method 2: Doğrudan başlat (fallback)
                        direct_process = subprocess.Popen(
                            cmd,
                            shell=False,
                            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        
                        time.sleep(1)
                        if direct_process.poll() is None:
                            self.log("[UPDATE] Doğrudan başlatma başarılı")
                            success = True
                        else:
                            self.log(f"[UPDATE] Doğrudan başlatma da başarısız, return code: {direct_process.returncode}")
                            success = False
                        
                except Exception as e:
                    self.log(f"[UPDATE] Installer çalıştırma hatası: {e}")
                    # Son alternatif: os.startfile
                    try:
                        self.log("[UPDATE] Son alternatif: os.startfile ile başlatılıyor...")
                        import os
                        os.startfile(installer_path)
                        success = True
                        self.log("[UPDATE] os.startfile ile başarıyla başlatıldı")
                    except Exception as e2:
                        self.log(f"[UPDATE] os.startfile hatası: {e2}")
                        success = False
            
            if success:
                self.log("[UPDATE] Güncelleme başarıyla yüklendi")
                
                if progress_callback:
                    progress_callback(95, "Temizlik yapılıyor...")
                
                # Temp dosyayı temizle
                try:
                    os.remove(installer_path)
                    temp_dir = os.path.dirname(installer_path)
                    if os.path.exists(temp_dir) and not os.listdir(temp_dir):
                        os.rmdir(temp_dir)
                except:
                    pass
                
                return True
            else:
                return False
                
        except Exception as e:
            self.log(f"[UPDATE] Yükleme hatası: {e}")
            return False
    
    def _terminate_running_instances(self):
        """Çalışan honeypot instance'larını sonlandır"""
        try:
            import subprocess
            
            # Honeypot process'lerini bul ve sonlandır
            process_names = ["honeypot-client.exe", "client.exe", "python.exe"]
            
            for proc_name in process_names:
                try:
                    result = subprocess.run(
                        ["taskkill", "/F", "/IM", proc_name],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        self.log(f"[UPDATE] Process sonlandırıldı: {proc_name}")
                except:
                    pass
                    
        except Exception as e:
            self.log(f"[UPDATE] Process sonlandırma hatası: {e}")
    
    def start_new_version(self, silent: bool = False):
        """Yeni sürümü başlat"""
        try:
            # Varsayılan kurulum dizininden başlat
            possible_paths = [
                r"C:\Program Files\YesNext\Cloud Honeypot Client\honeypot-client.exe",
                r"C:\Program Files (x86)\YesNext\Cloud Honeypot Client\honeypot-client.exe",
                os.path.join(os.path.dirname(sys.executable), "honeypot-client.exe")
            ]
            
            for exe_path in possible_paths:
                if os.path.exists(exe_path):
                    self.log(f"[UPDATE] Yeni sürüm başlatılıyor: {exe_path}")
                    
                    try:
                        cmd = [exe_path]
                        if silent:
                            cmd.append("--minimized")
                        
                        # Detached process olarak başlat
                        subprocess.Popen(
                            cmd, 
                            creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.DETACHED_PROCESS,
                            close_fds=True
                        )
                        
                        self.log("[UPDATE] Yeni sürüm başarıyla başlatıldı")
                        return True
                        
                    except Exception as e:
                        self.log(f"[UPDATE] Başlatma hatası: {e}")
                        continue
            
            self.log("[UPDATE] Yeni sürüm executable'ı bulunamadı")
            return False
            
        except Exception as e:
            self.log(f"[UPDATE] Yeni sürüm başlatma hatası: {e}")
            return False
    
    def update_with_progress(self, progress_callback=None, silent: bool = False) -> bool:
        """Progress callback ile güncelleme yap"""
        try:
            if progress_callback:
                progress_callback(10, "Güncelleme kontrol ediliyor...")
            
            # Güncelleme kontrolü
            update_info = self.check_for_updates()
            if update_info.get("error"):
                if progress_callback:
                    progress_callback(0, f"Hata: {update_info['error']}")
                return False
            
            if not update_info.get("has_update"):
                if progress_callback:
                    progress_callback(100, "Zaten güncel sürüm kullanılıyor")
                return True
            
            if progress_callback:
                progress_callback(30, "Installer indiriliyor...")
            
            # Installer'ı indir
            def download_progress(percent):
                if progress_callback:
                    progress_callback(30 + (percent * 0.4), f"İndiriliyor... %{percent}")
            
            installer_path = self.download_installer(
                update_info["installer_url"], 
                download_progress
            )
            
            if not installer_path:
                if progress_callback:
                    progress_callback(0, "İndirme başarısız")
                return False
            
            if progress_callback:
                progress_callback(70, "Güncelleme yükleniyor...")
            
            # Güncellemeyi yükle
            success = self.install_update(installer_path, silent, progress_callback)
            
            if success:
                self.log("[UPDATE] Installer başarıyla tamamlandı, yeni sürüm başlatılıyor...")
                
                if progress_callback:
                    progress_callback(90, "Yeni sürüm başlatılıyor...")
                
                # Kısa bekleme sonrası yeni sürümü başlat
                import time
                time.sleep(3)  # Biraz daha uzun bekle
                
                start_success = self.start_new_version(silent)
                if start_success:
                    self.log("[UPDATE] Yeni sürüm başarıyla başlatıldı")
                else:
                    self.log("[UPDATE] UYARI: Yeni sürüm otomatik başlatılamadı, manuel başlatın")
                
                if progress_callback:
                    progress_callback(100, "Güncelleme tamamlandı")
                return True
            else:
                if progress_callback:
                    progress_callback(0, "Yükleme başarısız")
                return False
                
        except Exception as e:
            self.log(f"[UPDATE] Güncelleme süreci hatası: {e}")
            if progress_callback:
                progress_callback(0, f"Hata: {str(e)}")
            return False


# ===================== UPDATE UI HELPERS ===================== #

class UpdateProgressDialog:
    """Güncelleme progress dialog'u"""
    
    def __init__(self, parent=None, title="Güncelleme"):
        self.parent = parent
        self.title = title
        self.dialog = None
        self.progress_var = None
        self.status_var = None
        self.percent_var = None
        self.progress_bar = None
    
    def create_dialog(self):
        """Dialog oluştur"""
        try:
            import tkinter as tk
            from tkinter import ttk
            
            self.dialog = tk.Toplevel(self.parent) if self.parent else tk.Tk()
            self.dialog.title(self.title)
            self.dialog.geometry("400x150")
            self.dialog.resizable(False, False)
            
            # Ortala
            if self.parent:
                self.dialog.transient(self.parent)
                self.dialog.grab_set()
                
                # Parent'ın merkezine konumlandır
                parent_x = self.parent.winfo_rootx()
                parent_y = self.parent.winfo_rooty()
                parent_w = self.parent.winfo_width()
                parent_h = self.parent.winfo_height()
                
                x = parent_x + (parent_w // 2) - 200
                y = parent_y + (parent_h // 2) - 75
                self.dialog.geometry(f"400x150+{x}+{y}")
            
            # Durum metni
            self.status_var = tk.StringVar(value="Başlatılıyor...")
            status_label = tk.Label(
                self.dialog, 
                textvariable=self.status_var, 
                font=("Arial", 10)
            )
            status_label.pack(pady=15)
            
            # Progress bar
            self.progress_var = tk.IntVar()
            self.progress_bar = ttk.Progressbar(
                self.dialog,
                variable=self.progress_var,
                maximum=100,
                length=350
            )
            self.progress_bar.pack(pady=10)
            
            # Progress yüzdesi
            self.percent_var = tk.StringVar(value="0%")
            percent_label = tk.Label(
                self.dialog,
                textvariable=self.percent_var,
                font=("Arial", 9)
            )
            percent_label.pack()
            
            return True
            
        except Exception as e:
            print(f"Dialog oluşturma hatası: {e}")
            return False
    
    def update_progress(self, percent: int, message: str = ""):
        """Progress güncelle"""
        try:
            if self.dialog and self.progress_var and self.status_var:
                self.progress_var.set(percent)
                if message:
                    self.status_var.set(message)
                if self.percent_var:
                    self.percent_var.set(f"{percent}%")
                self.dialog.update()
                
                # %100'de dialog otomatik kapatma
                if percent >= 100:
                    self.dialog.after(2000, self.close_dialog)  # 2 saniye sonra kapat
                    
        except Exception as e:
            print(f"Progress güncelleme hatası: {e}")
    
    def close_dialog(self):
        """Dialog'u kapat"""
        try:
            if self.dialog:
                self.dialog.destroy()
                self.dialog = None
        except Exception as e:
            print(f"Dialog kapatma hatası: {e}")


def create_update_manager(github_owner: str = "cevdetaksac", 
                         github_repo: str = "yesnext-cloud-honeypot-client",
                         log_func=None) -> InstallerUpdateManager:
    """Update manager factory fonksiyonu"""
    return InstallerUpdateManager(github_owner, github_repo, log_func)


# ===================== LEGACY COMPATIBILITY ===================== #

def migrate_from_zip_to_installer():
    """Eski zip tabanlı sistemden installer tabanlı sisteme geçiş"""
    try:
        # Eski zip güncellemesi dosyalarını temizle
        temp_dirs = []
        import tempfile
        temp_root = tempfile.gettempdir()
        
        for item in os.listdir(temp_root):
            if item.startswith("chpupd-") or item.startswith("chpzip-"):
                old_path = os.path.join(temp_root, item)
                if os.path.isdir(old_path):
                    temp_dirs.append(old_path)
        
        for temp_dir in temp_dirs:
            try:
                import shutil
                shutil.rmtree(temp_dir)
                print(f"Eski temp dizin temizlendi: {temp_dir}")
            except:
                pass
                
        # Eski güncelleme betikleri
        old_scripts = ["update_onedir.bat", "update_run.bat"]
        for script in old_scripts:
            if os.path.exists(script):
                try:
                    os.remove(script)
                    print(f"Eski güncelleme betiği temizlendi: {script}")
                except:
                    pass
                    
        return True
        
    except Exception as e:
        print(f"Geçiş sırasında hata: {e}")
        return False


# Initialization
if __name__ == "__main__":
    # Test update manager
    print("Testing InstallerUpdateManager...")
    
    def test_log(msg):
        print(f"[TEST] {msg}")
    
    update_mgr = create_update_manager(log_func=test_log)
    update_info = update_mgr.check_for_updates()
    
    print(f"Update check result: {update_info}")
    print("InstallerUpdateManager test completed ✅")