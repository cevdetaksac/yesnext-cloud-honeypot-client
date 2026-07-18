"""
Cloud Honeypot Client - Utilities Module
Yardımcı fonksiyonlar ve araçlar modülü
"""

import os
import sys
import json
import hashlib
import socket
import time
import struct
import tempfile
import ctypes
import ctypes.wintypes as wintypes
import subprocess
from typing import Dict, Any, Optional

def get_resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller.

    Priority order:
    1. Exe directory (NSIS installer copies updated files here)
    2. PyInstaller temp (_MEIPASS bundle)
    3. Current working directory (dev mode)
    """
    # 1) Exe (installer) dizini — NSIS güncellenen dosyayı buraya koyar
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    exe_path = os.path.join(exe_dir, relative_path)
    if os.path.exists(exe_path) and hasattr(sys, '_MEIPASS'):
        return exe_path

    # 2) PyInstaller bundle (_MEIPASS)
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    full_path = os.path.join(base_path, relative_path)

    # 3) Fallback: current working directory
    if not os.path.exists(full_path):
        fallback_path = os.path.join(os.path.abspath("."), relative_path)
        if os.path.exists(fallback_path):
            return fallback_path

    return full_path

class SystemUtils:
    """Sistem yardımcıları"""
    
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

def load_i18n(lang_file: str = "client_lang.json", language: str = "tr") -> dict:
    """Load all language data from JSON file.

    İki kaynaktan okur ve merge eder (installer güncellemelerini garantile):
    1. Exe (installer) dizinindeki dosya
    2. PyInstaller bundle (_MEIPASS) içindeki dosya
    Exe dizinindeki dosya daha güncel olabilir, öncelik ona verilir.
    """
    all_languages: dict = {"tr": {}, "en": {}}

    def _load_from(path: str) -> dict:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            print(f"[LANG] Error loading {path}: {e}")
        return {}

    # 1) PyInstaller bundle'dan yükle (base)
    try:
        meipass = sys._MEIPASS
        bundle_path = os.path.join(meipass, lang_file)
        base = _load_from(bundle_path)
        if base:
            for lang_code in base:
                if isinstance(base[lang_code], dict):
                    all_languages.setdefault(lang_code, {}).update(base[lang_code])
            print(f"[LANG] Base loaded from bundle: {bundle_path}")
    except AttributeError:
        pass  # Not running from PyInstaller

    # 2) Exe (installer) dizininden yükle (override) — en güncel
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    exe_path = os.path.join(exe_dir, lang_file)
    exe_data = _load_from(exe_path)
    if exe_data:
        for lang_code in exe_data:
            if isinstance(exe_data[lang_code], dict):
                all_languages.setdefault(lang_code, {}).update(exe_data[lang_code])
        print(f"[LANG] Override loaded from exe dir: {exe_path}")

    # 3) Fallback: resolved path (dev mode / cwd)
    if not exe_data and not any(all_languages.get(lc) for lc in all_languages):
        resolved = get_resource_path(lang_file)
        fallback = _load_from(resolved)
        if fallback:
            all_languages = fallback
            print(f"[LANG] Fallback loaded from: {resolved}")

    print(f"[LANG] Available languages: {list(all_languages.keys())}")
    tr_count = len(all_languages.get("tr", {}))
    en_count = len(all_languages.get("en", {}))
    print(f"[LANG] Key counts — TR: {tr_count}, EN: {en_count}")
    return all_languages

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
    def save(token: str, token_file_new: str, overwrite: bool = False):
        """Persist token with DPAPI. By default refuses to replace a different existing token."""
        try:
            token = (token or "").strip()
            if not token:
                return
            parent = os.path.dirname(token_file_new)
            if parent:
                os.makedirs(parent, exist_ok=True)
            if os.path.isfile(token_file_new) and not overwrite:
                existing = TokenStore.load(token_file_new)
                if existing and existing != token:
                    # Immutable identity: never clobber a different durable token
                    print(
                        f"token save refused: existing identity differs "
                        f"(file={token_file_new})"
                    )
                    return
                if existing and existing == token:
                    return  # already stored
            data = token.encode("utf-8")
            # küçük bir header ile integrity:
            h = hashlib.sha256(data).hexdigest().encode("ascii")
            payload = b"CHP1|" + h + b"|" + data
            enc = TokenStore._crypt_protect(payload)
            # Atomic replace to avoid partial writes during kill/update
            fd, tmp_path = tempfile.mkstemp(
                prefix="token_", suffix=".tmp", dir=parent or None
            )
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(enc)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, token_file_new)
            except Exception:
                try:
                    if os.path.isfile(tmp_path):
                        os.remove(tmp_path)
                except OSError:
                    pass
                raise
        except Exception as e:
            print(f"token save error: {e}")

    @staticmethod
    def load(token_file_new: str) -> Optional[str]:
        try:
            if os.path.exists(token_file_new):
                enc = open(token_file_new, "rb").read()
                if not enc:
                    return None
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
    def migrate_from_plain(
        token_file_old: str,
        token_file_new: str,
        only_if_missing: bool = True,
    ):
        try:
            if only_if_missing and TokenStore.load(token_file_new):
                # Still remove plaintext leftover if present
                if os.path.exists(token_file_old):
                    try:
                        os.remove(token_file_old)
                    except Exception:
                        pass
                return
            if os.path.exists(token_file_old):
                token = open(token_file_old, "r", encoding="utf-8").read().strip()
                if token:
                    TokenStore.save(token, token_file_new, overwrite=False)
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
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                return s.connect_ex(('127.0.0.1', int(port))) == 0
        except Exception:
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
                                  capture_output=True, text=True, timeout=5,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
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

def watchdog_main(parent_pid: int, log_func=None):
    """Watchdog ana fonksiyonu - process izleme ve yeniden başlatma"""
    if log_func is None:
        log_func = print
        
    attempts = 0
    max_attempts = 5
    
    # Check for installer stop flags at multiple locations
    def check_stop_flag():
        """Check if installer has requested watchdog to stop"""
        stop_locations = [
            os.path.join(os.environ.get('TEMP', ''), 'honeypot_watchdog_token.txt'),
            os.path.join(os.environ.get('APPDATA', ''), 'YesNext', 'CloudHoneypot', 'watchdog_token.txt'),
            os.path.join(os.environ.get('APPDATA', ''), 'YesNext', 'CloudHoneypotClient', 'watchdog.token'),
            os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 'YesNext', 'CloudHoneypot', 'watchdog_stop.flag'),
        ]
        for loc in stop_locations:
            try:
                if os.path.exists(loc):
                    with open(loc, 'r') as f:
                        content = f.read().strip().lower()
                        if content == 'stop':
                            log_func(f"[watchdog] Stop flag found at {loc}, exiting")
                            return True
            except:
                pass
        return False
    
    while attempts < max_attempts:
        time.sleep(5)
        
        # Check stop flags (installer places these)
        if check_stop_flag():
            return
        
        # Watchdog token kontrolü (eski yöntem)
        token = read_watchdog_token("")
        if token.lower() == 'stop':
            return
            
        # Parent process kontrolü
        alive = is_process_running_windows(int(parent_pid))
        if not alive:
            # Before restarting, check stop flags again
            if check_stop_flag():
                return
            
            log_func(f"[watchdog] Parent process {parent_pid} not found, attempting restart")
            attempts += 1
            
            try:
                # Yeni instance başlat
                if getattr(sys, 'frozen', False):
                    subprocess.Popen([sys.executable], shell=False,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    subprocess.Popen([sys.executable, os.path.abspath(sys.argv[0])], shell=False,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
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

# Default application configuration — single source of truth
DEFAULT_CONFIG: dict = {
    "application": {
        "name": "Cloud Honeypot Client",
        "version": "0.0.0",
        "author": "YesNext Technology"
    },
    "language": {
        "selected": "en",
        "selected_by_user": False,
        "available_languages": ["tr", "en"],
        "default": "en"
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
    "services": {
        "auto_start": False,
        "rdp_port": 53389,
        "honeypots": [
            {"port": 3389, "service": "RDP", "enabled": True},
            {"port": 1433, "service": "MSSQL", "enabled": False},
            {"port": 3306, "service": "MySQL", "enabled": False},
            {"port": 21, "service": "FTP", "enabled": False},
            {"port": 22, "service": "SSH", "enabled": False}
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

def load_config() -> dict:
    """Load application configuration - single file system"""
    try:
        # Single config file system - no AppData
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
                # Merge with defaults to ensure all keys exist
                return merge_configs(DEFAULT_CONFIG, config)
        else:
            # Create default config file if not exists
            save_config(DEFAULT_CONFIG)
            return DEFAULT_CONFIG.copy()
            
    except Exception as e:
        print(f"[CONFIG] Error loading config: {e}")
        return DEFAULT_CONFIG.copy()

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
    """Get service/port table from configuration file
    
    Returns:
        List[Tuple[str, str]]: Port table in format [(port, service), ...]
    """
    try:
        config = load_config()
        honeypots = config.get("services", {}).get("honeypots", [])
        
        port_table = []
        for svc_cfg in honeypots:
            port = str(svc_cfg.get("port", ""))
            service = str(svc_cfg.get("service", ""))
            
            if port and service:
                port_table.append((port, service))
        
        print(f"[CONFIG] Service table loaded from config: {len(port_table)} entries")
        return port_table
        
    except Exception as e:
        print(f"[CONFIG] Error loading service table: {e}")
        # Fallback to default table
        return [
            ("3389", "-", "RDP"),
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
        return get_config_value("services.rdp_port", 53389)
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
    """Update language configuration (exe config + ProgramData so upgrades keep user choice)."""
    config = load_config()
    if "language" not in config or not isinstance(config["language"], dict):
        config["language"] = {}
    config["language"]["selected"] = language
    config["language"]["selected_by_user"] = selected_by_user
    ok = save_config(config)
    try:
        prefs_dir = os.path.join(
            os.environ.get("ProgramData", r"C:\ProgramData"),
            "YesNext",
            "CloudHoneypotClient",
        )
        os.makedirs(prefs_dir, exist_ok=True)
        prefs_path = os.path.join(prefs_dir, "language_pref.json")
        with open(prefs_path, "w", encoding="utf-8") as fh:
            json.dump(
                {"selected": language, "selected_by_user": bool(selected_by_user)},
                fh,
                ensure_ascii=False,
            )
    except OSError:
        pass
    return ok


def detect_windows_ui_language() -> str:
    """Map Windows UI language to supported app language (tr|en)."""
    try:
        lang_id = int(ctypes.windll.kernel32.GetUserDefaultUILanguage())
        # LANGID primary language: Turkish=0x1F (0x041F)
        if (lang_id & 0xFF) == 0x1F:
            return "tr"
    except Exception:
        pass
    try:
        import locale
        loc = (locale.getdefaultlocale() or (None,))[0] or ""
        if loc.lower().startswith("tr"):
            return "tr"
    except Exception:
        pass
    return "en"


def _load_language_pref() -> Optional[dict]:
    try:
        prefs_path = os.path.join(
            os.environ.get("ProgramData", r"C:\ProgramData"),
            "YesNext",
            "CloudHoneypotClient",
            "language_pref.json",
        )
        if os.path.isfile(prefs_path):
            with open(prefs_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return None


def resolve_app_language() -> str:
    """First run: follow Windows UI language. After user picks a language, keep it across upgrades."""
    try:
        available = ["tr", "en"]
        prefs = _load_language_pref()
        if prefs and prefs.get("selected_by_user") and prefs.get("selected") in available:
            return prefs["selected"]

        config = load_config()
        lang_cfg = config.get("language") or {}
        available = lang_cfg.get("available_languages") or available
        if lang_cfg.get("selected_by_user") and lang_cfg.get("selected") in available:
            # Migrate into ProgramData so next installer overwrite keeps choice
            update_language_config(lang_cfg["selected"], selected_by_user=True)
            return lang_cfg["selected"]

        detected = detect_windows_ui_language()
        if detected not in available:
            detected = "en"
        update_language_config(detected, selected_by_user=False)
        return detected
    except Exception:
        return detect_windows_ui_language()


def _programdata_client_dir() -> str:
    base = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "YesNext",
        "CloudHoneypotClient",
    )
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return base


def _account_link_pref_path() -> str:
    return os.path.join(_programdata_client_dir(), "account_link.json")


def load_account_link_pref() -> dict:
    """Local cache of last known Account link status (API is source of truth when online)."""
    try:
        path = _account_link_pref_path()
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def is_account_linked() -> bool:
    """True when API (or local cache) says this client is linked to a YesNext Account."""
    try:
        data = load_account_link_pref()
        return bool(data.get("linked"))
    except Exception:
        return False


def get_linked_account_email() -> str:
    """Cached account email from last successful API status (may be masked)."""
    try:
        data = load_account_link_pref()
        email = data.get("email") or data.get("email_masked") or ""
        return str(email) if email else ""
    except Exception:
        return ""


def set_account_linked(
    linked: bool = True,
    *,
    source: str = "user",
    email: str = "",
    email_masked: str = "",
    account_id=None,
    raw: Optional[dict] = None,
) -> None:
    """Persist Account↔Client link state (ProgramData cache)."""
    try:
        path = _account_link_pref_path()
        prev = load_account_link_pref()
        payload = {
            "linked": bool(linked),
            "source": source,
            "updated_at": time.time(),
            "email": email or prev.get("email") or "",
            "email_masked": email_masked or prev.get("email_masked") or "",
            "account_id": account_id if account_id is not None else prev.get("account_id"),
        }
        if not linked:
            payload["email"] = email or ""
            payload["email_masked"] = email_masked or ""
            payload["account_id"] = account_id
        if isinstance(raw, dict):
            # Keep a small non-secret snapshot for UI (no tokens/hashes)
            payload["server_name"] = raw.get("server_name") or prev.get("server_name")
            payload["client_id"] = raw.get("client_id") or prev.get("client_id")
            payload["linked_at"] = raw.get("linked_at") or prev.get("linked_at")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
    except OSError:
        pass


def parse_account_link_payload(resp: Optional[dict]) -> Optional[bool]:
    """Extract account_linked from API JSON.

    Returns True/False when the payload explicitly carries link state;
    None when the response has no account-link fields (legacy / unrelated).
    """
    if not isinstance(resp, dict):
        return None
    linked = None
    for key in (
        "account_linked", "linked", "has_account", "is_linked",
        "linked_to_account", "has_account_membership",
    ):
        if key in resp:
            linked = bool(resp.get(key))
            break
    acct = resp.get("account")
    if linked is None and isinstance(acct, dict):
        if acct.get("linked") is False:
            linked = False
        elif acct.get("email") or acct.get("email_masked") or acct.get("id"):
            linked = True
    if linked is None and "accounts" in resp and isinstance(resp.get("accounts"), list):
        linked = len(resp["accounts"]) > 0
    return linked


def apply_account_link_from_payload(resp: Optional[dict], *, source: str = "api") -> Optional[bool]:
    """Update local cache from API payload. Returns linked bool or None if unknown."""
    linked = parse_account_link_payload(resp)
    if linked is None:
        return None
    email = ""
    email_masked = ""
    account_id = None
    acct = resp.get("account") if isinstance(resp, dict) else None
    if isinstance(acct, dict):
        email = str(acct.get("email") or "")
        email_masked = str(acct.get("email_masked") or "")
        account_id = acct.get("id")
    if not email:
        email = str((resp or {}).get("email") or "")
    if not email_masked:
        email_masked = str((resp or {}).get("email_masked") or "")
    set_account_linked(
        linked,
        source=source,
        email=email,
        email_masked=email_masked,
        account_id=account_id,
        raw=resp if isinstance(resp, dict) else None,
    )
    return linked


def refresh_account_link_status(token: str = "", api_client=None) -> Optional[bool]:
    """Ask cloud whether this client token is linked to an Account.

    Source of truth when API answers with account_linked (or equivalent).
    Returns True/False when cloud answers; None when endpoint missing / unknown.
    """
    tok = (token or "").strip()
    if not tok:
        return None
    try:
        resp = None
        if api_client is not None and hasattr(api_client, "get_account_status"):
            resp = api_client.get_account_status(tok)
        elif api_client is not None and hasattr(api_client, "api_request"):
            # Dedicated endpoint first
            resp = api_client.api_request(
                "GET", "agent/account-status",
                params={"token": tok},
                token=tok,
                timeout=8,
                verbose_logging=False,
            )
            # Fallback: client_status may embed account_linked (P1)
            if resp is None or parse_account_link_payload(resp) is None:
                cs = api_client.api_request(
                    "GET", "client_status",
                    params={"token": tok},
                    token=tok,
                    timeout=8,
                    verbose_logging=False,
                )
                if parse_account_link_payload(cs) is not None:
                    resp = cs
        else:
            import requests
            from client_constants import API_URL
            from client_security_utils import resolve_tls_verify
            base = API_URL.rstrip("/")
            for path in ("agent/account-status", "client_status"):
                try:
                    r = requests.get(
                        f"{base}/{path}",
                        params={"token": tok},
                        timeout=8,
                        verify=resolve_tls_verify(),
                    )
                    if r.status_code == 404:
                        # Route missing vs client missing — try next path on bare Not Found
                        try:
                            detail = (r.json() or {}).get("detail", "")
                        except Exception:
                            detail = ""
                        if path == "agent/account-status" and str(detail).lower() in (
                            "not found", "", "none"
                        ):
                            continue
                        if path == "agent/account-status":
                            continue
                        break
                    if 200 <= r.status_code < 300:
                        data = r.json()
                        if path == "client_status" and parse_account_link_payload(data) is None:
                            continue
                        resp = data
                        break
                except Exception:
                    continue
        return apply_account_link_from_payload(resp, source="api")
    except Exception:
        return None


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
        """Mevcut sürümü al — constants'dan (config dosyası eski kalabilir)"""
        try:
            from client_constants import VERSION
            return VERSION
        except ImportError:
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
            
            # Latest version'u saklayalım download için
            self._latest_version = latest_version
            
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
        """Installer'ı Downloads klasörüne sürüm numarası ile indir"""
        try:
            import requests
            import os
            
            self.log("[UPDATE] Installer indiriliyor...")
            
            # Sürüm bilgisini al (URL'den veya update info'dan)
            version = "unknown"
            try:
                if hasattr(self, '_latest_version') and self._latest_version:
                    version = self._latest_version
                else:
                    # URL'den version çıkarmayı dene
                    import re
                    version_match = re.search(r'v?(\d+\.\d+\.\d+)', download_url)
                    if version_match:
                        version = version_match.group(1)
            except:
                pass
            
            # Windows Downloads klasörünü bul
            downloads_dir = os.path.join(os.path.expanduser("~"), "Downloads")
            if not os.path.exists(downloads_dir):
                # Fallback: Desktop
                downloads_dir = os.path.join(os.path.expanduser("~"), "Desktop")
                self.log(f"[UPDATE] Downloads klasörü bulunamadı, Desktop kullanılıyor: {downloads_dir}")
            
            # Sürüm numarası ile dosya adı oluştur
            installer_filename = f"cloud-client-installer-v{version}.exe"
            installer_path = os.path.join(downloads_dir, installer_filename)
            
            self.log(f"[UPDATE] İndirme yeri: {installer_path}")
            
            response = requests.get(download_url, stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(installer_path, 'wb') as f:
                last_touch = time.time()
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)

                        # Keep machine-wide update lock fresh during long downloads
                        now = time.time()
                        if now - last_touch >= 15:
                            last_touch = now
                            try:
                                touch_update_lock()
                            except Exception:
                                pass

                        if progress_callback and total_size > 0:
                            progress = int((downloaded / total_size) * 100)
                            progress_callback(progress)
            
            self.log(f"[UPDATE] Installer başarıyla indirildi: {installer_path}")
            return installer_path
            
        except Exception as e:
            self.log(f"[UPDATE] İndirme hatası: {e}")
            return None
    
    def install_update(
        self,
        installer_path: str,
        silent: bool = False,
        progress_callback=None,
        launch_installer: bool = True,
    ) -> bool:
        """Güncellemeyi yükle. launch_installer=False ise yalnızca dosyayı doğrular."""
        try:
            import os
            if not os.path.exists(installer_path):
                self.log("[UPDATE] Installer dosyası bulunamadı")
                return False

            if not launch_installer:
                file_size = os.path.getsize(installer_path)
                if file_size < 1_000_000:
                    self.log(f"[UPDATE] Installer dosyası çok küçük: {file_size} bytes")
                    return False
                self.log(f"[UPDATE] İndirme tamamlandı ({file_size} bytes) — kurulum kullanıcı onayı bekliyor")
                if progress_callback:
                    progress_callback(100, "İndirme tamamlandı")
                return True
            
            self.log("[UPDATE] Installer başlatma hazırlanıyor...")
            if progress_callback:
                progress_callback(75, "Installer hazırlanıyor...")
            
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
                # Interactive mode - Downloads klasöründeki installer'ı başlat
                success = False
                import time
                
                try:
                    self.log(f"[UPDATE] Interactive installer başlatma - dosya: {installer_path}")
                    
                    # Dosya kontrolü - kritik!
                    if not os.path.exists(installer_path):
                        self.log(f"[UPDATE] ❌ HATA: Installer dosyası bulunamadı: {installer_path}")
                        success = False
                        return success
                    
                    file_size = os.path.getsize(installer_path)
                    if file_size < 1000000:  # 1MB'den küçükse problem var
                        self.log(f"[UPDATE] ❌ HATA: Installer dosyası çok küçük: {file_size} bytes")
                        success = False  
                        return success
                    
                    self.log(f"[UPDATE] ✅ Installer dosyası OK: {file_size} bytes")
                    
                    # Method 1: PowerShell ile admin yetki ile başlat (En güvenilir)
                    try:
                        self.log(f"[UPDATE] PowerShell ile admin yetki ile başlatılıyor...")
                        
                        if progress_callback:
                            progress_callback(85, "Installer admin yetkisi ile başlatılıyor...")
                        
                        import subprocess
                        
                        # PowerShell komutu - installer'ı admin olarak çalıştır
                        ps_command = f'Start-Process -FilePath "{installer_path}" -Verb RunAs -PassThru'
                        
                        result = subprocess.run([
                            'powershell', '-WindowStyle', 'Hidden', '-Command', ps_command
                        ], capture_output=True, text=True, timeout=15)
                        
                        if result.returncode == 0:
                            self.log("[UPDATE] ✅ PowerShell admin start başarılı")
                            
                            # Process kontrolü - installer gerçekten çalışıyor mu?
                            time.sleep(3)  # Installer'ın başlaması için bekle
                            
                            installer_name = os.path.basename(installer_path)
                            tasklist = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {installer_name}'], 
                                                    capture_output=True, text=True, timeout=5,
                                                    creationflags=subprocess.CREATE_NO_WINDOW)
                            
                            if installer_name in tasklist.stdout:
                                self.log("[UPDATE] ✅ Installer process aktif!")
                                success = True
                                if progress_callback:
                                    progress_callback(95, "✅ Installer başlatıldı! UAC onayından sonra kurulum başlayacak.")
                            else:
                                # Kullanıcı UAC'yi reddetti veya başka bir problem
                                self.log("[UPDATE] ⚠️ Installer process bulunamadı - UAC reddedilmiş olabilir")
                                success = True  # Yine de başarılı say, kullanıcı belki daha sonra çalıştırır
                                if progress_callback:
                                    progress_callback(90, "⚠️ UAC onayı gerekiyor - Installer Downloads klasöründe hazır")
                        else:
                            self.log(f"[UPDATE] PowerShell hatası: {result.stderr}")
                            raise Exception("PowerShell admin start failed")
                        
                    except Exception as e:
                        self.log(f"[UPDATE] PowerShell admin start hatası: {e}")
                        
                        # Method 2: Normal os.startfile deneme (fallback)
                        try:
                            self.log("[UPDATE] Fallback: os.startfile ile normal başlatma deneniyor...")
                            
                            if progress_callback:
                                progress_callback(80, "Installer normal mod ile başlatılıyor...")
                            
                            os.startfile(installer_path)
                            time.sleep(2)
                            
                            self.log("[UPDATE] ⚠️ os.startfile çalıştırıldı ama admin yetki gerekebilir")
                            success = True
                            
                            if progress_callback:
                                progress_callback(85, "⚠️ Installer başlatıldı - Manuel admin onayı gerekebilir")
                                
                        except Exception as e2:
                            self.log(f"[UPDATE] os.startfile hatası: {e2}")
                            
                            # Method 3: Explorer ile Downloads klasörünü aç (son çare)
                            try:
                                downloads_dir = os.path.dirname(installer_path)
                                installer_name = os.path.basename(installer_path)
                                
                                self.log(f"[UPDATE] Son çare: Downloads klasörü açılıyor...")
                                
                                if progress_callback:
                                    progress_callback(75, "Downloads klasörü açılıyor...")
                                
                                # Downloads klasörünü aç
                                os.startfile(downloads_dir)
                                
                                success = True  # Klasörü açtık, kullanıcı manuel çalıştırabilir
                                
                                if progress_callback:
                                    progress_callback(80, f"📁 Downloads klasörü açıldı - {installer_name} dosyasını çift tıklayın")
                                
                                self.log(f"[UPDATE] ✅ Downloads klasörü açıldı - kullanıcı {installer_name} dosyasını manuel çalıştırabilir")
                                
                                # Ek bilgi mesajı
                                try:
                                    import tkinter.messagebox as messagebox
                                    messagebox.showwarning(
                                        "Manuel Kurulum Gerekli",
                                        f"Downloads klasörü açıldı!\n\n"
                                        f"📁 Dosya: {installer_name}\n\n"
                                        f"🔧 Kurulum için:\n"
                                        f"1. Dosyaya çift tıklayın\n"
                                        f"2. 'Yönetici olarak çalıştır' seçin\n"
                                        f"3. UAC onayını verin\n\n"
                                        f"Mevcut uygulama şimdi kapanacak."
                                    )
                                except:
                                    pass  # GUI yoksa messagebox çalışmaz
                                    
                            except Exception as e3:
                                self.log(f"[UPDATE] Downloads klasörü açma hatası: {e3}")
                                success = False
                                
                                if progress_callback:
                                    progress_callback(0, f"❌ Installer başlatılamadı - Manuel olarak {installer_path} dosyasını çalıştırın")
                                
                except Exception as main_error:
                    self.log(f"[UPDATE] Ana installer başlatma hatası: {main_error}")
                    success = False
            
            if success:
                self.log("[UPDATE] Güncelleme başarıyla yüklendi")
                
                if progress_callback:
                    progress_callback(95, "Güncelleme tamamlandı")
                
                # Downloads klasöründeki dosyayı silme - kullanıcı manuel çalıştırabilir
                # Sadece temp klasördeyse sil
                if "temp" in installer_path.lower() or "tmp" in installer_path.lower():
                    try:
                        os.remove(installer_path)
                        temp_dir = os.path.dirname(installer_path)
                        if os.path.exists(temp_dir) and not os.listdir(temp_dir):
                            os.rmdir(temp_dir)
                        self.log("[UPDATE] Temp dosyalar temizlendi")
                    except:
                        pass
                else:
                    self.log(f"[UPDATE] Installer Downloads klasöründe korundu: {installer_path}")
                
                return True
            else:
                return False
                
        except Exception as e:
            self.log(f"[UPDATE] Yükleme hatası: {e}")
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
                progress_callback(70, "Güncelleme yükleniyor..." if silent else "İndirme tamamlanıyor...")
            
            # İnteraktif modda yalnızca indir; kurulum kullanıcı dialog'undan başlar
            success = self.install_update(
                installer_path,
                silent,
                progress_callback,
                launch_installer=silent,
            )
            
            if success:
                self.log("[UPDATE] ✅ Installer işlemi tamamlandı!")
                
                if progress_callback:
                    # Daha açık mesaj - kullanıcı ne yapması gerektiğini bilsin
                    downloads_dir = os.path.join(os.path.expanduser("~"), "Downloads")  
                    version = getattr(self, '_latest_version', 'latest')
                    installer_name = f"cloud-client-installer-v{version}.exe"
                    progress_callback(100, f"✅ {installer_name} Downloads klasörüne indirildi. Lütfen çalıştırın.")
                
                # Installer hakkında detaylı bilgi
                self.log(f"[UPDATE] Kullanıcı Downloads klasöründeki installer'ı manuel çalıştırabilir")
                return True
            else:
                self.log("[UPDATE] ❌ Installer başlatılamadı, manuel müdahale gerekli")
                if progress_callback:
                    progress_callback(0, "❌ Installer otomatik başlatılamadı. Downloads klasöründeki .exe dosyasını manuel çalıştırın.")
                return False
                
        except Exception as e:
            self.log(f"[UPDATE] Güncelleme süreci hatası: {e}")
            if progress_callback:
                progress_callback(0, f"Hata: {str(e)}")
            return False


# ===================== UPDATE UI HELPERS ===================== #

def onboarding_flag_path() -> str:
    base = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "YesNext",
        "CloudHoneypotClient",
    )
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return os.path.join(base, "force_gui_onboarding.flag")


def set_force_gui_onboarding(reason: str = "interactive_install") -> None:
    """After non-silent install — keep window visible until user registers/links."""
    try:
        with open(onboarding_flag_path(), "w", encoding="utf-8") as fh:
            fh.write(f"{reason}\n{time.time()}\n")
    except OSError:
        pass


def clear_force_gui_onboarding() -> None:
    try:
        path = onboarding_flag_path()
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def should_force_gui_visible(has_token: bool = False) -> bool:
    """True only while this machine has no durable agent token yet.

    Once a token exists, onboarding is done — allow minimize-to-tray and clear
    any stale force_gui_onboarding.flag (otherwise close-to-tray stays blocked forever).
    """
    if has_token:
        clear_force_gui_onboarding()
        return False
    try:
        if os.path.isfile(onboarding_flag_path()):
            return True
    except OSError:
        pass
    # No token yet → keep window visible for first registration
    return True


def _update_lock_path() -> str:
    """Machine-wide lock — SYSTEM SilentUpdater and user GUI must share the same file.

    Previous APPDATA path failed: interactive download locked user profile, while
    CloudHoneypot-SilentUpdater (S-1-5-18) looked at SystemProfile AppData → race kill.
    """
    base = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "YesNext",
        "CloudHoneypotClient",
    )
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return os.path.join(base, "update_in_progress.lock")


def acquire_update_lock(reason: str = "interactive") -> bool:
    """Mark that an update download/install is in progress (all sessions)."""
    try:
        path = _update_lock_path()
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"{reason}\n{os.getpid()}\n{time.time()}\n")
        return True
    except OSError:
        return False


def touch_update_lock() -> None:
    """Heartbeat during long downloads so lock is never treated as stale."""
    try:
        path = _update_lock_path()
        if os.path.isfile(path):
            os.utime(path, None)
            return
        acquire_update_lock("heartbeat")
    except OSError:
        pass


def is_update_in_progress(max_age_sec: float = 7200.0) -> bool:
    """True if update lock exists and is not stale."""
    try:
        path = _update_lock_path()
        if not os.path.isfile(path):
            # Migrate: also honour legacy per-user lock if present
            legacy = os.path.join(
                os.environ.get("APPDATA", os.path.expanduser("~")),
                "YesNext", "CloudHoneypotClient", "update_in_progress.lock",
            )
            if os.path.isfile(legacy):
                path = legacy
            else:
                return False
        age = time.time() - os.path.getmtime(path)
        if age > max_age_sec:
            try:
                os.remove(path)
            except OSError:
                pass
            return False
        return True
    except OSError:
        return False


def pause_competing_updaters() -> None:
    """Stop scheduled tasks that kill/restart the client mid-download."""
    import subprocess

    for task in (
        "CloudHoneypot-SilentUpdater",
        "CloudHoneypot-Updater",
        "CloudHoneypot-MemoryRestart",
        "CloudHoneypot-Watchdog",
    ):
        try:
            subprocess.run(
                ["schtasks", "/end", "/tn", task],
                capture_output=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            subprocess.run(
                ["schtasks", "/change", "/tn", task, "/disable"],
                capture_output=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            pass


def resume_competing_updaters() -> None:
    """Re-enable updater/watchdog tasks after interactive download ends without install."""
    import subprocess

    for task in (
        "CloudHoneypot-SilentUpdater",
        "CloudHoneypot-Updater",
        "CloudHoneypot-MemoryRestart",
        "CloudHoneypot-Watchdog",
    ):
        try:
            subprocess.run(
                ["schtasks", "/change", "/tn", task, "/enable"],
                capture_output=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            pass


def release_update_lock(*, resume_updaters: bool = True) -> None:
    """Clear interactive update lock."""
    try:
        path = _update_lock_path()
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass
    if resume_updaters:
        try:
            resume_competing_updaters()
        except Exception:
            pass


def prepare_client_for_installer(*, kill_processes: bool = True) -> None:
    """Installer öncesi watchdog/self-protect yeniden başlatmayı engelle.

    kill_processes=False: sadece görevleri durdur/devre dışı bırak (indirme sırasında kullanma).
    kill_processes=True: QUIT + kill-honeypot (yalnızca installer başlatılırken).
    Prefer launch_safe_update_install() for interactive/silent updates — it runs
    elevated and waits for a clean process exit before overwriting the onefile EXE.
    """
    import socket
    import subprocess

    # Always disarm self-protect on THIS process first (DACL + Guard).
    # Without this, update helpers cannot close the client reliably.
    try:
        from client_self_protection import disarm_for_update
        disarm_for_update(reason="prepare_client_for_installer")
    except Exception:
        pass

    flag_paths = [
        os.path.join(os.environ.get("TEMP", ""), "honeypot_watchdog_token.txt"),
        os.path.join(os.environ.get("APPDATA", ""), "YesNext", "CloudHoneypot", "watchdog_token.txt"),
        os.path.join(os.environ.get("APPDATA", ""), "YesNext", "CloudHoneypotClient", "watchdog.token"),
        os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "YesNext", "CloudHoneypot", "watchdog_stop.flag"),
    ]
    for path in flag_paths:
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("stop")
        except OSError:
            pass

    for task in (
        "CloudHoneypot-Background",
        "CloudHoneypot-Tray",
        "CloudHoneypot-Watchdog",
        "CloudHoneypot-Updater",
        "CloudHoneypot-SilentUpdater",
        "CloudHoneypot-MemoryRestart",
        "HoneypotClientGuard",
    ):
        try:
            subprocess.run(
                ["schtasks", "/end", "/tn", task],
                capture_output=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            subprocess.run(
                ["schtasks", "/change", "/tn", task, "/disable"],
                capture_output=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            pass

    if not kill_processes:
        return

    # Graceful QUIT via control socket (process exits itself → DACL bypass)
    try:
        with socket.create_connection(("127.0.0.1", 58632), timeout=0.8) as sock:
            sock.sendall(b"QUIT\n")
    except Exception:
        pass

    # Prefer dedicated kill script when available (SeDebugPrivilege)
    # -Force: we already finished download / are installing — lock may still say "download"
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "kill-honeypot.ps1")
    if os.path.isfile(script):
        try:
            # Mark lock as installing so kill script (and parallel tasks) know kill is intentional
            try:
                acquire_update_lock("installing")
            except Exception:
                pass
            subprocess.run(
                [
                    "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", script, "-Force",
                ],
                capture_output=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception:
            pass


def _update_helper_staging_dir() -> str:
    base = os.path.join(
        os.environ.get("ProgramData", r"C:\ProgramData"),
        "YesNext",
        "CloudHoneypotClient",
        "update",
    )
    os.makedirs(base, exist_ok=True)
    return base


def stage_update_install_helper() -> Optional[str]:
    """Copy update-and-install.ps1 to ProgramData so INSTDIR overwrite cannot break it."""
    import shutil

    src_candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "update-and-install.ps1"),
    ]
    if getattr(sys, "frozen", False):
        src_candidates.insert(
            0,
            os.path.join(os.path.dirname(sys.executable), "scripts", "update-and-install.ps1"),
        )
        try:
            mei = getattr(sys, "_MEIPASS", "") or ""
            if mei:
                src_candidates.insert(0, os.path.join(mei, "scripts", "update-and-install.ps1"))
        except Exception:
            pass

    src = next((p for p in src_candidates if os.path.isfile(p)), None)
    if not src:
        return None
    dst = os.path.join(_update_helper_staging_dir(), "update-and-install.ps1")
    try:
        shutil.copy2(src, dst)
        return dst
    except OSError:
        return src if os.path.isfile(src) else None


def _shell_execute_runas(file_path: str, params: str = "", *, show_cmd: int = 0) -> int:
    """ShellExecuteW runas. Returns >32 on success, 1223 if UAC cancelled, else error code."""
    try:
        rc = int(
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                file_path,
                params or None,
                None,
                int(show_cmd),
            )
        )
        return rc
    except Exception:
        return 0


def launch_safe_update_install(
    installer_path: str,
    *,
    silent: bool = False,
    show_gui_after: bool = True,
    expect_exit_pid: Optional[int] = None,
    elevate: bool = True,
    grace_wait_sec: int = 20,
) -> bool:
    """Start elevated update helper (detached). Caller should then exit quickly.

    Interactive path uses ShellExecuteW runas so the UAC prompt is visible (hidden
    CREATE_NO_WINDOW parents often swallow/skip UAC and the installer never starts).

    The helper waits for expect_exit_pid, force-kills leftovers, runs the installer,
    then starts the new app.
    """
    import subprocess

    if not installer_path or not os.path.isfile(installer_path):
        return False

    helper = stage_update_install_helper()
    if not helper:
        return False

    # Always re-stage helper from package so older ProgramData copies are refreshed
    pid = int(expect_exit_pid if expect_exit_pid is not None else os.getpid())
    already_admin = False
    try:
        already_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        already_admin = False
    if elevate:
        elevate = not already_admin

    acquire_update_lock("installing")
    # Stop respawn tasks only. Do NOT QUIT this process here — that raced with
    # ShellExecute/Popen and aborted interactive installs before the helper started.
    prepare_client_for_installer(kill_processes=False)

    staging = _update_helper_staging_dir()
    launcher = os.path.join(staging, f"run-update-{pid}.ps1")
    flags = []
    if silent:
        flags.append("-Silent")
    if show_gui_after:
        flags.append("-ShowGuiAfter")
    flag_str = " ".join(flags)
    # Escape single quotes in paths for PowerShell single-quoted strings
    helper_q = helper.replace("'", "''")
    installer_q = installer_path.replace("'", "''")
    grace = max(8, int(grace_wait_sec))
    launcher_body = (
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        f"& '{helper_q}' -InstallerPath '{installer_q}' "
        f"-ExpectExitPid {pid} -GraceWaitSec {grace} -KillRounds 4 {flag_str}\n"
        "exit $LASTEXITCODE\n"
    )
    try:
        # ASCII-friendly write; BOM-less UTF-8 is fine for this launcher
        with open(launcher, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(launcher_body)
    except OSError:
        return False

    try:
        if elevate:
            # Interactive: ShellExecute runas from this process (has desktop/GUI affinity)
            # so UAC is visible. Hidden powershell parents often fail to show UAC.
            params = f'-NoProfile -ExecutionPolicy Bypass -File "{launcher}"'
            rc = _shell_execute_runas("powershell.exe", params, show_cmd=0)  # SW_HIDE after consent
            if rc == 1223:
                # User cancelled UAC
                try:
                    release_update_lock()
                except Exception:
                    pass
                return False
            if rc <= 32:
                # Fallback: Start-Process -Verb RunAs (visible)
                ps = (
                    "Start-Process -FilePath 'powershell.exe' -Verb RunAs "
                    f"-ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"{launcher}\"' "
                    "-Wait:$false"
                )
                subprocess.Popen(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
                    creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0x00000010),
                    close_fds=True,
                )
            return True

        # Already admin / silent SYSTEM path
        subprocess.Popen(
            [
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", launcher,
            ],
            creationflags=subprocess.CREATE_NO_WINDOW
            | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200),
            close_fds=True,
        )
        return True
    except Exception:
        try:
            release_update_lock()
        except Exception:
            pass
        return False


def launch_installer_elevated_fallback(installer_path: str) -> bool:
    """Open NSIS installer with a visible window (UAC if needed)."""
    if not installer_path or not os.path.isfile(installer_path):
        return False
    try:
        already_admin = False
        try:
            already_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            already_admin = False

        if already_admin:
            # Visible; no UAC. DETACHED so it survives our upcoming exit.
            subprocess.Popen(
                [installer_path],
                cwd=os.path.dirname(installer_path) or None,
                close_fds=True,
                creationflags=getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200),
            )
            return True

        rc = _shell_execute_runas(installer_path, "", show_cmd=1)  # SW_SHOWNORMAL
        if rc == 1223:
            return False
        if rc > 32:
            return True
        # Fallback Start-Process -Verb RunAs
        q = installer_path.replace("'", "''")
        subprocess.Popen(
            [
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-Command",
                f"Start-Process -FilePath '{q}' -Verb RunAs",
            ],
            creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0x00000010),
            close_fds=True,
        )
        return True
    except Exception:
        return False


def launch_interactive_installer_and_exit_prep(installer_path: str) -> bool:
    """Interactive update: open NSIS now (visible), do NOT QUIT-self before launch.

    NSIS PreInstallKill handles leftover processes. Returning True means caller
    should exit the client shortly so the onefile EXE can be overwritten.
    """
    if not installer_path or not os.path.isfile(installer_path):
        return False
    try:
        acquire_update_lock("installing")
    except Exception:
        pass
    # Stop respawners only — do not QUIT ourselves here (that raced and aborted launch)
    try:
        prepare_client_for_installer(kill_processes=False)
    except Exception:
        pass
    return launch_installer_elevated_fallback(installer_path)


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

            self.dialog.update_idletasks()
            self.dialog.lift()
            self.dialog.attributes("-topmost", True)
            self.dialog.after(250, lambda: self.dialog.attributes("-topmost", False))
            
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