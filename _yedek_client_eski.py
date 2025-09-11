# -*- coding: utf-8 -*-
import os, sys, socket, ssl, threading, time, json, subprocess, ctypes, tempfile
import tkinter as tk
from tkinter import ttk, messagebox
import requests, webbrowser, logging, struct, hashlib, argparse
from ctypes import wintypes
import winreg
from typing import Optional, Union, Dict, Any
import firewall_agent as FW_AGENT

# Desteklenen tüneller ve varsayılan portları
DEFAULT_TUNNELS = {
    "RDP": {"listen_port": 3389},
    "MSSQL": {"listen_port": 1433}, 
    "MYSQL": {"listen_port": 3306},
    "FTP": {"listen_port": 21},
    "SSH": {"listen_port": 22},
}

# ===================== KURULUM & SABİTLER ===================== #
TEST_MODE = 0  # 1=log only, 0=real
__version__ = "2.0.0"

GITHUB_OWNER = "cevdetaksac"
GITHUB_REPO  = "yesnext-cloud-honeypot-client"
API_URL = "https://honeypot.yesnext.com.tr/api"
HONEYPOT_IP = "194.5.236.181"
HONEYPOT_TUNNEL_PORT = 4443

SERVER_NAME = socket.gethostname()
RECV_SIZE = 65536
CONNECT_TIMEOUT = 8

# Tek-instance kontrol portu (localhost)
CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 58632  # sabit yüksek port

# Uygulama sabitleri
APP_NAME = "Cloud Honeypot Client"
APP_STARTUP_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

# GUI Sabitler
WINDOW_WIDTH = 800
WINDOW_HEIGHT = 650
WINDOW_TITLE = APP_NAME

# Tray opsiyonel
TRY_TRAY = True
try:
    import pystray
    from pystray import MenuItem as TrayItem
    from PIL import Image, ImageDraw
except Exception:
                    pass

# ===================== UYGULAMA DİZİNİ ===================== #
def appdata_dir() -> str:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    path = os.path.join(base, "YesNext", "CloudHoneypotClient")
    os.makedirs(path, exist_ok=True)
    return path

def set_autostart(enable: bool = True):
    # Uygulamayı Windows başlangıcına ekler veya kaldırır
    try:
        executable = sys.executable
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, APP_STARTUP_KEY, 0, 
                           winreg.KEY_WRITE | winreg.KEY_READ) as key:
            if enable:
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, f'"{executable}"')
                log(f"Autostart enabled: {executable}")
            else:
                winreg.DeleteValue(key, APP_NAME)
                log("Autostart disabled")
    except Exception as e:
        LOGGER.error(f"Failed to set autostart: {e}")
        return False
    return True

LOG_FILE        = os.path.join(appdata_dir(), "client.log")
SETTINGS_FILE   = os.path.join(appdata_dir(), "settings.json")
CONSENT_FILE    = os.path.join(appdata_dir(), "consent.json")
STATUS_FILE     = os.path.join(appdata_dir(), "status.json")
TOKEN_FILE_NEW  = os.path.join(appdata_dir(), "token.dat")  # DPAPI ile şifreli
TOKEN_FILE_OLD  = "token.txt"  # eski düz metin (migrasyon için)
WATCHDOG_TOKEN_FILE = os.path.join(appdata_dir(), "watchdog.token")

# ===================== LOGGING ===================== #

try:
    import PIL
    import logging
    logging.getLogger('PIL').setLevel(logging.INFO)
except ImportError:
    pass

def init_logging(is_watchdog=False):
    logger = logging.getLogger("cloud-client")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    log_file = os.path.join(appdata_dir(), "watchdog.log") if is_watchdog else LOG_FILE

    try:
        # 1 MB x 5 yedek
        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=1_000_000, backupCount=5, encoding="utf-8"
        )
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                      datefmt="%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        console = logging.StreamHandler()
        console.setFormatter(formatter)
        logger.addHandler(console)
    except Exception as e:
        console = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        console.setFormatter(formatter)
        logger.addHandler(console)
        print(f"Log file error (will log to console): {e}")

    return logger


LOGGER = init_logging()

def log(msg):  # kısa alias
    try:
        LOGGER.info(str(msg))
    except Exception as e:
        LOGGER.error(f"Log error: {e}")

def run_cmd(cmd, timeout: int = 20, suppress_rc_log: bool = False):
    # Güvenli komut çalıştırma (shell=False), stdout/stderr loglar; zaman aşımı ile kilitlenmeyi önler.
    CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
    try:
        if isinstance(cmd, (list, tuple)):
            cmd_list = list(cmd)
            cmd_display = " ".join(str(x) for x in cmd_list)
        else:
            cmd_list = ["cmd", "/c", str(cmd)] if os.name == "nt" else ["/bin/sh", "-lc", str(cmd)]
            cmd_display = str(cmd)

        #log(f"$ {cmd_display}")
        if TEST_MODE != 0:
            return None

        completed = subprocess.run(
            cmd_list,
            shell=False,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            creationflags=CREATE_NO_WINDOW,
            timeout=timeout if timeout and timeout > 0 else None,
        )
        #if completed.stdout:
        #    log(completed.stdout.strip())
        if completed.stderr:
            log(completed.stderr.strip())
        if completed.returncode != 0 and not suppress_rc_log:
            log(f"Command exited with code {completed.returncode}")
        return completed
    except subprocess.TimeoutExpired as te:
        log(f"Command timeout after {timeout}s: {cmd_display}")
        return None
    except Exception as e:
        log(f"run_cmd error: {e}")
        return None

# ===================== WINDOWS FIREWALL HELPERS ===================== #
def firewall_allow_exists_tcp_port(port: int) -> bool:
    # Checks if an inbound allow firewall rule exists for given TCP local port (Windows only).
    if os.name != 'nt':
        return False
    try:
        ps = (
            f"$p={int(port)};"
            "$r = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | "
            "Get-NetFirewallPortFilter | Where-Object { $_.Protocol -eq 'TCP' -and $_.LocalPort -eq $p };"
            "if ($r) { Write-Output 'FOUND'; exit 0 } else { exit 1 }"
        )
        res = run_cmd(['powershell','-NoProfile','-Command', ps], timeout=10, suppress_rc_log=True)
        if res and hasattr(res, 'returncode') and res.returncode == 0 and getattr(res, 'stdout', '') and 'FOUND' in res.stdout:
            return True
    except Exception:
        pass
    # Fallback best-effort using netsh output (may be localized; ignore failures)
    try:
        res = run_cmd(['netsh','advfirewall','firewall','show','rule','name=all'], timeout=15, suppress_rc_log=True)
        if res and hasattr(res, 'returncode') and res.returncode == 0 and getattr(res, 'stdout', ''):
            txt = res.stdout.lower()
            if ('localport' in txt) and (str(int(port)) in txt):
                return True
    except Exception:
        pass
    return False


def ensure_firewall_allow_for_port(port: int, rule_name: str = None):
    # Ensure an inbound allow rule exists for TCP port; add if missing (Windows only).
    if os.name != 'nt':
        return
    if firewall_allow_exists_tcp_port(port):
        return
    name = rule_name or (f"RDP {port}" if str(port) in ('3389','53389') else f"Allow Port {port}")
    run_cmd([
        'netsh','advfirewall','firewall','add','rule', f'name={name}',
        'dir=in','action=allow','protocol=TCP', f'localport={int(port)}'
    ])

# ===================== WATCHDOG HELPERS ===================== #
STATE_FILE = os.path.join(appdata_dir(), 'state.json')
TASK_NAME_BOOT = "CloudHoneypotClientBoot"
TASK_NAME_LOGON = "CloudHoneypotClientLogon"

def write_watchdog_token(value: str):
    try:
        with open(WATCHDOG_TOKEN_FILE, 'w', encoding='utf-8') as f:
            f.write(value.strip())
    except Exception:
        pass

def read_watchdog_token() -> str:
    try:
        return open(WATCHDOG_TOKEN_FILE, 'r', encoding='utf-8').read().strip()
    except Exception:
        return ''

def is_process_running_windows(pid: int) -> bool:
    if os.name != 'nt':
        return False
    try:
        # Use direct invocation to preserve /FI argument correctly
        res = run_cmd(['tasklist','/FI', f'PID eq {pid}','/FO','CSV','/NH'], timeout=10, suppress_rc_log=True)
        if res and res.stdout:
            return any(str(pid) in line for line in (res.stdout or '').splitlines())
    except Exception:
        pass
    return False

def start_watchdog_if_needed():
    if os.name != 'nt':
        return
    try:
        if os.environ.get('CHP_WATCHDOG') == '1':
            return
        # Mark active to ensure restarts unless user allows exit
        write_watchdog_token('active')
        argv = []
        if getattr(sys, 'frozen', False):
            argv = [sys.executable, '--watchdog', str(os.getpid())]
        else:
            argv = [sys.executable, os.path.abspath(sys.argv[0]), '--watchdog', str(os.getpid())]
        env = os.environ.copy(); env['CHP_WATCHDOG'] = '1'
        subprocess.Popen(argv, shell=False, env=env)
    except Exception as e:
        log(f"start_watchdog error: {e}")

def watchdog_main(parent_pid: int):
    # Watchdog için ayrı logger başlat
    global LOGGER
    LOGGER = init_logging(is_watchdog=True)
    attempts = 0
    max_attempts = 5
    while attempts < max_attempts:
        time.sleep(5)
        tok = read_watchdog_token()
        if tok.lower() == 'stop':
            return
        # Check if parent process is alive
        alive = is_process_running_windows(int(parent_pid))
        if not alive:
            # Check if any protection services are active
            try:
                state_file = os.path.join(appdata_dir(), 'state.json')
                with open(state_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                    if state.get("selected_rows"):  # If any protection is active
                        log("[watchdog] Restarting application due to unexpected termination")
                        attempts += 1
                        # Start new instance
                        argv = []
                        if getattr(sys, 'frozen', False):
                            argv = [sys.executable]
                        else:
                            argv = [sys.executable, os.path.abspath(sys.argv[0])]
                        subprocess.Popen(argv, shell=False)
                        time.sleep(10)  # Wait to see if it starts successfully
                        continue
            except Exception as e:
                log(f"[watchdog] State check error: {e}")
        attempts = 0  # Reset attempts if parent is alive
        # Grace period for updater to relaunch (batch starts new exe)
        time.sleep(10)
        # If already relaunched by updater, exit
        # Best-effort: if any process named our exe exists, just continue waiting
        try:
            exe_name = os.path.basename(sys.executable)
            res = run_cmd(['tasklist','/FI', f'IMAGENAME eq {exe_name}','/FO','CSV','/NH'], timeout=10, suppress_rc_log=True)
            if res and exe_name.lower() in (res.stdout or '').lower():
                continue
        except Exception as e:
            log(f"Exception: {e}")
        # Relaunch
        try:
            attempts += 1
            if getattr(sys, 'frozen', False):
                subprocess.Popen([sys.executable], shell=False)
            else:
                subprocess.Popen([sys.executable, os.path.abspath(sys.argv[0])], shell=False)
        except Exception as e:
            log(f"Exception: {e}")
    # Give up after attempts
    return

# ===================== I18N & AYARLAR ===================== #
I18N = {
    "tr": {
        "app_title": "Cloud Honeypot Security (Tunnel)",
        "menu_settings": "Ayarlar",
        "menu_language": "Dil",
        "menu_lang_tr": "Türkçe",
        "menu_lang_en": "English",
        "menu_help": "Yardım",
        "menu_check_updates": "Güncellemeleri Denetle",
        "menu_logs": "Logları Aç",
        "update_none": "Güncel sürümü kullanıyorsunuz.",
        "update_found": "Yeni sürüm bulundu: {version}. İndirip yeniden başlatılsın mı?",
        "update_error": "Güncelleme sırasında hata: {err}",
        "restart_needed_lang": "Dil değişikliği için uygulama yeniden başlatılacak.",
        "server_info": "Sunucu Bilgileri",
        "lbl_pc_ip": "PC Adı / IP",
        "lbl_token": "Token",
        "lbl_dashboard": "Dashboard Adresi",
        "lbl_attacks": "Toplam Saldırılar",
        "copy": "Kopyalandı",
        "open": "Aç",
        "refresh": "Yenile",
        "port_tunnel": "Port Tünelleme",
        "col_listen": "Dinlenecek Port",
        "col_new": "Yeni Port/RDP",
        "col_service": "Servis",
        "col_active": "Aktif",
        "btn_secure": "Güvene Al",
        "btn_stop": "Korumayı Durdur",
        "btn_row_start": "Başlat",
        "btn_row_stop": "Durdur",
        "status": "Durum",
        "status_running": "Çalışıyor",
        "status_stopped": "Durduruldu",
        "warn_no_ports": "Hiçbir port seçmediniz!",
        "ok_tunneled": "{n} port tünellendi!",
        "stopped_all": "Tüm korumalar kaldırıldı.",
        "confirm_stop": "Tüm korumaları durdurmak istediğinize emin misiniz?",
        "note_rdp": "Not: RDP korumayı seçtiğinizde 60 sn içinde yeni porttan bağlanıp onay verin.",
        "tray_show": "Göster",
        "tray_exit": "Çıkış",
        "tray_warn_stop_first": "Önce Korumayı Durdur.",
        "consent_title": "Güvenlik Onayı",
        "consent_msg": (
            "Uygulama aşağıdaki işlemleri yapabilir:\n\n"
            "- Seçtiğiniz portları güvene alıp tünel açma\n"
            "- RDP portunu 3389 → 53389 taşıma ve hizmeti yeniden başlatma\n"
            "- Başlangıçta otomatik çalıştırma (Görev Zamanlayıcı)\n\n"
            "Devam etmek için onay verin ve tercihleri seçin."
        ),
        "consent_rdp": "RDP portunu 53389'a taşı ve hizmeti yönet",
        "consent_auto": "Başlangıçta otomatik çalıştır (Görev Zamanlayıcı)",
        "consent_accept": "Onayla ve Devam",
        "consent_cancel": "Vazgeç",
        "warn_no_consent": "İşlem iptal edildi: Onay verilmedi.",
        "rdp_title": "RDP İşlemi",
        "rdp_go_secure": "RDP portunuz 53389'a taşınacak.\n60 saniye içinde yeni porttan bağlanın.\nAksi halde eski porta dönülecek.",
        "rdp_rollback": "RDP portunuz 3389'a geri taşınacak.\n60 saniye içinde eski porttan bağlanın.\nAksi halde yeni port aktif kalacak.",
        "rdp_approve": "Onaylıyorum",
        "rollback_done": "Port {port} geri yüklendi.",
        "err_rdp": "RDP ayarlanamadı: {e}",
        "err_api_register": "API bağlantısı başarısız: {e}",
        "err_api_status": "API register status: {code}",
        "info": "Bilgi",
        "warn": "Uyarı",
        "error": "Hata",
        "menu_info": "Bilgi",
        "menu_github": "GitHub",
        "about_title": "Bilgi",
        "about_fmt": (
            "Sürüm: {ver}\n"
            "Log dosyası: {log}\n"
            "GitHub: {url}"
        ),
        "startup_title": "Bilgilendirme",
        "startup_notice": (
            "Bu uygulama tünel açmak ve saldırı verisi toplamak için ağ bağlantısı kurar.\n\n"
            "- Windows güvenlik duvarı/Defender bağlantı izni isteyebilir; lütfen izin verin.\n"
            "- Yönetici (Administrator) yetkisi gereklidir; yetki yoksa uygulama yeniden yönetici olarak açılır.\n\n"
            "Devam etmek için Tamam'a basın."
        ),
    },
    "en": {
        "app_title": "Cloud Honeypot Security (Tunnel)",
        "menu_settings": "Settings",
        "menu_language": "Language",
        "menu_lang_tr": "Türkçe",
        "menu_lang_en": "English",
        "menu_help": "Help",
        "menu_check_updates": "Check for Updates",
        "menu_logs": "Open Logs",
        "update_none": "You are running the latest version.",
        "update_found": "New version available: {version}. Download and restart?",
        "update_error": "Error during update: {err}",
        "restart_needed_lang": "The application will restart to apply language.",
        "server_info": "Server Info",
        "lbl_pc_ip": "PC Name / IP",
        "lbl_token": "Token",
        "lbl_dashboard": "Dashboard URL",
        "lbl_attacks": "Total Attacks",
        "copy": "Copied",
        "open": "Open",
        "refresh": "Refresh",
        "port_tunnel": "Port Tunneling",
        "col_listen": "Listen Port",
        "col_new": "New Port/RDP",
        "col_service": "Service",
        "col_active": "Active",
        "btn_secure": "Secure",
        "btn_stop": "Stop Protection",
        "btn_row_start": "Start",
        "btn_row_stop": "Stop",
        "status": "Status",
        "status_running": "Running",
        "status_stopped": "Stopped",
        "warn_no_ports": "No ports selected!",
        "ok_tunneled": "{n} ports secured!",
        "stopped_all": "All protections have been removed.",
        "confirm_stop": "Are you sure you want to stop all protections?",
        "note_rdp": "Note: When securing RDP, connect via the new port within 60s and confirm.",
        "tray_show": "Show",
        "tray_exit": "Exit",
        "tray_warn_stop_first": "Stop Protection first.",
        "consent_title": "Security Consent",
        "consent_msg": (
            "This app may perform:\n\n"
            "- Secure selected ports by tunneling\n"
            "- Move RDP 3389 → 53389 and restart the service\n"
            "- Autostart via Task Scheduler\n\n"
            "Please consent and choose preferences."
        ),
        "consent_rdp": "Move RDP to 53389 and manage service",
        "consent_auto": "Autostart on boot/logon (Task Scheduler)",
        "consent_accept": "Accept & Continue",
        "consent_cancel": "Cancel",
        "warn_no_consent": "Cancelled: No consent.",
        "rdp_title": "RDP Operation",
        "rdp_go_secure": "RDP will be moved to 53389.\nReconnect within 60s.\nOtherwise rollback to old port.",
        "rdp_rollback": "RDP will be moved back to 3389.\nReconnect within 60s.\nOtherwise keep new port.",
        "rdp_approve": "I Confirm",
        "rollback_done": "Port {port} restored.",
        "err_rdp": "RDP operation failed: {e}",
        "err_api_register": "API request failed: {e}",
        "err_api_status": "API register status: {code}",
        "info": "Info",
        "warn": "Warning",
        "error": "Error",
        "menu_info": "Info",
        "menu_github": "GitHub",
        "about_title": "About",
        "about_fmt": (
            "Version: {ver}\n"
            "Log file: {log}\n"
            "GitHub: {url}"
        ),
        "startup_title": "Notice",
        "startup_notice": (
            "This app opens a tunnel and collects attack data, requiring network access.\n\n"
            "- Windows Firewall/Defender may prompt; please allow the connection.\n"
            "- Administrator privileges are required; if missing, the app relaunches elevated.\n\n"
            "Press OK to continue."
        ),
    },
}

def read_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return {"language": data.get("language", "tr")}
    except Exception as e:
        log(f"read_settings error: {e}")
    return {"language": "tr"}

def write_settings(language: str):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump({"language": language}, f, ensure_ascii=False)
    except Exception as e:
        log(f"write_settings error: {e}")

# ===================== EXCEPTHOOK ===================== #
def install_excepthook():
    def _hook(exc_type, exc, tb):
        try:
            import traceback
            LOGGER.error("UNHANDLED EXCEPTION:\n" + "".join(traceback.format_exception(exc_type, exc, tb)))
            # Attempt self-restart once to behave like a resilient service
            try:
                if not os.environ.get('CHP_RELAUNCHED'):
                    env = os.environ.copy(); env['CHP_RELAUNCHED'] = '1'
                    exe = sys.executable if getattr(sys, 'frozen', False) else sys.executable
                    argv = [exe]
                    if getattr(sys, 'frozen', False):
                        # PyInstaller onefile/onedir: executable already the app
                        pass
                    else:
                        argv.append(os.path.abspath(sys.argv[0]))
                    argv += sys.argv[1:]
                    subprocess.Popen(argv, shell=False, env=env)
            except Exception:
                pass
        except Exception as e:
            log(f"Exception: {e}")
    try:
        sys.excepthook = _hook
    except Exception:
        pass

# ===================== DPAPI TOKEN STORE ===================== #
class TokenStore:
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
    def save(token: str):
        try:
            data = token.encode("utf-8")
            # küçük bir header ile integrity:
            h = hashlib.sha256(data).hexdigest().encode("ascii")
            payload = b"CHP1|" + h + b"|" + data
            enc = TokenStore._crypt_protect(payload)
            with open(TOKEN_FILE_NEW, "wb") as f:
                f.write(enc)
        except Exception as e:
            log(f"token save error: {e}")

    @staticmethod
    def load() -> Optional[str]:
        try:
            if os.path.exists(TOKEN_FILE_NEW):
                enc = open(TOKEN_FILE_NEW, "rb").read()
                dec = TokenStore._crypt_unprotect(enc)
                if not dec.startswith(b"CHP1|"):
                    return None
                _, h, data = dec.split(b"|", 2)
                if hashlib.sha256(data).hexdigest().encode("ascii") != h:
                    return None
                return data.decode("utf-8", "ignore").strip()
        except Exception as e:
            log(f"token load error: {e}")
        return None

    @staticmethod
    def migrate_from_plain():
        try:
            if os.path.exists(TOKEN_FILE_OLD):
                token = open(TOKEN_FILE_OLD, "r", encoding="utf-8").read().strip()
                if token:
                    TokenStore.save(token)
                try:
                    os.remove(TOKEN_FILE_OLD)
                except Exception:
                    pass
        except Exception as e:
            log(f"token migration error: {e}")

# ===================== HİZMET KONTROLÜ (TermService) ===================== #
class ServiceController:
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
            log(f"sc query error: {e}")
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
    def stop(svc_name: str, timeout: int = 40) -> bool:
        code = ServiceController._sc_query_code(svc_name)
        if code == 1:
            return True

        # 1) sc stop dene (kısa tekrarlar)
        for _ in range(2):
            run_cmd(['sc', 'stop', svc_name], timeout=10)
            if ServiceController._wait_state_code(svc_name, 1, 12):
                return True
            time.sleep(2)

        # 2) PowerShell Stop-Service -Force
        run_cmd(['powershell', '-NoProfile', '-Command',
                 f'Stop-Service -Name "{svc_name}" -Force -ErrorAction SilentlyContinue'], timeout=20)
        if ServiceController._wait_state_code(svc_name, 1, 15):
            return True

        log(f"Service {svc_name} did not stop in time")
        return False

    @staticmethod
    def start(svc_name: str, timeout: int = 40) -> bool:
        code = ServiceController._sc_query_code(svc_name)
        if code == 4:
            return True

        run_cmd(['sc', 'start', svc_name], timeout=10)
        if ServiceController._wait_state_code(svc_name, 4, timeout):
            return True

        run_cmd(['powershell', '-NoProfile', '-Command',
                 f'Start-Service -Name "{svc_name}" -ErrorAction SilentlyContinue'], timeout=20)
        return ServiceController._wait_state_code(svc_name, 4, 20)

    @staticmethod
    def restart(svc_name: str) -> bool:
        run_cmd(['powershell', '-NoProfile', '-Command',
                 f'Restart-Service -Name "{svc_name}" -Force -ErrorAction SilentlyContinue'], timeout=25)
        if ServiceController._wait_state_code(svc_name, 4, 20):
            return True
        # fallback
        return ServiceController.stop(svc_name, 20) and ServiceController.start(svc_name, 20)

    @staticmethod
    def switch_rdp_port(new_port: int) -> bool:
        try:
            cur = ServiceController.get_rdp_port()
            if cur and int(cur) == int(new_port):
                try:
                    ensure_firewall_allow_for_port(int(new_port), rule_name=f"RDP {new_port}")
                except Exception as e:
                    log(f"firewall allow check/add failed for port {new_port}: {e}")
                return True
        except Exception as e:
            log(f"Exception: {e}")
        run_cmd([
            'reg','add', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp',
            '/v','PortNumber','/t','REG_DWORD','/d', str(new_port), '/f'
        ])
        # Only add firewall allow if not already present (avoid duplicates on 3389/53389)
        try:
            ensure_firewall_allow_for_port(int(new_port), rule_name=f"RDP {new_port}")
        except Exception as e:
            log(f"firewall allow check/add failed for port {new_port}: {e}")
        return ServiceController.restart('TermService')

    @staticmethod
    def get_rdp_port() -> Optional[int]:
        if os.name != 'nt':
            return None
        try:
            import winreg as _wr
            key = _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp")
            val, typ = _wr.QueryValueEx(key, "PortNumber")
            _wr.CloseKey(key)
            if isinstance(val, int):
                return val
        except Exception as e:
            log(f"get_rdp_port error: {e}")
        return None

# ===================== TUNNEL THREAD ===================== #
class TunnelServerThread(threading.Thread):
    def __init__(self, app, listen_port: int, service_name: str):
        super().__init__(daemon=True)
        self.app = app
        self.listen_port = int(listen_port)
        self.service_name = service_name
        self.stop_evt = threading.Event()
        self.sock = None

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("0.0.0.0", self.listen_port))
            self.sock.listen(200)
            log(f"[{self.service_name}] 0.0.0.0:{self.listen_port} dinlemede")
        except Exception as e:
            log(f"[{self.service_name}] Port {self.listen_port} dinlenemedi: {e}")
            return

        while not self.stop_evt.is_set():
            try:
                self.sock.settimeout(1.0)
                client_sock, _ = self.sock.accept()
            except socket.timeout:
                continue
            except Exception as e:
                if not self.stop_evt.is_set():
                    log(f"[{self.service_name}] accept hata: {e}")
                continue

            th = threading.Thread(
                target=self.app.handle_incoming_connection,
                args=(client_sock, self.listen_port, self.service_name),
                daemon=True
            )
            th.start()
            try:
                self.app.state.setdefault("threads", []).append(th)
            except Exception:
                pass

    def stop(self):
        self.stop_evt.set()
        try:
            if self.sock:
                self.sock.close()
        except:
            pass

# ===================== ANA UYGULAMA ===================== #
class CloudHoneypotClient:
    # Default port mappings
    PORT_TABLOSU = [
        ("3389", "53389", "RDP"),
        ("1433", "-", "MSSQL"),
        ("3306", "-", "MySQL"),
        ("21",   "-", "FTP"),
        ("22",   "-", "SSH"),
    ]

    def get_token(self) -> Optional[str]:
        # Kaydedilmiş token'ı yükler
        # Önce eski plain text token'ı kontrol et ve migrate et
        TokenStore.migrate_from_plain()
        # DPAPI ile şifrelenmiş token'ı yükle
        return TokenStore.load()

    def load_settings(self) -> Dict[str, Any]:
        # Uygulama ayarlarını yükler
        try:
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
        except Exception as e:
            log(f"Ayarlar yüklenirken hata: {e}")
        return {"language": "tr", "tunnels": {}}

    def save_settings(self, settings: Dict[str, Any]):
        # Uygulama ayarlarını kaydeder
        try:
            os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(settings, f, ensure_ascii=False, indent=2)
        except Exception as e:
            log(f"Ayarlar kaydedilirken hata: {e}")

    def api_request(self, method: str, endpoint: str, data: Dict = None,
                    params: Dict = None, timeout: int = 8, json: Dict = None) -> Optional[Dict]:
        try:
            token = self.state.get("token")
            if not token:
                log("Token bulunamadı, API isteği yapılamıyor")
                return None

            base_url = API_URL.rstrip('/')
            # '/api' sonunu ayıkla
            if base_url.lower().endswith('/api'):
                base_url = base_url[:-4]

            ep = (endpoint or "").lstrip('/')  # <-- baştaki / temizle
            if ep.lower().startswith('api/'):
                ep = ep[4:]

            url = f"{base_url}/api/{ep}"

            # Log detayları
            log(f"[API] {method} isteği: {url}")
            if params:
                log(f"[API] Params: {params}")
            if data:
                log(f"[API] Data: {data}")
            if json:
                log(f"[API] JSON: {json}")

            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }

            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=params,
                json=json if json else data,
                timeout=timeout
            )

            log(f"[API] Yanıt: HTTP {response.status_code}")
            if response.status_code != 200:
                log(f"[API] Hata yanıtı: {response.text[:200]}")
                return None

            # JSON yanıtı varsa döndür
            if response.headers.get('content-type', '').startswith('application/json'):
                try:
                    result = response.json()
                    log(f"[API] Başarılı yanıt: {str(result)[:200]}")
                    return result
                except Exception as e:
                    log(f"[API] JSON parse hatası: {e}")
                    return None
            # JSON olmayan başarılı yanıt
            return {"status": "success"}

        except requests.exceptions.RequestException as e:
            log(f"[API] Network hatası: {e}")
            return None
        except Exception as e:
            log(f"[API] Beklenmeyen hata: {e}")
            return None

    def __init__(self):
        install_excepthook()
        self.lang = read_settings().get("language", "tr")

        
        # Initialize threading controls for API synchronization
        self.reconciliation_lock = threading.Lock()
        self.rdp_transition_complete = threading.Event()
        
        # Initialize state
        self.state = {
            "running": False,
            "servers": {},    # listen_port -> TunnelServerThread
            "threads": [],
            "token": None,
            "public_ip": None,
            "tray": None,
            "selected_rows": [],   # [('3389','53389','RDP'), ...]
            "selected_ports_map": None,  # iid -> bool
            "ctrl_sock": None,
            "reconciliation_paused": False,
            "remote_desired": {}  # Cache for remote management
        }
        
        # Initialize GUI elements
        self.root = None
        self.btn_primary = None
        self.tree = None
        self.attack_entry = None
        self.ip_entry = None
        self.show_cb = None
        
        # Start API retry thread
        threading.Thread(target=self.api_retry_loop, daemon=True).start()

    # ---------- First-run notice ---------- #
    def _read_status_raw(self):
        try:
            if os.path.exists(STATUS_FILE):
                with open(STATUS_FILE, "r", encoding="utf-8") as f:
                    d = json.load(f)
                    return d if isinstance(d, dict) else {}
        except Exception as e:
            log(f"read status raw error: {e}")
        return {}

    def _write_status_raw(self, data: dict):
        try:
            with open(STATUS_FILE, "w", encoding="utf-8") as f:
                json.dump(data or {}, f, ensure_ascii=False)
        except Exception as e:
            log(f"write status raw error: {e}")

    def first_run_notice(self):
        try:
            st = self._read_status_raw()
            if st.get("first_notice_shown"):
                return
            # Show a simple info for firewall and elevation
            messagebox.showinfo(self.t("startup_title"), self.t("startup_notice"))
            st["first_notice_shown"] = True
            self._write_status_raw(st)
        except Exception as e:
            log(f"first_run_notice error: {e}")

    # ---------- I18N ---------- #
    def t(self, key: str) -> str:
        return I18N.get(self.lang, I18N["tr"]).get(key, key)

    # ---------- Yardımcılar ---------- #
    def current_executable(self):
        if getattr(sys, 'frozen', False):
            return sys.executable
        return os.path.abspath(sys.argv[0])

    def http_get_json(self, url, timeout=8):
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return r.json()

    def http_download(self, url, dest_path, timeout=30):
        with requests.get(url, stream=True, timeout=timeout) as r:
            r.raise_for_status()
            with open(dest_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=65536):
                    if chunk:
                        f.write(chunk)

    def sha256_file(self, p):
        h = hashlib.sha256()
        with open(p, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    def ensure_admin(self):
        try:
            if os.name != "nt":
                return
            # Elevate early so user just runs and goes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                if getattr(sys, 'frozen', False):
                    exe = sys.executable
                    params = " ".join(sys.argv[1:])
                else:
                    exe = sys.executable
                    script = os.path.abspath(sys.argv[0])
                    params = f'"{script}" ' + " ".join(sys.argv[1:])
                ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
                sys.exit(0)
        except Exception as e:
            log(f"ensure_admin error: {e}")

    # ---------- Token ---------- #
    def register_client(self) -> Optional[str]:
        retry_count = 0
        while retry_count < 3:  # 3 kez dene
            try:
                ip = self.get_public_ip()
                resp = requests.post(f"{API_URL}/register",
                                     json={"server_name": f"{SERVER_NAME} ({ip})", "ip": ip},
                                     timeout=8)
                if resp.status_code == 200:
                    data = resp.json()
                    tok = data.get("token")
                    if tok:
                        TokenStore.save(tok)
                        return tok
                else:
                    if self.root:  # GUI modunda
                        messagebox.showwarning("Uyarı", 
                            f"API kaydı başarısız (HTTP {resp.status_code}). Tekrar deneniyor...")
                    log(f"API kaydı başarısız (HTTP {resp.status_code}). Tekrar deneniyor...")
            except Exception as e:
                if self.root:  # GUI modunda
                    messagebox.showwarning("Uyarı", 
                        f"API kaydı başarısız ({str(e)}). Tekrar deneniyor...")
                log(f"API kaydı başarısız: {e}. Tekrar deneniyor...")
            
            retry_count += 1
            time.sleep(5)  # 5 saniye bekle ve tekrar dene
        
        # 3 deneme sonrası hala başarısız
        if self.root:  # GUI modunda
            messagebox.showwarning("Uyarı", 
                "API kaydı başarısız. Program çalışmaya devam edecek ve arkaplanda bağlantıyı deneyecek.")
        return None

    def load_token(self) -> Optional[str]:
        TokenStore.migrate_from_plain()
        tok = TokenStore.load()
        if tok:
            return tok
        return self.register_client()

    # ---------- API Connection ---------- #
    def try_api_connection(self, show_error=True):
        # API bağlantısını kontrol eder
        try:
            # Strip any trailing slash from API_URL
            base_url = API_URL.rstrip('/')
            health_url = f"{base_url.rsplit('/api', 1)[0]}/healthz"
            logging.info(f"Checking API health at {health_url}...")
            r = requests.get(health_url, timeout=5)
            
            if r.status_code == 200:
                try:
                    health_data = r.json()
                    if health_data.get("status") == "ok":
                        client_count = health_data.get("clients", 0)
                        logging.info(f"API connection successful - {client_count} clients registered")
                        return True
                except ValueError:
                    logging.warning("API health check succeeded but returned invalid JSON")
            
            if r.status_code in [401, 403]:  # API çalışıyor ama token gerekiyor
                logging.info("API connection successful but requires authentication")
                return True
                
            logging.error(f"API connection failed: HTTP {r.status_code}")
            if show_error and self.root:
                messagebox.showwarning("Uyarı", 
                    f"API bağlantısı başarısız (HTTP {r.status_code}). Bağlantı tekrar denenecek.")
            
        except requests.exceptions.Timeout:
            logging.error("API connection timeout after 5 seconds")
            if show_error and self.root:
                messagebox.showwarning("Uyarı", 
                    "API bağlantısı zaman aşımına uğradı. Bağlantı tekrar denenecek.")
                    
        except requests.exceptions.ConnectionError as e:
            logging.error(f"API connection error: Network connectivity issue - {str(e)}")
            if show_error and self.root:
                messagebox.showwarning("Uyarı", 
                    "API sunucusuna bağlanılamadı. İnternet bağlantınızı kontrol edin.")
                    
        except Exception as e:
            logging.error(f"Unexpected error connecting to API: {str(e)}", exc_info=True)
            if show_error and self.root:
                messagebox.showwarning("Uyarı", 
                    f"API bağlantısında beklenmeyen hata ({str(e)}). Bağlantı tekrar denenecek.")
        
        return False

    def api_retry_loop(self):
        # Arkaplanda API bağlantısını sürekli dener
        retry_count = 0
        max_quick_retries = 3  # Number of quick retries before slowing down
        
        while True:
            if not self.try_api_connection(show_error=(retry_count == 0)):
                retry_count += 1
                
                # For the first few failures, retry quickly
                if retry_count <= max_quick_retries:
                    logging.warning(f"API connection failed (attempt {retry_count}/{max_quick_retries}), retrying in 5 seconds...")
                    time.sleep(5)
                else:
                    # After max_quick_retries, slow down to avoid overwhelming the network/server
                    logging.warning(f"API connection still failing after {retry_count} attempts, will retry in 60 seconds...")
                    time.sleep(60)
                continue
                
            # Reset retry count on successful connection
            if retry_count > 0:
                logging.info(f"API connection restored after {retry_count} retries")
                retry_count = 0
                
            time.sleep(60)  # Check connection every minute when healthy

# ---------- IP & heartbeat ---------- #
    def get_public_ip(self):
        try:
            return requests.get("https://api.ipify.org", timeout=5).text.strip()
        except Exception as e:
            log(f"get_public_ip error: {e}")
            return "0.0.0.0"

    def update_client_ip(self, new_ip):
        try:
            token = self.state.get("token")
            if not token: return
            payload = {"token": token, "ip": new_ip}
            r = requests.post(f"{API_URL}/update-ip", json=payload, timeout=6)
            if r.status_code == 200:
                log(f"update-ip OK: {new_ip}")
            else:
                log(f"update-ip HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            log(f"update-ip error: {e}")

    def send_heartbeat_once(self, status_override=None):
        try:
            token = self.state.get("token")
            if not token:
                return
            ip = self.state.get("public_ip") or self.get_public_ip()
            status = "online" if self.state.get("running") else "offline"
            if status_override in ("online", "offline"):
                status = status_override
            payload = {
                "token": token,
                "ip": ip,
                "hostname": SERVER_NAME,
                "running": self.state.get("running", False),
                "status": status
            }
            requests.post(f"{API_URL}/heartbeat", json=payload, timeout=6)
        except Exception as e:
            log(f"heartbeat send err: {e}")

    def heartbeat_loop(self):
        last_ip = None
        while True:
            try:
                token = self.state.get("token")
                if token:
                    ip = self.get_public_ip()
                    if ip and ip != last_ip:
                        self.update_client_ip(ip)
                        last_ip = ip
                    self.state["public_ip"] = ip
                    # GUI'deki IP bilgisini güncelle
                    if self.ip_entry and self.root:
                        try:
                            self.root.after(0, lambda: self.safe_set_entry(self.ip_entry, f"{SERVER_NAME} ({ip})"))
                        except:
                            self.safe_set_entry(self.ip_entry, f"{SERVER_NAME} ({ip})")
                    self.send_heartbeat_once()
            except Exception as e:
                log(f"heartbeat error: {e}")
            time.sleep(60)

    # ---------- Attack Count ---------- #
    def fetch_attack_count_sync(self, token):
        try:
            r = requests.get(f"{API_URL}/attack-count", params={"token": token}, timeout=5)
            if r.status_code == 200:
                return int(r.json().get("count", 0))
        except Exception as e:
            log(f"fetch_attack_count error: {e}")
        return None

    def refresh_attack_count(self, async_thread=True):
        token = self.state.get("token")
        if not token or not self.root or not self.attack_entry:
            return
        def worker():
            cnt = self.fetch_attack_count_sync(token)
            if cnt is None: return
            try:
                self.root.after(0, lambda: self.safe_set_entry(self.attack_entry, str(cnt)))
            except:
                self.safe_set_entry(self.attack_entry, str(cnt))
        if async_thread:
            threading.Thread(target=worker, daemon=True).start()
        else:
            worker()

    def poll_attack_count(self):
        self.refresh_attack_count(async_thread=True)
        try:
            self.root.after(10_000, self.poll_attack_count)
        except:
            pass

    # ---------- Tek-instans ---------- #
    def control_server_loop(self, sock):
        while True:
            try:
                conn, _ = sock.accept()
            except Exception:
                    pass
            try:
                conn.settimeout(2.0)
                buf = b""
                while True:
                    ch = conn.recv(1)
                    if not ch or ch == b"\n": break
                    buf += ch
                cmd = buf.decode("utf-8", "ignore").strip().upper()
                if cmd == "SHOW":
                    def do_show():
                        if self.show_cb:
                            try: self.show_cb()
                            except: pass
                    try:
                        if self.root: self.root.after(0, do_show)
                        else: do_show()
                    except:
                        do_show()
            except Exception:
                pass
            finally:
                try: conn.close()
                except: pass

    def start_single_instance_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((CONTROL_HOST, CONTROL_PORT))
        except OSError:
            try:
                with socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=1.0) as c:
                    c.sendall(b"SHOW\n")
            except Exception:
                pass
            sys.exit(0)
        s.listen(5)
        self.state["ctrl_sock"] = s
        th = threading.Thread(target=self.control_server_loop, args=(s,), daemon=True)
        th.start()

    # ---------- TLS & Tünel ---------- #
    def create_tls_socket(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((HONEYPOT_IP, HONEYPOT_TUNNEL_PORT), timeout=CONNECT_TIMEOUT)
        tls = ctx.wrap_socket(raw, server_hostname=HONEYPOT_IP)
        return tls

    def send_json(self, sock, obj):
        data = (json.dumps(obj, separators=(',', ':')) + "\n").encode("utf-8")
        sock.sendall(data)

    def pipe_streams(self, src, dst):
        try:
            while True:
                data = src.recv(RECV_SIZE)
                if not data: break
                dst.sendall(data)
        except:
            pass
        finally:
            for s in (dst, src):
                try: s.shutdown(socket.SHUT_RDWR)
                except: pass
                try: s.close()
                except: pass

    def handle_incoming_connection(self, local_sock, listen_port, service_name):
        try:
            peer = local_sock.getpeername()
            attacker_ip, attacker_port = peer[0], peer[1]
        except:
            attacker_ip, attacker_port = "0.0.0.0", 0

        try:
            remote = self.create_tls_socket()
        except Exception as e:
            log(f"[{service_name}:{listen_port}] TLS bağlanamadı: {e}")
            try: local_sock.close()
            except: pass
            return

        try:
            handshake = {
                "op": "open",
                "token": self.state.get("token"),
                "client_ip": self.state.get("public_ip") or self.get_public_ip(),
                "hostname": SERVER_NAME,
                "service": service_name,
                "listen_port": int(listen_port),
                "attacker_ip": attacker_ip,
                "attacker_port": attacker_port
            }
            self.send_json(remote, handshake)
        except Exception as e:
            log(f"Handshake hata: {e}")
            try:
                remote.close(); local_sock.close()
            except: pass
            return

        t1 = threading.Thread(target=self.pipe_streams, args=(local_sock, remote), daemon=True)
        t2 = threading.Thread(target=self.pipe_streams, args=(remote, local_sock), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        log(f"[{service_name}:{listen_port}] bağlantı kapandı ({attacker_ip}:{attacker_port})")

    def tunnel_sync_loop(self):
        # Düzenli olarak tünel durumlarını API ile senkronize eder
        while True:
            try:
                current_time = time.time()
                last_sync = self.state.get("last_tunnel_sync", 0)
                sync_interval = self.state.get("tunnel_sync_interval", 30)
                
                if current_time - last_sync >= sync_interval:
                    self.sync_tunnel_states()
                    self.state["last_tunnel_sync"] = current_time
                    
            except Exception as e:
                log(f"Tünel senkronizasyon döngüsü hatası: {e}")
                
            time.sleep(5)  # CPU kullanımını azaltmak için kısa bekleme

# ---------- Watchdog ---------- #
    def tunnel_watchdog_loop(self):
        while True:
            try:
                if self.state.get("running"):
                    desired = {(str(p[0]), str(p[2]).upper()) for p in self.state.get("selected_rows", [])}
                    # Eksik/ölüleri başlat
                    for (listen_port, new_port, service) in self.state.get("selected_rows", []):
                        lp = int(str(listen_port))
                        st = self.state["servers"].get(lp)
                        if (st is None) or (not st.is_alive()):
                            try:
                                st2 = TunnelServerThread(self, lp, str(service))
                                st2.start()
                                time.sleep(0.2)
                                if st2.is_alive():
                                    self.state["servers"][lp] = st2
                                    log(f"[watchdog] {service}:{lp} yeniden başlatıldı")
                            except Exception as e:
                                log(f"[watchdog] {service}:{lp} başlatılamadı: {e}")

                    # Fazlalıkları durdur
                    for lp, st in list(self.state["servers"].items()):
                        key = (str(lp), str(st.service_name).upper())
                        if key not in desired:
                            try:
                                st.stop()
                                del self.state["servers"][lp]
                            except Exception:
                                pass
            except Exception as e:
                log(f"watchdog loop err: {e}")
            time.sleep(10)

    # ---------- Kalıcılık ---------- #
    def write_status(self, active_rows, running=True):
        self.state["selected_rows"] = [(str(a[0]), str(a[1]), str(a[2])) for a in active_rows]
        data = self._read_status_raw()
        data["active_ports"] = self.state["selected_rows"]
        data["running"] = running
        data["fresh_install"] = False
        self._write_status_raw(data)

    def read_status(self):
        if not os.path.exists(STATUS_FILE):
            self.write_status([], running=False)
            return [], False
        try:
            data = json.load(open(STATUS_FILE, "r", encoding="utf-8"))
            if data.get("fresh_install", False):  # <-- default artık False
                self.write_status([], running=False)
                return [], False
            rows = data.get("active_ports", [])
            running = bool(data.get("running", False))
            norm = [(str(r[0]), str(r[1]), str(r[2])) for r in rows]
            return norm, running
        except Exception as e:
            log(f"read_status error: {e}")
            return [], False

    # ---------- Autostart (Task Scheduler) ---------- #
    def task_command_daemon(self):
        if getattr(sys, 'frozen', False):
            return f'"{sys.executable}" --daemon'
        return f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}" --daemon'

    def task_command_minimized(self):
        if getattr(sys, 'frozen', False):
            return f'"{sys.executable}" --minimized'
        return f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}" --minimized'

    def install_autostart_system_boot(self):
        run_cmd([
            'schtasks','/Create','/TN', TASK_NAME_BOOT,
            '/SC','ONSTART','/RU','SYSTEM',
            '/TR', self.task_command_daemon(), '/F'
        ])
        # Not running immediately to avoid spawning extra background instances
        # Task will run on next boot as intended

    def install_autostart_user_logon(self):
        user = os.environ.get("USERNAME") or ""
        run_cmd([
            'schtasks','/Create','/TN', TASK_NAME_LOGON,
            '/SC','ONLOGON','/RU', user,
            '/TR', self.task_command_minimized(), '/RL','HIGHEST','/F'
        ])

    def remove_autostart(self):
        run_cmd(['schtasks','/End','/TN', TASK_NAME_BOOT])
        run_cmd(['schtasks','/Delete','/TN', TASK_NAME_BOOT, '/F'])
        run_cmd(['schtasks','/Delete','/TN', TASK_NAME_LOGON, '/F'])

    # ---------- Consent ---------- #
    def read_consent(self):
        try:
            if os.path.exists(CONSENT_FILE):
                with open(CONSENT_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return {
                            "accepted": bool(data.get("accepted", False)),
                            "rdp_move": bool(data.get("rdp_move", True)),
                            "autostart": bool(data.get("autostart", False)),
                        }
        except Exception as e:
            log(f"read_consent error: {e}")
        return {"accepted": False, "rdp_move": True, "autostart": False}

    def write_consent(self, accepted: bool, rdp_move: bool, autostart: bool):
        try:
            data = {
                "accepted": bool(accepted),
                "rdp_move": bool(rdp_move),
                "autostart": bool(autostart),
                "ts": int(time.time()),
                "app": "CloudHoneypotClient",
            }
            with open(CONSENT_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
        except Exception as e:
            log(f"write_consent error: {e}")

    def ensure_consent_ui(self):
        cons = self.read_consent()
        if cons.get("accepted"):
            self.state["consent"] = cons
            return cons

        win = tk.Toplevel(self.root)
        win.title(self.t("consent_title"))
        try:
            win.grab_set(); win.transient(self.root)
        except Exception as e:
            log(f"Exception: {e}")

        tk.Label(win, text=self.t("consent_msg"), justify="left", font=("Arial", 10)).pack(padx=16, pady=12)

        var_rdp = tk.BooleanVar(value=True)
        var_auto = tk.BooleanVar(value=False)
        tk.Checkbutton(win, text=self.t("consent_rdp"),  variable=var_rdp).pack(anchor="w", padx=16)
        tk.Checkbutton(win, text=self.t("consent_auto"), variable=var_auto).pack(anchor="w", padx=16)

        accepted = {"val": False}

        def do_accept():
            accepted["val"] = True
            self.write_consent(True, var_rdp.get(), var_auto.get())
            self.state["consent"] = self.read_consent()
            try: win.destroy()
            except: pass

        def do_cancel():
            accepted["val"] = False
            self.write_consent(False, var_rdp.get(), var_auto.get())
            self.state["consent"] = self.read_consent()
            try: win.destroy()
            except: pass

        frm = tk.Frame(win)
        frm.pack(pady=10)
        tk.Button(frm, text=self.t("consent_accept"), bg="#4CAF50", fg="white", command=do_accept).pack(side="left", padx=6)
        tk.Button(frm, text=self.t("consent_cancel"), command=do_cancel).pack(side="left", padx=6)

        win.wait_window()
        return self.state.get("consent", cons)

    # ---------- UI yardımcı ---------- #
    def safe_set_entry(self, entry: tk.Entry, text: str):
        try:
            entry.config(state="normal"); entry.delete(0, tk.END); entry.insert(0, text); entry.config(state="readonly")
        except Exception as e:
            log(f"safe_set_entry error: {e}")

    def set_primary_button(self, text, cmd, color):
        if self.btn_primary:
            self.btn_primary.config(text=text, command=cmd, bg=color)

    # ---------- Güncelleme ---------- #
    def check_updates_and_prompt(self):
        try:
            api = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
            data = self.http_get_json(api, timeout=8)
            latest_tag = data.get("tag_name") or data.get("name")
            if not latest_tag:
                messagebox.showinfo("Update", self.t("update_none")); return
            latest_ver = str(latest_tag).lstrip('v')
            cur_ver    = str(__version__).lstrip('v')
            if latest_ver <= cur_ver:
                messagebox.showinfo("Update", self.t("update_none")); return

            # Use onedir ZIP + hashes
            assets = data.get("assets", [])
            asset_zip = None
            asset_hashes = None
            for a in assets:
                n = str(a.get("name", "")).lower()
                if n == "client-onedir.zip":
                    asset_zip = a.get("browser_download_url")
                if n == "hashes.txt":
                    asset_hashes = a.get("browser_download_url")
            if not asset_zip:
                messagebox.showerror("Update", self.t("update_error").format(err="asset not found (client-onedir.zip)")); return
            if not messagebox.askyesno("Update", self.t("update_found").format(version=latest_ver)):
                return

            tmpdir = tempfile.mkdtemp(prefix="chpupd-")
            zip_path = os.path.join(tmpdir, "client-onedir.zip")
            self.http_download(asset_zip, zip_path, timeout=60)
            if asset_hashes:
                sha_path = os.path.join(tmpdir, "hashes.txt")
                self.http_download(asset_hashes, sha_path, timeout=30)
                try:
                    exp = None
                    with open(sha_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if 'client-onedir.zip' in line:
                                exp = line.strip().split()[0]
                                break
                    calc = self.sha256_file(zip_path)
                    if exp and calc.lower() != exp.lower():
                        messagebox.showerror("Update", self.t("update_error").format(err="sha256 mismatch"))
                        return
                except Exception as e:
                    log(f"sha check error: {e}")
            self.apply_onedir_update(zip_path, minimized=True)
        except Exception as e:
            log(f"update error: {e}")
            try:
                messagebox.showerror("Update", self.t("update_error").format(err=str(e)))
            except Exception:
                pass


    def check_updates_and_apply_silent(self):
        try:
            api = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
            data = self.http_get_json(api, timeout=8)
            latest_tag = data.get("tag_name") or data.get("name")
            if not latest_tag:
                return
            latest_ver = str(latest_tag).lstrip('v')
            cur_ver    = str(__version__).lstrip('v')
            if latest_ver <= cur_ver:
                return
            # Assets
            assets = data.get("assets", [])
            asset_zip = None
            asset_hashes = None
            for a in assets:
                n = str(a.get("name", "")).lower()
                if n == "client-onedir.zip":
                    asset_zip = a.get("browser_download_url")
                if n == "hashes.txt":
                    asset_hashes = a.get("browser_download_url")
            if not asset_zip:
                return
            tmpdir = tempfile.mkdtemp(prefix="chpupd-")
            zip_path = os.path.join(tmpdir, "client-onedir.zip")
            self.http_download(asset_zip, zip_path, timeout=60)
            if asset_hashes:
                sha_path = os.path.join(tmpdir, "hashes.txt")
                self.http_download(asset_hashes, sha_path, timeout=30)
                try:
                    exp = None
                    with open(sha_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if 'client-onedir.zip' in line:
                                exp = line.strip().split()[0]
                                break
                    calc = self.sha256_file(zip_path)
                    if exp and calc.lower() != exp.lower():
                        return
                except Exception as e:
                    log(f"sha check silent error: {e}")
            self.apply_onedir_update(zip_path)
        except Exception as e:
            log(f"update silent error: {e}")
    def schedule_self_update_and_exit(self, new_exe_path):
        try:
            cur = self.current_executable()
            target = cur
            up_dir = os.path.dirname(cur)
            bat_path = os.path.join(up_dir, "update_run.bat")
            bat = rf"""
@echo off
setlocal enableextensions
set NEWEXE="{new_exe_path}"
set TARGET="{target}"
ping 127.0.0.1 -n 3 >NUL
:loop
copy /y %NEWEXE% %TARGET% >NUL 2>&1
if errorlevel 1 (
  ping 127.0.0.1 -n 2 >NUL
  goto loop
)
start "" %TARGET%
del "%~f0" & exit /b 0
"""
            with open(bat_path, 'w', encoding='utf-8') as f:
                f.write(bat)
            try:
                write_watchdog_token('stop')
            except Exception:
                pass
            CREATE_NO_WINDOW = 0x08000000 if os.name == 'nt' else 0
            subprocess.Popen(["cmd", "/c", bat_path], shell=False, creationflags=CREATE_NO_WINDOW)
        except Exception as e:
            log(f"schedule update error: {e}")
        finally:
            try: os._exit(0)
            except: sys.exit(0)

    def apply_onedir_update(self, zip_path, minimized=False):
        try:
            import zipfile, shutil
            MIN = ("--minimized" if minimized else "")
            dest_dir = os.path.dirname(self.current_executable())
            tmp_extract = tempfile.mkdtemp(prefix="chpzip-")
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(tmp_extract)
            # Prepare updater script to copy all files then restart
            bat_path = os.path.join(dest_dir, "update_onedir.bat")
            bat = f"""
@echo off
setlocal enableextensions
set SRC="{tmp_extract}"
set DST="{dest_dir}"
REM wait a moment to ensure current process exits
ping 127.0.0.1 -n 3 >NUL
:copyloop
robocopy %SRC% %DST% /E /NFL /NDL /NJH /NJS /NP >NUL
if %ERRORLEVEL% GEQ 8 (
  ping 127.0.0.1 -n 2 >NUL
  goto copyloop
)
            start "" "%DST%\\client-onedir.exe" {MIN}
del "%~f0" & exit /b 0
"""
            with open(bat_path, 'w', encoding='utf-8') as f:
                f.write(bat)
            try:
                write_watchdog_token('stop')
            except Exception:
                pass
            CREATE_NO_WINDOW = 0x08000000 if os.name == 'nt' else 0
            subprocess.Popen(["cmd", "/c", bat_path], shell=False, creationflags=CREATE_NO_WINDOW)
        except Exception as e:
            log(f"apply_onedir_update error: {e}")
        finally:
            try: os._exit(0)
            except: sys.exit(0)

    # ---------- RDP move popup ---------- #
    def rdp_move_popup(self, mode, on_confirm):
        # RDP port değişikliği için kullanıcı onay penceresi
        # 
        # Args:
        #     mode: "secure" (3389->53389) veya "rollback" (53389->3389)
        #     on_confirm: Onay sonrası çağrılacak fonksiyon
        # Tüm API iletişimini durdur
        with self.reconciliation_lock:
            self.state["reconciliation_paused"] = True
            log("RDP geçiş süreci başladı - Tüm API iletişimi duraklatıldı")
            
        # GUI elementlerini oluştur    
        popup = tk.Toplevel(self.root)
        popup.title(self.t("rdp_title"))
        msg = self.t("rdp_go_secure") if mode == "secure" else self.t("rdp_rollback")
        tk.Label(popup, text=msg, font=("Arial", 11), justify="center").pack(padx=20, pady=15)

        status_frame = tk.Frame(popup)
        status_frame.pack(pady=6)

        prog_label = tk.Label(status_frame, text="İşlem sürüyor...", font=("Arial", 10))
        prog_label.pack()

        countdown_label = tk.Label(status_frame, text="", font=("Arial", 20, "bold"), fg="red")

        confirm_button = tk.Button(popup, text=self.t("rdp_approve"), command=lambda: None,
                                   bg="#cccccc", fg="white", padx=15, pady=5, state="disabled")
        confirm_button.pack(pady=10)

        countdown_id = [None]
        transition_success = [False]  # RDP geçişinin başarısını takip etmek için

        def do_rollback():
            # Zaman aşımı veya iptal durumunda port değişikliğini geri al
            if countdown_id[0]:
                try:
                    popup.after_cancel(countdown_id[0])
                except Exception:
                    pass

            # Eğer geçiş başarılıysa ve rollback gerekiyorsa
            if transition_success[0]:
                rollback_port = 3389 if mode == "secure" else 53389
                log(f"Zaman aşımı veya iptal. RDP portu {rollback_port} portuna geri alınıyor.")
                
                def handle_rollback():
                    try:
                        # API iletişiminin duraklatıldığından emin ol
                        if not self.state.get("reconciliation_paused"):
                            with self.reconciliation_lock:
                                self.state["reconciliation_paused"] = True
                        
                        # RDP portunu geri al
                        success = self.start_rdp_transition("rollback" if mode == "secure" else "secure")
                        if not success:
                            raise RuntimeError("RDP port geri alma işlemi başarısız")
                        
                        # Kullanıcıyı bilgilendir
                        try:
                            messagebox.showwarning(self.t("warn"), self.t("rollback_done").format(port=rollback_port))
                        except Exception:
                            pass
                            
                        # API'yi bilgilendir
                        log("RDP port geri alındı, API'ye bildirim yapılıyor...")
                        if rollback_port == 3389:
                            # Güvenli moddan normal moda dönüş
                            if not self.report_tunnel_action_to_api("RDP", "stop", None):
                                log("API'ye stop bildirimi başarısız")
                        else:
                            # Normal moddan güvenli moda dönüş
                            if not self.report_tunnel_action_to_api("RDP", "start", "53389"):
                                log("API'ye start bildirimi başarısız")
                            
                        # API yanıtını bekle
                        time.sleep(5)
                        
                    finally:
                        # Her durumda API senkronizasyonunu devam ettir
                        with self.reconciliation_lock:
                            self.state["reconciliation_paused"] = False
                        log("RDP geçiş süreci tamamlandı - API iletişimi yeniden başlatıldı")
                        
                threading.Thread(target=handle_rollback, daemon=True).start()

                if mode == "rollback" and rollback_port == 53389:
                    threading.Thread(target=self.start_single_row, args=('3389', '53389', 'RDP', False), daemon=True).start()

            try:
                popup.destroy()
            except Exception:
                pass

        def do_confirm():
            # Eğer geçiş başarılı değilse onay alamaz
            if not transition_success[0]:
                log("RDP geçişi başarısız olduğu için onay işlemi gerçekleştirilemiyor.")
                try:
                    messagebox.showerror(self.t("error"), "RDP geçişi başarısız olduğu için onaylanamıyor.")
                    popup.destroy()
                except Exception:
                    pass
                return

            if countdown_id[0]:
                try:
                    popup.after_cancel(countdown_id[0])
                except Exception:
                    pass
                    
            try:
                popup.destroy()
            except Exception:
                pass
                
            # Handle RDP transition completion and API notification
            def confirm_and_resume():
                try:
                    # Ensure API communication remains paused
                    if not self.state.get("reconciliation_paused"):
                        with self.reconciliation_lock:
                            self.state["reconciliation_paused"] = True
                            log("API iletişimi yeniden duraklatıldı")
                            
                    # Execute the confirmation callback first
                    on_confirm()

                    # Butonun durumu Durdur olarak güncelleniyor
                    self.set_primary_button(self.t('btn_stop'), self.remove_tunnels, "#E53935")
                    self.state["running"] = True
                    self._update_row_ui("3389", "RDP", True)

                    log("RDP port geçişi başarılı, API'ye bildirim yapılıyor...")
                    # Report new RDP state to API
                    if mode == "secure":
                        self.report_tunnel_action_to_api("RDP", "start", "53389")
                    else:
                        self.report_tunnel_action_to_api("RDP", "stop", "3389")

                    # Wait for API notification to complete
                    time.sleep(5)

                    # Resume API synchronization
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = False
                    log("RDP geçiş süreci tamamlandı - API iletişimi yeniden başlatıldı")

                    # Senkronizasyon thread'i yoksa başlat
                    if not any(t.name == "tunnel_sync_loop" and t.is_alive() for t in threading.enumerate()):
                        threading.Thread(target=self.tunnel_sync_loop, name="tunnel_sync_loop", daemon=True).start()
                    
                except Exception as e:
                    log(f"RDP durum güncellemesi sırasında hata: {str(e)}")
                    # Hata durumunda eski porta geri dön
                    try:
                        if mode == "secure":
                            self.start_rdp_transition("rollback")
                        else:
                            self.start_rdp_transition("secure")
                    except Exception:
                        pass
                    # Make sure to resume API communication even if there's an error
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = False
                    
            threading.Thread(target=confirm_and_resume, daemon=True).start()

        confirm_button.config(command=do_confirm)

        def countdown(sec=60):
            if sec < 0:
                do_rollback()
                return
            countdown_label.config(text=str(sec))
            countdown_id[0] = popup.after(1000, countdown, sec - 1)

        def worker():
            try:
                success = self.start_rdp_transition(mode)
                if not success:
                    raise RuntimeError("Port geçişi tamamlanamadı - Servis başlatılamadı veya port değiştirilemedi.")
                    
                transition_success[0] = True
                log("RDP port geçişi başarılı. Kullanıcı onayı bekleniyor...")

                prog_label.pack_forget()
                countdown_label.pack()
                confirm_button.config(state="normal", bg="#4CAF50")
                countdown()

            except Exception as e:
                log(f"RDP port değiştirme hatası: {e}")
                try:
                    messagebox.showerror(self.t("error"), self.t("err_rdp").format(e=e))
                    popup.destroy()
                except Exception:
                    pass

        threading.Thread(target=worker, daemon=True).start()
        popup.protocol("WM_DELETE_WINDOW", do_rollback)

    # ---------- Uygulama kontrol ---------- #
    def apply_tunnels(self, selected_rows):
        started = 0
        clean_rows = []
        for (listen_port, new_port, service) in selected_rows:
            if self.start_single_row(str(listen_port), str(new_port), str(service), manual_action=True):
                clean_rows.append((str(listen_port), str(new_port), str(service)))
                started += 1

        if started == 0:
            try: messagebox.showerror(self.t("error"), "Ports are busy or cannot be listened.")
            except: pass
            return False

        self.write_status(clean_rows, running=True)
        self.state["running"] = True
        self.update_tray_icon()
        self.send_heartbeat_once("online")
        return True

    def remove_tunnels(self):
        for p, st in list(self.state["servers"].items()):
            try: st.stop()
            except: pass
        self.state["servers"].clear()
        self.state["running"] = False
        self.update_tray_icon()
        try:
            self.write_status(self.state.get("selected_rows", []), running=False)
        except: pass
        self.send_heartbeat_once("offline")

    # ---------- Tünel Durum Yönetimi ---------- #
    def get_tunnel_state(self) -> Dict[str, Any]:
        # API'den güncel tünel durumlarını alır (/api/premium/tunnel-status)
        # Returns:
        #     Dict[str, Any]: Her servis için durum bilgileri
        #     Format: {'RDP': {'desired': 'started', 'new_port': 53389}, ...}
        try:
            token = self.state.get("token")
            if not token:
                log("[TunnelState] Token bulunamadı")
                return {}

            log("[TunnelState] API'den durum bilgisi alınıyor...")
            
            # API'den durumları al
            response = self.api_request(
                method="GET",
                endpoint="premium/tunnel-status",  # /api prefix api_request'te ekleniyor
                params={"token": token}
            )

            if not response:
                log("[TunnelState] API yanıt vermedi")
                return {}
                
            if not isinstance(response, dict):
                log(f"[TunnelState] Geçersiz API yanıtı: {type(response)}")
                return {}
                
            # API yanıtını detaylı logla
            log("[TunnelState] -------- Güncel Durum --------")
            for service, info in response.items():
                status_str = (
                    f"Servis: {service}\n"
                    f"  Durum: {info.get('status', 'unknown')}\n"
                    f"  İstenen: {info.get('desired', 'unknown')}\n"
                    f"  Port: {info.get('listen_port', 'N/A')}\n"
                    f"  Yeni Port: {info.get('new_port', 'N/A')}"
                )
                log(f"[TunnelState] {status_str}")
            log("[TunnelState] ------------------------------")
                    
            return response
                
        except Exception as e:
            log(f"Tünel durumu alınırken hata: {e}")
            return {}

    def save_tunnel_state(self, tunnels: Dict[str, Any]):
        try:
            settings = self.load_settings()
            t_settings = settings.get('tunnels', {})
            
            for service, config in tunnels.items():
                if service in DEFAULT_TUNNELS:
                    t_settings.setdefault(service, {})
                    if 'desired' in config:
                        t_settings[service]['desired'] = config['desired']
                    if 'new_port' in config:
                        t_settings[service]['new_port'] = config['new_port']
            
            settings['tunnels'] = t_settings
            self.save_settings(settings)
        except Exception as e:
            log(f"Tünel durumu kaydedilirken hata: {e}")

    def get_local_tunnel_state(self) -> Dict[str, Any]:
        state = {}
        for svc, cfg in DEFAULT_TUNNELS.items():
            lp = int(cfg["listen_port"])
            running = self._is_service_running(lp, svc)
            item = {"status": "started" if running else "stopped", "listen_port": lp}
            if svc == "RDP":
                item["new_port"] = ServiceController.get_rdp_port()
            state[svc] = item
        return state

    def sync_tunnel_states(self):
        if self.state.get("reconciliation_paused"):
            log("Senkronizasyon duraklatıldı, atlanıyor...")
            return
        try:
            remote = self.api_request("GET", "premium/tunnel-status") or {}
            local  = self.get_local_tunnel_state()

            for service, remote_cfg in remote.items():
                if service not in DEFAULT_TUNNELS: 
                    continue
                listen_port = str(DEFAULT_TUNNELS[service]["listen_port"])
                desired = (remote_cfg.get('desired') or 'stopped').lower()
                local_status = (local.get(service, {}).get('status') or 'stopped').lower()

                if desired == 'started' and local_status != 'started':
                    newp = str(remote_cfg.get('new_port') or listen_port)
                    self.start_single_row(listen_port, newp, service)
                    # UI güncelleme: listen_port ile
                    self._update_row_ui(listen_port, service, True)
                elif desired == 'stopped' and local_status != 'stopped':
                    newp = str(remote_cfg.get('new_port') or listen_port)
                    self.stop_single_row(listen_port, newp, service)

            self.report_tunnel_status_once()
        except Exception as e:
            log(f"Tünel durumları senkronize edilirken hata: {e}")
        finally:
            with self.reconciliation_lock:
                self.state["reconciliation_paused"] = False


# ---------- Per-row helpers ---------- #
    def is_port_in_use(self, port: int) -> bool:
        try:
            if os.name == 'nt':
                ps = (
                    f"$p={int(port)};"
                    "$l=Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue;"
                    "if ($l) { Write-Output 'FOUND'; exit 0 } else { exit 1 }"
                )
                res = run_cmd(['powershell','-NoProfile','-Command', ps], timeout=8, suppress_rc_log=True)
                if res and getattr(res, 'returncode', 1) == 0 and getattr(res, 'stdout', '').find('FOUND') >= 0:
                    return True
        except Exception as e:
            log(f"Exception: {e}")
        # Fallback cross-platform bind test
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", int(port)))
            s.close()
            return False
        except OSError:
            return True
        except Exception:
                    pass

    def _find_tree_item(self, listen_port: str, service_name: str):
        try:
            for iid in self.tree.get_children(""):
                vals = self.tree.item(iid).get("values") or []
                if len(vals) >= 3 and str(vals[0]) == str(listen_port) and str(vals[2]).upper() == str(service_name).upper():
                    return iid
        except Exception as e:
            log(f"Exception: {e}")
        return None

    def _update_row_ui(self, listen_port: str, service_name: str, active: bool):
        def apply():
            # RDP için ana butonu da güncelle ve logla
            if service_name.upper() == 'RDP':
                if active:
                    self.set_primary_button(self.t('btn_stop'), self.remove_tunnels, "#E53935")
                    log(f"[UI] Updating row UI for {service_name}: btn_stop")
                else:
                    self.set_primary_button(self.t('btn_row_start'), self.apply_tunnels, "#4CAF50")
                    log(f"[UI] Updating row UI for {service_name}: btn_row_start")
            # Prefer new stacked UI controls
            try:
                key = (str(listen_port), str(service_name).upper())
                rc = getattr(self, 'row_controls', {}).get(key)
                if rc:
                    btn = rc.get("button"); fr = rc.get("frame"); st = rc.get("status")
                    # Hangi butonun güncelleneceğini logla
                    log(f"[UI] Updating row UI for {key}: {'Active' if active else 'Inactive'}")
                    if active:
                        if btn: btn.config(text=self.t('btn_row_stop'), bg="#E53935")
                        if fr: fr.configure(bg="#EEF7EE")
                        if st: st.config(text=f"{self.t('status')}: {self.t('status_running')}")
                    else:
                        if btn: btn.config(text=self.t('btn_row_start'), bg="#4CAF50")
                        if fr: fr.configure(bg="#ffffff")
                        if st: st.config(text=f"{self.t('status')}: {self.t('status_stopped')}")
                    return
            except Exception:
                pass
            # Fallback to legacy tree view if present
            try:
                iid = self._find_tree_item(listen_port, service_name)
                if iid:
                    self.tree.set(iid, self.t("col_active"), "Stop" if active else "Start")
                    self.tree.item(iid, tags=("aktif",) if active else ())
            except Exception:
                pass
        try:
            if self.root:
                self.root.after(0, apply)
                return
        except Exception as e:
            log(f"Exception: {e}")
        apply()

    def _active_rows_from_servers(self):
        rows = []
        try:
            for (p1, p2, svc) in self.PORT_TABLOSU:
                lp = int(str(p1))
                if self.state["servers"].get(lp):
                    rows.append((str(p1), str(p2), str(svc)))
        except Exception as e:
            log(f"Exception: {e}")
        return rows

    def start_single_row(self, p1: str, p2: str, service: str, manual_action: bool = False) -> bool:
        # Tek bir tünel servisini başlatır
        # 
        # Args:
        #     p1: Dinleme portu
        #     p2: Hedef port
        #     service: Servis adı
        #     manual_action: Kullanıcı tarafından tetiklenip tetiklenmediği
        try:
            self.ensure_admin()
        except Exception:
            log("Admin yetkileri alınamadı")
            return False
            
        # RDP için her zaman 3389 tünellenir, koruma aktif olsa bile
        if service.upper() == 'RDP':
            listen_port = '3389'
        else:
            listen_port = str(p1)
        service_upper = str(service).upper()

        if service_upper == 'RDP' and listen_port == '3389':
            # RDP özel durumu
            with self.reconciliation_lock:
                self.state["reconciliation_paused"] = True
                log("RDP geçişi için API senkronizasyonu duraklatıldı.")

            if manual_action:
                # Kullanıcı kaynaklı RDP geçişi - onay penceresi göster
                log("Manuel RDP güvenli port başlatma akışı tetiklendi.")

                def on_rdp_confirm():
                    # RDP port değişikliği onaylandığında çalışacak callback
                    log("RDP port geçişi kullanıcı tarafından onaylandı.")
                    ensure_firewall_allow_for_port(3389, "RDP 3389 (Tunnel)")

                    # Tünel sunucusunu başlat
                    st = TunnelServerThread(self, listen_port, service)
                    st.start()
                    time.sleep(0.15)
                    
                    if st.is_alive():
                        # Tünel başarıyla başlatıldı
                        self.state["servers"][int(listen_port)] = st
                        self.write_status(self._active_rows_from_servers(), running=True)
                        self.state["running"] = True
                        self.update_tray_icon()
                        self.send_heartbeat_once("online")
                        self._update_row_ui(listen_port, service, True)
                        self.state["remote_desired"][service_upper] = "started"
                        
                        # API'ye bildir (ayrı thread'de)
                        threading.Thread(
                            target=self.report_tunnel_action_to_api,
                            args=(service, 'start', p2),
                            daemon=True
                        ).start()
                    else:
                        log("Kullanıcı onayından sonra tünel başlatılamadı.")
                        return False

                self.rdp_move_popup(mode="secure", on_confirm=on_rdp_confirm)
                return True
            else: # API-driven
                # RDP API-driven start (manual_action == False)
                log("API tarafından RDP güvenli port başlatma akışı tetiklendi.")
                try:
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = True
                        log("RDP geçişi için API senkronizasyonu duraklatıldı.")

                    if ServiceController.get_rdp_port() != 53389:
                        if not self.start_rdp_transition("secure"):
                            log("API akışı: RDP 53389'a taşınamadı.")
                            return False

                    # 3389 (tünel) + 53389 (RDP) için firewall
                    ensure_firewall_allow_for_port(3389,  "RDP 3389 (Tunnel)")
                    ensure_firewall_allow_for_port(53389, "RDP 53389")

                    # 3389 tünel
                    st = TunnelServerThread(self, '3389', service)
                    st.start(); time.sleep(0.15)
                    if not st.is_alive():
                        log("RDP tüneli başlatılamadı.")
                        return False

                    self.state["servers"][3389] = st
                    self.write_status(self._active_rows_from_servers(), running=True)
                    self.state["running"] = True
                    self.update_tray_icon(); self.send_heartbeat_once("online")
                    self._update_row_ui('3389', service, True)
                    self.state["remote_desired"][service_upper] = "started"
                    self.set_primary_button(self.t('btn_stop'), self.remove_tunnels, "#E53935")

                    # API bildirimi
                    threading.Thread(target=self.report_tunnel_action_to_api, args=(service, 'start', p2), daemon=True).start()

                    # 8-9: 5 sn bekle, resume
                    def _resume():
                        time.sleep(5)
                        with self.reconciliation_lock:
                            self.state["reconciliation_paused"] = False
                        log("RDP geçiş süreci tamamlandı - API iletişimi yeniden başlatıldı")
                    threading.Thread(target=_resume, daemon=True).start()
                    return True

                except Exception as e:
                    log(f"API RDP başlatma hatası: {e}")
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = False
                    return False

        # Non-RDP flow
        if self.is_port_in_use(int(listen_port)):
            try:
                if not messagebox.askyesno(self.t("warn"), f"Port {listen_port} seems to be in use by a service. Continue?"):
                    return False
            except Exception:
                pass
        
        st = TunnelServerThread(self, listen_port, service)
        st.start(); time.sleep(0.15)
        if st.is_alive():
            self.state["servers"][int(listen_port)] = st
            self.write_status(self._active_rows_from_servers(), running=True)
            self.state["running"] = True
            self.update_tray_icon(); self.send_heartbeat_once("online")
            self._update_row_ui(listen_port, service, True)
            self.state["remote_desired"][service_upper] = "started"
            
            # Report to API and wait for confirmation
            def notify_and_resume():
                try:
                    self.report_tunnel_action_to_api(service, 'start', p2)
                finally:
                    # Resume reconciliation after a short delay
                    time.sleep(3)
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = False
            
            threading.Thread(target=notify_and_resume, daemon=True).start()
            return True
        
        try: messagebox.showerror(self.t("error"), "Port is busy or cannot be listened.")
        except: pass
        return False

    def stop_single_row(self, p1: str, p2: str, service: str, manual_action: bool = False) -> bool:
        # Pause reconciliation before making changes
        with self.reconciliation_lock:
            self.state["reconciliation_paused"] = True

        service_upper = str(service).upper()
        # RDP dashboard akışında tünel her zaman 3389'u dinler
        listen_port = '3389' if service_upper == 'RDP' else str(p1)

        if service_upper == 'RDP' and listen_port == '3389':
            # Önce tüneli kapat
            st = self.state["servers"].pop(int(listen_port), None)
            if st:
                try: st.stop()
                except Exception: pass

            if manual_action:
                self.log("Manuel RDP güvenli port durdurma akışı tetiklendi.")
                def on_rdp_confirm_rollback():
                    self.write_status(self._active_rows_from_servers(), running=bool(self.state["servers"]))
                    if not self.state["servers"]:
                        self.state["running"] = False
                        self.send_heartbeat_once("offline")
                    self.update_tray_icon()
                    self._update_row_ui(listen_port, service, False)
                    self.state["remote_desired"][service_upper] = "stopped"
                    threading.Thread(target=self.report_tunnel_action_to_api,
                                    args=(service, 'stop', p2), daemon=True).start()
                self.rdp_move_popup(mode="rollback", on_confirm=on_rdp_confirm_rollback)
                return True
            else:
                # API-driven
                ensure_firewall_allow_for_port(3389,  "RDP 3389")
                ensure_firewall_allow_for_port(53389, "RDP 53389")
                if not self.start_rdp_transition("rollback"):
                    log("API akışı: RDP 3389'a geri alınamadı.")

                self.write_status(self._active_rows_from_servers(), running=bool(self.state["servers"]))
                if not self.state["servers"]:
                    self.state["running"] = False
                    self.send_heartbeat_once("offline")
                self.update_tray_icon()
                self._update_row_ui('3389', service, False)
                self.state["remote_desired"][service_upper] = "stopped"
                threading.Thread(target=self.report_tunnel_action_to_api, args=(service, 'stop', p2), daemon=True).start()

                def _resume():
                    time.sleep(5)
                    with self.reconciliation_lock:
                        self.state["reconciliation_paused"] = False
                    log("RDP geçiş süreci tamamlandı - API iletişimi yeniden başlatıldı")
                threading.Thread(target=_resume, daemon=True).start()
                return True

        # Non-RDP stop
        st = self.state["servers"].pop(int(listen_port), None)
        if st:
            try:
                st.stop()
            except Exception:
                pass
        
        self.write_status(self._active_rows_from_servers(), running=len(self.state["servers"]) > 0)
        if not self.state["servers"]:
            self.state["running"] = False
            self.send_heartbeat_once("offline")
        self.update_tray_icon()
        self._update_row_ui(listen_port, service, False)
        self.state["remote_desired"][service_upper] = "stopped"
        
        # Report to API and wait for confirmation
        def notify_and_resume():
            try:
                self.report_tunnel_action_to_api(service, 'stop', p2)
            finally:
                # Resume reconciliation after a short delay
                time.sleep(3)
                with self.reconciliation_lock:
                    self.state["reconciliation_paused"] = False
        
        threading.Thread(target=notify_and_resume, daemon=True).start()
        return True

    def report_tunnel_status_once(self):
        # Güncel tünel durumlarını API'ye bildirir (/api/agent/tunnel-status)
        # Her servis için status, listening_port ve varsa new_port bilgilerini gönderir
        try:
            token = self.state.get("token")
            if not token:
                log("Token bulunamadı, tünel durumu raporlanamıyor")
                return False

            # Durum raporu hazırla - sadece tanımlı servisleri raporla
            statuses = []
            for service, default_config in DEFAULT_TUNNELS.items():
                listen_port = default_config["listen_port"]
                running = self._is_service_running(listen_port, service)
                status = {
                    "service": service,
                    "status": "started" if running else "stopped",
                    "listen_port": listen_port
                }
                # RDP için hem 3389 hem 53389 portunu kontrol et
                if service == "RDP":
                    current_port = ServiceController.get_rdp_port()
                    status["new_port"] = current_port
                    rdp_running = self._is_service_running(3389, service) or self._is_service_running(53389, service)
                    status["status"] = "started" if rdp_running else "stopped"
                statuses.append(status)
                log(f"Tünel durumu: {service} -> {status['status']} (port: {listen_port})")

            # /api/agent/tunnel-status endpoint'ine gönder
            response = self.api_request(
                method="POST",
                endpoint="agent/tunnel-status",
                json={
                    "token": token,
                    "statuses": statuses  # API modeline uygun format
                }
            )

            if not response:
                log("Tünel durumu güncellemesi başarısız")
                return False

            if isinstance(response, dict):
                if response.get("status") == "ok":
                    log("Tünel durumları başarıyla güncellendi")
                    return True
                
                error = response.get("error", "Bilinmeyen hata")
                log(f"Tünel durumu güncelleme hatası: {error}")
                
            return False

        except Exception as e:
            log(f"Tünel durumu raporlanırken hata: {e}")
            return False

    def report_tunnel_action_to_api(self, service: str, action: str,
                                    new_port: Optional[Union[str, int]] = None) -> bool:
        try:
            token = self.state.get("token")
            if not token:
                log("Token yok; eylem bildirilemedi")
                return False

            payload = {
                "token": token,
                "service": str(service or "").upper(),
                "action": action if action in ("start", "stop") else "stop",
            }
            if new_port and str(new_port) != '-':
                payload["new_port"] = int(str(new_port))

            resp = self.api_request("POST", "premium/tunnel-set", json=payload)
            if isinstance(resp, dict) and resp.get("status") in ("queued", "ok", "success"):
                # yerel önbellek güncelle
                self.active_tunnels = getattr(self, "active_tunnels", {})
                self.active_tunnels.setdefault(payload["service"], {})\
                    .update({"running": payload["action"] == "start",
                            "new_port": payload.get("new_port")})
                log(f"Tünel eylemi bildirildi: {payload}")
                return True

            log(f"Tünel eylemi bildirimi başarısız: {resp}")
            return False
        except Exception as e:
            log(f"Tünel eylemi raporlanırken hata: {e}")
            return False

    # --- helper: registry'yi restart etmeden yazmak için ---
    def _set_rdp_port_registry(self, new_port: int) -> bool:
        res = run_cmd([
            'reg','add','HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp',
            '/v','PortNumber','/t','REG_DWORD','/d', str(int(new_port)), '/f'
        ], timeout=10, suppress_rc_log=True)
        ok = (res is not None and getattr(res, "returncode", 1) == 0)
        if not ok:
            log(f"set_rdp_port_registry failed for {new_port}")
        return ok

    def _ensure_rdp_firewall_both(self):
        try:
            ensure_firewall_allow_for_port(3389,  "RDP 3389")
            ensure_firewall_allow_for_port(53389, "RDP 53389")
        except Exception as e:
            log(f"ensure_rdp_firewall_both err: {e}")

    def start_rdp_transition(self, transition_mode: str = "secure") -> bool:
        """
        3389<->53389 arası güvenli geri/ileri geçiş.
        Adımlar: stop TermService -> firewall iki port -> reg set -> start TermService -> dinleme/doğrulama.
        """
        try:
            if transition_mode not in ("secure", "rollback"):
                log(f"Geçersiz geçiş modu: {transition_mode}")
                return False

            target = 53389 if transition_mode == "secure" else 3389
            source = 3389  if transition_mode == "secure" else 53389
            deadline = time.time() + 60

            # Zaten hedefte ve dinliyorsa bitir
            cur = ServiceController.get_rdp_port()
            if cur == target:
                svc_ok    = (ServiceController._sc_query_code("TermService") == 4)
                tgt_listen = self.is_port_in_use(target)
                if svc_ok and tgt_listen:
                    log(f"RDP zaten {target} portunda ve dinlemede")
                    return True
                log("Registry hedefte ama dinleme yok; TermService restart edilecek")

            # 2) Servisi durdur
            if not ServiceController.stop("TermService", timeout=40):
                log("TermService durdurulamadı")
                return False

            # 3) Firewall iki port için de garanti
            self._ensure_rdp_firewall_both()

            # 4) Registry'yi hedef porta yaz
            if not self._set_rdp_port_registry(target):
                # başarısızsa eski durumu geri getir ve çık
                self._set_rdp_port_registry(source)
                ServiceController.start("TermService")
                return False

            # 5) Servisi başlat
            if not ServiceController.start("TermService", timeout=40):
                log("TermService başlatılamadı")
                return False

            # 5→ doğrulama
            while time.time() < deadline:
                svc_ok     = (ServiceController._sc_query_code("TermService") == 4)
                reg_ok     = (ServiceController.get_rdp_port() == target)
                tgt_listen = self.is_port_in_use(target)
                src_listen = self.is_port_in_use(source)
                log(f"[RDP transition] svc_ok={svc_ok} reg_ok={reg_ok} tgt_listen={tgt_listen} src_listen={src_listen}")
                # kaynak portun boşalması şartı senin talebine uygun
                if svc_ok and reg_ok and tgt_listen and not src_listen:
                    log(f"RDP {target} portuna taşındı (dinleme aktif)")
                    return True
                time.sleep(1)

            # 60 sn timeout → rollback
            log(f"Timeout, {source} portuna geri dönülüyor")
            ServiceController.stop("TermService")
            self._set_rdp_port_registry(source)
            ServiceController.start("TermService")
            return False

        except Exception as e:
            log(f"RDP geçiş hatası: {e}")
            try:
                # emniyet rollback
                ServiceController.stop("TermService")
                self._set_rdp_port_registry(3389 if transition_mode == "secure" else 53389)
                ServiceController.start("TermService")
            except Exception:
                pass
            return False


        

# ---------- Remote management helpers ---------- #
    def _collect_open_ports_windows(self):
        items = []
        # Güvenlik riski oluşturabilecek yaygın portlar
        risky_ports = {
            20: "FTP Data",
            21: "FTP Control",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            135: "RPC",
            137: "NetBIOS",
            139: "NetBIOS",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            1434: "MSSQL Browser",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            53389: "RDP Alternative"
        }
        
        try:
            # Sadece TCP portlarını kontrol et
            cmd = ["netstat", "-ano", "-p", "TCP"]
            res = run_cmd(cmd, timeout=10, suppress_rc_log=True)
            if not res or res.returncode != 0:
                return items
                
            for line in (res.stdout or "").splitlines():
                L = line.split()
                if not L or len(L) < 5:
                    continue
                    
                # Sadece TCP dinleme portlarını işle
                if L[0].upper() == "TCP":
                    local = L[1]
                    state = L[3]
                    pid = L[4] if len(L) >= 5 else None
                    
                    # Sadece LISTEN durumundaki portları al
                    if state.upper() not in ("LISTEN", "LISTENING"):
                        continue
                        
                    try:
                        addr, port = local.rsplit(":", 1)
                        port = int(port) if port.isdigit() else None
                        
                        # Port numarası geçerli ve risk listesinde ise ekle
                        if port and (port in risky_ports or port < 1024):
                            items.append({
                                "port": port,
                                "proto": "TCP",
                                "addr": addr,
                                "state": state.upper(),
                                "service": risky_ports.get(port, "Unknown"),
                                "pid": int(pid) if (pid and pid.isdigit()) else None,
                            })
                    except Exception:
                        continue
        except Exception as e:
            log(f"collect_open_ports error: {e}")
        # Keep only listening-like entries and with valid port
        out = []
        for it in items:
            try:
                if it.get("port") and (it.get("state") in ("LISTEN", "LISTENING", "LISTEN-DRAIN", "ESTABLISHED") or it.get("proto")=="UDP"):
                    out.append(it)
            except Exception:
                pass
        return out

    def report_open_ports_once(self):
        try:
            token = self.state.get("token")
            if not token:
                return
            ports = self._collect_open_ports_windows() if os.name == 'nt' else []
            payload = {"token": token, "ports": ports}
            r = requests.post(f"{API_URL}/agent/open-ports", json=payload, timeout=8)
            if r.status_code != 200:
                log(f"open-ports HTTP {r.status_code}: {r.text[:120]}")
        except Exception as e:
            log(f"report_open_ports_once err: {e}")

    def report_open_ports_loop(self):
        while True:
            try:
                self.report_open_ports_once()
            except Exception as e:
                log(f"report_open_ports_loop err: {e}")
            time.sleep(600)

    def _normalize_service(self, s: str) -> str:
        s = (s or '').upper()
        if s == 'MYSQL':
            return 'MySQL'
        return s

    def _is_service_running(self, listen_port: int, service_name: str) -> bool:
        try:
            st = self.state["servers"].get(int(listen_port))
            if not st:
                return False
            return str(st.service_name or '').upper() == str(service_name or '').upper()
        except Exception:
            return False

    def reconcile_remote_tunnels_loop(self):
        # Uzaktan tünel yönetimi döngüsü - API ile senkronizasyonu sağlar
        log("Uzaktan yönetim döngüsü başlatıldı.")
        while True:
            try:
                with self.reconciliation_lock:
                    if self.state.get("reconciliation_paused"):
                        log("Senkronizasyon duraklatıldı, bekleniyor...")
                        time.sleep(1)
                        continue

                token = self.state.get("token")
                if not token:
                    log("Token bulunamadı, bekleniyor...")
                    time.sleep(15)
                    continue

                # Hedef durumu API'den al
                response = self.api_request("GET", "premium/tunnel-status", params={"token": token})
                if not response:
                    log("Tünel durumları alınamadı - Sunucu yanıt vermedi")
                    time.sleep(15)
                    continue

                if not isinstance(response, dict):
                    log(f"Geçersiz API yanıt formatı: {response}")
                    time.sleep(15)
                    continue

                data = response
                if data:
                    log(f"API'den hedef durum alındı: {data}")
                if data:
                    log(f"API'den hedef durum alındı: {data}")

                # expected: { 'RDP': {listen_port:3389, desired:'started'|'stopped', new_port:53389}, ... }
                order = [("RDP",3389), ("MSSQL",1433), ("MYSQL",3306), ("FTP",21), ("SSH",22)]
                for svc_u, lp in order:
                    entry = data.get(svc_u)
                    if not isinstance(entry, dict):
                        continue
                    desired = (entry.get('desired') or 'stopped').lower()
                    running = self._is_service_running(lp, svc_u)
                    prev = self.state["remote_desired"].get(svc_u)
                    if prev == desired and ((desired=='started' and running) or (desired=='stopped' and not running)):
                        continue

                    if desired == 'started' and not running:
                        log(f"API komutu: '{svc_u}' servisi başlatılıyor.")
                        try:
                            if svc_u == 'RDP' and ServiceController.get_rdp_port() != 53389:
                                ServiceController.switch_rdp_port(53389)
                            newp = entry.get('new_port') or (53389 if svc_u=='RDP' else '-')
                            self.start_single_row(str(lp), str(newp), self._normalize_service(svc_u))
                        except Exception as e:
                            log(f"remote start {svc_u} err: {e}")
                    elif desired == 'stopped' and running:
                        log(f"API komutu: '{svc_u}' servisi durduruluyor.")
                        try:
                            self.stop_single_row(str(lp), str(entry.get('new_port') or '-'), self._normalize_service(svc_u))
                            if svc_u == 'RDP' and ServiceController.get_rdp_port() != 3389:
                                ServiceController.switch_rdp_port(3389)
                        except Exception as e:
                            log(f"remote stop {svc_u} err: {e}")
                    self.state["remote_desired"][svc_u] = desired
                # push current status back so dashboard sees up-to-date state
                try:
                    self.report_tunnel_status_once()
                except Exception:
                    pass
            except Exception as e:
                log(f"reconcile_remote_tunnels err: {e}")
            time.sleep(300)

    # ---------- Tray ---------- #
    def tray_make_image(self, active):
        from PIL import Image, ImageDraw
        col = "green" if active else "red"
        img = Image.new('RGB', (64, 64), "white")
        d = ImageDraw.Draw(img)
        d.ellipse((8, 8, 56, 56), fill=col)
        return img

    def tray_loop(self):
        if not TRY_TRAY:
            return
            
        # Tray ikonu oluştur
        icon = pystray.Icon("honeypot_client")
        self.state["tray"] = icon
        icon.title = f"{self.t('app_title')} v{__version__}"
        icon.icon = self.tray_make_image(self.state["running"])
        
        def show_window():
            try:
                if self.root:
                    # Pencereyi göster ve öne getir
                    self.root.deiconify()
                    self.root.lift()
                    self.root.focus_force()
                    
                    # Pencere konumunu merkeze al
                    screen_width = self.root.winfo_screenwidth()
                    screen_height = self.root.winfo_screenheight()
                    window_width = WINDOW_WIDTH
                    window_height = WINDOW_HEIGHT
                    center_x = int(screen_width/2 - window_width/2)
                    center_y = int(screen_height/2 - window_height/2)
                    self.root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
            except Exception as e:
                log(f"Show window error: {e}")
                
        def minimize_to_tray():
            try:
                if self.root:
                    self.root.withdraw()
            except Exception as e:
                log(f"Minimize error: {e}")
                
        def exit_app():
            if self.state["running"]:
                messagebox.showwarning(self.t("warn"), self.t("tray_warn_stop_first"))
                return
                
            # Watchdog'u durdur
            try:
                write_watchdog_token('stop')
            except Exception as e:
                log(f"Watchdog stop error: {e}")
                
            # Tray ikonunu kaldır
            try:
                icon.stop()
            except Exception:
                pass
                
            # Ana pencereyi kapat
            if self.root:
                self.root.destroy()
                
            # Single instance kontrolünü kapat
            try:
                self.stop_single_instance_server()
            except Exception:
                pass
                
            os._exit(0)
            
        # Callback'leri kaydet
        self.show_cb = show_window
        self.minimize_cb = minimize_to_tray
        
        # Tray menüsünü oluştur
        try:
            menu = pystray.Menu(
                TrayItem(self.t('tray_show'), lambda: show_window(), default=True),
                TrayItem(self.t('tray_exit'), lambda: exit_app())
            )
            icon.menu = menu
        except Exception as e:
            log(f"Tray menu error: {e}")
            # Fallback: basit menü
            icon.menu = (
                TrayItem(self.t('tray_show'), lambda: show_window()),
                TrayItem(self.t('tray_exit'), lambda: exit_app())
            )
            
        # Tray ikonunu başlat    
        icon.run()

    def update_tray_icon(self):
        if not TRY_TRAY: return
        icon = self.state.get("tray")
        if not icon: return
        icon.icon = self.tray_make_image(self.state["running"])
        icon.title = f"{self.t('app_title')} v{__version__}"
        icon.visible = True
        
    def on_close(self):
        # Pencere kapatma işleyicisi
        try:
            # Tray ikonu varsa minimize et
            if TRY_TRAY and self.state.get("tray"):
                if hasattr(self, 'minimize_cb') and self.minimize_cb:
                    self.minimize_cb()
            # Tray yoksa normal kapat
            else:
                if self.state["running"]:
                    messagebox.showwarning(self.t("warn"), self.t("tray_warn_stop_first"))
                    return
                self.root.destroy()
                try:
                    write_watchdog_token('stop')
                except:
                    pass
                self.stop_single_instance_server()
                os._exit(0)
        except Exception as e:
            log(f"Window close error: {e}")

    def stop_single_instance_server(self):
        s = self.state.get("ctrl_sock")
        if s:
            try: s.close()
            except: pass
            self.state["ctrl_sock"] = None

    # ---------- Update Watchdog (hourly) ---------- #
    def update_watchdog_loop(self):
        while True:
            try:
                # 3600 seconds
                for _ in range(360):
                    time.sleep(10)
                self.check_updates_and_apply_silent()
            except Exception as e:
                log(f"update_watchdog_loop error: {e}")

    # ---------- Daemon ---------- #
    def run_daemon(self):
        self.state["token"] = self.load_token()
        self.state["public_ip"] = self.get_public_ip()
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        threading.Thread(target=self.tunnel_watchdog_loop, daemon=True).start()
        # Remote management: report open ports + reconcile desired tunnels
        try:
            threading.Thread(target=self.report_open_ports_loop, daemon=True).start()
        except Exception as e:
            log(f"open ports reporter start failed: {e}")
        try:
            threading.Thread(target=self.reconcile_remote_tunnels_loop, daemon=True).start()
        except Exception as e:
            log(f"remote tunnels loop start failed: {e}")
        # Start firewall agent in background (Windows/Linux)
        try:
            self.start_firewall_agent()
        except Exception as e:
            log(f"firewall agent start failed (daemon): {e}")
        # Start external watchdog
        try:
            start_watchdog_if_needed()
        except Exception as e:
            log(f"watchdog start error: {e}")
        # Hourly update checker
        try:
            threading.Thread(target=self.update_watchdog_loop, daemon=True).start()
        except Exception as e:
            log(f"update watchdog thread error: {e}")

        cons = self.read_consent()
        if not cons.get("accepted"):
            log("Daemon: kullanıcı onayı yok, tünel uygulanmayacak.")
            return

        saved_rows, saved_running = self.read_status()
        rows = saved_rows if saved_rows else [(p1, p2, s) for (p1, p2, s) in self.PORT_TABLOSU]
        self.state["selected_rows"] = [(str(a[0]), str(a[1]), str(a[2])) for a in rows]

        if not rows:
            log("Daemon: aktif port yok, beklemede.")

        while True:
            try:
                if rows and not self.state.get("running"):
                    ok = self.apply_tunnels(rows)
                    if ok:
                        log("Daemon: Tüneller aktif (arka plan).")
                time.sleep(5)
            except KeyboardInterrupt:
                break
            except Exception as e:
                log(f"Daemon loop err: {e}")
        try:
            self.remove_tunnels()
        except Exception as e:
            log(f"Exception: {e}")
        log("Daemon: durduruldu.")

    # ---------- Firewall Agent ---------- #
    def start_firewall_agent(self):
        if FW_AGENT is None:
            log("firewall_agent module not available; skipping.")
            return
        token = self.state.get("token")
        if not token:
            log("No token; firewall agent not started.")
            return
        # Derive API base root (strip trailing /api if present)
        base = (API_URL or "").strip().rstrip('/')
        if base.lower().endswith('/api'):
            api_base_root = base[:-4]
        else:
            api_base_root = base
        cidr_feed = os.environ.get("CIDR_FEED_BASE", "https://www.ipdeny.com/ipblocks/data/countries")

        def agent_thread():
            try:
                agent = FW_AGENT.Agent(
                    api_base=api_base_root,
                    token=token,
                    refresh_interval=int(os.environ.get("REFRESH_INTERVAL_SEC", "10")),
                    cidr_feed_base=cidr_feed,
                    logger=LOGGER,
                )
                log(f"Firewall agent starting; API_BASE={api_base_root}, FEED={cidr_feed}")
                agent.run_forever()
            except Exception as e:
                log(f"Firewall agent error: {e}")

        # Start once; keep reference if needed
        if not self.state.get("fw_agent_started"):
            threading.Thread(target=agent_thread, daemon=True).start()
            self.state["fw_agent_started"] = True

    # ---------- GUI ---------- #
    def build_gui(self, minimized=False):
        # One-time notice for simplicity and firewall prompts
        try:
            # Ensure root exists before messagebox
            if not self.root:
                self.root = tk.Tk()
                self.root.withdraw()  # Geçici olarak gizle
                
                # Ana pencere özelliklerini ayarla
                self.root.title(f"{self.t('app_title')} v{__version__}")
                self.root.protocol("WM_DELETE_WINDOW", self.on_close)
                self.root.resizable(True, True)
                
                # Ekran merkezi pozisyonunu hesapla
                window_width = WINDOW_WIDTH
                window_height = WINDOW_HEIGHT
                screen_width = self.root.winfo_screenwidth()
                screen_height = self.root.winfo_screenheight()
                center_x = int(screen_width/2 - window_width/2)
                center_y = int(screen_height/2 - window_height/2)
                
                # Pencereyi merkeze konumlandır
                self.root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
                
            self.first_run_notice()
            
            # Continue building actual UI below (root will be reconfigured)
            if not minimized:
                try:
                    self.root.deiconify()  # Pencereyi göster
                    self.root.lift()  # Öne getir
                    self.root.focus_force()  # Fokusla
                except Exception as e:
                    log(f"Window show error: {e}")
                    pass
        except Exception as e:
            log(f"build_gui pre-notice error: {e}")
        self.start_single_instance_server()

        token = self.load_token()
        self.state["token"] = token
        self.state["public_ip"] = self.get_public_ip()
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        threading.Thread(target=self.tunnel_watchdog_loop, daemon=True).start()
        # Remote management: report open ports + reconcile desired tunnels
        try:
            threading.Thread(target=self.report_open_ports_loop, daemon=True).start()
        except Exception as e:
            log(f"open ports reporter start failed: {e}")
        try:
            threading.Thread(target=self.reconcile_remote_tunnels_loop, daemon=True).start()
        except Exception as e:
            log(f"remote tunnels loop start failed: {e}")
        # Start firewall agent in background
        try:
            self.start_firewall_agent()
        except Exception as e:
            log(f"firewall agent start failed (gui): {e}")
        # Start external watchdog
        try:
            start_watchdog_if_needed()
        except Exception as e:
            log(f"watchdog start error: {e}")
        # Hourly update checker
        try:
            threading.Thread(target=self.update_watchdog_loop, daemon=True).start()
        except Exception as e:
            log(f"update watchdog thread error: {e}")

        dashboard_url = f"https://honeypot.yesnext.com.tr/dashboard?token={token}"

        if not self.root:
            self.root = tk.Tk()
        else:
            try:
                self.root.deiconify()
            except Exception:
                pass
        self.root.title(f"{self.t('app_title')} v{__version__}")
        self.root.geometry("820x620")
        self.root.configure(bg="#f5f5f5")

        # dil (settings)
        self.lang = read_settings().get("language", "tr")

        try:
            self.ensure_consent_ui()
        except Exception as e:
            log(f"consent ui error: {e}")

        # Menu
        menubar = tk.Menu(self.root)
        menu_settings = tk.Menu(menubar, tearoff=0)
        def set_lang(code):
            try: write_settings(code)
            except: pass
            messagebox.showinfo(self.t("info"), self.t("restart_needed_lang"))
            exe = self.current_executable()
            try:
                subprocess.Popen([exe] + sys.argv[1:], shell=False)
            except Exception:
                pass
            os._exit(0)
        lang_menu = tk.Menu(menu_settings, tearoff=0)
        lang_menu.add_command(label=self.t("menu_lang_tr"), command=lambda: set_lang("tr"))
        lang_menu.add_command(label=self.t("menu_lang_en"), command=lambda: set_lang("en"))
        menu_settings.add_cascade(label=self.t("menu_language"), menu=lang_menu)
        menubar.add_cascade(label=self.t("menu_settings"), menu=menu_settings)

        menu_help = tk.Menu(menubar, tearoff=0)
        # Static version label as disabled entry at the top
        menu_help.add_command(label=f"Sürüm: v{__version__}" if self.lang == 'tr' else f"Version: v{__version__}", state='disabled')
        # Logs opener
        def open_logs():
            try:
                if os.name == 'nt':
                    os.startfile(LOG_FILE)
                else:
                    webbrowser.open(f"file://{LOG_FILE}")
            except Exception as e:
                log(f"open_logs error: {e}")
        menu_help.add_command(label=self.t("menu_logs"), command=open_logs)
        # GitHub opener
        def open_github():
            try:
                webbrowser.open(f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}")
            except Exception as e:
                log(f"open_github error: {e}")
        menu_help.add_command(label=self.t("menu_github"), command=open_github)
        menu_help.add_separator()
        menu_help.add_command(label=self.t("menu_check_updates"), command=self.check_updates_and_prompt)
        menubar.add_cascade(label=self.t("menu_help"), menu=menu_help)
        self.root.config(menu=menubar)

        # Kapatma → tray
        def on_close():
            # Always minimize to tray; app keeps running in background
            try:
                self.root.withdraw()
            except Exception:
                pass
        self.root.protocol("WM_DELETE_WINDOW", on_close)

        style = ttk.Style()
        try: style.theme_use("clam")
        except: pass
        style.configure("TButton", font=("Arial", 11), padding=6)
        style.configure("Treeview.Heading", font=("Arial", 10, "bold"))
        style.configure("Treeview", rowheight=28)

        # Sunucu Bilgileri
        frame1 = tk.LabelFrame(self.root, text=self.t("server_info"), padx=10, pady=10, bg="#f5f5f5", font=("Arial", 11, "bold"))
        frame1.pack(fill="x", padx=15, pady=10)

        def copy_entry(entry: tk.Entry):
            try:
                value = entry.get()
                self.root.clipboard_clear(); self.root.clipboard_append(value); self.root.update()
                messagebox.showinfo(self.t("copy"), value)
            except Exception as e:
                log(f"copy_entry error: {e}")

        def open_dashboard():
            webbrowser.open(dashboard_url)

        attack_count_val = self.fetch_attack_count_sync(token)
        if attack_count_val is None: attack_count_val = 0

        info_rows = [
            (self.t("lbl_pc_ip"), f"{SERVER_NAME} ({self.state['public_ip']})", "ip"),
            (self.t("lbl_token"), token, "token"),
            (self.t("lbl_dashboard"), dashboard_url, "dash"),
            (self.t("lbl_attacks"), str(attack_count_val), "attacks"),
        ]

        # satırlar
        for idx, (label, value, key) in enumerate(info_rows):
            tk.Label(frame1, text=label + ":", font=("Arial", 11), bg="#f5f5f5",
                     width=18, anchor="w").grid(row=idx, column=0, sticky="w", pady=3)
            entry = tk.Entry(frame1, width=60, font=("Arial", 10))
            if value is not None:
                entry.insert(0, str(value))
            entry.config(state="readonly")
            entry.grid(row=idx, column=1, padx=5, pady=3)

            tk.Button(frame1, text="📋", command=lambda e=entry: copy_entry(e)).grid(row=idx, column=2, padx=3)

            if key == "dash":
                tk.Button(frame1, text="🌐 " + self.t("open"), command=open_dashboard).grid(row=idx, column=3, padx=3)

            if key == "attacks":
                tk.Button(frame1, text="↻ " + self.t("refresh"), command=lambda: self.refresh_attack_count(async_thread=True)).grid(row=idx, column=3, padx=3)
                self.attack_entry = entry

            if key == "ip":
                self.ip_entry = entry

        self.poll_attack_count()

        # Port Tünelleme
        frame2 = tk.LabelFrame(self.root, text=self.t("port_tunnel"), padx=10, pady=10, bg="#f5f5f5", font=("Arial", 11, "bold"))
        frame2.pack(fill="both", expand=True, padx=15, pady=10)

        # Stacked per-row controls (better UX than table cell clicks)
        self.row_controls = {}
        saved_rows, saved_running = self.read_status()

        def make_row(parent, p1, p2, servis):
            fr = tk.Frame(parent, bg="#ffffff", padx=8, pady=8, highlightbackground="#ddd", highlightthickness=1)
            fr.pack(fill="x", pady=6)
            # Columns grow: make the middle space flexible so the button sticks right
            try:
                fr.grid_columnconfigure(2, weight=1)
            except Exception:
                pass
            # Labels
            tk.Label(fr, text=f"{self.t('col_service')}: {servis}", bg="#ffffff", font=("Arial", 11, "bold"), anchor="w").grid(row=0, column=0, sticky="w")
            tk.Label(fr, text=f"{self.t('col_listen')}: {p1}", bg="#ffffff", anchor="w").grid(row=1, column=0, sticky="w")
            tk.Label(fr, text=f"{self.t('col_new')}: {p2}", bg="#ffffff", anchor="w").grid(row=1, column=1, sticky="w", padx=10)
            # Status label
            status_lbl = tk.Label(fr, text=f"{self.t('status')}: {self.t('status_stopped')}", bg="#ffffff", anchor="w")
            status_lbl.grid(row=1, column=2, sticky="w", padx=10)
            # Button (right aligned)
            btn = tk.Button(fr, text=self.t('btn_row_start'), bg="#4CAF50", fg="white", padx=18, pady=6, font=("Arial", 10, "bold"))

            def toggle():
                is_rdp = (str(servis).upper() == 'RDP')

                if is_rdp:
                    self.state['reconciliation_paused'] = True
                    log("RDP işlemi için uzlaştırma döngüsü duraklatıldı.")

                try:
                    cur = btn["text"].lower()
                    if cur == self.t('btn_row_start').lower():
                        # Pass manual_action=True for GUI-initiated actions
                        if self.start_single_row(str(p1), str(p2), str(servis), manual_action=True):
                            # For non-RDP, the UI updates instantly.
                            # For RDP, the popup handles the flow, but we can preemptively update the UI.
                            if not is_rdp:
                                btn.config(text=self.t('btn_row_stop'), bg="#E53935")
                                fr.configure(bg="#EEF7EE")
                                status_lbl.config(text=f"{self.t('status')}: {self.t('status_running')}")
                    else:
                        # Pass manual_action=True for GUI-initiated actions
                        if self.stop_single_row(str(p1), str(p2), str(servis), manual_action=True):
                            if not is_rdp:
                                btn.config(text=self.t('btn_row_start'), bg="#4CAF50")
                                fr.configure(bg="#ffffff")
                                status_lbl.config(text=f"{self.t('status')}: {self.t('status_stopped')}")
                finally:
                    if is_rdp:
                        self.state['reconciliation_paused'] = False
                        log("RDP işlemi tamamlandı, uzlaştırma döngüsü devam ettiriliyor.")
                        # Immediately report the new status to the API
                        threading.Thread(target=self.report_tunnel_status_once, daemon=True).start()

            btn.config(command=toggle)
            btn.grid(row=0, column=3, rowspan=2, sticky="e", padx=10)
            self.row_controls[(str(p1), str(servis).upper())] = {"frame": fr, "button": btn, "status": status_lbl}

        for (p1, p2, servis) in self.PORT_TABLOSU:
            make_row(frame2, p1, p2, servis)

        # Apply previous state to UI
        if saved_rows:
            for (sp1, sp2, ssvc) in saved_rows:
                key = (str(sp1), str(ssvc).upper())
                rc = self.row_controls.get(key)
                if rc:
                    rc["button"].config(text=self.t('btn_row_stop'), bg="#E53935")
                    rc["frame"].configure(bg="#EEF7EE")
                    rc["status"].config(text=f"{self.t('status')}: {self.t('status_running')}")

        # Optional silent auto-update on startup if configured and no active tunnels
        try:
            if os.environ.get('AUTO_UPDATE_SILENT') == '1':
                if not self.state.get('servers'):
                    self.check_updates_and_apply_silent()
        except Exception as e:
            log(f"auto-update silent error: {e}")

        # Tray
        if TRY_TRAY:
            threading.Thread(target=self.tray_loop, daemon=True).start()

        # Başlangıçta tüm servisleri durmuş olarak başlat
        self.state["running"] = False
        self.state["servers"] = {}
        self.state["selected_rows"] = []
        self.write_status([], running=False)
        # Tray ikonunu kırmızı olarak güncelle (pasif)
        try:
            self.update_tray_icon()
        except Exception as e:
            log(f"Exception: {e}")
            if minimized:
                self.root.withdraw()

        def _show_window():
            try:
                self.root.deiconify(); self.root.lift(); self.root.focus_force()
            except: pass
        self.show_cb = _show_window

        # Otomatik saldırı sayacı
        self.root.after(0, self.poll_attack_count)

        self.root.mainloop()

# ===================== MAIN ===================== #
if __name__ == "__main__":
    # Log dizinini oluştur
    log_dir = os.path.join(os.environ.get('APPDATA', ''), 'YesNext', 'CloudHoneypotClient')
    os.makedirs(log_dir, exist_ok=True)

    # Loglamayı başlat
    LOGGER = init_logging(is_watchdog=False)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--daemon", action="store_true", help="Run as a daemon service")
    parser.add_argument("--minimized", type=str, default="true", help="Start minimized")
    parser.add_argument("--watchdog", type=int, default=None, help="Watchdog process ID")
    parser.add_argument("--install", action="store_true", help="Install the service")
    parser.add_argument("--remove", action="store_true", help="Remove the service")
    args = parser.parse_args()

    if args.watchdog is not None:
        watchdog_main(args.watchdog)
        sys.exit(0)

    app = CloudHoneypotClient()

    # Check API connectivity at startup
    log("Checking API connectivity...")
    try:
        if not app.try_api_connection(show_error=True):
            log("Initial API connectivity check failed")
            sys.exit(1)
        log("API connectivity check successful")
    except Exception as e:
        log(f"API connectivity error: {str(e)}")
        messagebox.showerror("Connection Error", 
                          "Unable to connect to API service. Please check your internet connection and try again.")
        sys.exit(1)

    app.ensure_admin()

    if args.install:
        # İlk kurulum kontrolü
        if not os.path.exists(os.path.join(os.environ.get('PROGRAMDATA', ''), 'YesNext', 'CloudHoneypotClient', 'service_installed')):
            msg = "Bu uygulama sunucu güvenliği için servis olarak kayıt olacak ve Windows başlangıcında otomatik çalışacaktır.\n\n" + \
                  "This application will be registered as a service for server security and will run automatically at Windows startup."
            if messagebox.askokcancel("Cloud Honeypot Client", msg):
                # TODO: Servis kurulum kodları buraya gelecek
                os.makedirs(os.path.join(os.environ.get('PROGRAMDATA', ''), 'YesNext', 'CloudHoneypotClient'), exist_ok=True)
                with open(os.path.join(os.environ.get('PROGRAMDATA', ''), 'YesNext', 'CloudHoneypotClient', 'service_installed'), 'w') as f:
                    f.write('1')
            else:
                sys.exit(1)
        sys.exit(0)
    elif args.remove:
        # TODO: Servis kaldırma kodları buraya gelecek
        if os.path.exists(os.path.join(os.environ.get('PROGRAMDATA', ''), 'YesNext', 'CloudHoneypotClient', 'service_installed')):
            os.remove(os.path.join(os.environ.get('PROGRAMDATA', ''), 'YesNext', 'CloudHoneypotClient', 'service_installed'))
        sys.exit(0)

    if args.daemon:
        app.run_daemon()
        sys.exit(0)

    # Get token and public IP before building GUI
    try:
        app.state["token"] = app.get_token()
        app.state["public_ip"] = requests.get("https://api.ipify.org").text.strip()
    except Exception as e:
        LOGGER.error(f"Token/IP alınamadı: {str(e)}")
        app.state["token"] = None
        app.state["public_ip"] = "unknown"

    # minimized parametresini boolean'a çevir
    is_minimized = args.minimized.lower() == "true"
    app.build_gui(minimized=is_minimized)


