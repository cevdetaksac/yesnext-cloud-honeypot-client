# -*- coding: utf-8 -*-
import os, sys, socket, ssl, threading, time, json, subprocess, ctypes, struct, hashlib, tempfile, argparse
import tkinter as tk
from tkinter import ttk, messagebox
import requests, webbrowser, logging
from logging.handlers import RotatingFileHandler

# ===================== KURULUM & SABİTLER ===================== #
TEST_MODE = 0  # 1=log only, 0=real
__version__ = "1.3.2"

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

# Görev adları
TASK_NAME_BOOT  = "CloudHoneypotClient"
TASK_NAME_LOGON = "CloudHoneypotClientTray"

# Tray opsiyonel
TRY_TRAY = True
try:
    import pystray
    from pystray import MenuItem as TrayItem
    from PIL import Image, ImageDraw
except Exception:
    TRY_TRAY = False

# ===================== UYGULAMA DİZİNİ ===================== #
def appdata_dir() -> str:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    path = os.path.join(base, "YesNext", "CloudHoneypotClient")
    os.makedirs(path, exist_ok=True)
    return path

LOG_FILE        = os.path.join(appdata_dir(), "client.log")
SETTINGS_FILE   = os.path.join(appdata_dir(), "settings.json")
CONSENT_FILE    = os.path.join(appdata_dir(), "consent.json")
STATUS_FILE     = os.path.join(appdata_dir(), "status.json")
TOKEN_FILE_NEW  = os.path.join(appdata_dir(), "token.dat")  # DPAPI ile şifreli
TOKEN_FILE_OLD  = "token.txt"  # eski düz metin (migrasyon için)

# ===================== LOGGING ===================== #
def init_logging():
    logger = logging.getLogger("cloud-client")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)

    fh = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fmt = logging.Formatter(fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    return logger

LOGGER = init_logging()

def log(msg):  # kısa alias
    try: LOGGER.info(str(msg))
    except: pass

def run_cmd(cmd):
    """Güvenli komut çalıştırma (shell=False), stdout/stderr loglar."""
    CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
    try:
        if isinstance(cmd, (list, tuple)):
            cmd_list = list(cmd)
            cmd_display = " ".join(cmd_list)
        else:
            # string ise system shell'ine değil; cmd/sh ile çağır
            cmd_list = ["cmd", "/c", str(cmd)] if os.name == "nt" else ["/bin/sh", "-lc", str(cmd)]
            cmd_display = str(cmd)

        LOGGER.info(f"$ {cmd_display}")
        if TEST_MODE != 0:
            return None

        completed = subprocess.run(
            cmd_list, shell=False, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW
        )
        if completed.stdout:
            LOGGER.info(completed.stdout.strip())
        if completed.stderr:
            LOGGER.warning(completed.stderr.strip())
        if completed.returncode != 0:
            LOGGER.error(f"Command exited with code {completed.returncode}")
        return completed
    except Exception as e:
        LOGGER.exception(f"run_cmd error: {e}")
        return None

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
        "warn_no_ports": "Hiçbir port seçmediniz!",
        "ok_tunneled": "{n} port tünellendi!",
        "stopped_all": "Tüm korumalar kaldırıldı.",
        "confirm_stop": "Tüm korumaları durdurmak istediğinize emin misiniz?",
        "note_rdp": "Not: RDP korumayı seçtiğinizde 45 sn içinde yeni porttan bağlanıp onay verin.",
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
        "rdp_go_secure": "RDP portunuz 53389'a taşınacak.\n45 saniye içinde yeni porttan bağlanın.\nAksi halde eski porta dönülecek.",
        "rdp_rollback": "RDP portunuz 3389'a geri taşınacak.\n45 saniye içinde eski porttan bağlanın.\nAksi halde yeni port aktif kalacak.",
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
        "warn_no_ports": "No ports selected!",
        "ok_tunneled": "{n} ports secured!",
        "stopped_all": "All protections have been removed.",
        "confirm_stop": "Are you sure you want to stop all protections?",
        "note_rdp": "Note: When securing RDP, connect via the new port within 45s and confirm.",
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
        "rdp_go_secure": "RDP will be moved to 53389.\nReconnect within 45s.\nOtherwise rollback to old port.",
        "rdp_rollback": "RDP will be moved back to 3389.\nReconnect within 45s.\nOtherwise keep new port.",
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
        except Exception:
            pass
    try:
        sys.excepthook = _hook
    except Exception:
        pass

# ===================== DPAPI TOKEN STORE ===================== #
class TokenStore:
    CRYPTPROTECT_UI_FORBIDDEN = 0x1

    @staticmethod
    def _crypt_protect(data: bytes) -> bytes:
        blob_in  = ctypes.c_buffer(data, len(data))
        blob_out = ctypes.c_void_p()
        crypt32  = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        if not crypt32.CryptProtectData(
            ctypes.byref(ctypes.c_buffer(struct.pack("I", len(data)) + data)),
            None, None, None, None,
            TokenStore.CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(blob_out)
        ):
            raise RuntimeError("CryptProtectData failed")
        cb = ctypes.cast(blob_out, ctypes.POINTER(ctypes.c_ubyte))
        size = ctypes.cast(blob_out, ctypes.POINTER(ctypes.c_ulong))[0]
        out = ctypes.string_at(cb, size)
        kernel32.LocalFree(blob_out)
        return out

    @staticmethod
    def _crypt_unprotect(data: bytes) -> bytes:
        blob_in  = ctypes.c_buffer(data, len(data))
        blob_out = ctypes.c_void_p()
        crypt32  = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        if not crypt32.CryptUnprotectData(
            ctypes.byref(ctypes.c_buffer(struct.pack("I", len(data)) + data)),
            None, None, None, None,
            TokenStore.CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(blob_out)
        ):
            raise RuntimeError("CryptUnprotectData failed")
        cb = ctypes.cast(blob_out, ctypes.POINTER(ctypes.c_ubyte))
        size = ctypes.cast(blob_out, ctypes.POINTER(ctypes.c_ulong))[0]
        out = ctypes.string_at(cb, size)
        kernel32.LocalFree(blob_out)
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
    def load() -> str or None:
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
        sc query <svc> çıktısından STATE satırındaki sayısal kodu döndürür.
        1=STOPPED, 2=START_PENDING, 3=STOP_PENDING, 4=RUNNING, 5=CONTINUE_PENDING, 6=PAUSE_PENDING, 7=PAUSED
        Dil bağımsız çalışır.
        """
        try:
            creationflags = 0x08000000 if os.name == 'nt' else 0
            completed = subprocess.run(['sc', 'query', svc_name], shell=False, capture_output=True, text=True, creationflags=creationflags)
            txt = (completed.stdout or "")
            for line in txt.splitlines():
                if 'STATE' in line.upper():
                    # ör: "        STATE              : 4  RUNNING"
                    after = line.split(':', 1)[1].strip()
                    num = after.split()[0]
                    return int(num)
        except Exception as e:
            log(f"sc query error: {e}")
        return -1

    @staticmethod
    def _wait_state_code(svc_name: str, desired_code: int, timeout: int = 60) -> bool:
        t0 = time.time()
        while time.time() - t0 < timeout:
            code = ServiceController._sc_query_code(svc_name)
            if code == desired_code:
                return True
            time.sleep(1)
        return False

    @staticmethod
    def stop(svc_name: str, timeout: int = 60) -> bool:
        code = ServiceController._sc_query_code(svc_name)
        if code == 1:
            return True
        try:
            run_cmd(['sc', 'stop', svc_name])
        except Exception:
            pass
        if ServiceController._wait_state_code(svc_name, 1, timeout):
            return True
        # Fallback PowerShell (bazı durumlarda gerekli)
        try:
            run_cmd(['powershell', '-NoProfile', '-Command', f'Stop-Service -Name "{svc_name}" -Force -ErrorAction SilentlyContinue'])
            return ServiceController._wait_state_code(svc_name, 1, 30)
        except Exception:
            pass
        log(f"Service {svc_name} did not stop in time")
        return False

    @staticmethod
    def start(svc_name: str, timeout: int = 60) -> bool:
        code = ServiceController._sc_query_code(svc_name)
        if code == 4:
            return True
        try:
            run_cmd(['sc', 'start', svc_name])
        except Exception:
            pass
        if ServiceController._wait_state_code(svc_name, 4, timeout):
            return True
        # Fallback PowerShell
        try:
            run_cmd(['powershell', '-NoProfile', '-Command', f'Start-Service -Name "{svc_name}" -ErrorAction SilentlyContinue'])
            return ServiceController._wait_state_code(svc_name, 4, 30)
        except Exception:
            pass
        log(f"Service {svc_name} did not start in time")
        return False

    @staticmethod
    def switch_rdp_port(new_port: int):
        run_cmd([
            'reg','add', r'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp',
            '/v','PortNumber','/t','REG_DWORD','/d', str(new_port), '/f'
        ])
        run_cmd([
            'netsh','advfirewall','firewall','add','rule', f'name=RDP {new_port}',
            'dir=in','action=allow','protocol=TCP', f'localport={new_port}'
        ])
        ServiceController.stop('TermService', timeout=60)
        ServiceController.start('TermService', timeout=60)

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
            self.app.threads.append(th)

    def stop(self):
        self.stop_evt.set()
        try:
            if self.sock:
                self.sock.close()
        except:
            pass

# ===================== ANA UYGULAMA ===================== #
class CloudHoneypotClient:
    PORT_TABLOSU = [
        ("3389", "53389", "RDP"),
        ("1433", "-", "MSSQL"),
        ("3306", "-", "MySQL"),
        ("21",   "-", "FTP"),
        ("22",   "-", "SSH"),
    ]

    def __init__(self):
        install_excepthook()
        self.lang = read_settings().get("language", "tr")
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
        }
        self.root = None
        self.btn_primary = None
        self.tree = None
        self.attack_entry = None
        self.ip_entry = None
        self.show_cb = None

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
    def register_client(self) -> str or None:
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
                messagebox.showerror(self.t("error"), self.t("err_api_status").format(code=resp.status_code))
        except Exception as e:
            messagebox.showerror(self.t("error"), self.t("err_api_register").format(e=e))
        return None

    def load_token(self) -> str or None:
        TokenStore.migrate_from_plain()
        tok = TokenStore.load()
        if tok:
            return tok
        return self.register_client()

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
                break
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
        self._write_status_raw(data)

    def read_status(self):
        if not os.path.exists(STATUS_FILE):
            return [], False
        try:
            data = json.load(open(STATUS_FILE, "r", encoding="utf-8"))
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
        except Exception:
            pass

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
            self.apply_onedir_update(zip_path)
        except Exception as e:
            log(f"update error: {e}")
            try:
                messagebox.showerror("Update", self.t("update_error").format(err=str(e)))
            except Exception:
                pass

    def schedule_self_update_and_exit(self, new_exe_path):
        try:
            cur = self.current_executable()
            target = cur
            up_dir = os.path.dirname(cur)
            bat_path = os.path.join(up_dir, "update_run.bat")
            bat = f"""
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
            subprocess.Popen(["cmd", "/c", bat_path], shell=False)
        except Exception as e:
            log(f"schedule update error: {e}")
        finally:
            try: os._exit(0)
            except: sys.exit(0)

    def apply_onedir_update(self, zip_path):
        try:
            import zipfile, shutil
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
start "" "%DST%\client-onedir.exe" --minimized
del "%~f0" & exit /b 0
"""
            with open(bat_path, 'w', encoding='utf-8') as f:
                f.write(bat)
            subprocess.Popen(["cmd", "/c", bat_path], shell=False)
        except Exception as e:
            log(f"apply_onedir_update error: {e}")
        finally:
            try: os._exit(0)
            except: sys.exit(0)

    # ---------- RDP move popup ---------- #
    def rdp_move_popup(self, mode, on_confirm):
        popup = tk.Toplevel(self.root)
        popup.title(self.t("rdp_title"))
        msg = self.t("rdp_go_secure") if mode=="secure" else self.t("rdp_rollback")
        tk.Label(popup, text=msg, font=("Arial", 11), justify="center").pack(padx=20, pady=15)
        countdown_label = tk.Label(popup, text="45", font=("Arial", 20, "bold"), fg="red")
        countdown_label.pack()

        def rollback(port_):
            ServiceController.switch_rdp_port(port_)
            messagebox.showwarning(self.t("warn"), self.t("rollback_done").format(port=port_))
            popup.destroy()

        def confirm_success():
            popup.destroy()
            on_confirm()

        def countdown(sec=45):
            if sec <= 0:
                if mode == "secure": rollback(3389)
                else: rollback(53389)
                return
            countdown_label.config(text=str(sec))
            popup.after(1000, countdown, sec-1)

        try:
            if mode == "secure": ServiceController.switch_rdp_port(53389)
            else: ServiceController.switch_rdp_port(3389)
        except Exception as e:
            messagebox.showerror(self.t("error"), self.t("err_rdp").format(e=e))
            try: popup.destroy()
            except: pass
            return

        countdown()
        tk.Button(popup, text=self.t("rdp_approve"), command=confirm_success,
                  bg="#4CAF50", fg="white", padx=15, pady=5).pack(pady=10)

    # ---------- Uygulama kontrol ---------- #
    def apply_tunnels(self, selected_rows):
        started = 0
        clean_rows = []
        for row in selected_rows:
            listen_port, new_port, service = str(row[0]), str(row[1]), str(row[2])
            st = TunnelServerThread(self, listen_port, service)
            st.start()
            time.sleep(0.15)
            if st.is_alive():
                self.state["servers"][int(listen_port)] = st
                clean_rows.append((listen_port, new_port, service))
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
        icon = pystray.Icon("honeypot_client")
        self.state["tray"] = icon
        icon.title = "Cloud Honeypot Client"
        icon.icon = self.tray_make_image(self.state["running"])

        def show_cb():
            try:
                if self.root:
                    self.root.deiconify(); self.root.lift(); self.root.focus_force()
            except: pass

        def exit_cb():
            if self.state["running"]:
                messagebox.showwarning(self.t("warn"), self.t("tray_warn_stop_first"))
                return
            icon.stop()
            if self.root:
                self.root.destroy()
            self.stop_single_instance_server()
            os._exit(0)

        self.show_cb = show_cb
        icon.menu = (
            TrayItem(self.t('tray_show'), lambda: show_cb()),
            TrayItem(self.t('tray_exit'), lambda: exit_cb())
        )
        icon.run()

    def update_tray_icon(self):
        if not TRY_TRAY: return
        icon = self.state.get("tray")
        if not icon: return
        icon.icon = self.tray_make_image(self.state["running"])
        icon.visible = True

    def stop_single_instance_server(self):
        s = self.state.get("ctrl_sock")
        if s:
            try: s.close()
            except: pass
            self.state["ctrl_sock"] = None

    # ---------- Daemon ---------- #
    def run_daemon(self):
        self.state["token"] = self.load_token()
        self.state["public_ip"] = self.get_public_ip()
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        threading.Thread(target=self.tunnel_watchdog_loop, daemon=True).start()

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
        except Exception:
            pass
        log("Daemon: durduruldu.")

    # ---------- GUI ---------- #
    def build_gui(self, minimized=False):
        # One-time notice for simplicity and firewall prompts
        try:
            # Ensure root exists before messagebox
            if not self.root:
                self.root = tk.Tk()
                self.root.withdraw()
                self.root.title(f"{self.t('app_title')} v{__version__}")
            self.first_run_notice()
            # Continue building actual UI below (root will be reconfigured)
            try:
                self.root.deiconify()
            except Exception:
                pass
        except Exception as e:
            log(f"build_gui pre-notice error: {e}")
        self.start_single_instance_server()

        token = self.load_token()
        self.state["token"] = token
        self.state["public_ip"] = self.get_public_ip()
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        threading.Thread(target=self.tunnel_watchdog_loop, daemon=True).start()

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
            if TRY_TRAY:
                self.root.withdraw()
            else:
                self.root.withdraw()
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
            entry.insert(0, value); entry.config(state="readonly")
            entry.grid(row=idx, column=1, padx=5, pady=3)

            tk.Button(frame1, text="📋", command=lambda e=entry: copy_entry(e)).grid(row=idx, column=2, padx=3)

            if key == "dash":
                tk.Button(frame1, text="🌐 " + self.t("open"), command=open_dashboard).grid(row=idx, column=3, padx=3)

            if key == "attacks":
                tk.Button(frame1, text="↻ " + self.t("refresh"), command=lambda: self.refresh_attack_count(async_thread=True)).grid(row=idx, column=3, padx=3)
                self.attack_entry = entry

            if key == "ip":
                self.ip_entry = entry

        # Port Tünelleme
        frame2 = tk.LabelFrame(self.root, text=self.t("port_tunnel"), padx=10, pady=10, bg="#f5f5f5", font=("Arial", 11, "bold"))
        frame2.pack(fill="both", expand=True, padx=15, pady=10)

        columns = (self.t("col_listen"), self.t("col_new"), self.t("col_service"), self.t("col_active"))
        self.tree = ttk.Treeview(frame2, columns=columns, show="headings", height=len(self.PORT_TABLOSU))
        self.tree.pack(fill="x")

        for col in columns:
            self.tree.heading(col, text=col); self.tree.column(col, anchor="center", width=170)

        self.tree.tag_configure("aktif", background="#C8E6C9")

        selected_ports = {}
        self.state["selected_ports_map"] = selected_ports
        row_ids = []
        for (p1, p2, servis) in self.PORT_TABLOSU:
            iid = self.tree.insert("", "end", values=(p1, p2, servis, "☐"))
            selected_ports[iid] = False
            row_ids.append((iid, p1, p2, servis))

        # Önceki seçimleri uygula
        saved_rows, saved_running = self.read_status()
        if saved_rows:
            for iid, p1, p2, servis in row_ids:
                for sr in saved_rows:
                    if str(sr[0]) == str(p1) and str(sr[2]).upper() == str(servis).upper():
                        selected_ports[iid] = True
                        self.tree.set(iid, self.t("col_active"), "☑")
                        self.tree.item(iid, tags=("aktif",))
                        break

        def toggle_checkbox(event):
            col = self.tree.identify_column(event.x)
            if col != "#4": return
            item_id = self.tree.identify_row(event.y)
            if item_id and self.btn_primary["text"] == self.t("btn_secure"):
                cur = selected_ports[item_id]
                selected_ports[item_id] = not cur
                self.tree.set(item_id, self.t("col_active"), "☑" if selected_ports[item_id] else "☐")
                self.tree.item(item_id, tags=("aktif",) if selected_ports[item_id] else ())
        self.tree.bind("<Button-1>", toggle_checkbox)

        frame3 = tk.Frame(self.root, bg="#f5f5f5", pady=20)
        frame3.pack(fill="x")

        # Tek buton
        self.btn_primary = tk.Button(frame3, text=self.t("btn_secure"), font=("Arial", 13, "bold"),
                                     bg="#4CAF50", fg="white", padx=25, pady=12)
        self.btn_primary.pack(side="left", padx=10)

        note = tk.Label(self.root, text=self.t("note_rdp"), font=("Arial", 9), fg="red", bg="#f5f5f5", justify="center")
        note.pack(pady=5)

        # Buton aksiyonları
        def finalize_secure(active_rows):
            for iid in selected_ports.keys():
                if selected_ports[iid]:
                    self.tree.item(iid, tags=("aktif",))
            self.tree.unbind("<Button-1>")
            self.set_primary_button(self.t("btn_stop"), stop_protection, "#E53935")
            messagebox.showinfo(self.t("info"), self.t("ok_tunneled").format(n=len(active_rows)))

        def do_secure_ports():
            cons = self.read_consent()
            if not cons.get("accepted"):
                cons = self.ensure_consent_ui()
                if not cons.get("accepted"):
                    messagebox.showwarning(self.t("warn"), self.t("warn_no_consent"))
                    return
            self.ensure_admin()
            active_rows = [self.tree.item(iid)["values"][:3] for iid, val in selected_ports.items() if val]
            if not active_rows:
                messagebox.showwarning(self.t("warn"), self.t("warn_no_ports"))
                return
            if any(str(p[0]) == "3389" for p in active_rows) and cons.get("rdp_move", True):
                non_rdp = [p for p in active_rows if str(p[0]) != "3389"]
                def after_rdp():
                    ok = self.apply_tunnels([("3389","53389","RDP")] + non_rdp)
                    if ok:
                        if cons.get("autostart", False):
                            self.install_autostart_system_boot()
                            self.install_autostart_user_logon()
                        finalize_secure([("3389","53389","RDP","☑")] + non_rdp)
                        self.refresh_attack_count(async_thread=True)
                self.rdp_move_popup("secure", after_rdp)
                return
            ok = self.apply_tunnels(active_rows)
            if ok:
                if cons.get("autostart", False):
                    self.install_autostart_system_boot()
                    self.install_autostart_user_logon()
                finalize_secure(active_rows)
                self.refresh_attack_count(async_thread=True)

        def stop_protection():
            if not messagebox.askyesno(self.t("warn"), self.t("confirm_stop")):
                return
            was_active, _ = self.read_status()
            def finish_stop():
                self.remove_tunnels()
                self.remove_autostart()
                for iid in selected_ports.keys():
                    selected_ports[iid] = False
                    self.tree.set(iid, self.t("col_active"), "☐")
                    self.tree.item(iid, tags=())
                self.tree.bind("<Button-1>", toggle_checkbox)
                self.set_primary_button(self.t("btn_secure"), do_secure_ports, "#4CAF50")
                messagebox.showinfo(self.t("info"), self.t("stopped_all"))
                self.refresh_attack_count(async_thread=True)
            if any(str(p[0]) == "3389" for p in was_active):
                self.rdp_move_popup("rollback", finish_stop)
            else:
                finish_stop()

        self.set_primary_button(self.t("btn_secure"), do_secure_ports, "#4CAF50")

        # Tray
        if TRY_TRAY:
            def tray_thread():
                self.tray_loop()
            threading.Thread(target=tray_thread, daemon=True).start()

        # Eski durum otomatik başlasın
        if saved_rows and saved_running:
            ok = self.apply_tunnels(saved_rows)
            if ok:
                self.tree.unbind("<Button-1>")
                self.set_primary_button(self.t("btn_stop"), stop_protection, "#E53935")
                if minimized:
                    self.root.withdraw()

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
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--minimized", action="store_true")
    args, _ = parser.parse_known_args()

    app = CloudHoneypotClient()
    # Elevate early to keep UX simple: download & run
    app.ensure_admin()

    if args.daemon:
        app.run_daemon()
        sys.exit(0)

    app.build_gui(minimized=args.minimized)
