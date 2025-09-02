import os, sys, socket, ssl, threading, time, json, subprocess
import tkinter as tk
from tkinter import ttk, messagebox
import requests, webbrowser

# ===================== AYAR ===================== #
TEST_MODE = 0  # 1=log only, 0=real
__version__ = "1.0.0"
GITHUB_OWNER = "cevdetaksac"
GITHUB_REPO = "yesnext-cloud-honeypot-client"
API_URL = "https://honeypot.yesnext.com.tr/api"
HONEYPOT_IP = "194.5.236.181"
HONEYPOT_TUNNEL_PORT = 4443
SERVER_NAME = socket.gethostname()
STATUS_FILE = "status.json"
LOG_FILE = "client.log"
CONSENT_FILE = "consent.json"
SETTINGS_FILE = "settings.json"
HANDSHAKE_TIMEOUT = 5
CONNECT_TIMEOUT = 8
RECV_SIZE = 65536
TASK_NAME_BOOT = "CloudHoneypotClient"
TASK_NAME_LOGON = "CloudHoneypotClientTray"

# Tek-instance kontrol portu (localhost)
CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 58632  # sabit yüksek port

# Tray opsiyonel
TRY_TRAY = True
try:
    import pystray
    from pystray import MenuItem as TrayItem
    from PIL import Image, ImageDraw
except Exception:
    TRY_TRAY = False

# Watchdog durumu (global)
WATCHDOG_STARTED = False

STATE = {
    "running": False,
    "servers": {},    # listen_port -> ServerThread
    "threads": [],
    "token": None,
    "public_ip": None,
    "tray": None,
    "selected_rows": [],  # [('3389','53389','RDP'), ...]
    "root": None,
    "btn_primary": None,  # tek buton
    "tree": None,
    "selected_ports_map": None,  # iid -> bool
    "show_cb": None,      # mevcut örneği öne getirme
    "ctrl_sock": None,    # tek-instance server socket
    "attack_entry": None, # Toplam Saldırılar entry referansı
    "ip_entry": None,     # PC Adı/IP entry referansı (opsiyonel güncelleme)
}

# ===================== YARDIMCI ===================== #
def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except:
        pass

def run_cmd(cmd):
    try:
        log(f"$ {cmd}")
        if TEST_MODE == 0:
            if isinstance(cmd, (list, tuple)):
                subprocess.run(list(cmd), shell=False)
            else:
                subprocess.run(cmd, shell=True)
    except Exception as e:
        log(f"run_cmd error: {e}")

# ===================== SETTINGS & I18N & UPDATE ===================== #
def _settings_path():
    return os.path.abspath(SETTINGS_FILE)

def read_settings():
    try:
        if os.path.exists(_settings_path()):
            with open(_settings_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return {"language": data.get("language", "tr")}
    except Exception as e:
        log(f"read_settings error: {e}")
    return {"language": "tr"}

def write_settings(language: str):
    try:
        with open(_settings_path(), "w", encoding="utf-8") as f:
            json.dump({"language": language}, f, ensure_ascii=False)
    except Exception as e:
        log(f"write_settings error: {e}")

I18N = {
    "tr": {
        "app_title": "Cloud Honeypot Security (Tunnel)",
        "menu_settings": "Ayarlar",
        "menu_language": "Dil",
        "menu_lang_tr": "Türkçe",
        "menu_lang_en": "English",
        "menu_help": "Yardım",
        "menu_check_updates": "Güncellemeleri Denetle",
        "update_none": "Güncel sürümü kullanıyorsunuz.",
        "update_found": "Yeni sürüm bulundu: {version}. İndirip yeniden başlatılsın mı?",
        "update_error": "Güncelleme sırasında hata: {err}",
        "restart_needed_lang": "Dil değişikliği için uygulama yeniden başlatılacak.",
    },
    "en": {
        "app_title": "Cloud Honeypot Security (Tunnel)",
        "menu_settings": "Settings",
        "menu_language": "Language",
        "menu_lang_tr": "Türkçe",
        "menu_lang_en": "English",
        "menu_help": "Help",
        "menu_check_updates": "Check for Updates",
        "update_none": "You are running the latest version.",
        "update_found": "New version available: {version}. Download and restart?",
        "update_error": "Error during update: {err}",
        "restart_needed_lang": "The application will restart to apply language.",
    },
}

def t(key: str) -> str:
    lang = STATE.get("lang", "tr")
    return I18N.get(lang, I18N["tr"]).get(key, key)

def _current_executable():
    if getattr(sys, 'frozen', False):
        return sys.executable
    return os.path.abspath(sys.argv[0])

def _http_get_json(url, timeout=8):
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()

def _http_download(url, dest_path, timeout=30):
    with requests.get(url, stream=True, timeout=timeout) as r:
        r.raise_for_status()
        with open(dest_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)

def _sha256_file(p):
    import hashlib
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def check_updates_and_prompt(root):
    try:
        api = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
        data = _http_get_json(api, timeout=8)
        latest_tag = data.get("tag_name") or data.get("name")
        if not latest_tag:
            messagebox.showinfo("Update", t("update_none"))
            return
        latest_ver = str(latest_tag).lstrip('v')
        cur_ver = str(__version__).lstrip('v')
        if latest_ver <= cur_ver:
            messagebox.showinfo("Update", t("update_none"))
            return
        assets = data.get("assets", [])
        asset_exe = None
        asset_sha = None
        for a in assets:
            n = str(a.get("name", "")).lower()
            if n in ("client.exe", "client-windows.exe", "client-signed.exe"):
                asset_exe = a.get("browser_download_url")
            if n.endswith(".sha256"):
                asset_sha = a.get("browser_download_url")
        if not asset_exe:
            messagebox.showerror("Update", t("update_error").format(err="asset not found"))
            return
        if not messagebox.askyesno("Update", t("update_found").format(version=latest_ver)):
            return
        import tempfile
        tmpdir = tempfile.mkdtemp(prefix="chpupd-")
        new_path = os.path.join(tmpdir, "client-new.exe")
        _http_download(asset_exe, new_path, timeout=60)
        if asset_sha:
            sha_path = os.path.join(tmpdir, "client.sha256")
            _http_download(asset_sha, sha_path, timeout=30)
            try:
                exp = open(sha_path, 'r', encoding='utf-8', errors='ignore').read().strip().split()[0]
                calc = _sha256_file(new_path)
                if exp and calc.lower() != exp.lower():
                    messagebox.showerror("Update", t("update_error").format(err="sha256 mismatch"))
                    return
            except Exception as e:
                log(f"sha check error: {e}")
        schedule_self_update_and_exit(new_path)
    except Exception as e:
        log(f"update error: {e}")
        try:
            messagebox.showerror("Update", t("update_error").format(err=str(e)))
        except Exception:
            pass

def schedule_self_update_and_exit(new_exe_path):
    try:
        cur = _current_executable()
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

# Uygulama çapında beklenmeyen hataları günlükle
def _install_excepthook():
    def _hook(exc_type, exc, tb):
        try:
            import traceback
            log("UNHANDLED EXCEPTION:\n" + "".join(traceback.format_exception(exc_type, exc, tb)))
        except Exception:
            pass
    try:
        sys.excepthook = _hook
    except Exception:
        pass

def ensure_admin():
    """Yönetici değilse kendini UAC ile yeniden başlatır."""
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            exe = sys.executable
            params = " ".join([f'"{os.path.abspath(sys.argv[0])}"'] + sys.argv[1:])
            if exe.lower().endswith("python.exe") or exe.lower().endswith("pythonw.exe"):
                params = f'"{os.path.abspath(sys.argv[0])}" ' + " ".join(sys.argv[1:])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
            sys.exit(0)
    except Exception as e:
        log(f"ensure_admin error: {e}")

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org", timeout=5).text.strip()
    except Exception as e:
        log(f"get_public_ip error: {e}")
        return "0.0.0.0"

def register_client():
    try:
        ip = get_public_ip()
        resp = requests.post(f"{API_URL}/register",
                             json={"server_name": f"{SERVER_NAME} ({ip})","ip": ip},
                             timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            with open("token.txt", "w", encoding="utf-8") as f:
                f.write(data["token"])
            return data["token"]
        else:
            messagebox.showerror("Hata", f"API register status: {resp.status_code}")
    except Exception as e:
        messagebox.showerror("Hata", f"API bağlantısı başarısız: {e}")
    return None

def load_token():
    if os.path.exists("token.txt"):
        try:
            return open("token.txt","r",encoding="utf-8").read().strip()
        except:
            pass
    return register_client()

def update_client_ip(new_ip):
    """IP değiştiğinde token ile API'ye güncelleme isteği gönder."""
    try:
        token = STATE.get("token")
        if not token: return
        payload = {"token": token, "ip": new_ip}
        r = requests.post(f"{API_URL}/update-ip", json=payload, timeout=6)
        if r.status_code == 200:
            log(f"update-ip OK: {new_ip}")
        else:
            log(f"update-ip HTTP {r.status_code}: {r.text[:200]}")
    except Exception as e:
        log(f"update-ip error: {e}")

# ===================== CONSENT ===================== #
def _consent_path():
    return os.path.abspath(CONSENT_FILE)

def read_consent():
    try:
        if os.path.exists(_consent_path()):
            with open(_consent_path(), "r", encoding="utf-8") as f:
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

def write_consent(accepted: bool, rdp_move: bool, autostart: bool):
    try:
        data = {
            "accepted": bool(accepted),
            "rdp_move": bool(rdp_move),
            "autostart": bool(autostart),
            "ts": int(time.time()),
            "app": "CloudHoneypotClient",
        }
        with open(_consent_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
    except Exception as e:
        log(f"write_consent error: {e}")

def ensure_consent_ui(root):
    """Uygulama açılışında kullanıcıdan görünür onay al.
    Onay verilmezse ayarları pasif kabul eder."""
    cons = read_consent()
    if cons.get("accepted"):
        STATE["consent"] = cons
        return cons

    win = tk.Toplevel(root)
    win.title("Güvenlik Onayı")
    try:
        win.grab_set()
        win.transient(root)
    except Exception:
        pass
    msg = (
        "Uygulama aşağıdaki işlemleri yapabilir:\n\n"
        "- Seçtiğiniz portları güvene alıp tünel açma\n"
        "- RDP portunu 3389 → 53389 taşıma ve hizmeti yeniden başlatma\n"
        "- Başlangıçta otomatik çalıştırma (Görev Zamanlayıcı)\n\n"
        "Devam etmek için onay verin ve tercihleri seçin."
    )
    tk.Label(win, text=msg, justify="left", font=("Arial", 10)).pack(padx=16, pady=12)

    var_rdp = tk.BooleanVar(value=True)
    var_auto = tk.BooleanVar(value=False)
    tk.Checkbutton(win, text="RDP portunu 53389'a taşı ve hizmeti yönet", variable=var_rdp).pack(anchor="w", padx=16)
    tk.Checkbutton(win, text="Başlangıçta otomatik çalıştır (Görev Zamanlayıcı)", variable=var_auto).pack(anchor="w", padx=16)

    accepted = {"val": False}

    def do_accept():
        accepted["val"] = True
        write_consent(True, var_rdp.get(), var_auto.get())
        STATE["consent"] = read_consent()
        try:
            win.destroy()
        except Exception:
            pass

    def do_cancel():
        accepted["val"] = False
        write_consent(False, var_rdp.get(), var_auto.get())
        STATE["consent"] = read_consent()
        try:
            win.destroy()
        except Exception:
            pass

    frm = tk.Frame(win)
    frm.pack(pady=10)
    tk.Button(frm, text="Onayla ve Devam", bg="#4CAF50", fg="white", command=do_accept).pack(side="left", padx=6)
    tk.Button(frm, text="Vazgeç", command=do_cancel).pack(side="left", padx=6)

    win.wait_window()
    return STATE.get("consent", cons)
def safe_set_entry(entry: tk.Entry, text: str):
    try:
        entry.config(state="normal")
        entry.delete(0, tk.END)
        entry.insert(0, text)
        entry.config(state="readonly")
    except Exception as e:
        log(f"safe_set_entry error: {e}")

def fetch_attack_count_sync(token):
    try:
        r = requests.get(f"{API_URL}/attack-count", params={"token": token}, timeout=5)
        if r.status_code == 200:
            return int(r.json().get("count", 0))
    except Exception as e:
        log(f"fetch_attack_count error: {e}")
    return None

def refresh_attack_count(async_thread=True):
    """Toplam Saldırılar değerini API'den çek ve UI'ı güncelle."""
    token = STATE.get("token")
    root = STATE.get("root")
    entry = STATE.get("attack_entry")
    if not token or not root or not entry:
        return
    def worker():
        cnt = fetch_attack_count_sync(token)
        if cnt is None:
            return
        try:
            root.after(0, lambda: safe_set_entry(entry, str(cnt)))
        except:
            safe_set_entry(entry, str(cnt))
    if async_thread:
        threading.Thread(target=worker, daemon=True).start()
    else:
        worker()

def poll_attack_count():
    """10 sn'de bir otomatik yenile."""
    refresh_attack_count(async_thread=True)
    # 10.000 ms
    try:
        STATE["root"].after(10_000, poll_attack_count)
    except:
        pass

def send_heartbeat_once(status_override=None):
    """
    API'ye tek seferlik heartbeat gönderir.
    status_override: 'online' | 'offline' | None
    None ise STATE["running"] durumundan türetir.
    """
    try:
        token = STATE.get("token")
        if not token:
            return
        ip = STATE.get("public_ip") or get_public_ip()
        status = "online" if STATE.get("running") else "offline"
        if status_override in ("online", "offline"):
            status = status_override

        payload = {
            "token": token,
            "ip": ip,
            "hostname": SERVER_NAME,
            "running": STATE.get("running", False),
            "status": status
        }
        requests.post(f"{API_URL}/heartbeat", json=payload, timeout=6)
    except Exception as e:
        log(f"heartbeat send err: {e}")


def heartbeat_loop():
    last_ip = None
    while True:
        try:
            token = STATE.get("token")
            if token:
                ip = get_public_ip()
                if ip and ip != last_ip:
                    update_client_ip(ip)
                    last_ip = ip
                STATE["public_ip"] = ip

                # GUI'deki IP bilgisini güncelle (varsa)
                ip_entry = STATE.get("ip_entry")
                if ip_entry:
                    try:
                        STATE["root"].after(0, lambda: safe_set_entry(ip_entry, f"{SERVER_NAME} ({ip})"))
                    except:
                        safe_set_entry(ip_entry, f"{SERVER_NAME} ({ip})")

                # ⬇️ Artık status: 'online'/'offline' ile gönderiyoruz
                send_heartbeat_once()
        except Exception as e:
            log(f"heartbeat error: {e}")
        time.sleep(60)


# ===================== WATCHDOG ===================== #
def _ensure_watchdog():
    global WATCHDOG_STARTED
    if WATCHDOG_STARTED:
        return
    WATCHDOG_STARTED = True
    threading.Thread(target=_tunnel_watchdog_loop, daemon=True).start()

def _tunnel_watchdog_loop():
    """Tünel iş parçalarını izler; düşenleri yeniden başlatmayı dener."""
    while True:
        try:
            if STATE.get("running"):
                desired = {(str(p[0]), str(p[2]).upper()) for p in STATE.get("selected_rows", [])}
                # Eksik ya da ölü iş parçalarını yeniden başlat
                for (listen_port, new_port, service) in STATE.get("selected_rows", []):
                    lp = int(str(listen_port))
                    st = STATE["servers"].get(lp)
                    if (st is None) or (not st.is_alive()):
                        try:
                            st2 = ServerThread(lp, str(service))
                            st2.start()
                            time.sleep(0.2)
                            if st2.is_alive():
                                STATE["servers"][lp] = st2
                                log(f"[watchdog] {service}:{lp} yeniden başlatıldı")
                        except Exception as e:
                            log(f"[watchdog] {service}:{lp} başlatılamadı: {e}")

                # Fazla (artık seçili olmayan) iş parçalarını durdur
                for lp, st in list(STATE["servers"].items()):
                    key = (str(lp), str(st.service_name).upper())
                    if key not in desired:
                        try:
                            st.stop()
                            del STATE["servers"][lp]
                        except Exception:
                            pass
        except Exception as e:
            log(f"watchdog loop err: {e}")
        time.sleep(10)

# ===================== SINGLE-INSTANCE ===================== #
def _control_server_loop(sock):
    # Gelen SHOW komutları GUI thread'inde işlenmeli
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
                    cb = STATE.get("show_cb")
                    if cb: 
                        try: cb()
                        except: pass
                root = STATE.get("root")
                try:
                    if root: root.after(0, do_show)
                    else: do_show()
                except:
                    do_show()
        except Exception:
            pass
        finally:
            try: conn.close()
            except: pass

def start_single_instance_server():
    # Bir GUI/TRAY örneği zaten çalışıyorsa SHOW isteği gönderip çık
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((CONTROL_HOST, CONTROL_PORT))
    except OSError:
        # Port kullanımda: başka örnek var → SHOW de, çık
        try:
            with socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=1.0) as c:
                c.sendall(b"SHOW\n")
        except Exception:
            pass
        sys.exit(0)
    s.listen(5)
    STATE["ctrl_sock"] = s
    th = threading.Thread(target=_control_server_loop, args=(s,), daemon=True)
    th.start()

def stop_single_instance_server():
    s = STATE.get("ctrl_sock")
    if s:
        try:
            s.close()
        except:
            pass
        STATE["ctrl_sock"] = None

# ===================== TUNNEL ===================== #
def create_tls_socket():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # PROD: CA ekleyip aç
    raw = socket.create_connection((HONEYPOT_IP, HONEYPOT_TUNNEL_PORT), timeout=CONNECT_TIMEOUT)
    tls = ctx.wrap_socket(raw, server_hostname=HONEYPOT_IP)
    return tls

def send_json(sock, obj):
    data = (json.dumps(obj, separators=(',', ':')) + "\n").encode("utf-8")
    sock.sendall(data)

def pipe_streams(src, dst):
    try:
        while True:
            data = src.recv(RECV_SIZE)
            if not data:
                break
            dst.sendall(data)
    except:
        pass
    finally:
        for s in (dst, src):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                s.close()
            except:
                pass

def handle_incoming_connection(local_sock, listen_port, service_name):
    try:
        peer = local_sock.getpeername()
        attacker_ip, attacker_port = peer[0], peer[1]
    except:
        attacker_ip, attacker_port = "0.0.0.0", 0

    try:
        remote = create_tls_socket()
    except Exception as e:
        log(f"[{service_name}:{listen_port}] TLS bağlanamadı: {e}")
        try: local_sock.close()
        except: pass
        return

    try:
        handshake = {
            "op": "open",
            "token": STATE.get("token"),
            "client_ip": STATE.get("public_ip") or get_public_ip(),
            "hostname": SERVER_NAME,
            "service": service_name,
            "listen_port": int(listen_port),
            "attacker_ip": attacker_ip,
            "attacker_port": attacker_port
        }
        send_json(remote, handshake)
    except Exception as e:
        log(f"Handshake hata: {e}")
        try:
            remote.close(); local_sock.close()
        except: pass
        return

    t1 = threading.Thread(target=pipe_streams, args=(local_sock, remote), daemon=True)
    t2 = threading.Thread(target=pipe_streams, args=(remote, local_sock), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    log(f"[{service_name}:{listen_port}] bağlantı kapandı ({attacker_ip}:{attacker_port})")

class ServerThread(threading.Thread):
    def __init__(self, listen_port, service_name):
        super().__init__(daemon=True)
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
                target=handle_incoming_connection,
                args=(client_sock, self.listen_port, self.service_name),
                daemon=True
            )
            th.start()
            STATE["threads"].append(th)

    def stop(self):
        self.stop_evt.set()
        try:
            if self.sock:
                self.sock.close()
        except:
            pass

# ===================== KALICILIK (STATUS) ===================== #
def write_status(active_rows, running=True):
    """active_rows: [('3389','53389','RDP'), ...]"""
    STATE["selected_rows"] = [(str(a[0]), str(a[1]), str(a[2])) for a in active_rows]
    with open(STATUS_FILE, "w", encoding="utf-8") as f:
        json.dump({"active_ports": STATE["selected_rows"], "running": running}, f)

def read_status():
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

# ===================== AUTOSTART ===================== #
def _task_command_for_daemon():
    if getattr(sys, 'frozen', False):
        return f'"{sys.executable}" --daemon'
    return f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}" --daemon'

def _task_command_for_minimized():
    if getattr(sys, 'frozen', False):
        return f'"{sys.executable}" --minimized'
    return f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}" --minimized'

def install_autostart_system_boot():
    """SYSTEM olarak, BOOT’ta başlatan görev (arka plan daemon)"""
    cmd = f'schtasks /Create /TN "{TASK_NAME_BOOT}" /SC ONSTART /RU "SYSTEM" /TR {_task_command_for_daemon()} /F'
    run_cmd(cmd)
    # Oturuma bağlı kalmadan hemen daemon'u başlatmayı dene
    run_cmd(f'schtasks /Run /TN "{TASK_NAME_BOOT}"')

def install_autostart_user_logon():
    """Kullanıcı oturum açınca tray’da başlat (minimized GUI)"""
    user = os.environ.get("USERNAME") or ""
    cmd = f'schtasks /Create /TN "{TASK_NAME_LOGON}" /SC ONLOGON /RU "{user}" /TR {_task_command_for_minimized()} /RL HIGHEST /F'
    run_cmd(cmd)

def remove_autostart():
    # Çalışan görev(ler)i sonlandır ve sil
    run_cmd(f'schtasks /End /TN "{TASK_NAME_BOOT}"')
    run_cmd(f'schtasks /Delete /TN "{TASK_NAME_BOOT}" /F')
    run_cmd(f'schtasks /Delete /TN "{TASK_NAME_LOGON}" /F')

# ===================== RDP TAŞIMA ===================== #
def switch_rdp_port(new_port):
    run_cmd(f'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v PortNumber /t REG_DWORD /d {new_port} /f')
    run_cmd(f'netsh advfirewall firewall add rule name="RDP {new_port}" dir=in action=allow protocol=TCP localport={new_port}')
    run_cmd('sc stop TermService')
    time.sleep(1.5)
    run_cmd('sc start TermService')

# --- Hardened implementations (shell=False, reliable service control) ---
def _sc_query_state(svc_name: str) -> str:
    try:
        out = subprocess.check_output(['sc', 'query', svc_name], shell=False, stderr=subprocess.STDOUT)
        txt = out.decode('utf-8', 'ignore')
        for line in txt.splitlines():
            if 'STATE' in line:
                parts = line.split()
                if parts:
                    return parts[-1].strip().upper()
    except Exception as e:
        log(f"sc query error: {e}")
    return "UNKNOWN"

def _sc_wait_state(svc_name: str, desired: str, timeout: int = 45) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        st = _sc_query_state(svc_name)
        if st == desired.upper():
            return True
        time.sleep(1.0)
    return False

def stop_service(svc_name: str, timeout: int = 45) -> bool:
    try:
        run_cmd(['sc', 'stop', svc_name])
    except Exception:
        pass
    ok = _sc_wait_state(svc_name, 'STOPPED', timeout)
    if not ok:
        log(f"Service {svc_name} did not stop in time")
    return ok

def start_service(svc_name: str, timeout: int = 45) -> bool:
    try:
        run_cmd(['sc', 'start', svc_name])
    except Exception:
        pass
    ok = _sc_wait_state(svc_name, 'RUNNING', timeout)
    if not ok:
        log(f"Service {svc_name} did not start in time")
    return ok

def _install_autostart_system_boot_safe():
    cmd = [
        'schtasks', '/Create', '/TN', TASK_NAME_BOOT,
        '/SC', 'ONSTART', '/RU', 'SYSTEM',
        '/TR', _task_command_for_daemon(), '/F'
    ]
    run_cmd(cmd)
    run_cmd(['schtasks', '/Run', '/TN', TASK_NAME_BOOT])

def _install_autostart_user_logon_safe():
    user = os.environ.get("USERNAME") or ""
    cmd = [
        'schtasks', '/Create', '/TN', TASK_NAME_LOGON,
        '/SC', 'ONLOGON', '/RU', user,
        '/TR', _task_command_for_minimized(), '/RL', 'HIGHEST', '/F'
    ]
    run_cmd(cmd)

def _remove_autostart_safe():
    run_cmd(['schtasks', '/End', '/TN', TASK_NAME_BOOT])
    run_cmd(['schtasks', '/Delete', '/TN', TASK_NAME_BOOT, '/F'])
    run_cmd(['schtasks', '/Delete', '/TN', TASK_NAME_LOGON, '/F'])

def _switch_rdp_port_safe(new_port):
    run_cmd([
        'reg', 'add', r'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp',
        '/v', 'PortNumber', '/t', 'REG_DWORD', '/d', str(new_port), '/f'
    ])
    run_cmd([
        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
        f'name=RDP {new_port}', 'dir=in', 'action=allow', 'protocol=TCP', f'localport={new_port}'
    ])
    stop_service('TermService', timeout=60)
    start_service('TermService', timeout=60)

# Override original implementations with hardened ones
install_autostart_system_boot = _install_autostart_system_boot_safe
install_autostart_user_logon = _install_autostart_user_logon_safe
remove_autostart = _remove_autostart_safe
switch_rdp_port = _switch_rdp_port_safe

def rdp_move_popup(root, mode, on_confirm):
    popup = tk.Toplevel(root)
    popup.title("RDP İşlemi")
    msg = "RDP portunuz 53389'a taşınacak.\n45 saniye içinde yeni porttan bağlanın.\nAksi halde eski porta dönülecek." if mode=="secure" \
          else "RDP portunuz 3389'a geri taşınacak.\n45 saniye içinde eski porttan bağlanın.\nAksi halde yeni port aktif kalacak."
    tk.Label(popup, text=msg, font=("Arial", 11), justify="center").pack(padx=20, pady=15)
    countdown_label = tk.Label(popup, text="45", font=("Arial", 20, "bold"), fg="red")
    countdown_label.pack()

    def rollback(port_):
        switch_rdp_port(port_)
        messagebox.showwarning("Rollback", f"Port {port_} geri yüklendi.")
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
        if mode == "secure": switch_rdp_port(53389)
        else: switch_rdp_port(3389)
    except Exception as e:
        messagebox.showerror("Hata", f"RDP ayarlanamadı: {e}")
        try: popup.destroy()
        except: pass
        return

    countdown()
    tk.Button(popup, text="Onaylıyorum", command=confirm_success,
              bg="#4CAF50", fg="white", padx=15, pady=5).pack(pady=10)

# ===================== TUNNEL KONTROL ===================== #
def apply_tunnels(selected_rows):
    """
    selected_rows: [('3389','53389','RDP'), ...]
    """
    started = 0
    clean_rows = []
    for row in selected_rows:
        listen_port, new_port, service = str(row[0]), str(row[1]), str(row[2])
        st = ServerThread(listen_port, service)
        st.start()
        time.sleep(0.15)
        if st.is_alive():
            STATE["servers"][int(listen_port)] = st
            clean_rows.append((listen_port, new_port, service))
            started += 1
    if started == 0:
        try: messagebox.showerror("Hata", "Seçili portlar dinlenemedi. Portlar meşgul olabilir.")
        except: pass
        return False

    write_status(clean_rows, running=True)
    STATE["running"] = True
    # Watchdog'u devreye al
    _ensure_watchdog()
    update_tray_icon()
    # ⬇️ Anlık 'online' heartbeat
    send_heartbeat_once("online")
    return True

def remove_tunnels():
    for p, st in list(STATE["servers"].items()):
        try: st.stop()
        except: pass
    STATE["servers"].clear()
    STATE["running"] = False
    update_tray_icon()
    try:
        write_status(STATE.get("selected_rows", []), running=False)
    except: pass
    # ⬇️ Anlık 'offline' heartbeat
    send_heartbeat_once("offline")

# ===================== TRAY ===================== #
def _tray_make_image(active):
    from PIL import Image, ImageDraw
    col = "green" if active else "red"
    img = Image.new('RGB', (64, 64), "white")
    d = ImageDraw.Draw(img)
    d.ellipse((8, 8, 56, 56), fill=col)
    return img

def tray_loop():
    if not TRY_TRAY:
        return
    icon = pystray.Icon("honeypot_client")
    STATE["tray"] = icon
    icon.title = "Cloud Honeypot Client"
    icon.icon = _tray_make_image(STATE["running"])

    def show_cb():
        try:
            if STATE["root"]:
                STATE["root"].deiconify()
                STATE["root"].lift()
                STATE["root"].focus_force()
        except: pass

    def secure_cb():
        if STATE["btn_primary"] and STATE["btn_primary"]["text"] == "Güvene Al":
            STATE["btn_primary"].invoke()

    def stop_cb():
        if STATE["btn_primary"] and STATE["btn_primary"]["text"] == "Korumayı Durdur":
            STATE["btn_primary"].invoke()

    def exit_cb():
        if STATE["running"]:
            messagebox.showwarning("Uyarı", "Önce Korumayı Durdur.")
            return
        icon.stop()
        if STATE["root"]:
            STATE["root"].destroy()
        stop_single_instance_server()
        os._exit(0)

    STATE["show_cb"] = show_cb
    icon.menu = (
        TrayItem('Göster', lambda: show_cb()),
        TrayItem('Çıkış', lambda: exit_cb())
    )
    icon.run()

def update_tray_icon():
    if not TRY_TRAY: return
    icon = STATE.get("tray")
    if not icon: return
    icon.icon = _tray_make_image(STATE["running"])
    icon.visible = True

# ===================== DAEMON ===================== #
def run_daemon():
    STATE["token"] = load_token()
    STATE["public_ip"] = get_public_ip()
    threading.Thread(target=heartbeat_loop, daemon=True).start()

    saved_rows, saved_running = read_status()
    rows = saved_rows if saved_rows else [(p1, p2, s) for (p1, p2, s) in PORT_TABLOSU]

    if not rows:
        log("Daemon: aktif port yok, beklemede.")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            return

    ok = apply_tunnels(rows)
    if not ok:
        log("Daemon: Tüneller başlatılamadı, çıkılıyor.")
        return

    log("Daemon: Tüneller aktif (arka plan).")
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        remove_tunnels()
        log("Daemon: durduruldu.")

# --- Daemon davranışını daha dayanıklı hale getiren geliştirilmiş sürüm ---
def _run_daemon_improved():
    _install_excepthook()
    STATE["token"] = load_token()
    STATE["public_ip"] = get_public_ip()
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    _ensure_watchdog()

    # Kullanıcı onayı yoksa tünelleri uygulama
    cons = read_consent()
    if not cons.get("accepted"):
        log("Daemon: kullanıcı onayı yok, tünel uygulanmayacak.")
        return

    saved_rows, saved_running = read_status()
    rows = saved_rows if saved_rows else [(p1, p2, s) for (p1, p2, s) in PORT_TABLOSU]
    # Daemon, seçimleri bilsin
    STATE["selected_rows"] = [(str(a[0]), str(a[1]), str(a[2])) for a in rows]

    if not rows:
        log("Daemon: aktif port yok, beklemede.")
    # Tünelleri devreye almayı tekrar dener; port meşgulse boşuna çıkmaz
    while True:
        try:
            if rows and not STATE.get("running"):
                ok = apply_tunnels(rows)
                if ok:
                    log("Daemon: Tüneller aktif (arka plan).")
            time.sleep(5)
        except KeyboardInterrupt:
            break
        except Exception as e:
            log(f"Daemon loop err: {e}")
    # Çıkış yolu
    try:
        remove_tunnels()
    except Exception:
        pass
    log("Daemon: durduruldu.")

# Varolan run_daemon fonksiyonunu yeni sürümle değiştir
run_daemon = _run_daemon_improved

# ===================== GUI ===================== #
PORT_TABLOSU = [
    ("3389", "53389", "RDP"),
    ("1433", "-", "MSSQL"),
    ("3306", "-", "MySQL"),
    ("21",   "-", "FTP"),
    ("22",   "-", "SSH"),
]

def _set_primary_button(text, cmd, color):
    btn = STATE["btn_primary"]
    btn.config(text=text, command=cmd, bg=color)

def build_gui(minimized=False):
    # ---- Single-instance server: ikinci açılış SHOW gönderip çıkacak
    start_single_instance_server()

    token = load_token()
    STATE["token"] = token
    STATE["public_ip"] = get_public_ip()
    threading.Thread(target=heartbeat_loop, daemon=True).start()

    dashboard_url = f"https://honeypot.yesnext.com.tr/dashboard?token={token}"

    root = tk.Tk()
    STATE["root"] = root
    # Dil ayarı
    try:
        STATE["lang"] = read_settings().get("language", "tr")
    except Exception:
        STATE["lang"] = "tr"
    root.title(t("app_title"))
    root.geometry("820x620")
    root.configure(bg="#f5f5f5")
    try:
        ensure_consent_ui(root)
    except Exception as e:
        log(f"consent ui error: {e}")

    # Menü çubuğu: Ayarlar/Dil ve Yardım/Güncellemeleri Denetle
    menubar = tk.Menu(root)
    menu_settings = tk.Menu(menubar, tearoff=0)
    def set_lang(code):
        try:
            write_settings(code)
        except Exception:
            pass
        messagebox.showinfo("Info", t("restart_needed_lang"))
        # Restart
        exe = _current_executable()
        try:
            subprocess.Popen([exe] + sys.argv[1:], shell=False)
        except Exception:
            pass
        os._exit(0)
    lang_menu = tk.Menu(menu_settings, tearoff=0)
    lang_menu.add_command(label=t("menu_lang_tr"), command=lambda: set_lang("tr"))
    lang_menu.add_command(label=t("menu_lang_en"), command=lambda: set_lang("en"))
    menu_settings.add_cascade(label=t("menu_language"), menu=lang_menu)
    menubar.add_cascade(label=t("menu_settings"), menu=menu_settings)

    menu_help = tk.Menu(menubar, tearoff=0)
    menu_help.add_command(label=t("menu_check_updates"), command=lambda: check_updates_and_prompt(root))
    menubar.add_cascade(label=t("menu_help"), menu=menu_help)
    root.config(menu=menubar)

    # X: kapanma yok, tray'a küçült
    def on_close():
        if TRY_TRAY:
            root.withdraw()
        else:
            root.withdraw()
    root.protocol("WM_DELETE_WINDOW", on_close)

    style = ttk.Style()
    try: style.theme_use("clam")
    except: pass
    style.configure("TButton", font=("Arial", 11), padding=6)
    style.configure("Treeview.Heading", font=("Arial", 10, "bold"))
    style.configure("Treeview", rowheight=28)

    frame1 = tk.LabelFrame(root, text="Sunucu Bilgileri", padx=10, pady=10, bg="#f5f5f5", font=("Arial", 11, "bold"))
    frame1.pack(fill="x", padx=15, pady=10)

    def copy_entry(entry: tk.Entry):
        try:
            value = entry.get()
            root.clipboard_clear(); root.clipboard_append(value); root.update()
            messagebox.showinfo("Kopyalandı", value)
        except Exception as e:
            log(f"copy_entry error: {e}")

    def copy_text(value):
        root.clipboard_clear(); root.clipboard_append(value); root.update()
        messagebox.showinfo("Kopyalandı", value)

    def open_dashboard():
        webbrowser.open(dashboard_url)

    # İlk değerler
    attack_count_val = fetch_attack_count_sync(token)
    if attack_count_val is None: attack_count_val = 0

    info_rows = [
        ("PC Adı / IP", f"{SERVER_NAME} ({STATE['public_ip']})", "ip"),
        ("Token", token, "token"),
        ("Dashboard Adresi", dashboard_url, "dash"),
        ("Toplam Saldırılar", str(attack_count_val), "attacks"),
    ]

    for idx, (label, value, key) in enumerate(info_rows):
        tk.Label(frame1, text=label + ":", font=("Arial", 11), bg="#f5f5f5",
                 width=18, anchor="w").grid(row=idx, column=0, sticky="w", pady=3)
        entry = tk.Entry(frame1, width=60, font=("Arial", 10))
        entry.insert(0, value); entry.config(state="readonly")
        entry.grid(row=idx, column=1, padx=5, pady=3)

        # Kopya butonu (entry'den kopyala)
        tk.Button(frame1, text="📋", command=lambda e=entry: copy_entry(e)).grid(row=idx, column=2, padx=3)

        if key == "dash":
            # Dashboard aç
            tk.Button(frame1, text="🌐 Aç", command=open_dashboard).grid(row=idx, column=3, padx=3)

        if key == "attacks":
            # ↻ Yenile
            tk.Button(frame1, text="↻", command=lambda: refresh_attack_count(async_thread=True)).grid(row=idx, column=3, padx=3)
            STATE["attack_entry"] = entry

        if key == "ip":
            STATE["ip_entry"] = entry

    frame2 = tk.LabelFrame(root, text="Port Tünelleme", padx=10, pady=10, bg="#f5f5f5", font=("Arial", 11, "bold"))
    frame2.pack(fill="both", expand=True, padx=15, pady=10)

    columns = ("Dinlenecek Port", "Yeni Port/RDP", "Servis", "Aktif")
    tree = ttk.Treeview(frame2, columns=columns, show="headings", height=len(PORT_TABLOSU))
    STATE["tree"] = tree
    tree.pack(fill="x")

    for col in columns:
        tree.heading(col, text=col); tree.column(col, anchor="center", width=170)

    tree.tag_configure("aktif", background="#C8E6C9")

    selected_ports = {}
    STATE["selected_ports_map"] = selected_ports
    row_ids = []
    for (p1, p2, servis) in PORT_TABLOSU:
        iid = tree.insert("", "end", values=(p1, p2, servis, "☐"))
        selected_ports[iid] = False
        row_ids.append((iid, p1, p2, servis))

    # Önceki seçimleri GUI'ye uygula
    saved_rows, saved_running = read_status()
    if saved_rows:
        for iid, p1, p2, servis in row_ids:
            for sr in saved_rows:
                if str(sr[0]) == str(p1) and str(sr[2]).upper() == str(servis).upper():
                    selected_ports[iid] = True
                    tree.set(iid, "Aktif", "☑")
                    tree.item(iid, tags=("aktif",))
                    break

    def toggle_checkbox(event):
        col = tree.identify_column(event.x)
        if col != "#4": return
        item_id = tree.identify_row(event.y)
        if item_id and STATE["btn_primary"]["text"] == "Güvene Al":
            cur = selected_ports[item_id]
            selected_ports[item_id] = not cur
            tree.set(item_id, "Aktif", "☑" if selected_ports[item_id] else "☐")
            tree.item(item_id, tags=("aktif",) if selected_ports[item_id] else ())
    tree.bind("<Button-1>", toggle_checkbox)

    frame3 = tk.Frame(root, bg="#f5f5f5", pady=20)
    frame3.pack(fill="x")

    # Tek buton
    btn_primary = tk.Button(frame3, text="Güvene Al", font=("Arial", 13, "bold"),
                            bg="#4CAF50", fg="white", padx=25, pady=12)
    STATE["btn_primary"] = btn_primary
    btn_primary.pack(side="left", padx=10)

    note = tk.Label(root, text="Not: RDP korumayı seçtiğinizde 45 sn içinde yeni porttan bağlanıp onay verin.",
                    font=("Arial", 9), fg="red", bg="#f5f5f5", justify="center")
    note.pack(pady=5)

    # Buton aksiyonları
    def finalize_secure(active_rows):
        for iid in selected_ports.keys():
            if selected_ports[iid]:
                tree.item(iid, tags=("aktif",))
        tree.unbind("<Button-1>")
        _set_primary_button("Korumayı Durdur", stop_protection, "#E53935")
        messagebox.showinfo("Başarılı", f"{len(active_rows)} port tünellendi!")

    def do_secure_ports():
        # Kullanıcı onayı
        cons = read_consent()
        if not cons.get("accepted"):
            cons = ensure_consent_ui(root)
            if not cons.get("accepted"):
                messagebox.showwarning("Uyarı", "İşlem iptal edildi: Onay verilmedi.")
                return
        ensure_admin()
        active_rows = [tree.item(iid)["values"][:3] for iid, val in selected_ports.items() if val]
        if not active_rows:
            messagebox.showwarning("Uyarı", "Hiçbir port seçmediniz!")
            return
        # RDP seçiliyse önce taşı
        if any(str(p[0]) == "3389" for p in active_rows) and cons.get("rdp_move", True):
            non_rdp = [p for p in active_rows if str(p[0]) != "3389"]
            def after_rdp():
                ok = apply_tunnels([("3389","53389","RDP")] + non_rdp)
                if ok:
                    if cons.get("autostart", False):
                        install_autostart_system_boot()
                        install_autostart_user_logon()
                    finalize_secure([("3389","53389","RDP","☑")] + non_rdp)
                    refresh_attack_count(async_thread=True)  # anlık güncelle
            rdp_move_popup(root, "secure", after_rdp)
            return
        ok = apply_tunnels(active_rows)
        if ok:
            if cons.get("autostart", False):
                install_autostart_system_boot()
                install_autostart_user_logon()
            finalize_secure(active_rows)
            refresh_attack_count(async_thread=True)

    def stop_protection():
        if not messagebox.askyesno("Onay", "Tüm korumaları durdurmak istediğinize emin misiniz?"):
            return
        was_active, _ = read_status()
        def finish_stop():
            remove_tunnels()
            remove_autostart()
            # checkbox'ları temizle
            for iid in selected_ports.keys():
                selected_ports[iid] = False
                tree.set(iid, "Aktif", "☐")
                tree.item(iid, tags=())
            tree.bind("<Button-1>", toggle_checkbox)
            _set_primary_button("Güvene Al", do_secure_ports, "#4CAF50")
            messagebox.showinfo("Durdu", "Tüm korumalar kaldırıldı.")
            refresh_attack_count(async_thread=True)
        if any(str(p[0]) == "3389" for p in was_active):
            rdp_move_popup(root, "rollback", finish_stop)
        else:
            finish_stop()

    _set_primary_button("Güvene Al", do_secure_ports, "#4CAF50")

    # Tray (opsiyonel) — arka planda kalıcılık
    if TRY_TRAY:
        def tray_thread():
            tray_loop()
        threading.Thread(target=tray_thread, daemon=True).start()

    # Eğer önceki durum "running" ise otomatik başlat + UI'yi ona göre ayarla
    if saved_rows and saved_running:
        ok = apply_tunnels(saved_rows)
        if ok:
            tree.unbind("<Button-1>")
            _set_primary_button("Korumayı Durdur", stop_protection, "#E53935")
            if minimized:
                root.withdraw()

    if minimized:
        root.withdraw()

    # SHOW komutu geldiğinde pencereyi öne getir
    def _show_window():
        try:
            root.deiconify(); root.lift(); root.focus_force()
        except: pass
    STATE["show_cb"] = _show_window

    # Otomatik saldırı sayacı poller’ı başlat
    root.after(0, poll_attack_count)

    root.mainloop()

# ===================== MAIN ===================== #
if __name__ == "__main__":
    # Daemon modu (servis benzeri, arka plan)
    if len(sys.argv) > 1 and sys.argv[1] == "--daemon":
        run_daemon()
        sys.exit(0)

    # Minimized GUI (ONLOGON için)
    minimized = (len(sys.argv) > 1 and sys.argv[1] == "--minimized")
    build_gui(minimized=minimized)
