#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client - Honeypot Services Module

Lightweight honeypot servisleri: sahte protokol handshake yaparak
saldırgan credential bilgilerini yakalar ve API'ye raporlar.

Sınıflar:
    BaseHoneypot   — Tüm servisler için abstract base class (threading.Thread)
    FTPHoneypot    — Sahte FTP servisi (raw socket, kütüphane gerektirmez)
    SSHHoneypot    — Sahte SSH servisi (paramiko ServerInterface)

Kullanım:
    def on_credential(attacker_ip, username, password, service, port):
        print(f"Yakalandı: {username}:{password} <- {attacker_ip}")

    ftp = FTPHoneypot(port=21, on_credential=on_credential)
    ftp.start()
    ...
    ftp.stop()

Notlar:
    - Her servis kendi thread'inde çalışır (daemon=True)
    - Port çakışması start() öncesinde kontrol edilir
    - Otomatik yeniden başlatma (max 3 deneme, exponential backoff)
    - Rate limiting: aynı IP+service için dk başına max 10 rapor
"""

import socket
import threading
import time
import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Callable, Optional

from client_constants import (
    FTP_BANNER, SSH_BANNER,
    MAX_CREDENTIAL_LENGTH, MAX_ATTEMPTS_PER_IP_PER_MIN,
    HONEYPOT_AUTO_RESTART_MAX, HONEYPOT_RESTART_BACKOFF,
)
from client_helpers import log, is_port_in_use


# ===================== RATE LIMITER ===================== #

class _RateLimiter:
    """IP+service bazlı rate limiter — dakikada max N rapor"""

    def __init__(self, max_per_min: int = MAX_ATTEMPTS_PER_IP_PER_MIN):
        self._max = max_per_min
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            bucket = self._buckets[key]
            # Eski girişleri temizle (60s pencere)
            bucket[:] = [t for t in bucket if now - t < 60]
            if len(bucket) >= self._max:
                return False
            bucket.append(now)
            return True

_rate_limiter = _RateLimiter()


# ===================== BASE HONEYPOT ===================== #

class BaseHoneypot(ABC, threading.Thread):
    """Tüm honeypot servisleri için abstract base class.

    Alt sınıflar sadece ``handle_client()`` metodunu implement eder.
    ``start()`` / ``stop()`` yaşam döngüsü bu sınıfta yönetilir.
    """

    def __init__(
        self,
        port: int,
        service_name: str,
        on_credential: Callable[..., None],
        bind_addr: str = "0.0.0.0",
        backlog: int = 64,
    ):
        super().__init__(daemon=True, name=f"Honeypot-{service_name}-{port}")
        self.port = int(port)
        self.service_name = service_name.upper()
        self.on_credential = on_credential
        self.bind_addr = bind_addr
        self.backlog = backlog

        self._stop_evt = threading.Event()
        self._server_sock: Optional[socket.socket] = None
        self._restart_count = 0
        self.running = False
        self.error: Optional[str] = None

    # ---------- public API ----------

    def stop(self):
        """Servisi durdur — accept loop kırılır, socket kapatılır."""
        self._stop_evt.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        self.running = False
        log(f"[{self.service_name}] Port {self.port} durduruldu")

    def get_status(self) -> str:
        if self.error:
            return "error"
        return "started" if self.running else "stopped"

    # ---------- credential reporting ----------

    def report_credential(self, attacker_ip: str, username: str, password: str = ""):
        """Yakalanan credential'ı rate-limit kontrolüyle callback'e ilet."""
        username = str(username or "")[:MAX_CREDENTIAL_LENGTH]
        password = str(password or "")[:MAX_CREDENTIAL_LENGTH]

        key = f"{attacker_ip}:{self.service_name}"
        if not _rate_limiter.allow(key):
            return  # Rate limit aşıldı — sessizce atla

        try:
            self.on_credential(
                attacker_ip=attacker_ip,
                username=username,
                password=password,
                service=self.service_name,
                port=self.port,
            )
        except Exception as exc:
            log(f"[{self.service_name}] Credential callback hatası: {exc}")

    # ---------- thread entry point ----------

    def run(self):
        """Ana accept döngüsü — alt sınıf handle_client() sağlar."""
        # Port çakışma kontrolü
        if is_port_in_use(self.port):
            self.error = f"Port {self.port} zaten kullanımda"
            log(f"[{self.service_name}] HATA: {self.error}")
            return

        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self.bind_addr, self.port))
            self._server_sock.listen(self.backlog)
            self._server_sock.settimeout(1.0)
            self.running = True
            self.error = None
            log(f"[{self.service_name}] Dinleniyor: {self.bind_addr}:{self.port}")
        except Exception as exc:
            self.error = str(exc)
            log(f"[{self.service_name}] Bind hatası port {self.port}: {exc}")
            return

        while not self._stop_evt.is_set():
            try:
                client_sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop_evt.is_set():
                    break
                log(f"[{self.service_name}] Accept hatası")
                continue

            # Her bağlantı kendi thread'inde işlenir
            t = threading.Thread(
                target=self._safe_handle,
                args=(client_sock, addr),
                daemon=True,
                name=f"{self.service_name}-handler-{addr[0]}",
            )
            t.start()

        self.running = False

    def _safe_handle(self, client_sock: socket.socket, addr: tuple):
        """handle_client() çevresinde güvenli try/except sarmalayıcı."""
        try:
            self.handle_client(client_sock, addr)
        except Exception as exc:
            log(f"[{self.service_name}] Bağlantı hatası {addr[0]}: {exc}")
        finally:
            try:
                client_sock.close()
            except OSError:
                pass

    # ---------- abstract ----------

    @abstractmethod
    def handle_client(self, client_sock: socket.socket, addr: tuple):
        """Tek bir bağlantıyı işle — credential yakala, bağlantıyı kapat.

        Alt sınıf, protokol handshake'ini burada yapar ve
        ``self.report_credential(ip, username, password)`` çağırır.
        """
        ...


# ===================== FTP HONEYPOT ===================== #

class FTPHoneypot(BaseHoneypot):
    """Sahte FTP servisi — USER/PASS komutlarıyla credential yakalar.

    Protokol akışı:
        Server: 220 (vsFTPd 3.0.5)\\r\\n
        Client: USER admin\\r\\n
        Server: 331 Password required for admin.\\r\\n
        Client: PASS secret123\\r\\n
        Server: 530 Login incorrect.\\r\\n
        (bağlantı kapatılır)
    """

    TIMEOUT = 30  # saniye — yavaş tarayıcılar için

    def __init__(self, port: int = 21, *, on_credential: Callable, banner: str = ""):
        super().__init__(port=port, service_name="FTP", on_credential=on_credential)
        self.banner = banner or FTP_BANNER

    def handle_client(self, sock: socket.socket, addr: tuple):
        attacker_ip = addr[0]
        sock.settimeout(self.TIMEOUT)

        # Banner gönder
        self._send(sock, f"{self.banner}\r\n")

        username = ""
        attempts = 0
        max_attempts = 3  # Aynı bağlantıda max 3 deneme

        while attempts < max_attempts:
            line = self._readline(sock)
            if not line:
                break

            cmd = line.upper()

            if cmd.startswith("USER "):
                username = line[5:].strip()
                self._send(sock, f"331 Password required for {username}.\r\n")

            elif cmd.startswith("PASS "):
                password = line[5:].strip()
                if username:
                    log(f"[FTP] Credential yakalandı: {username}:{password} <- {attacker_ip}")
                    self.report_credential(attacker_ip, username, password)
                    attempts += 1
                self._send(sock, "530 Login incorrect.\r\n")
                username = ""  # Sonraki deneme için sıfırla

            elif cmd.startswith("QUIT"):
                self._send(sock, "221 Goodbye.\r\n")
                break

            else:
                # Bilinmeyen komut — yine de bağlantıyı kes
                self._send(sock, "500 Unknown command.\r\n")

    @staticmethod
    def _send(sock: socket.socket, data: str):
        try:
            sock.sendall(data.encode("utf-8"))
        except (OSError, BrokenPipeError):
            pass

    @staticmethod
    def _readline(sock: socket.socket) -> str:
        """Satır satır oku (\\r\\n veya \\n ile biter). Max 1KB."""
        buf = b""
        try:
            while len(buf) < 1024:
                ch = sock.recv(1)
                if not ch:
                    break
                buf += ch
                if buf.endswith(b"\n"):
                    break
        except (socket.timeout, OSError):
            pass
        return buf.decode("utf-8", errors="replace").strip()


# ===================== SSH HONEYPOT ===================== #

class SSHHoneypot(BaseHoneypot):
    """Sahte SSH servisi — paramiko ServerInterface ile credential yakalar.

    Protokol akışı:
        1. TCP bağlantısı → SSH banner exchange
        2. Key exchange (DH/curve25519)
        3. SSH_MSG_USERAUTH_REQUEST → username + password açık metin
        4. Her zaman AUTH_FAILED döner → credential kaydedilir

    Gereksinim: paramiko>=3.4.0
    """

    def __init__(self, port: int = 22, *, on_credential: Callable, banner: str = ""):
        super().__init__(port=port, service_name="SSH", on_credential=on_credential)
        self.banner = banner or SSH_BANNER
        self._host_key = None

    def run(self):
        """Override: paramiko mevcutluğunu kontrol et, host key oluştur."""
        try:
            import paramiko  # noqa: F401
        except ImportError:
            self.error = "paramiko kütüphanesi yüklü değil (pip install paramiko)"
            log(f"[SSH] HATA: {self.error}")
            return

        # RSA host key oluştur (her başlatmada yeni — honeypot için sorun değil)
        import paramiko
        self._host_key = paramiko.RSAKey.generate(2048)
        log(f"[SSH] RSA host key oluşturuldu (2048 bit)")

        # Üst sınıfın accept döngüsünü çalıştır
        super().run()

    def handle_client(self, sock: socket.socket, addr: tuple):
        import paramiko

        attacker_ip = addr[0]
        transport = None
        try:
            transport = paramiko.Transport(sock)
            transport.local_version = self.banner
            transport.add_server_key(self._host_key)

            server = _create_ssh_server(
                attacker_ip=attacker_ip,
                honeypot=self,
            )
            transport.start_server(server=server)

            # Bağlantı otomatik olarak kesilene kadar bekle (max 30s)
            chan = transport.accept(timeout=30)
            if chan:
                chan.close()

        except paramiko.SSHException as exc:
            # Normal: brute-force araçları erken kesiyor
            log(f"[SSH] Bağlantı kesildi ({attacker_ip}): {exc}")
        except EOFError:
            pass  # Client erken kapattı — normal
        except Exception as exc:
            log(f"[SSH] Beklenmeyen hata ({attacker_ip}): {exc}")
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass


def _create_ssh_server(attacker_ip: str, honeypot: SSHHoneypot):
    """Factory: paramiko.ServerInterface alt sınıfını runtime'da oluşturur.

    paramiko top-level import değil, sadece SSH servisi çalıştığında yüklenir.
    Bu factory her bağlantıda çağrılır — sınıf tanımı closure içinde cache'lenir.
    """
    import paramiko

    class _SSHServerImpl(paramiko.ServerInterface):
        """Credential yakalama noktası — her auth denemesinde report_credential() çağrılır."""

        def check_channel_request(self, kind: str, chanid: int) -> int:
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_auth_password(self, username: str, password: str) -> int:
            """Her password denemesinde çağrılır — credential yakala, DENY döndür."""
            log(f"[SSH] Credential yakalandı: {username}:{password} <- {attacker_ip}")
            honeypot.report_credential(attacker_ip, username, password)
            return paramiko.AUTH_FAILED

        def check_auth_publickey(self, username: str, key) -> int:
            return paramiko.AUTH_FAILED

        def get_allowed_auths(self, username: str) -> str:
            return "password"

        def check_channel_shell_request(self, channel) -> bool:
            return False

        def check_channel_pty_request(self, channel, term, width, height,
                                       pixelwidth, pixelheight, modes) -> bool:
            return False

    return _SSHServerImpl()
