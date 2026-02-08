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
    MySQLHoneypot  — Sahte MySQL servisi (native handshake, kütüphane gerektirmez)
    MSSQLHoneypot  — Sahte MSSQL servisi (TDS pre-login, kütüphane gerektirmez)
    RDPHoneypot    — Sahte RDP servisi (X.224 + NTLM handshake, kütüphane gerektirmez)

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

import hashlib
import os
import socket
import struct
import threading
import time
import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Callable, Optional

from client_constants import (
    FTP_BANNER, SSH_BANNER, MYSQL_VERSION, MSSQL_VERSION, RDP_CERT_CN,
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


# ===================== MYSQL HONEYPOT ===================== #

class MySQLHoneypot(BaseHoneypot):
    """Sahte MySQL servisi — native auth handshake ile credential yakalar.

    MySQL wire protocol (COM_* yok — sadece auth aşaması):
        1. Server → Client: Initial Handshake (protocol v10)
           - 20-byte random challenge (salt)
           - Server version string
           - Capability flags (CLIENT_SECURE_CONNECTION)
        2. Client → Server: Handshake Response
           - Username (null-terminated)
           - Auth response (SHA1 hash of password + salt)
           - Database name (opsiyonel)
        3. Server → Client: ERR_Packet (Access denied)

    Credential yakalama:
        - Username: handshake response'dan parse edilir (plaintext)
        - Password: SHA1 hash olarak gelir, plaintext olarak yakalanamaz
        - Brute-force araçları genelde aynı password'u dener → hash log'lanır

    Not: Harici kütüphane gerektirmez — tamamen raw socket + struct.
    """

    TIMEOUT = 30

    # MySQL protocol constants
    _PROTOCOL_VERSION = 10
    _SERVER_STATUS_AUTOCOMMIT = 0x0002
    _CLIENT_LONG_PASSWORD = 0x00000001
    _CLIENT_PROTOCOL_41 = 0x00000200
    _CLIENT_SECURE_CONNECTION = 0x00008000
    _CLIENT_PLUGIN_AUTH = 0x00080000
    _CHARSET_UTF8 = 33  # utf8_general_ci

    def __init__(self, port: int = 3306, *, on_credential: Callable, version: str = ""):
        super().__init__(port=port, service_name="MYSQL", on_credential=on_credential)
        self.version = version or MYSQL_VERSION

    def handle_client(self, sock: socket.socket, addr: tuple):
        attacker_ip = addr[0]
        sock.settimeout(self.TIMEOUT)

        # 1) Initial Handshake Packet gönder
        salt = os.urandom(20)  # Challenge bytes
        handshake = self._build_handshake_packet(salt)
        self._send_packet(sock, handshake, seq=0)

        # 2) Client Handshake Response'u oku
        try:
            payload, _ = self._read_packet(sock)
            if not payload:
                return
        except (socket.timeout, OSError, ValueError):
            return

        # 3) Username'i parse et
        username = self._parse_username(payload)
        if username:
            log(f"[MYSQL] Credential yakalandı: {username}:<hash> <- {attacker_ip}")
            self.report_credential(attacker_ip, username, "<mysql_native_hash>")

        # 4) ERR_Packet gönder — Access denied
        err = self._build_err_packet(
            error_code=1045,
            message=f"Access denied for user '{username}'@'{attacker_ip}' (using password: YES)",
        )
        self._send_packet(sock, err, seq=2)

    def _build_handshake_packet(self, salt: bytes) -> bytes:
        """MySQL Protocol v10 Initial Handshake paketini oluştur."""
        salt_part1 = salt[:8]
        salt_part2 = salt[8:]

        buf = bytearray()
        # Protocol version
        buf.append(self._PROTOCOL_VERSION)
        # Server version (null-terminated)
        buf.extend(self.version.encode("ascii") + b"\x00")
        # Connection ID (random 4 bytes)
        buf.extend(struct.pack("<I", os.getpid() & 0xFFFFFFFF))
        # Auth-plugin-data-part-1 (8 bytes) + filler
        buf.extend(salt_part1)
        buf.append(0x00)  # filler
        # Capability flags (lower 2 bytes)
        cap_lower = (
            self._CLIENT_LONG_PASSWORD
            | self._CLIENT_PROTOCOL_41
            | self._CLIENT_SECURE_CONNECTION
            | self._CLIENT_PLUGIN_AUTH
        ) & 0xFFFF
        buf.extend(struct.pack("<H", cap_lower))
        # Character set
        buf.append(self._CHARSET_UTF8)
        # Status flags
        buf.extend(struct.pack("<H", self._SERVER_STATUS_AUTOCOMMIT))
        # Capability flags (upper 2 bytes)
        cap_upper = (
            self._CLIENT_LONG_PASSWORD
            | self._CLIENT_PROTOCOL_41
            | self._CLIENT_SECURE_CONNECTION
            | self._CLIENT_PLUGIN_AUTH
        ) >> 16
        buf.extend(struct.pack("<H", cap_upper))
        # Auth plugin data length
        buf.append(len(salt) + 1)  # 21
        # Reserved (10 zero bytes)
        buf.extend(b"\x00" * 10)
        # Auth-plugin-data-part-2 (rest of salt + null)
        buf.extend(salt_part2)
        buf.append(0x00)
        # Auth plugin name
        buf.extend(b"mysql_native_password\x00")

        return bytes(buf)

    @staticmethod
    def _build_err_packet(error_code: int, message: str) -> bytes:
        """MySQL ERR_Packet oluştur."""
        buf = bytearray()
        buf.append(0xFF)  # ERR marker
        buf.extend(struct.pack("<H", error_code))
        buf.extend(b"#28000")  # SQL state marker + state
        buf.extend(message.encode("utf-8", errors="replace"))
        return bytes(buf)

    @staticmethod
    def _parse_username(payload: bytes) -> str:
        """Handshake Response'dan username'i çıkar.

        Protocol 4.1 format:
            4 bytes: capability flags
            4 bytes: max packet size
            1 byte:  charset
            23 bytes: reserved (zeros)
            null-terminated: username
        """
        if len(payload) < 36:
            return ""
        # Username starts at offset 32 (4+4+1+23)
        username_start = 32
        null_pos = payload.find(b"\x00", username_start)
        if null_pos == -1:
            return ""
        try:
            return payload[username_start:null_pos].decode("utf-8", errors="replace")
        except Exception:
            return ""

    @staticmethod
    def _send_packet(sock: socket.socket, payload: bytes, seq: int = 0):
        """MySQL wire format: 3-byte length + 1-byte sequence + payload."""
        length = len(payload)
        header = struct.pack("<I", length)[:3] + bytes([seq & 0xFF])
        try:
            sock.sendall(header + payload)
        except (OSError, BrokenPipeError):
            pass

    @staticmethod
    def _read_packet(sock: socket.socket) -> tuple[bytes, int]:
        """MySQL paketi oku — (payload, seq_id) döndürür."""
        header = b""
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                return b"", 0
            header += chunk
        length = struct.unpack("<I", header[:3] + b"\x00")[0]
        seq = header[3]
        if length > 65536:  # Güvenlik: çok büyük paketleri reddet
            return b"", seq
        payload = b""
        while len(payload) < length:
            chunk = sock.recv(length - len(payload))
            if not chunk:
                break
            payload += chunk
        return payload, seq


# ===================== MSSQL HONEYPOT ===================== #

class MSSQLHoneypot(BaseHoneypot):
    """Sahte Microsoft SQL Server servisi — TDS protokolü ile credential yakalar.

    TDS (Tabular Data Stream) wire protocol:
        1. Client → Server: TDS Pre-Login (type 0x12)
        2. Server → Client: TDS Pre-Login Response
        3. Client → Server: TDS Login7 (type 0x10)
           - Username + Password (XOR-obfuscated, plaintext'e dönüştürülebilir)
        4. Server → Client: TDS Login Response (Error Token — login failed)

    Credential yakalama:
        - Username: Login7 paketinden plaintext olarak parse edilir
        - Password: XOR obfuscation ile gelir — kolayca decode edilir
          (her byte: nibble swap → XOR 0xA5)

    Not: Harici kütüphane gerektirmez — tamamen raw socket + struct.
    """

    TIMEOUT = 30

    # TDS packet types
    _TDS_PRELOGIN = 0x12
    _TDS_LOGIN7 = 0x10
    _TDS_RESPONSE = 0x04
    _TDS_STATUS_EOM = 0x01  # End of message

    # TDS Pre-Login tokens
    _PL_VERSION = 0x00
    _PL_ENCRYPTION = 0x01
    _PL_INSTOPT = 0x02
    _PL_THREADID = 0x03
    _PL_MARS = 0x04
    _PL_TERMINATOR = 0xFF

    # Encryption options
    _ENCRYPT_NOT_SUP = 0x02  # Encryption not supported

    def __init__(self, port: int = 1433, *, on_credential: Callable, version: str = ""):
        super().__init__(port=port, service_name="MSSQL", on_credential=on_credential)
        self.version = version or MSSQL_VERSION

    def handle_client(self, sock: socket.socket, addr: tuple):
        attacker_ip = addr[0]
        sock.settimeout(self.TIMEOUT)

        # 1) Client Pre-Login bekle
        try:
            pkt_type, payload = self._read_tds_packet(sock)
        except (socket.timeout, OSError, ValueError):
            return

        if pkt_type != self._TDS_PRELOGIN:
            return  # TDS değilse bağlantıyı kapat

        # 2) Pre-Login Response gönder
        prelogin_resp = self._build_prelogin_response()
        self._send_tds_packet(sock, self._TDS_RESPONSE, prelogin_resp)

        # 3) Login7 paketi bekle
        try:
            pkt_type, payload = self._read_tds_packet(sock)
        except (socket.timeout, OSError, ValueError):
            return

        if pkt_type != self._TDS_LOGIN7:
            return

        # 4) Credential parse et
        username, password = self._parse_login7(payload)
        if username:
            log(f"[MSSQL] Credential yakalandı: {username}:{password} <- {attacker_ip}")
            self.report_credential(attacker_ip, username, password)

        # 5) Login failed response gönder
        err_resp = self._build_login_error(username, attacker_ip)
        self._send_tds_packet(sock, self._TDS_RESPONSE, err_resp)

    def _build_prelogin_response(self) -> bytes:
        """TDS Pre-Login Response — version + encryption bilgisi."""
        # Option tokens: VERSION, ENCRYPTION, TERMINATOR
        # Her token: 1 byte type + 2 bytes offset + 2 bytes length
        # Data section follows option tokens

        # Version data: 4 bytes version + 2 bytes build
        version_data = struct.pack(">I", 0x0F000000)  # SQL Server 2019 = 15.x
        version_data += struct.pack(">H", 0x0000)     # Build

        # Encryption data: 1 byte
        encrypt_data = bytes([self._ENCRYPT_NOT_SUP])

        # Calculate offsets (header = 3 tokens * 5 bytes + terminator)
        header_len = 2 * 5 + 1  # 2 options + terminator
        version_offset = header_len
        encrypt_offset = version_offset + len(version_data)

        buf = bytearray()
        # VERSION token
        buf.append(self._PL_VERSION)
        buf.extend(struct.pack(">H", version_offset))
        buf.extend(struct.pack(">H", len(version_data)))
        # ENCRYPTION token
        buf.append(self._PL_ENCRYPTION)
        buf.extend(struct.pack(">H", encrypt_offset))
        buf.extend(struct.pack(">H", len(encrypt_data)))
        # Terminator
        buf.append(self._PL_TERMINATOR)
        # Data
        buf.extend(version_data)
        buf.extend(encrypt_data)

        return bytes(buf)

    @staticmethod
    def _parse_login7(payload: bytes) -> tuple[str, str]:
        """TDS Login7 paketinden username ve password çıkar.

        Login7 fixed header (94 bytes), ardından:
            Offset  Length  Field
            ------- ------  -----
            36-37   2       HostName offset
            38-39   2       HostName length
            40-41   2       UserName offset (from start of packet)
            42-43   2       UserName length (in chars, UTF-16LE)
            44-45   2       Password offset
            46-47   2       Password length (in chars, UTF-16LE)

        Password XOR decode:
            Her byte: nibble swap (rotate 4 bit) → XOR 0xA5
        """
        if len(payload) < 48:
            return "", ""

        try:
            # Username offset/length
            user_offset = struct.unpack("<H", payload[40:42])[0]
            user_length = struct.unpack("<H", payload[42:44])[0]  # chars, not bytes
            # Password offset/length
            pass_offset = struct.unpack("<H", payload[44:46])[0]
            pass_length = struct.unpack("<H", payload[46:48])[0]

            # Parse username (UTF-16LE, no obfuscation)
            username = ""
            if user_length > 0 and user_offset + user_length * 2 <= len(payload):
                user_bytes = payload[user_offset:user_offset + user_length * 2]
                username = user_bytes.decode("utf-16-le", errors="replace")

            # Parse password (UTF-16LE, XOR-obfuscated)
            password = ""
            if pass_length > 0 and pass_offset + pass_length * 2 <= len(payload):
                pass_bytes = bytearray(payload[pass_offset:pass_offset + pass_length * 2])
                # Decode: her byte → swap nibbles → XOR 0xA5
                for i in range(len(pass_bytes)):
                    b = pass_bytes[i]
                    b = ((b >> 4) & 0x0F) | ((b << 4) & 0xF0)  # nibble swap
                    b ^= 0xA5
                    pass_bytes[i] = b
                password = bytes(pass_bytes).decode("utf-16-le", errors="replace")

            return username, password

        except Exception:
            return "", ""

    @staticmethod
    def _build_login_error(username: str, client_ip: str) -> bytes:
        """TDS Error Token — Login failed mesajı.

        Error Token format:
            0xAA (ERROR token type)
            2 bytes: token length
            4 bytes: error number (18456 = login failed)
            1 byte:  state
            1 byte:  class (severity)
            2 bytes: message length (chars)
            N bytes: message (UTF-16LE)
            1 byte:  server name length
            N bytes: server name (UTF-16LE)
            1 byte:  proc name length
            0 bytes: proc name
            4 bytes: line number
        """
        msg = f"Login failed for user '{username}'."
        msg_utf16 = msg.encode("utf-16-le")
        server_name = "MSSQL-SERVER"
        server_utf16 = server_name.encode("utf-16-le")

        error_token = bytearray()
        error_token.append(0xAA)  # ERROR token

        # Build token data (we'll prepend length after)
        token_data = bytearray()
        token_data.extend(struct.pack("<I", 18456))  # Error number
        token_data.append(1)   # State
        token_data.append(14)  # Class (severity)
        token_data.extend(struct.pack("<H", len(msg)))  # Message length (chars)
        token_data.extend(msg_utf16)
        token_data.append(len(server_name))  # Server name length
        token_data.extend(server_utf16)
        token_data.append(0)  # Proc name length (empty)
        token_data.extend(struct.pack("<I", 1))  # Line number

        # Token length (2 bytes, after 0xAA marker)
        error_token.extend(struct.pack("<H", len(token_data)))
        error_token.extend(token_data)

        # DONE token (0xFD) — session bitmesini bildir
        done_token = bytearray()
        done_token.append(0xFD)  # DONE token
        done_token.extend(struct.pack("<H", 0x0000))  # Status: DONE_FINAL
        done_token.extend(struct.pack("<H", 0x0000))  # CurCmd
        done_token.extend(struct.pack("<Q", 0))       # DoneRowCount (8 bytes)

        return bytes(error_token) + bytes(done_token)

    @staticmethod
    def _send_tds_packet(sock: socket.socket, pkt_type: int, data: bytes):
        """TDS paketi gönder — 8-byte header + payload."""
        length = 8 + len(data)
        header = struct.pack(">BBH", pkt_type, 0x01, length)  # type, status=EOM, length
        header += struct.pack(">HH", 0, 0)  # SPID=0, PacketID=0, Window=0
        try:
            sock.sendall(header + data)
        except (OSError, BrokenPipeError):
            pass

    @staticmethod
    def _read_tds_packet(sock: socket.socket) -> tuple[int, bytes]:
        """TDS paketi oku — (packet_type, payload) döndürür."""
        # TDS header: 8 bytes
        header = b""
        while len(header) < 8:
            chunk = sock.recv(8 - len(header))
            if not chunk:
                return 0, b""
            header += chunk

        pkt_type = header[0]
        length = struct.unpack(">H", header[2:4])[0]

        if length < 8 or length > 65536:
            return pkt_type, b""

        remaining = length - 8
        payload = b""
        while len(payload) < remaining:
            chunk = sock.recv(remaining - len(payload))
            if not chunk:
                break
            payload += chunk

        return pkt_type, payload


# ===================== RDP HONEYPOT ===================== #

class RDPHoneypot(BaseHoneypot):
    """Sahte RDP servisi — X.224 + NTLM handshake ile credential yakalar.

    RDP bağlantı akışı (NLA / CredSSP OFF):
        1. Client → Server: X.224 Connection Request (Cookie: username)
        2. Server → Client: X.224 Connection Confirm
        3. Client → Server: MCS Connect Initial (+ GCC blocks)
        4. Server → Client: MCS Connect Response
        (credential yakalama 1. adımda Cookie'den yapılır)

    RDP bağlantı akışı (NLA / CredSSP ON — çoğu modern client):
        1. Client → Server: X.224 Connection Request (Cookie: username)
           → requestedProtocols = PROTOCOL_HYBRID (NLA)
        2. Server → Client: X.224 Connection Confirm
           → selectedProtocol = PROTOCOL_RDP (NLA'yı reddeder → fallback)
        3. Client ya bağlantıyı keser ya da RDP Security ile devam eder

    Credential yakalama stratejisi:
        - X.224 Cookie ("Cookie: mstshash=username") → username plaintext
        - Password: RDP NLA olmadan, standard RDP Security ile alınamaz
          (RSA + RC4 encrypted). Bu honeypot sadece username + bağlantı girişimi
          yakalar. Password için saldırganın client'ına güvenilmez.
        - Birçok brute-force aracı (hydra, ncrack, crowbar) username'i
          Cookie'de gönderir — bu yeterli bir IoC (Indicator of Compromise).

    Not: Harici kütüphane gerektirmez — tamamen raw socket + struct.
    """

    TIMEOUT = 30

    # X.224 / TPKT constants
    _TPKT_VERSION = 3
    _X224_CR = 0xE0  # Connection Request
    _X224_CC = 0xD0  # Connection Confirm

    # RDP Negotiation
    _TYPE_RDP_NEG_REQ = 0x01
    _TYPE_RDP_NEG_RSP = 0x02
    _PROTOCOL_RDP = 0x00000000
    _PROTOCOL_SSL = 0x00000001
    _PROTOCOL_HYBRID = 0x00000002  # NLA / CredSSP

    def __init__(self, port: int = 3389, *, on_credential: Callable, cert_cn: str = ""):
        super().__init__(port=port, service_name="RDP", on_credential=on_credential)
        self.cert_cn = cert_cn or RDP_CERT_CN

    def handle_client(self, sock: socket.socket, addr: tuple):
        attacker_ip = addr[0]
        sock.settimeout(self.TIMEOUT)

        # 1) X.224 Connection Request oku
        try:
            tpkt_data = self._read_tpkt(sock)
            if not tpkt_data or len(tpkt_data) < 7:
                return
        except (socket.timeout, OSError):
            return

        # Cookie'den username parse et
        username = self._parse_x224_cookie(tpkt_data)
        requested_protocols = self._parse_requested_protocols(tpkt_data)

        if username:
            log(f"[RDP] Bağlantı girişimi: {username} <- {attacker_ip}")
            self.report_credential(attacker_ip, username, "<rdp_connection_attempt>")

        # 2) X.224 Connection Confirm gönder
        #    NLA/CredSSP'yi reddedip standard RDP Security'ye zorla
        cc_packet = self._build_x224_confirm(requested_protocols)
        try:
            sock.sendall(cc_packet)
        except (OSError, BrokenPipeError):
            return

        # 3) MCS Connect Initial beklemeyi dene (opsiyonel — ek bilgi)
        #    Çoğu brute-force aracı NLA reddedildikten sonra bağlantıyı keser
        try:
            mcs_data = self._read_tpkt(sock)
            if mcs_data and len(mcs_data) > 20:
                # MCS Connect Initial geldi → client RDP Security ile devam ediyor
                # MCS Connect Response gönder ve bağlantıyı kapat
                mcs_response = self._build_mcs_connect_response()
                sock.sendall(mcs_response)
        except (socket.timeout, OSError):
            pass  # Client bağlantıyı kesti — normal

    @staticmethod
    def _read_tpkt(sock: socket.socket) -> bytes:
        """TPKT paketi oku (4-byte header + payload).

        TPKT Header:
            byte 0: Version (3)
            byte 1: Reserved (0)
            byte 2-3: Length (big-endian, header dahil)
        """
        header = b""
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                return b""
            header += chunk

        if header[0] != 3:  # TPKT version check
            return b""

        length = struct.unpack(">H", header[2:4])[0]
        if length < 4 or length > 65536:
            return b""

        remaining = length - 4
        payload = b""
        while len(payload) < remaining:
            chunk = sock.recv(remaining - len(payload))
            if not chunk:
                break
            payload += chunk

        return header + payload

    @staticmethod
    def _parse_x224_cookie(tpkt_data: bytes) -> str:
        """X.224 Connection Request'ten Cookie'yi parse et.

        Format: "Cookie: mstshash=<username>\r\n"
        X.224 CR header 7 byte (TPKT 4 + X.224 header 3),
        sonra variable-length cookie/routing token gelir.
        """
        try:
            # TPKT(4) + X.224 length(1) + X.224 type(1) + dst-ref(2) + src-ref(2) + class(1)
            # = offset 11'den itibaren cookie/routingToken başlar
            # Ama bazı client'lar farklı offset kullanır, bu yüzden string search yapalım
            data_str = tpkt_data.decode("ascii", errors="replace")

            # "Cookie: mstshash=" pattern'ini ara
            cookie_marker = "Cookie: mstshash="
            idx = data_str.find(cookie_marker)
            if idx == -1:
                # Alternatif: bazı araçlar farklı format kullanır
                cookie_marker = "mstshash="
                idx = data_str.find(cookie_marker)
                if idx == -1:
                    return ""

            start = idx + len(cookie_marker)
            # CR veya LF'ye kadar oku
            end = start
            while end < len(data_str) and data_str[end] not in ("\r", "\n", "\x00"):
                end += 1

            username = data_str[start:end].strip()
            return username[:256] if username else ""

        except Exception:
            return ""

    @staticmethod
    def _parse_requested_protocols(tpkt_data: bytes) -> int:
        """X.224 CR'den requestedProtocols değerini çıkar.

        RDP Negotiation Request (varsa):
            Son 8 byte: type(1) + flags(1) + length(2) + requestedProtocols(4)
            type = 0x01 (NEG_REQ)
        """
        try:
            # Negotiation Request genellikle paketin sonundadır
            if len(tpkt_data) >= 8:
                # Son 8 byte'a bak
                neg_block = tpkt_data[-8:]
                if neg_block[0] == 0x01:  # TYPE_RDP_NEG_REQ
                    req_protocols = struct.unpack("<I", neg_block[4:8])[0]
                    return req_protocols
        except Exception:
            pass
        return 0

    def _build_x224_confirm(self, requested_protocols: int) -> bytes:
        """X.224 Connection Confirm paketi oluştur.

        Eğer client NLA/CredSSP istiyorsa, biz PROTOCOL_RDP seçeriz
        (NLA'yı reddederiz). Bu, bazı client'ları standard RDP Security'ye
        zorlar, bazıları ise bağlantıyı keser.
        """
        x224_payload = bytearray()

        if requested_protocols != 0:
            # RDP Negotiation Response ekle
            # type(1) + flags(1) + length(2) + selectedProtocol(4)
            neg_resp = bytearray(8)
            neg_resp[0] = self._TYPE_RDP_NEG_RSP  # type
            neg_resp[1] = 0x00  # flags
            struct.pack_into("<H", neg_resp, 2, 8)  # length = 8
            struct.pack_into("<I", neg_resp, 4, self._PROTOCOL_RDP)  # always select RDP

            # X.224 CC header
            x224_header_len = 6 + len(neg_resp)  # X.224 header (6 bytes) + neg response
            x224_payload.append(x224_header_len)  # length indicator
            x224_payload.append(self._X224_CC)  # type = CC
            x224_payload.extend(b"\x00\x00")  # dst-ref
            x224_payload.extend(b"\x00\x00")  # src-ref
            x224_payload.append(0x00)  # class options
            x224_payload.extend(neg_resp)
        else:
            # Basit X.224 CC (negotiation yok)
            x224_payload.append(6)  # length indicator
            x224_payload.append(self._X224_CC)
            x224_payload.extend(b"\x00\x00")  # dst-ref
            x224_payload.extend(b"\x00\x00")  # src-ref
            x224_payload.append(0x00)  # class options

        # TPKT header
        total_len = 4 + len(x224_payload)
        tpkt = bytearray(4)
        tpkt[0] = self._TPKT_VERSION
        tpkt[1] = 0x00  # reserved
        struct.pack_into(">H", tpkt, 2, total_len)

        return bytes(tpkt + x224_payload)

    def _build_mcs_connect_response(self) -> bytes:
        """Minimal MCS Connect Response — bağlantıyı düzgün kapatmak için.

        Gerçek bir MCS response göndermek yerine, RDP standard security
        ile devam eden client'ı bilgilendirmek için minimal bir TPKT paketi
        gönderir. Çoğu brute-force aracı bu noktada zaten bağlantıyı keser.
        """
        # Minimal X.224 Data + MCS Disconnect Provider Ultimatum
        # Bu, client'a "bağlantı reddedildi" mesajı verir
        disconnect = bytearray()
        # X.224 Data header
        disconnect.append(0x02)  # length indicator
        disconnect.append(0xF0)  # X.224 DT (Data)
        disconnect.append(0x80)  # EOT flag

        # MCS Disconnect Provider Ultimatum (BER encoding)
        # Tag: 0x21 (SEQUENCE), followed by reason
        disconnect.extend(b"\x21\x80")  # MCS disconnect
        disconnect.extend(b"\x02\x01\x00")  # reason: user-requested (0)
        disconnect.extend(b"\x00\x00")  # terminator

        # TPKT wrapper
        total_len = 4 + len(disconnect)
        tpkt = bytearray(4)
        tpkt[0] = self._TPKT_VERSION
        tpkt[1] = 0x00
        struct.pack_into(">H", tpkt, 2, total_len)

        return bytes(tpkt + disconnect)
