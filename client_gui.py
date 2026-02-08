#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloud Honeypot Client — Modern GUI Module (CustomTkinter).

Tüm GUI bileşenlerini içerir. client.py'deki iş mantığından bağımsızdır.
CloudHoneypotClient instance'ı üzerinden veri ve aksiyonlara erişir.
"""

import os
import sys
import time
import threading
import webbrowser
import subprocess
from tkinter import messagebox
from typing import Dict, Any

import customtkinter as ctk

from client_helpers import log, ClientHelpers
from client_utils import (
    get_config_value, update_language_config, get_resource_path
)
from client_constants import (
    LOG_FILE, RDP_SECURE_PORT, GITHUB_OWNER, GITHUB_REPO, __version__
)


# ─── Renk Paleti ─── #
COLORS = {
    "bg":           "#1a1a2e",
    "card":         "#16213e",
    "card_active":  "#1b3a4b",
    "accent":       "#0f3460",
    "green":        "#00c853",
    "green_hover":  "#00e676",
    "red":          "#ff1744",
    "red_hover":    "#ff5252",
    "orange":       "#ff9100",
    "orange_hover": "#ffab40",
    "blue":         "#2979ff",
    "blue_hover":   "#448aff",
    "text":         "#e0e0e0",
    "text_dim":     "#9e9e9e",
    "text_bright":  "#ffffff",
    "border":       "#2a2a4a",
    "entry_bg":     "#0d1b2a",
    "status_dot_on":"#00e676",
    "status_dot_off":"#ff1744",
}

# ─── Servis Emoji Haritası ─── #
SERVICE_ICONS = {
    "RDP":   "🖥️",
    "MSSQL": "🗄️",
    "MYSQL": "🐬",
    "FTP":   "📁",
    "SSH":   "🔐",
}


class ModernGUI:
    """CustomTkinter tabanlı modern GUI — CloudHoneypotClient'a bağlanır."""

    def __init__(self, app):
        """
        Args:
            app: CloudHoneypotClient instance
        """
        self.app = app
        self.row_controls: Dict[str, dict] = {}

    # ─── Yardımcılar ─── #
    def t(self, key: str) -> str:
        return self.app.t(key)

    def _gui_safe(self, func):
        """Thread-safe CTk çağrısı"""
        try:
            if self.app.root and self.app.root.winfo_exists():
                self.app.root.after(0, func)
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════
    #  ANA BUILD
    # ═══════════════════════════════════════════════════════════════
    def build(self, root: ctk.CTk, startup_mode: str = "gui"):
        """Ana GUI'yi oluşturur — client.py build_gui() tarafından çağrılır."""
        self.root = root
        self._start_time = time.time()  # uptime izleme

        # ── Tema ── #
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        root.title(f"{self.t('app_title')} v{__version__}")
        root.geometry("880x740")
        root.configure(fg_color=COLORS["bg"])
        root.minsize(800, 640)

        # ── İkon ── #
        self._set_window_icon(root)

        # ── Birleşik Üst Bar (Kimlik + Menü) ── #
        self._build_top_bar(root)

        # ── Kapatma → tray ── #
        root.protocol("WM_DELETE_WINDOW", self.app.on_close)

        # ── Ana scroll container ── #
        container = ctk.CTkScrollableFrame(root, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=16, pady=(4, 16))

        # ── Başlık Bandı ── #
        self._build_header(container)

        # ── Dashboard İstatistik Kartları ── #
        self._build_dashboard(container)

        # ── Honeypot Servisleri ── #
        self._build_services_section(container)

        # ── app referansları (eski alanlar artık yok) ── #
        self.app.ip_entry = None
        self.app.attack_entry = None

        # ── Periyodik Dashboard Güncelleme (her 5 sn) ── #
        self._schedule_dashboard_refresh()

        # ── Başlangıç modu ── #
        if startup_mode == "minimized":
            self.app._tray_mode.set()
            root.withdraw()
        else:
            if not self.app._tray_mode.is_set():
                root.deiconify()

    # ═══════════════════════════════════════════════════════════════
    #  BİRLEŞİK ÜST BAR  (Kimlik + Dashboard + Menü — tek satır)
    # ═══════════════════════════════════════════════════════════════
    def _build_top_bar(self, root):
        """Sol: PC/IP | Token  —  Sağ: v3.0 | Dashboard | Ayarlar | Yardım"""
        bar = ctk.CTkFrame(root, fg_color=COLORS["card"], corner_radius=0, height=36)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)

        # Token & IP yükle
        token = self.app.state.get("token", "")
        public_ip = self.app.state.get("public_ip", "")
        from client_constants import SERVER_NAME
        dashboard_url = f"https://honeypot.yesnext.com.tr/dashboard?token={token or ''}"

        # ════════ SOL TARAF ════════ #
        # PC Adı
        ctk.CTkLabel(
            bar, text=f"💻 {SERVER_NAME}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left", padx=(10, 2))

        # IP
        ip_lbl = ctk.CTkLabel(
            bar, text=f"({public_ip})" if public_ip else "",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"],
        )
        ip_lbl.pack(side="left", padx=(0, 6))
        self._identity_ip_lbl = ip_lbl

        # Separator
        ctk.CTkFrame(bar, width=1, fg_color=COLORS["border"]).pack(
            side="left", fill="y", padx=4, pady=7
        )

        # Token
        token_short = token[:16] + "…" if len(token) > 16 else token
        ctk.CTkLabel(
            bar, text=f"Token: {token_short}",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=COLORS["text_dim"],
        ).pack(side="left", padx=(6, 2))

        # Kopyala
        ctk.CTkButton(
            bar, text="📋", width=26, height=22,
            font=ctk.CTkFont(size=10),
            fg_color="transparent", hover_color=COLORS["accent"],
            corner_radius=4,
            command=lambda: self._copy_to_clipboard(token),
        ).pack(side="left", padx=(0, 4))

        # ════════ SAĞ TARAF ════════ #
        # Yardım butonu
        help_btn = ctk.CTkButton(
            bar, text=f"❓ {self.t('menu_help')}",
            font=ctk.CTkFont(size=11), width=70, height=26,
            fg_color="transparent", hover_color=COLORS["accent"],
            text_color=COLORS["text"], corner_radius=5,
        )
        help_btn.pack(side="right", padx=(2, 8), pady=5)
        help_btn.configure(command=lambda: self._show_popup_menu(help_btn, "help"))

        # Ayarlar butonu
        settings_btn = ctk.CTkButton(
            bar, text=f"⚙ {self.t('menu_settings')}",
            font=ctk.CTkFont(size=11), width=76, height=26,
            fg_color="transparent", hover_color=COLORS["accent"],
            text_color=COLORS["text"], corner_radius=5,
        )
        settings_btn.pack(side="right", padx=2, pady=5)
        settings_btn.configure(command=lambda: self._show_popup_menu(settings_btn, "settings"))

        # Dashboard butonu
        ctk.CTkButton(
            bar, text="📊 Dashboard",
            font=ctk.CTkFont(size=11), width=90, height=26,
            fg_color=COLORS["accent"], hover_color=COLORS["blue"],
            text_color=COLORS["text_bright"], corner_radius=5,
            command=lambda: webbrowser.open(dashboard_url),
        ).pack(side="right", padx=2, pady=5)

        # Separator
        ctk.CTkFrame(bar, width=1, fg_color=COLORS["border"]).pack(
            side="right", fill="y", padx=4, pady=7
        )

        # Versiyon (text)
        ctk.CTkLabel(
            bar, text=f"v{__version__}",
            font=ctk.CTkFont(size=11), text_color=COLORS["text_dim"],
        ).pack(side="right", padx=(4, 4))

    def _copy_to_clipboard(self, text: str):
        """Metni panoya kopyala ve bildirim göster."""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
            messagebox.showinfo(self.t("copy"), text)
        except Exception as e:
            log(f"clipboard error: {e}")

    # ═══════════════════════════════════════════════════════════════
    #  BAŞLIK BANDI
    # ═══════════════════════════════════════════════════════════════
    def _build_header(self, parent):
        hdr = ctk.CTkFrame(parent, fg_color=COLORS["accent"], corner_radius=12, height=52)
        hdr.pack(fill="x", pady=(0, 12))
        hdr.pack_propagate(False)

        lbl = ctk.CTkLabel(
            hdr,
            text=f"🛡️  {self.t('app_title')}  v{__version__}",
            font=ctk.CTkFont(size=17, weight="bold"),
            text_color=COLORS["text_bright"],
        )
        lbl.pack(side="left", padx=16)

        # Sağ taraf — durum göstergesi
        self._header_status = ctk.CTkLabel(
            hdr,
            text="● " + self.t("protection_inactive"),
            font=ctk.CTkFont(size=13),
            text_color=COLORS["red"],
        )
        self._header_status.pack(side="right", padx=16)

    def update_header_status(self, active: bool):
        """Koruma durumu badge'ini güncelle"""
        try:
            if active:
                self._header_status.configure(
                    text="● " + self.t("protection_active"),
                    text_color=COLORS["green"],
                )
            else:
                self._header_status.configure(
                    text="● " + self.t("protection_inactive"),
                    text_color=COLORS["red"],
                )
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════
    #  DASHBOARD İSTATİSTİK KARTLARI
    # ═══════════════════════════════════════════════════════════════
    def _build_dashboard(self, parent):
        """Mini dashboard — canlı istatistik kartları."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        # Başlık
        hdr_row = ctk.CTkFrame(sec, fg_color="transparent")
        hdr_row.pack(fill="x", padx=16, pady=(12, 6))

        ctk.CTkLabel(
            hdr_row, text=f"📈  {self.t('dash_title')}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        # Canlı pulse göstergesi (●)
        self._pulse_dot = ctk.CTkLabel(
            hdr_row, text="●",
            font=ctk.CTkFont(size=10),
            text_color=COLORS["green"],
        )
        self._pulse_dot.pack(side="right", padx=8)
        self._pulse_visible = True

        sep = ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(0, 10))

        # Kart grid — 2 satır × 3 sütun
        grid = ctk.CTkFrame(sec, fg_color="transparent")
        grid.pack(fill="x", padx=12, pady=(0, 14))
        for c in range(3):
            grid.columnconfigure(c, weight=1)

        # Referans dict — refresh'te güncellenir
        self._dash_cards: Dict[str, dict] = {}

        # ── İlk değerleri hesapla ── #
        token = self.app.state.get("token", "")
        total_attacks = self.app.fetch_attack_count_sync(token) if token else 0
        if total_attacks is None:
            total_attacks = 0
        # Cache for re-use (info section, dashboard refresh)
        self.app._last_attack_count = total_attacks
        active_count = len(self.app.service_manager.running_services)
        session_attacks = 0
        try:
            session_attacks = self.app.service_manager.session_stats.get("total_credentials", 0)
        except Exception:
            pass

        # ── Kartları oluştur ── #
        cards_data = [
            # (key, emoji, label_key, value, color, row, col)
            ("total_attacks",   "🎯", "dash_total_attacks",   str(total_attacks),   COLORS["red"],    0, 0),
            ("session_attacks", "⚡", "dash_session_attacks",  str(session_attacks), COLORS["orange"], 0, 1),
            ("active_services", "🟢", "dash_active_services",  f"{active_count}/5",  COLORS["green"],  0, 2),
            ("uptime",          "⏱️", "dash_uptime",           "0dk",                COLORS["blue"],   1, 0),
            ("last_attack",     "🕵️", "dash_last_attack",      self.t("dash_no_attack"), COLORS["text_dim"], 1, 1),
            ("connection",      "🌐", "dash_connection",       self.t("dash_connected"), COLORS["green"], 1, 2),
        ]

        for key, emoji, label_key, value, color, row, col in cards_data:
            card = self._create_stat_card(grid, emoji, self.t(label_key), value, color)
            card.grid(row=row, column=col, padx=6, pady=5, sticky="nsew")
            self._dash_cards[key] = card

    def _create_stat_card(self, parent, emoji: str, label: str, value: str, color: str) -> ctk.CTkFrame:
        """Tek bir istatistik kartı oluşturur. {'frame', 'value_lbl'} referansları döner."""
        card = ctk.CTkFrame(parent, fg_color=COLORS["bg"], corner_radius=10,
                            border_width=1, border_color=COLORS["border"])

        # Emoji
        ctk.CTkLabel(
            card, text=emoji, font=ctk.CTkFont(size=20),
        ).pack(anchor="w", padx=12, pady=(10, 0))

        # Değer (büyük rakam)
        value_lbl = ctk.CTkLabel(
            card, text=value,
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=color,
        )
        value_lbl.pack(anchor="w", padx=12, pady=(2, 0))

        # Açıklama
        ctk.CTkLabel(
            card, text=label,
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"],
        ).pack(anchor="w", padx=12, pady=(0, 10))

        # value_lbl referansı card objesine ekleniyor
        card._value_lbl = value_lbl  # type: ignore[attr-defined]
        return card

    # ─── Dashboard Refresh ─── #
    def _schedule_dashboard_refresh(self):
        """Her 5 saniyede bir dashboard kartlarını günceller."""
        self._refresh_dashboard()
        try:
            if self.root and self.root.winfo_exists():
                self.root.after(5000, self._schedule_dashboard_refresh)
        except Exception:
            pass

    def _refresh_dashboard(self):
        """Dashboard kartlarının anlık değerlerini güncelle."""
        try:
            if not hasattr(self, '_dash_cards') or not self._dash_cards:
                return

            sm = self.app.service_manager

            # 1) Aktif servisler
            active_count = len(sm.running_services)
            total_services = len(self.app.PORT_TABLOSU)
            self._update_card("active_services", f"{active_count}/{total_services}",
                              COLORS["green"] if active_count > 0 else COLORS["text_dim"])

            # 2) Oturum saldırıları
            sess = sm.session_stats
            session_count = sess.get("total_credentials", 0)
            self._update_card("session_attacks", str(session_count),
                              COLORS["orange"] if session_count > 0 else COLORS["text_dim"])

            # 3) Toplam saldırılar (API'den — _last_attack_count client.py tarafından güncellenir)
            total = getattr(self.app, '_last_attack_count', None)
            if total is not None:
                self._update_card("total_attacks", str(total),
                                  COLORS["red"] if total > 0 else COLORS["text_dim"])

            # 4) Uptime
            elapsed = int(time.time() - self._start_time)
            self._update_card("uptime", self._format_uptime(elapsed), COLORS["blue"])

            # 5) Son saldırı zamanı
            last_ts = sess.get("last_attack_ts")
            if last_ts:
                ago = self._format_ago(time.time() - last_ts)
                last_ip = sess.get("last_attacker_ip", "")
                last_svc = sess.get("last_service", "")
                display = f"{last_ip} ({last_svc})" if last_ip else ago
                self._update_card("last_attack", display, COLORS["orange"])
            else:
                self._update_card("last_attack", self.t("dash_no_attack"), COLORS["text_dim"])

            # 6) API bağlantı durumu
            api_ok = getattr(self.app, '_last_attack_count', None) is not None
            if api_ok:
                self._update_card("connection", self.t("dash_connected"), COLORS["green"])
            else:
                self._update_card("connection", self.t("dash_disconnected"), COLORS["red"])

            # Pulse animasyonu
            self._pulse_visible = not self._pulse_visible
            if hasattr(self, '_pulse_dot'):
                pulse_color = COLORS["green"] if active_count > 0 else COLORS["text_dim"]
                self._pulse_dot.configure(
                    text_color=pulse_color if self._pulse_visible else COLORS["bg"]
                )

            # Header badge senkronizasyonu
            self.update_header_status(active_count > 0)

        except Exception:
            pass

    def _update_card(self, key: str, value: str, color: str):
        """Bir dashboard kartının değerini güncelle."""
        card = self._dash_cards.get(key)
        if card and hasattr(card, '_value_lbl'):
            try:
                card._value_lbl.configure(text=value, text_color=color)
            except Exception:
                pass

    def _format_uptime(self, seconds: int) -> str:
        """Saniyeyi insanca okunur süreye çevirir."""
        d = self.t("dash_days")
        h = self.t("dash_hours")
        m = self.t("dash_minutes")
        if seconds < 60:
            return f"<1{m}"
        elif seconds < 3600:
            return f"{seconds // 60}{m}"
        elif seconds < 86400:
            hrs = seconds // 3600
            mins = (seconds % 3600) // 60
            return f"{hrs}{h} {mins}{m}"
        else:
            days = seconds // 86400
            hrs = (seconds % 86400) // 3600
            return f"{days}{d} {hrs}{h}"

    def _format_ago(self, seconds: float) -> str:
        """Saniyeyi '3dk önce' formatına çevirir."""
        s = int(seconds)
        if s < 10:
            return self.t("dash_just_now")
        elif s < 60:
            return self.t("dash_ago").format(val=f"{s}{self.t('dash_seconds')}")
        elif s < 3600:
            return self.t("dash_ago").format(val=f"{s // 60}{self.t('dash_minutes')}")
        elif s < 86400:
            return self.t("dash_ago").format(val=f"{s // 3600}{self.t('dash_hours')}")
        else:
            return self.t("dash_ago").format(val=f"{s // 86400}{self.t('dash_days')}")

    # ═══════════════════════════════════════════════════════════════
    #  HONEYPOT SERVİSLERİ
    # ═══════════════════════════════════════════════════════════════
    def _build_services_section(self, parent):
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 8))

        # Başlık
        ctk.CTkLabel(
            sec, text=f"🐝  {self.t('port_tunnel')}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=16, pady=(12, 8))

        sep = ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(0, 8))

        # Servis kartları
        saved_rows, saved_running = self.app.read_status()
        running_names = [str(r[1]).upper() for r in saved_rows] if saved_rows else []

        for (port, service) in self.app.PORT_TABLOSU:
            is_active = str(service).upper() in running_names
            self._build_service_card(sec, str(port), str(service), is_active)

        # Alt padding
        ctk.CTkFrame(sec, height=8, fg_color="transparent").pack()

    def _build_service_card(self, parent, port: str, service: str, initially_active: bool):
        """Tek bir servis kartı oluşturur."""
        svc_upper = service.upper()
        icon = SERVICE_ICONS.get(svc_upper, "⚙️")

        # ── Kart Frame ── #
        card_color = COLORS["card_active"] if initially_active else COLORS["bg"]
        card = ctk.CTkFrame(parent, fg_color=card_color, corner_radius=10,
                            border_width=1, border_color=COLORS["border"])
        card.pack(fill="x", padx=16, pady=3)

        # ── İç container: sol / sağ ayrımı ── #
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=12, pady=10)

        # ── Sol: İkon + İsim ── #
        left = ctk.CTkFrame(inner, fg_color="transparent")
        left.pack(side="left", fill="y")

        ctk.CTkLabel(
            left, text=icon, font=ctk.CTkFont(size=22),
            text_color=COLORS["text_bright"],
        ).pack(side="left", padx=(0, 10))

        name_frame = ctk.CTkFrame(left, fg_color="transparent")
        name_frame.pack(side="left")

        ctk.CTkLabel(
            name_frame, text=service,
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            name_frame, text=f"Port: {port}",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_dim"],
        ).pack(anchor="w")

        # ── Sağ: Butonlar + Durum (sağa hizalı) ── #
        right = ctk.CTkFrame(inner, fg_color="transparent")
        right.pack(side="right", fill="y")

        # ── Durum göstergesi ── #
        status_text = self.t("status_running") if initially_active else self.t("status_stopped")
        status_color = COLORS["status_dot_on"] if initially_active else COLORS["status_dot_off"]

        status_frame = ctk.CTkFrame(right, fg_color="transparent")
        status_frame.pack(side="left", padx=(0, 12))

        status_dot = ctk.CTkLabel(
            status_frame, text="●",
            font=ctk.CTkFont(size=14),
            text_color=status_color,
        )
        status_dot.pack(side="left", padx=(0, 4))

        status_lbl = ctk.CTkLabel(
            status_frame, text=status_text,
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_dim"],
        )
        status_lbl.pack(side="left")

        # ── Buton grubu ── #
        btn_inner = ctk.CTkFrame(right, fg_color="transparent")
        btn_inner.pack(side="left")

        # RDP özel butonu
        rdp_btn = None
        if svc_upper == "RDP":
            rdp_btn = self._build_rdp_move_button(btn_inner)
            rdp_btn.pack(side="left", padx=(0, 6))

        # Başlat / Durdur butonu
        if initially_active:
            btn_text = self.t("btn_row_stop")
            btn_color = COLORS["red"]
            btn_hover = COLORS["red_hover"]
        else:
            btn_text = self.t("btn_row_start")
            btn_color = COLORS["green"]
            btn_hover = COLORS["green_hover"]

        toggle_btn = ctk.CTkButton(
            btn_inner, text=btn_text, width=100, height=36,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=btn_color, hover_color=btn_hover,
            corner_radius=8,
        )
        toggle_btn.pack(side="left")

        # ── Referans kaydet ── #
        ctrl = {
            "card": card, "button": toggle_btn, "status_lbl": status_lbl,
            "status_dot": status_dot, "rdp_button": rdp_btn,
        }
        self.row_controls[(port, svc_upper)] = ctrl

        # client.py uyumluluğu
        self.app.row_controls[(port, svc_upper)] = {
            "frame": card, "button": toggle_btn, "status": status_lbl,
        }
        if rdp_btn:
            self.app.row_controls[(port, svc_upper)]["rdp_button"] = rdp_btn

        # ── Toggle komutu ── #
        def toggle(p=port, s=service, b=toggle_btn, c=card, sl=status_lbl, sd=status_dot):
            self._toggle_service(p, s, b, c, sl, sd)

        toggle_btn.configure(command=toggle)

    def _build_rdp_move_button(self, parent) -> ctk.CTkButton:
        """RDP Taşı butonu oluşturur."""
        try:
            is_protected, _ = self.app.rdp_manager.get_rdp_protection_status()
            target = 3389 if is_protected else RDP_SECURE_PORT
            color = COLORS["orange"] if is_protected else COLORS["blue"]
            hover = COLORS["orange_hover"] if is_protected else COLORS["blue_hover"]
        except Exception:
            target = RDP_SECURE_PORT
            color = COLORS["blue"]
            hover = COLORS["blue_hover"]

        btn = ctk.CTkButton(
            parent, text=f"RDP Taşı: {target}", width=120, height=36,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=color, hover_color=hover, corner_radius=8,
            command=self.app.toggle_rdp_protection,
        )
        return btn

    # ─── Servis Toggle ─── #
    def _toggle_service(self, port, service, btn, card, status_lbl, status_dot):
        """Tek bir servisi başlat/durdur — iş mantığı client.py'de."""
        svc_upper = str(service).upper()
        is_rdp = svc_upper == "RDP"

        if is_rdp:
            self.app.service_manager.reconciliation_paused = True
            log("RDP işlemi için uzlaştırma döngüsü duraklatıldı.")

        try:
            cur_text = btn.cget("text").lower()
            if cur_text == self.t("btn_row_start").lower():
                if self.app.start_single_row(port, service, manual_action=True):
                    if not is_rdp:
                        self._set_card_active(btn, card, status_lbl, status_dot)
            else:
                if self.app.stop_single_row(port, service, manual_action=True):
                    if not is_rdp:
                        self._set_card_inactive(btn, card, status_lbl, status_dot)
        finally:
            if is_rdp:
                self.app.service_manager.reconciliation_paused = False
                log("RDP işlemi tamamlandı, uzlaştırma döngüsü devam ettiriliyor.")
                threading.Thread(target=self.app.report_service_status_once, daemon=True).start()

    # ─── Kart Durumu Güncelleyiciler ─── #
    def _set_card_active(self, btn, card, status_lbl, status_dot):
        btn.configure(text=self.t("btn_row_stop"), fg_color=COLORS["red"], hover_color=COLORS["red_hover"])
        card.configure(fg_color=COLORS["card_active"])
        status_lbl.configure(text=self.t("status_running"))
        status_dot.configure(text_color=COLORS["status_dot_on"])

    def _set_card_inactive(self, btn, card, status_lbl, status_dot):
        btn.configure(text=self.t("btn_row_start"), fg_color=COLORS["green"], hover_color=COLORS["green_hover"])
        card.configure(fg_color=COLORS["bg"])
        status_lbl.configure(text=self.t("status_stopped"))
        status_dot.configure(text_color=COLORS["status_dot_off"])

    # ═══════════════════════════════════════════════════════════════
    #  UPDATE ROW UI — client.py._update_row_ui tarafından çağrılır
    # ═══════════════════════════════════════════════════════════════
    def update_row_ui(self, listen_port: str, service_name: str, active: bool):
        """Bir servis satırının UI durumunu güncelle (thread-safe)."""
        def apply():
            key = (str(listen_port), str(service_name).upper())
            ctrl = self.row_controls.get(key)
            if not ctrl:
                return
            btn = ctrl["button"]
            card = ctrl["card"]
            sl = ctrl["status_lbl"]
            sd = ctrl["status_dot"]
            if active:
                self._set_card_active(btn, card, sl, sd)
            else:
                self._set_card_inactive(btn, card, sl, sd)

            # Header badge
            any_active = len(self.app.service_manager.running_services) > 0
            self.update_header_status(any_active)

        self._gui_safe(apply)

    # ═══════════════════════════════════════════════════════════════
    #  RDP BUTON GÜNCELLEME
    # ═══════════════════════════════════════════════════════════════
    def update_rdp_button(self):
        """RDP Taşı butonunun metnini/rengini güncel duruma göre güncelle."""
        try:
            rdp_ctrl = self.row_controls.get(("3389", "RDP"))
            if not rdp_ctrl or not rdp_ctrl.get("rdp_button"):
                return
            rdp_btn = rdp_ctrl["rdp_button"]
            is_protected, _ = self.app.rdp_manager.get_rdp_protection_status()
            target = 3389 if is_protected else RDP_SECURE_PORT
            if is_protected:
                rdp_btn.configure(text=f"RDP Taşı: {target}",
                                  fg_color=COLORS["orange"], hover_color=COLORS["orange_hover"])
            else:
                rdp_btn.configure(text=f"RDP Taşı: {target}",
                                  fg_color=COLORS["blue"], hover_color=COLORS["blue_hover"])
        except Exception as e:
            log(f"RDP buton güncelleme hatası: {e}")

    def _close_popup(self):
        """Mevcut popup'ı güvenli şekilde kapat."""
        popup = getattr(self, "_active_popup", None)
        if popup is not None:
            try:
                popup.destroy()
            except Exception:
                pass
            self._active_popup = None
        # Global click binding'i temizle
        bid = getattr(self, "_popup_click_bid", None)
        if bid is not None:
            try:
                self.root.unbind("<Button-1>", bid)
            except Exception:
                pass
            self._popup_click_bid = None

    def _show_popup_menu(self, anchor_widget, menu_type: str):
        """CTkToplevel popup menü — dark mode uyumlu."""
        # Zaten açıksa kapat (toggle davranışı)
        if getattr(self, "_active_popup", None) is not None:
            self._close_popup()
            return

        popup = ctk.CTkToplevel(self.root)
        popup.overrideredirect(True)
        popup.configure(fg_color=COLORS["card"])
        popup.attributes("-topmost", True)
        self._active_popup = popup

        # Pozisyon hesapla
        x = anchor_widget.winfo_rootx()
        y = anchor_widget.winfo_rooty() + anchor_widget.winfo_height() + 2
        popup.geometry(f"+{x}+{y}")

        def _run_and_close(action):
            """Menü öğesi tıklanınca: önce kapat, sonra action çalıştır."""
            def _handler():
                self._close_popup()
                action()
            return _handler

        items = []
        if menu_type == "settings":
            items = [
                (f"🇹🇷  {self.t('menu_lang_tr')}", _run_and_close(lambda: self._set_lang("tr"))),
                (f"🇬🇧  {self.t('menu_lang_en')}", _run_and_close(lambda: self._set_lang("en"))),
            ]
        elif menu_type == "help":
            items = [
                (f"📄  {self.t('menu_logs')}", _run_and_close(self._open_logs)),
                (f"🌐  {self.t('menu_github')}", _run_and_close(self._open_github)),
                (None, None),  # separator
                (f"🔄  {self.t('menu_check_updates')}", _run_and_close(self.app.check_updates_and_prompt)),
            ]

        for label, cmd in items:
            if label is None:
                ctk.CTkFrame(popup, height=1, fg_color=COLORS["border"]).pack(fill="x", padx=8, pady=2)
            else:
                btn = ctk.CTkButton(
                    popup, text=label, anchor="w",
                    font=ctk.CTkFont(size=12), height=32, width=200,
                    fg_color="transparent", hover_color=COLORS["accent"],
                    text_color=COLORS["text"], corner_radius=4,
                    command=cmd,
                )
                btn.pack(fill="x", padx=4, pady=1)

        # Dışına tıklanınca kapat (root üzerinde global click)
        def _on_root_click(event):
            try:
                # Tıklanan widget popup içinde mi kontrol et
                w = event.widget
                while w is not None:
                    if w == popup:
                        return  # popup içine tıklandı, kapatma
                    w = getattr(w, "master", None)
            except Exception:
                pass
            self._close_popup()

        # Bir sonraki event loop'ta bind et (mevcut click'i yutmasın)
        self.root.after(50, lambda: self._bind_popup_click(_on_root_click))

    def _bind_popup_click(self, handler):
        """Popup dışı click handler'ı güvenli şekilde bağla."""
        if getattr(self, "_active_popup", None) is None:
            return  # Popup zaten kapandı
        try:
            self._popup_click_bid = self.root.bind("<Button-1>", handler, add="+")
        except Exception:
            pass

    def _set_lang(self, code: str):
        try:
            update_language_config(code, True)
            log(f"[CONFIG] Language changed to: {code}")
        except Exception as e:
            log(f"[CONFIG] Language change error: {e}")
        messagebox.showinfo(self.t("info"), self.t("restart_needed_lang"))
        exe = ClientHelpers.current_executable()
        try:
            subprocess.Popen([exe] + sys.argv[1:], shell=False,
                             creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass
        sys.exit(0)

    def _open_logs(self):
        try:
            if os.name == "nt":
                os.startfile(LOG_FILE)
            else:
                webbrowser.open(f"file://{LOG_FILE}")
        except Exception as e:
            log(f"open_logs error: {e}")
            messagebox.showerror(self.t("error"), self.t("log_file_error").format(error=e))

    def _open_github(self):
        try:
            webbrowser.open(f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}")
        except Exception as e:
            log(f"open_github error: {e}")

    # ─── Window İkon ─── #
    def _set_window_icon(self, root):
        try:
            icon_path = get_resource_path("certs/honeypot.ico")
            if os.path.exists(icon_path):
                root.iconbitmap(icon_path)
                try:
                    from PIL import Image, ImageTk
                    img = Image.open(icon_path)
                    photo = ImageTk.PhotoImage(img)
                    root.iconphoto(True, photo)
                except Exception:
                    pass
        except Exception as e:
            log(f"Icon setup error: {e}")

    # ═══════════════════════════════════════════════════════════════
    #  CONSENT DİALOG (modern)
    # ═══════════════════════════════════════════════════════════════
    def show_consent_dialog(self) -> dict:
        """Modern onay dialogu gösterir. Kabul edilmişse skip eder."""
        cons = self.app.read_consent()
        if cons.get("accepted"):
            self.app.state["consent"] = cons
            return cons

        dialog = ctk.CTkToplevel(self.root)
        dialog.title(self.t("consent_title"))
        dialog.geometry("520x380")
        dialog.configure(fg_color=COLORS["bg"])
        dialog.transient(self.root)
        dialog.grab_set()

        # İçerik
        ctk.CTkLabel(
            dialog, text=self.t("consent_msg").replace("\\n", "\n"),
            font=ctk.CTkFont(size=13), text_color=COLORS["text"],
            justify="left", wraplength=480,
        ).pack(padx=20, pady=(20, 12))

        var_rdp = ctk.BooleanVar(value=True)
        var_auto = ctk.BooleanVar(value=False)

        ctk.CTkCheckBox(
            dialog, text=self.t("consent_rdp"), variable=var_rdp,
            fg_color=COLORS["green"], hover_color=COLORS["green_hover"],
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=24, pady=4)

        ctk.CTkCheckBox(
            dialog, text=self.t("consent_auto"), variable=var_auto,
            fg_color=COLORS["green"], hover_color=COLORS["green_hover"],
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=24, pady=4)

        accepted = {"val": False}

        def do_accept():
            accepted["val"] = True
            self.app.write_consent(True, var_rdp.get(), var_auto.get())
            self.app.state["consent"] = self.app.read_consent()
            dialog.destroy()

        def do_cancel():
            self.app.write_consent(False, var_rdp.get(), var_auto.get())
            self.app.state["consent"] = self.app.read_consent()
            dialog.destroy()

        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(pady=16)

        ctk.CTkButton(
            btn_frame, text=self.t("consent_accept"), width=140, height=38,
            fg_color=COLORS["green"], hover_color=COLORS["green_hover"],
            font=ctk.CTkFont(size=13, weight="bold"), corner_radius=8,
            command=do_accept,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            btn_frame, text=self.t("consent_cancel"), width=120, height=38,
            fg_color=COLORS["accent"], hover_color=COLORS["red"],
            font=ctk.CTkFont(size=13), corner_radius=8,
            command=do_cancel,
        ).pack(side="left", padx=8)

        dialog.wait_window()
        return self.app.state.get("consent", cons)
