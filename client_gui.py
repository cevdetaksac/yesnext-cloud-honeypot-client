#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloud Honeypot Client — Modern GUI Module (CustomTkinter).

Tüm GUI bileşenlerini içerir. client.py'deki iş mantığından bağımsızdır.
CloudHoneypotClient instance'ı üzerinden veri ve aksiyonlara erişir.
"""

import os
import time
import threading
import webbrowser
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
    "RDP":   "🖥",
    "MSSQL": "🗃",
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
        root.geometry("900x760")
        root.configure(fg_color=COLORS["bg"])
        root.minsize(820, 660)

        # ── İkon ── #
        self._set_window_icon(root)

        # ── Birleşik Üst Bar (Kimlik + Menü) ── #
        self._build_top_bar(root)

        # ── Kapatma → tray ── #
        root.protocol("WM_DELETE_WINDOW", self.app.on_close)

        # ── Başlık Bandı ── #
        self._build_header(root)

        # ── Tab View (3 sekme) ── #
        self._tabview = ctk.CTkTabview(
            root, fg_color="transparent",
            segmented_button_fg_color=COLORS["card"],
            segmented_button_selected_color=COLORS["accent"],
            segmented_button_selected_hover_color=COLORS["blue"],
            segmented_button_unselected_color=COLORS["card"],
            segmented_button_unselected_hover_color=COLORS["border"],
            text_color=COLORS["text_bright"],
            text_color_disabled=COLORS["text_dim"],
            corner_radius=10,
        )
        self._tabview.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        # Tab isimleri — build() anında self.t() ile çözümlenir.
        # CTkTabview rename/dict manipulation tab click'i bozar,
        # bu yüzden runtime'da DEĞİŞTİRİLMEZ. Dil değişince _rebuild_gui() çağrılır.
        self._tab_status_name = self.t("tab_status")
        self._tab_threat_name = self.t("tab_threat_center")
        self._tab_services_name = self.t("tab_services")

        self._tabview.add(self._tab_status_name)
        self._tabview.add(self._tab_threat_name)
        self._tabview.add(self._tab_services_name)
        self._tabview.set(self._tab_status_name)

        # Scrollable content for each tab
        tab1_scroll = ctk.CTkScrollableFrame(
            self._tabview.tab(self._tab_status_name), fg_color="transparent")
        tab1_scroll.pack(fill="both", expand=True)

        tab2_scroll = ctk.CTkScrollableFrame(
            self._tabview.tab(self._tab_threat_name), fg_color="transparent")
        tab2_scroll.pack(fill="both", expand=True)

        tab3_scroll = ctk.CTkScrollableFrame(
            self._tabview.tab(self._tab_services_name), fg_color="transparent")
        tab3_scroll.pack(fill="both", expand=True)

        # ── Tab 1: Anlık Durum — Dashboard kartları + IP Tablosu ── #
        self._build_dashboard(tab1_scroll)
        self._build_ip_activity_table(tab1_scroll)

        # ── Tab 2: Tehdit Merkezi — Threat detection + response ── #
        self._build_threat_center(tab2_scroll)

        # ── Tab 3: Honeypot Servisleri ── #
        self._build_services_section(tab3_scroll)

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
            bar, text=self.t("btn_dashboard"),
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
        hdr = ctk.CTkFrame(parent, fg_color=COLORS["accent"], corner_radius=0, height=44)
        hdr.pack(fill="x", pady=(0, 0))
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
        """Mini dashboard — canlı istatistik kartları (Tab 1: Anlık Durum)."""
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

        # ── Kartları oluştur (Tab 1 — Anlık Durum) ── #
        cards_data = [
            # (key, emoji, label_key, value, color, row, col, click_handler)
            ("total_attacks",   "🎯", "dash_total_attacks",   str(total_attacks),   COLORS["red"],    0, 0, "_detail_total_attacks"),
            ("session_attacks", "⚡", "dash_session_attacks",  str(session_attacks), COLORS["orange"], 0, 1, "_detail_session_attacks"),
            ("active_services", "🟢", "dash_active_services",  f"{active_count}/5",  COLORS["green"],  0, 2, "_detail_active_services"),
            ("uptime",          "⏱️", "dash_uptime",           "0dk",                COLORS["blue"],   1, 0, None),
            ("last_attack",     "🕵️", "dash_last_attack",      self.t("dash_no_attack"), COLORS["text_dim"], 1, 1, "_detail_last_attack"),
            ("connection",      "🌐", "dash_connection",       self.t("dash_connected"), COLORS["green"], 1, 2, "_detail_api_health"),
        ]

        for key, emoji, label_key, value, color, row, col, handler_name in cards_data:
            handler = getattr(self, handler_name, None) if handler_name else None
            card = self._create_stat_card(grid, emoji, self.t(label_key), value, color,
                                          on_click=handler)
            card.grid(row=row, column=col, padx=6, pady=5, sticky="nsew")
            self._dash_cards[key] = card

        # ── Faz 3 Durum Kartları — Satır 3 ── #
        faz3_cards_data = [
            ("ransomware",      "🧬", self.t("card_ransomware"),    "SAFE",  COLORS["green"],    2, 0, "_detail_ransomware"),
            ("cpu_usage",       "💻", self.t("card_cpu_ram"),     "—",     COLORS["text_dim"], 2, 1, "_detail_cpu_ram"),
            ("self_protect",    "🔒", self.t("card_protection"),    "ACTIVE", COLORS["green"],   2, 2, "_detail_self_protect"),
        ]

        for key, emoji, label, value, color, row, col, handler_name in faz3_cards_data:
            handler = getattr(self, handler_name, None) if handler_name else None
            card = self._create_stat_card(grid, emoji, label, value, color,
                                          on_click=handler)
            card.grid(row=row, column=col, padx=6, pady=5, sticky="nsew")
            self._dash_cards[key] = card

    # ═══════════════════════════════════════════════════════════════
    #  TAB 2: TEHDİT MERKEZİ
    # ═══════════════════════════════════════════════════════════════
    def _build_threat_center(self, parent):
        """Tab 2 — Tehdit Merkezi: Threat kartlar + güvenlik istihbaratı + feed + response."""
        # ── Threat Detection Kartları ── #
        threat_sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        threat_sec.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            threat_sec, text=self.t("section_threat_detection"),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=16, pady=(12, 8))

        sep = ctk.CTkFrame(threat_sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(0, 10))

        threat_grid = ctk.CTkFrame(threat_sec, fg_color="transparent")
        threat_grid.pack(fill="x", padx=12, pady=(0, 14))
        for c in range(3):
            threat_grid.columnconfigure(c, weight=1)

        threat_cards_data = [
            ("threat_level",    "🛡️", self.t("card_threat_level"),  "SAFE", COLORS["green"],    0, 0, "_detail_threat_level"),
            ("events_per_hour", "📊", self.t("card_events_per_hour"),   "0",    COLORS["text_dim"], 0, 1, "_detail_events_per_hour"),
            ("blocked_ips",     "🚫", self.t("card_tracked_ips"),   "0",    COLORS["text_dim"], 0, 2, "_detail_blocked_ips"),
        ]

        for key, emoji, label, value, color, row, col, handler_name in threat_cards_data:
            handler = getattr(self, handler_name, None) if handler_name else None
            card = self._create_stat_card(threat_grid, emoji, label, value, color,
                                          on_click=handler)
            card.grid(row=row, column=col, padx=6, pady=5, sticky="nsew")
            self._dash_cards[key] = card

        # ── Live Threat Feed ── #
        self._build_threat_feed(threat_sec)

        # ── Quick Response Buttons ── #
        self._build_response_buttons(threat_sec)

        # ── System Security Overview (v4.0.2) ── #
        self._build_security_overview(parent)

        # ── User Accounts (v4.0.2) ── #
        self._build_user_accounts_panel(parent)

        # ── Network Shares (v4.0.2) ── #
        self._build_network_shares_panel(parent)

        # ── Suspicious Services (v4.0.2) ── #
        self._build_suspicious_services_panel(parent)

        # ── Command History ── #
        self._build_command_history(parent)

        # ── Active Sessions ── #
        self._build_active_sessions(parent)

        # ── Trend Mini-Charts ── #
        self._build_trend_panel(parent)

    # ═══════════════════════════════════════════════════════════════
    #  SECURITY INTELLIGENCE PANELS (v4.0.2)
    # ═══════════════════════════════════════════════════════════════

    # ─── System Security Overview ─── #
    def _build_security_overview(self, parent):
        """Genel güvenlik durumu — yeşil/kırmızı check listesi."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        hdr = ctk.CTkFrame(sec, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            hdr, text=self.t("section_system_security"),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        ctk.CTkButton(
            hdr, text="🔄", width=28, height=22,
            font=ctk.CTkFont(size=11),
            fg_color=COLORS["bg"], border_width=1, border_color=COLORS["border"],
            hover_color="#2a2b3e",
            command=self._refresh_security_intel,
        ).pack(side="right")

        sep = ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(4, 8))

        self._security_checks_frame = ctk.CTkFrame(sec, fg_color="transparent")
        self._security_checks_frame.pack(fill="x", padx=16, pady=(0, 12))

        # Başlangıç: "Taranıyor..." göster
        self._security_check_label = ctk.CTkLabel(
            self._security_checks_frame,
            text=self.t("loading_system_scanning"),
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_dim"],
        )
        self._security_check_label.pack(anchor="w", padx=4, pady=2)

        # İlk taramayı başlat
        self._refresh_security_intel()

    # ─── User Accounts Panel ─── #
    def _build_user_accounts_panel(self, parent):
        """Windows kullanıcı hesapları — aktif, devre dışı, gizli."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        hdr = ctk.CTkFrame(sec, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            hdr, text=self.t("section_user_accounts"),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        ctk.CTkButton(
            hdr, text="🔄", width=28, height=22,
            font=ctk.CTkFont(size=11),
            fg_color=COLORS["bg"], border_width=1, border_color=COLORS["border"],
            hover_color="#2a2b3e",
            command=self._refresh_user_accounts,
        ).pack(side="right")

        sep = ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(4, 8))

        self._users_content_frame = ctk.CTkFrame(sec, fg_color="transparent")
        self._users_content_frame.pack(fill="x", padx=16, pady=(0, 12))

        self._users_loading_label = ctk.CTkLabel(
            self._users_content_frame,
            text=self.t("loading_users_scanning"),
            font=ctk.CTkFont(size=12), text_color=COLORS["text_dim"],
        )
        self._users_loading_label.pack(anchor="w", padx=4, pady=2)

    # ─── Network Shares Panel ─── #
    def _build_network_shares_panel(self, parent):
        """Ağ paylaşımları — açık paylaşımlar."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        hdr = ctk.CTkFrame(sec, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            hdr, text=self.t("section_network_shares"),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        sep = ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(4, 8))

        self._shares_content_frame = ctk.CTkFrame(sec, fg_color="transparent")
        self._shares_content_frame.pack(fill="x", padx=16, pady=(0, 12))

        self._shares_loading_label = ctk.CTkLabel(
            self._shares_content_frame,
            text=self.t("loading_shares_scanning"),
            font=ctk.CTkFont(size=12), text_color=COLORS["text_dim"],
        )
        self._shares_loading_label.pack(anchor="w", padx=4, pady=2)

    # ─── Suspicious Services Panel ─── #
    def _build_suspicious_services_panel(self, parent):
        """Windows dışı 3. parti çalışan servisler."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        hdr = ctk.CTkFrame(sec, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            hdr, text=self.t("section_third_party_services"),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        sep = ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(4, 8))

        self._services_content_frame = ctk.CTkFrame(sec, fg_color="transparent")
        self._services_content_frame.pack(fill="x", padx=16, pady=(0, 12))

        self._services_loading_label = ctk.CTkLabel(
            self._services_content_frame,
            text=self.t("loading_services_scanning"),
            font=ctk.CTkFont(size=12), text_color=COLORS["text_dim"],
        )
        self._services_loading_label.pack(anchor="w", padx=4, pady=2)

    # ═══════════════════════════════════════════════════════════════
    #  SECURITY DATA COLLECTORS (v4.0.2) — background threads
    # ═══════════════════════════════════════════════════════════════

    def _refresh_security_intel(self):
        """Tüm güvenlik panellerini arka planda yenile."""
        import threading as _th
        _th.Thread(target=self._collect_security_overview, daemon=True).start()
        _th.Thread(target=self._collect_user_accounts, daemon=True).start()
        _th.Thread(target=self._collect_network_shares, daemon=True).start()
        _th.Thread(target=self._collect_suspicious_services, daemon=True).start()

    def _refresh_user_accounts(self):
        """Sadece kullanıcı hesaplarını yenile."""
        import threading as _th
        _th.Thread(target=self._collect_user_accounts, daemon=True).start()

    # ─── Collector: System Security Overview ─── #
    def _collect_security_overview(self):
        """Sistem güvenlik kontrollerini çalıştır ve GUI'yi güncelle."""
        import subprocess
        checks = []
        CREATE_NW = 0x08000000

        # 1) Windows Firewall
        try:
            r = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=5, creationflags=CREATE_NW,
            )
            fw_on = "ON" in r.stdout.upper() if r.returncode == 0 else False
            checks.append((self.t("check_firewall"), fw_on,
                           self.t("check_active") if fw_on else self.t("check_disabled_warning"),
                           None if fw_on else "firewall"))
        except Exception:
            checks.append((self.t("check_firewall"), None, self.t("check_unable_to_verify")))

        # 2) Windows Defender / Antivirus
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NW,
            )
            av_on = "TRUE" in r.stdout.upper().strip() if r.returncode == 0 else False
            checks.append((self.t("check_antivirus"), av_on,
                           self.t("check_realtime_on") if av_on else self.t("check_disabled_warning"),
                           None if av_on else "antivirus"))
        except Exception:
            checks.append((self.t("check_antivirus"), None, self.t("check_unable_to_verify")))

        # 3) WinRM (uzaktan yönetim — kapalı olmalı)
        try:
            r = subprocess.run(
                ["sc", "query", "WinRM"],
                capture_output=True, text=True, timeout=5, creationflags=CREATE_NW,
            )
            winrm_running = "RUNNING" in r.stdout.upper() if r.returncode == 0 else False
            checks.append((self.t("check_winrm"), not winrm_running,
                           self.t("check_closed_safe") if not winrm_running else self.t("check_open_remote_risk"),
                           "winrm" if winrm_running else None))
        except Exception:
            checks.append((self.t("check_winrm"), True, self.t("check_service_not_found")))

        # 4) RDP Network Level Authentication
        try:
            r = subprocess.run(
                ["reg", "query",
                 r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                 "/v", "UserAuthentication"],
                capture_output=True, text=True, timeout=5, creationflags=CREATE_NW,
            )
            nla_on = "0x1" in r.stdout if r.returncode == 0 else False
            checks.append((self.t("check_rdp_nla"), nla_on,
                           self.t("check_nla_active") if nla_on else self.t("check_nla_off_risk"),
                           None if nla_on else "nla"))
        except Exception:
            checks.append((self.t("check_rdp_nla"), None, self.t("check_unable_to_verify")))

        # 5) Ransomware Shield
        rs = getattr(self.app, 'ransomware_shield', None)
        if rs:
            try:
                stats = rs.get_stats() if hasattr(rs, 'get_stats') else {}
                running = stats.get("running", False)
                alerts = stats.get("canary_alerts", 0)
                canary_count = stats.get("canary_files", 0)
                if running and alerts == 0:
                    checks.append((self.t("check_ransomware_shield"), True,
                                   self.t("check_rs_active").format(count=canary_count)))
                elif running and alerts > 0:
                    checks.append((self.t("check_ransomware_shield"), False,
                                   f"⚠️ {self.t('check_rs_alerts').format(count=alerts)}"))
                else:
                    checks.append((self.t("check_ransomware_shield"), False, self.t("check_rs_not_running")))
            except Exception:
                checks.append((self.t("check_ransomware_shield"), None, self.t("check_unable_to_verify")))
        else:
            checks.append((self.t("check_ransomware_shield"), False, self.t("check_rs_not_installed")))

        # 6) Windows Update (son güncelleme tarihi)
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-HotFix | Sort-Object InstalledOn -Descending | "
                 "Select-Object -First 1).InstalledOn.ToString('dd.MM.yyyy')"],
                capture_output=True, text=True, timeout=15, creationflags=CREATE_NW,
            )
            if r.returncode == 0 and r.stdout.strip():
                last_update = r.stdout.strip()
                checks.append((self.t("check_last_update"), True, last_update))
            else:
                checks.append((self.t("check_last_update"), None, self.t("check_info_unavailable")))
        except Exception:
            checks.append((self.t("check_last_update"), None, self.t("check_unable_to_verify")))

        # GUI'yi güncelle (thread-safe)
        self._gui_safe(lambda: self._render_security_checks(checks))

    def _render_security_checks(self, checks: list):
        """Güvenlik kontrol sonuçlarını GUI'de göster — aksiyon butonları ile."""
        try:
            # Mevcut widget'ları temizle
            for w in self._security_checks_frame.winfo_children():
                w.destroy()

            all_ok = all(c[1] is True for c in checks)

            # Genel durum banner
            if all_ok:
                banner_text = self.t("security_all_ok")
                banner_color = COLORS["green"]
            else:
                fail_count = sum(1 for c in checks if c[1] is False)
                banner_text = self.t("security_warnings_found").format(count=fail_count)
                banner_color = COLORS["orange"]

            banner = ctk.CTkLabel(
                self._security_checks_frame,
                text=banner_text,
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=banner_color,
            )
            banner.pack(anchor="w", padx=4, pady=(0, 8))

            # Her kontrol için satır — check_id ile aksiyon butonu eklenir
            for item in checks:
                name, status, detail = item[0], item[1], item[2]
                check_id = item[3] if len(item) > 3 else None

                row = ctk.CTkFrame(self._security_checks_frame, fg_color="transparent")
                row.pack(fill="x", padx=4, pady=1)

                if status is True:
                    icon = "✅"
                    color = COLORS["green"]
                elif status is False:
                    icon = "❌"
                    color = COLORS["red"]
                else:
                    icon = "⚪"
                    color = COLORS["text_dim"]

                ctk.CTkLabel(
                    row, text=f"{icon}  {name}:",
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=color, width=180, anchor="w",
                ).pack(side="left")

                ctk.CTkLabel(
                    row, text=detail,
                    font=ctk.CTkFont(size=12),
                    text_color=COLORS["text_dim"], anchor="w",
                ).pack(side="left", padx=(4, 0))

                # Aksiyon butonları — sadece sorunlu öğeler için
                if status is False and check_id:
                    btn_cfg = self._get_fix_button_config(check_id)
                    if btn_cfg:
                        ctk.CTkButton(
                            row, text=btn_cfg["text"],
                            width=btn_cfg.get("width", 70), height=22,
                            font=ctk.CTkFont(size=10),
                            fg_color=btn_cfg.get("color", COLORS["accent"]),
                            hover_color=btn_cfg.get("hover", COLORS["blue"]),
                            text_color=COLORS["text_bright"],
                            corner_radius=4,
                            command=btn_cfg["command"],
                        ).pack(side="right", padx=(4, 0))

        except Exception:
            pass

    def _get_fix_button_config(self, check_id: str) -> dict:
        """Güvenlik sorunları için düzeltme butonu konfigürasyonu."""
        configs = {
            "winrm": {
                "text": self.t("btn_fix_winrm"),
                "color": COLORS["red"],
                "hover": COLORS["red_hover"],
                "width": 60,
                "command": self._fix_winrm,
            },
            "nla": {
                "text": self.t("btn_fix_nla"),
                "color": COLORS["blue"],
                "hover": COLORS["blue_hover"],
                "width": 80,
                "command": self._fix_nla,
            },
            "antivirus": {
                "text": self.t("btn_fix_antivirus"),
                "color": COLORS["orange"],
                "hover": COLORS["orange_hover"],
                "width": 50,
                "command": self._fix_antivirus,
            },
            "firewall": {
                "text": self.t("btn_fix_firewall_warn"),
                "color": COLORS["orange"],
                "hover": COLORS["orange_hover"],
                "width": 200,
                "command": lambda: None,  # Sadece uyarı
            },
        }
        return configs.get(check_id)

    # ── Güvenlik Düzeltme Aksiyonları ─────────────────────────────

    def _fix_winrm(self):
        """WinRM servisini kapat."""
        if not messagebox.askyesno("WinRM", self.t("fix_winrm_confirm")):
            return
        import subprocess
        CREATE_NW = 0x08000000
        def _do():
            try:
                subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Stop-Service WinRM -Force; "
                     "Set-Service WinRM -StartupType Disabled; "
                     "Disable-PSRemoting -Force -ErrorAction SilentlyContinue"],
                    capture_output=True, timeout=15, creationflags=CREATE_NW,
                )
                self._gui_safe(lambda: messagebox.showinfo("WinRM", self.t("fix_winrm_ok")))
            except Exception:
                self._gui_safe(lambda: messagebox.showerror("WinRM", self.t("fix_winrm_fail")))
            self._refresh_security_intel()
        threading.Thread(target=_do, daemon=True).start()

    def _fix_nla(self):
        """RDP NLA'yı aktifleştir."""
        if not messagebox.askyesno("RDP NLA", self.t("fix_nla_confirm")):
            return
        import subprocess
        CREATE_NW = 0x08000000
        def _do():
            try:
                subprocess.run(
                    ["reg", "add",
                     r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                     "/v", "UserAuthentication", "/t", "REG_DWORD", "/d", "1", "/f"],
                    capture_output=True, timeout=10, creationflags=CREATE_NW,
                )
                self._gui_safe(lambda: messagebox.showinfo("RDP NLA", self.t("fix_nla_ok")))
            except Exception:
                self._gui_safe(lambda: messagebox.showerror("RDP NLA", self.t("fix_nla_fail")))
            self._refresh_security_intel()
        threading.Thread(target=_do, daemon=True).start()

    def _fix_antivirus(self):
        """Windows Defender gerçek zamanlı korumayı aç."""
        if not messagebox.askyesno("Antivirus", self.t("fix_av_confirm")):
            return
        import subprocess
        CREATE_NW = 0x08000000
        def _do():
            try:
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Set-MpPreference -DisableRealtimeMonitoring $false"],
                    capture_output=True, text=True, timeout=15, creationflags=CREATE_NW,
                )
                if r.returncode == 0:
                    self._gui_safe(lambda: messagebox.showinfo("Antivirus", self.t("fix_av_ok")))
                else:
                    self._gui_safe(lambda: messagebox.showerror("Antivirus", self.t("fix_av_fail")))
            except Exception:
                self._gui_safe(lambda: messagebox.showerror("Antivirus", self.t("fix_av_fail")))
            self._refresh_security_intel()
        threading.Thread(target=_do, daemon=True).start()

    # ─── Collector: User Accounts ─── #
    def _collect_user_accounts(self):
        """Windows kullanıcı hesaplarını topla — grup üyelikleri + IIS tespiti."""
        import subprocess, json, base64
        CREATE_NW = 0x08000000
        users = []

        # 1) Kullanıcı listesini al
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-LocalUser | Select-Object Name, Enabled, "
                 "LastLogon, Description | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NW,
            )
            if r.returncode == 0 and r.stdout.strip():
                data = json.loads(r.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                users = data
        except Exception:
            pass

        # 2) Her kullanıcının grup üyeliklerini topla (EncodedCommand ile $_ escape)
        group_map: dict = {}   # username -> [group1, group2, ...]
        try:
            ps_groups = (
                'Get-LocalGroup | ForEach-Object { $g=$_.Name; '
                'try { Get-LocalGroupMember -Group $g -ErrorAction Stop | '
                'ForEach-Object { [PSCustomObject]@{Group=$g; User=$_.Name} } } '
                'catch {} } | ConvertTo-Json -Depth 3'
            )
            encoded_g = base64.b64encode(ps_groups.encode('utf-16-le')).decode('ascii')
            r2 = subprocess.run(
                ["powershell", "-NoProfile", "-EncodedCommand", encoded_g],
                capture_output=True, text=True, timeout=20, creationflags=CREATE_NW,
            )
            if r2.returncode == 0 and r2.stdout.strip():
                memberships = json.loads(r2.stdout.strip())
                if isinstance(memberships, dict):
                    memberships = [memberships]
                for m in memberships:
                    raw_user = m.get("User", "")
                    # User can be DOMAIN\name or just name
                    short = raw_user.split("\\")[-1] if "\\" in raw_user else raw_user
                    group_map.setdefault(short, []).append(m.get("Group", ""))
        except Exception:
            pass

        # 3) IIS App Pool kimliklerini tespit et (EncodedCommand ile $_ escape)
        iis_pool_users: set = set()
        try:
            ps_iis = (
                'try { Import-Module WebAdministration -ErrorAction Stop; '
                'Get-ChildItem IIS:\\AppPools | Select-Object Name, '
                '@{N="Identity";E={$_.processModel.userName}}, '
                '@{N="IdType";E={$_.processModel.identityType}} '
                '| ConvertTo-Json } catch { "[]" }'
            )
            encoded_i = base64.b64encode(ps_iis.encode('utf-16-le')).decode('ascii')
            r3 = subprocess.run(
                ["powershell", "-NoProfile", "-EncodedCommand", encoded_i],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NW,
            )
            if r3.returncode == 0 and r3.stdout.strip():
                pools = json.loads(r3.stdout.strip())
                if isinstance(pools, dict):
                    pools = [pools]
                for p in pools:
                    id_type = str(p.get("IdType", ""))
                    identity = p.get("Identity", "") or ""
                    pool_name = p.get("Name", "") or ""
                    # ApplicationPoolIdentity → IIS APPPOOL\<poolname>
                    if "ApplicationPoolIdentity" in id_type:
                        iis_pool_users.add(pool_name.lower())
                    elif identity:
                        short = identity.split("\\")[-1] if "\\" in identity else identity
                        iis_pool_users.add(short.lower())
        except Exception:
            pass

        # Attach enrichment to each user
        for u in users:
            name = u.get("Name", "")
            u["_groups"] = group_map.get(name, [])
            u["_is_iis"] = name.lower() in iis_pool_users

        self._gui_safe(lambda: self._render_user_accounts(users))

    def _render_user_accounts(self, users: list):
        """Kullanıcı hesaplarını tablo formatında göster — Tür, Gruplar, Son Giriş, Aksiyon."""
        import re as _re
        try:
            for w in self._users_content_frame.winfo_children():
                w.destroy()

            if not users:
                ctk.CTkLabel(
                    self._users_content_frame,
                    text=self.t("users_info_unavailable"),
                    font=ctk.CTkFont(size=12), text_color=COLORS["text_dim"],
                ).pack(anchor="w", padx=4, pady=2)
                return

            # ── Domain uzantısı ile IIS App Pool tespiti ──
            domain_pattern = _re.compile(
                r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.(com|com\.tr|net|org|io|dev|info|biz|co|co\.uk|edu|gov)$',
                _re.IGNORECASE
            )

            active_users = []
            disabled_users = []

            for u in users:
                name = u.get("Name", "")
                enabled = u.get("Enabled", False)
                desc = u.get("Description", "") or ""
                last_logon = u.get("LastLogon", "")
                groups = u.get("_groups", [])
                is_iis_pool = u.get("_is_iis", False)

                # Domain adı benzeri kullanıcılar da IIS App Pool
                if not is_iis_pool and domain_pattern.match(name):
                    is_iis_pool = True

                # Son giriş tarihini formatla
                logon_str = ""
                if last_logon and isinstance(last_logon, str) and "/Date(" in last_logon:
                    try:
                        ts = int(last_logon.split("(")[1].split(")")[0]) / 1000
                        from datetime import datetime
                        logon_str = datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M")
                    except Exception:
                        logon_str = ""

                # Kullanıcı türünü belirle
                nl = name.lower()
                if nl == "administrator":
                    user_type = self.t("user_type_admin")
                    type_color = COLORS["orange"]
                elif is_iis_pool:
                    user_type = "IIS App Pool"
                    type_color = "#4fc3f7"
                elif nl in ("defaultaccount", "guest", "wdagutilityaccount",
                            "varsayılanhesap"):
                    user_type = self.t("user_type_system")
                    type_color = COLORS["text_dim"]
                else:
                    user_type = self.t("user_type_user")
                    type_color = COLORS["green"]

                # Grup listesini oluştur
                group_tags = []
                gl = [g.lower() for g in groups]
                if any("admin" in g for g in gl):
                    group_tags.append("Admin")
                if any(g in ("remote desktop users", "uzak masaüstü kullanıcıları") for g in gl):
                    group_tags.append("RDP")
                if any("iis" in g for g in gl):
                    group_tags.append("IIS")
                if any("users" in g and "admin" not in g and "remote" not in g for g in gl):
                    group_tags.append("Users")
                # Diğer özel gruplar
                known_groups = {
                    "administrators", "users", "remote desktop users",
                    "uzak masaüstü kullanıcıları", "iis_iusrs",
                    "guests", "system managed accounts group",
                    "device owners", "performance log users",
                    "performance monitor users", "event log readers",
                    "distributed com users", "cryptographic operators",
                    "network configuration operators",
                    "access control assistance operators",
                    "certificate service dcom access",
                    "backup operators", "hyper-v administrators",
                    "power users", "replicator",
                }
                for g in groups:
                    if g.lower() not in known_groups:
                        group_tags.append(g)
                groups_str = ", ".join(group_tags) if group_tags else "—"

                entry = {
                    "name": name, "enabled": enabled, "desc": desc,
                    "logon": logon_str, "groups_str": groups_str,
                    "user_type": user_type, "type_color": type_color,
                    "is_iis": is_iis_pool,
                }

                if not enabled:
                    disabled_users.append(entry)
                else:
                    active_users.append(entry)

            # Genel özet
            total = len(users)
            active_count = len(active_users)
            disabled_count = len(disabled_users)
            iis_count = sum(1 for u in active_users if u["is_iis"])

            parts = [f"{self.t('users_total')}: {total}", f"{self.t('users_active')}: {active_count}"]
            if iis_count:
                parts.append(f"{self.t('users_iis')}: {iis_count}")
            parts.append(f"{self.t('users_disabled')}: {disabled_count}")

            ctk.CTkLabel(
                self._users_content_frame,
                text="👥  " + "  |  ".join(parts),
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLORS["green"],
            ).pack(anchor="w", padx=4, pady=(0, 4))

            # ── Tablo başlığı ──
            hdr = ctk.CTkFrame(self._users_content_frame, fg_color=COLORS["bg"],
                               corner_radius=4)
            hdr.pack(fill="x", padx=4, pady=(0, 2))
            for text, w in [(self.t("users_col_name"), 140), (self.t("users_col_type"), 90), (self.t("users_col_groups"), 130),
                            (self.t("users_col_last_logon"), 120), ("", 70)]:
                ctk.CTkLabel(
                    hdr, text=text, width=w, anchor="w",
                    font=ctk.CTkFont(size=10, weight="bold"),
                    text_color=COLORS["text_dim"],
                ).pack(side="left", padx=2)

            # ── Disable callback ──
            def _on_disable_click(username: str):
                import tkinter.messagebox as mbox
                if username.lower() == "administrator":
                    mbox.showwarning(self.t("warn"), self.t("users_admin_no_disable"))
                    return
                ok = mbox.askyesno(
                    self.t("msgbox_disable_user_title"),
                    self.t("msgbox_disable_user_confirm").format(user=username),
                )
                if not ok:
                    return
                auto_response = getattr(self.app, 'auto_response', None)
                if auto_response:
                    result = auto_response.disable_account(username)
                    if result:
                        mbox.showinfo(self.t("info"), self.t("msgbox_user_disabled_ok").format(user=username))
                        import threading as _th
                        _th.Thread(target=self._collect_user_accounts, daemon=True).start()
                    else:
                        mbox.showerror(self.t("error"), self.t("msgbox_user_disabled_fail").format(user=username))
                else:
                    mbox.showerror(self.t("error"), self.t("msgbox_autoresponse_unavailable"))

            # ── Aktif kullanıcı satırları ──
            for u in active_users:
                row = ctk.CTkFrame(self._users_content_frame, fg_color="transparent")
                row.pack(fill="x", padx=4, pady=1)

                is_admin = u["name"].lower() == "administrator"

                # İkon
                if is_admin:
                    icon = "👑"
                elif u["is_iis"]:
                    icon = "🌐"
                else:
                    icon = "👤"

                # Kullanıcı adı
                ctk.CTkLabel(
                    row, text=f"{icon} {u['name']}",
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=u["type_color"], width=140, anchor="w",
                ).pack(side="left", padx=2)

                # Tür sütunu
                ctk.CTkLabel(
                    row, text=u["user_type"],
                    font=ctk.CTkFont(size=10),
                    text_color=u["type_color"], width=90, anchor="w",
                ).pack(side="left", padx=2)

                # Gruplar sütunu
                ctk.CTkLabel(
                    row, text=u["groups_str"],
                    font=ctk.CTkFont(size=10),
                    text_color=COLORS["text_dim"], width=130, anchor="w",
                ).pack(side="left", padx=2)

                # Son giriş sütunu
                ctk.CTkLabel(
                    row, text=u["logon"] if u["logon"] else "—",
                    font=ctk.CTkFont(size=10),
                    text_color=COLORS["text_dim"], width=120, anchor="w",
                ).pack(side="left", padx=2)

                # Pasife Al butonu (admin hariç)
                if not is_admin:
                    uname = u["name"]
                    ctk.CTkButton(
                        row, text=self.t("btn_disable_user"), width=70, height=20,
                        font=ctk.CTkFont(size=10),
                        fg_color="#8B0000", hover_color="#B22222",
                        command=lambda n=uname: _on_disable_click(n),
                    ).pack(side="right", padx=(4, 0))

            # ── Devre dışı kullanıcılar ──
            if disabled_users:
                ctk.CTkLabel(
                    self._users_content_frame,
                    text=f"🔒  {self.t('users_disabled_accounts')} ({disabled_count}):",
                    font=ctk.CTkFont(size=11),
                    text_color=COLORS["text_dim"],
                ).pack(anchor="w", padx=4, pady=(6, 2))

                names = ", ".join(u["name"] for u in disabled_users)
                ctk.CTkLabel(
                    self._users_content_frame,
                    text=f"    {names}",
                    font=ctk.CTkFont(size=11),
                    text_color=COLORS["text_dim"],
                    wraplength=700,
                ).pack(anchor="w", padx=4, pady=0)

        except Exception:
            pass

    # ─── Collector: Network Shares ─── #
    def _collect_network_shares(self):
        """Ağ paylaşımlarını topla."""
        import subprocess
        CREATE_NW = 0x08000000
        shares = []

        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-SmbShare | Select-Object Name, Path, Description, "
                 "ShareType, CurrentUsers | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10, creationflags=CREATE_NW,
            )
            if r.returncode == 0 and r.stdout.strip():
                import json
                data = json.loads(r.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                shares = data
        except Exception:
            pass

        self._gui_safe(lambda: self._render_network_shares(shares))

    def _render_network_shares(self, shares: list):
        """Ağ paylaşımlarını GUI'de göster."""
        try:
            for w in self._shares_content_frame.winfo_children():
                w.destroy()

            if not shares:
                ctk.CTkLabel(
                    self._shares_content_frame,
                    text=self.t("shares_info_unavailable"),
                    font=ctk.CTkFont(size=12), text_color=COLORS["text_dim"],
                ).pack(anchor="w", padx=4, pady=2)
                return

            # Varsayılan Windows paylaşımları
            default_shares = {"ADMIN$", "C$", "IPC$", "D$", "E$"}

            custom_shares = [s for s in shares
                             if s.get("Name", "") not in default_shares]
            default_only = len(custom_shares) == 0

            if default_only:
                ctk.CTkLabel(
                    self._shares_content_frame,
                    text=self.t("shares_default_only"),
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=COLORS["green"],
                ).pack(anchor="w", padx=4, pady=(0, 4))
            else:
                ctk.CTkLabel(
                    self._shares_content_frame,
                    text=self.t("shares_custom_detected").format(count=len(custom_shares)),
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=COLORS["orange"],
                ).pack(anchor="w", padx=4, pady=(0, 4))

            for s in shares:
                name = s.get("Name", "")
                path = s.get("Path", "")
                desc = s.get("Description", "") or ""
                users = s.get("CurrentUsers", 0) or 0
                is_default = name in default_shares

                row = ctk.CTkFrame(self._shares_content_frame, fg_color="transparent")
                row.pack(fill="x", padx=4, pady=1)

                icon = "📁" if is_default else "📂"
                color = COLORS["text_dim"] if is_default else COLORS["orange"]

                ctk.CTkLabel(
                    row, text=f"{icon} {name}",
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=color, width=120, anchor="w",
                ).pack(side="left")

                detail = path or desc
                if users > 0:
                    detail += f"  ({users} {self.t('shares_connected_users')})"
                ctk.CTkLabel(
                    row, text=detail,
                    font=ctk.CTkFont(size=11),
                    text_color=COLORS["text_dim"], anchor="w",
                ).pack(side="left", padx=(4, 0))

        except Exception:
            pass

    # ─── Collector: Suspicious Services ─── #
    def _collect_suspicious_services(self):
        """Windows dışı 3. parti çalışan servisleri topla."""
        import subprocess, base64
        CREATE_NW = 0x08000000
        services = []

        try:
            # PowerShell scriptini EncodedCommand ile gönder ($_ escape sorununu önler)
            ps_script = (
                'Get-CimInstance Win32_Service | '
                'Where-Object { $_.State -eq "Running" } | '
                'Select-Object Name, DisplayName, PathName, StartMode, StartName | '
                'ConvertTo-Json -Depth 2'
            )
            encoded = base64.b64encode(ps_script.encode('utf-16-le')).decode('ascii')
            r = subprocess.run(
                ["powershell", "-NoProfile", "-EncodedCommand", encoded],
                capture_output=True, text=True, timeout=20, creationflags=CREATE_NW,
            )
            if r.returncode == 0 and r.stdout.strip():
                import json
                data = json.loads(r.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                services = data
        except Exception:
            pass

        self._gui_safe(lambda: self._render_suspicious_services(services))

    def _render_suspicious_services(self, services: list):
        """3. parti servisleri GUI'de göster."""
        try:
            for w in self._services_content_frame.winfo_children():
                w.destroy()

            if not services:
                ctk.CTkLabel(
                    self._services_content_frame,
                    text=self.t("services_info_unavailable"),
                    font=ctk.CTkFont(size=12), text_color=COLORS["text_dim"],
                ).pack(anchor="w", padx=4, pady=2)
                return

            # Microsoft/Windows path'leri (güvenli kabul)
            safe_paths = [
                "c:\\windows\\", "c:\\program files\\common files\\microsoft",
                "c:\\program files\\windows", "\\systemroot\\",
                "c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
            ]

            # Bilinen güvenli 3. parti uygulamalar
            known_safe = [
                "mysql", "mssql", "sqlserver", "apache", "nginx", "iis",
                "maestropanel", "google", "chrome", "honeypot", "yesnext",
                "sqlbackup", "php", "node", "cloudflare", "defender",
            ]

            third_party = []
            for svc in services:
                path = (svc.get("PathName") or "").lower()
                name = (svc.get("Name") or "").lower()
                display = svc.get("DisplayName") or svc.get("Name", "")

                # Windows/Microsoft yolundan çalışanları atla
                is_system = any(path.startswith(sp) for sp in safe_paths)
                if is_system:
                    continue

                # Bilinen güvenli mi?
                is_known = any(k in name or k in path for k in known_safe)
                third_party.append({
                    "name": svc.get("Name", ""),
                    "display": display,
                    "path": svc.get("PathName", ""),
                    "start_mode": svc.get("StartMode", ""),
                    "account": svc.get("StartName", ""),
                    "known": is_known,
                })

            if not third_party:
                ctk.CTkLabel(
                    self._services_content_frame,
                    text=self.t("services_no_suspicious"),
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=COLORS["green"],
                ).pack(anchor="w", padx=4, pady=2)
                return

            unknown_count = sum(1 for s in third_party if not s["known"])
            if unknown_count == 0:
                summary = self.t("services_all_known").format(count=len(third_party))
                summary_color = COLORS["green"]
            else:
                summary = self.t("services_unknown_detected").format(count=unknown_count)
                summary_color = COLORS["orange"]

            ctk.CTkLabel(
                self._services_content_frame,
                text=summary,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=summary_color,
            ).pack(anchor="w", padx=4, pady=(0, 6))

            # Bilinmeyenleri önce göster
            sorted_svcs = sorted(third_party, key=lambda x: x["known"])
            for svc in sorted_svcs[:15]:  # En fazla 15 göster
                row = ctk.CTkFrame(self._services_content_frame, fg_color="transparent")
                row.pack(fill="x", padx=4, pady=1)

                if svc["known"]:
                    icon = "✅"
                    color = COLORS["text_dim"]
                else:
                    icon = "⚠️"
                    color = COLORS["orange"]

                ctk.CTkLabel(
                    row, text=f"{icon} {svc['display']}",
                    font=ctk.CTkFont(size=11, weight="bold" if not svc["known"] else "normal"),
                    text_color=color, anchor="w",
                ).pack(side="left")

                # Kısa path göster
                short_path = svc["path"][:60] + "..." if len(svc["path"]) > 60 else svc["path"]
                ctk.CTkLabel(
                    row, text=f"  {short_path}",
                    font=ctk.CTkFont(size=10),
                    text_color=COLORS["text_dim"], anchor="w",
                ).pack(side="left", padx=(4, 0))

            if len(third_party) > 15:
                ctk.CTkLabel(
                    self._services_content_frame,
                    text=self.t("services_more_count").format(count=len(third_party) - 15),
                    font=ctk.CTkFont(size=11),
                    text_color=COLORS["text_dim"],
                ).pack(anchor="w", padx=4, pady=(4, 0))

        except Exception:
            pass

    # ─── Live Threat Feed (v4.0 Faz 2) ─── #
    def _build_threat_feed(self, parent):
        """Scrollable live threat feed — shows last 20 alerts in real-time."""
        feed_frame = ctk.CTkFrame(parent, fg_color="transparent")
        feed_frame.pack(fill="x", padx=12, pady=(0, 4))

        ctk.CTkLabel(
            feed_frame, text=self.t("section_live_threat_feed"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=4, pady=(0, 4))

        self._threat_feed_box = ctk.CTkTextbox(
            feed_frame, height=100, fg_color=COLORS["bg"],
            border_width=1, border_color=COLORS["border"],
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_dim"],
            state="disabled", wrap="word",
        )
        self._threat_feed_box.pack(fill="x", padx=4, pady=(0, 6))

        # Placeholder — veri gelince otomatik temizlenir
        self._threat_feed_box.configure(state="normal")
        self._threat_feed_box.insert("1.0", self.t("placeholder_threat_feed"))
        self._threat_feed_box.configure(state="disabled")
        self._threat_feed_has_data = False

    def _build_response_buttons(self, parent):
        """Quick-action response buttons for dashboard."""
        btn_frame = ctk.CTkFrame(parent, fg_color="transparent")
        btn_frame.pack(fill="x", padx=12, pady=(0, 10))

        ctk.CTkLabel(
            btn_frame, text=self.t("section_quick_response"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=4, pady=(0, 6))

        btn_row = ctk.CTkFrame(btn_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=4)

        buttons = [
            (self.t("btn_block_ip"),   self._on_block_ip_click),
            (self.t("btn_logoff"),     self._on_logoff_click),
            (self.t("btn_disable"),    self._on_disable_click),
            (self.t("btn_snapshot"),   self._on_snapshot_click),
        ]
        for i, (label, cmd) in enumerate(buttons):
            btn = ctk.CTkButton(
                btn_row, text=label, width=100, height=28,
                font=ctk.CTkFont(size=11),
                fg_color=COLORS.get("bg", "#1a1b2e"),
                border_width=1, border_color=COLORS["border"],
                hover_color="#2a2b3e",
                command=cmd,
            )
            btn.pack(side="left", padx=(0, 6), pady=2)

        # Silent hours status indicator
        self._silent_hours_label = ctk.CTkLabel(
            btn_row, text="",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"],
        )
        self._silent_hours_label.pack(side="right", padx=4)

    def append_threat_feed(self, text: str):
        """Append a line to the live threat feed (thread-safe via root.after)."""
        def _append():
            try:
                if not hasattr(self, '_threat_feed_box'):
                    return
                self._threat_feed_box.configure(state="normal")
                # İlk gerçek veri geldiğinde placeholder'ı temizle
                if not getattr(self, '_threat_feed_has_data', False):
                    self._threat_feed_box.delete("1.0", "end")
                    self._threat_feed_has_data = True
                self._threat_feed_box.insert("end", text + "\n")
                self._threat_feed_box.see("end")
                # Keep only last 200 lines
                content = self._threat_feed_box.get("1.0", "end")
                lines = content.splitlines()
                if len(lines) > 200:
                    self._threat_feed_box.delete("1.0", f"{len(lines)-200}.0")
                self._threat_feed_box.configure(state="disabled")
            except Exception:
                pass
        if self.root:
            self.root.after(0, _append)

    # ─── Quick Response Button Handlers ─── #
    def _on_block_ip_click(self):
        """Prompt for IP and block it via AutoResponse."""
        dialog = ctk.CTkInputDialog(
            text=self.t("dialog_enter_ip"), title=self.t("dialog_block_ip_title"),
        )
        ip = dialog.get_input()
        if ip and ip.strip():
            ip = ip.strip()
            auto_response = getattr(self.app, 'auto_response', None)
            if auto_response:
                ok = auto_response.block_ip(ip, reason="Manual block from dashboard")
                self.show_toast(
                    self.t("toast_ip_blocked") if ok else self.t("toast_block_failed"),
                    self.t("toast_ip_blocked_msg").format(ip=ip) if ok else self.t("toast_ip_block_failed_msg").format(ip=ip),
                    "high" if ok else "warning",
                )

    def _on_logoff_click(self):
        """Prompt for username and logoff."""
        dialog = ctk.CTkInputDialog(
            text=self.t("dialog_enter_user_logoff"), title=self.t("dialog_logoff_title"),
        )
        username = dialog.get_input()
        if username and username.strip():
            username = username.strip()
            auto_response = getattr(self.app, 'auto_response', None)
            if auto_response:
                ok = auto_response.logoff_user(username)
                self.show_toast(
                    self.t("toast_session_closed") if ok else self.t("toast_logoff_failed"),
                    self.t("toast_logoff_ok_msg").format(user=username) if ok else self.t("toast_logoff_fail_msg").format(user=username),
                    "high" if ok else "warning",
                )

    def _on_disable_click(self):
        """Prompt for username and disable account."""
        dialog = ctk.CTkInputDialog(
            text=self.t("dialog_enter_user_disable"), title=self.t("dialog_disable_title"),
        )
        username = dialog.get_input()
        if username and username.strip():
            username = username.strip()
            auto_response = getattr(self.app, 'auto_response', None)
            if auto_response:
                ok = auto_response.disable_account(username)
                self.show_toast(
                    self.t("toast_account_disabled") if ok else self.t("toast_disable_failed"),
                    self.t("toast_disable_ok_msg").format(user=username) if ok else self.t("toast_disable_fail_msg").format(user=username),
                    "high" if ok else "warning",
                )

    def _on_snapshot_click(self):
        """Take a system snapshot via RemoteCommandExecutor."""
        remote_cmd = getattr(self.app, 'remote_commands', None)
        if remote_cmd:
            result = remote_cmd._cmd_snapshot({})
            if result.get("success"):
                cpu = result.get("cpu_percent", 0)
                mem = result.get("memory", {})
                mem_pct = mem.get("percent", 0)
                conns = result.get("connections", 0)
                self.show_toast(
                    self.t("toast_snapshot_title"),
                    f"CPU: {cpu}%  |  RAM: {mem_pct}%  |  Connections: {conns}",
                    "info", duration_ms=8000,
                )
            else:
                self.show_toast(self.t("toast_snapshot_failed"), result.get("error", "Unknown error"), "warning")

    # ═══════════════════════════════════════════════════════════════
    #  IP AKTİVİTE TABLOSU (Tab 1 — Anlık Durum)
    # ═══════════════════════════════════════════════════════════════

    def _build_ip_activity_table(self, parent):
        """Anlık IP aktivite tablosu — giriş denemeleri, durum, butonlar."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        hdr = ctk.CTkFrame(sec, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            hdr, text=self.t("section_ip_activity"),
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        ctk.CTkButton(
            hdr, text="🔄", width=28, height=22,
            font=ctk.CTkFont(size=11),
            fg_color=COLORS["bg"], border_width=1, border_color=COLORS["border"],
            hover_color="#2a2b3e",
            command=self._refresh_ip_table,
        ).pack(side="right")

        sep = ctk.CTkFrame(sec, height=1, fg_color=COLORS["border"])
        sep.pack(fill="x", padx=16, pady=(4, 8))

        # Tablo başlığı
        header_row = ctk.CTkFrame(sec, fg_color=COLORS["accent"], corner_radius=4)
        header_row.pack(fill="x", padx=16, pady=(0, 2))

        cols = [
            (self.t("ip_col_address"), 140),
            (self.t("ip_col_service"), 65),
            (self.t("ip_col_attempts"), 60),
            (self.t("ip_col_last_time"), 130),
            (self.t("ip_col_status"), 80),
        ]
        for text, width in cols:
            ctk.CTkLabel(
                header_row, text=text, width=width,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=COLORS["text_bright"], anchor="w",
            ).pack(side="left", padx=4, pady=4)

        ctk.CTkLabel(
            header_row, text=self.t("ip_col_actions"),
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=COLORS["text_bright"], anchor="w",
        ).pack(side="left", padx=4, pady=4, fill="x", expand=True)

        # Tablo içeriği — scrollable
        self._ip_table_frame = ctk.CTkScrollableFrame(
            sec, fg_color="transparent", height=180,
        )
        self._ip_table_frame.pack(fill="x", padx=16, pady=(0, 12))

        # Boş mesaj
        self._ip_table_empty = ctk.CTkLabel(
            self._ip_table_frame,
            text=self.t("ip_no_activity"),
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_dim"],
        )
        self._ip_table_empty.pack(anchor="w", padx=4, pady=8)

    def _refresh_ip_table(self):
        """ThreatEngine IP pool'undan verileri alıp tabloyu güncelle."""
        threading.Thread(target=self._collect_ip_table_data, daemon=True).start()

    def _collect_ip_table_data(self):
        """Arka planda IP verilerini topla."""
        threat_engine = getattr(self.app, 'threat_engine', None)
        auto_response = getattr(self.app, 'auto_response', None)
        if not threat_engine:
            return

        rows = []
        contexts = threat_engine.get_all_contexts()
        blocked_ips = getattr(threat_engine, '_rule_blocked_ips', set())
        whitelist_ips = getattr(threat_engine, '_whitelist_ips', set())

        # AutoResponse'daki aktif blokları da kontrol et (firewall gerçeği)
        ar_blocked: set = set()
        if auto_response:
            try:
                ar_blocked = set(getattr(auto_response, '_blocks', {}).keys())
            except Exception:
                pass

        for ip, ctx in contexts.items():
            if ip in ("local", "", "127.0.0.1", "::1"):
                continue
            if ctx.threat_score < 1 and ctx.failed_attempts < 1:
                continue

            services = list(ctx.services_targeted) if ctx.services_targeted else ["—"]
            service_str = "/".join(services[:2])

            attempts = ctx.failed_attempts
            last_seen = ctx.last_seen

            if ip in whitelist_ips:
                status = "whitelisted"
            elif ip in blocked_ips or ip in ar_blocked or ctx.is_blocked:
                status = "blocked"
            else:
                status = "watching"

            rows.append({
                "ip": ip,
                "service": service_str,
                "attempts": attempts,
                "last_seen": last_seen,
                "status": status,
                "score": ctx.threat_score,
            })

        # En yeni ilk sıraya
        rows.sort(key=lambda r: r["last_seen"], reverse=True)
        # Max 50 satır
        rows = rows[:50]

        self._gui_safe(lambda: self._render_ip_table(rows))

    def _render_ip_table(self, rows: list):
        """IP tablosunu GUI'ye render et."""
        try:
            for w in self._ip_table_frame.winfo_children():
                w.destroy()

            if not rows:
                ctk.CTkLabel(
                    self._ip_table_frame,
                    text=self.t("ip_no_activity"),
                    font=ctk.CTkFont(size=12),
                    text_color=COLORS["text_dim"],
                ).pack(anchor="w", padx=4, pady=8)
                return

            from datetime import datetime

            for i, r in enumerate(rows):
                bg = COLORS["bg"] if i % 2 == 0 else COLORS["card"]
                row_frame = ctk.CTkFrame(
                    self._ip_table_frame, fg_color=bg,
                    corner_radius=4, height=30,
                )
                row_frame.pack(fill="x", pady=1)
                row_frame.pack_propagate(False)

                # IP
                ip_color = COLORS["red"] if r["status"] == "blocked" else (
                    COLORS["green"] if r["status"] == "whitelisted" else COLORS["text"])
                ctk.CTkLabel(
                    row_frame, text=r["ip"], width=140,
                    font=ctk.CTkFont(family="Consolas", size=11),
                    text_color=ip_color, anchor="w",
                ).pack(side="left", padx=4)

                # Servis
                ctk.CTkLabel(
                    row_frame, text=r["service"], width=65,
                    font=ctk.CTkFont(size=11),
                    text_color=COLORS["text_dim"], anchor="w",
                ).pack(side="left", padx=4)

                # Deneme sayısı
                att_color = COLORS["red"] if r["attempts"] >= 3 else (
                    COLORS["orange"] if r["attempts"] >= 1 else COLORS["text_dim"])
                ctk.CTkLabel(
                    row_frame, text=str(r["attempts"]), width=60,
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=att_color, anchor="w",
                ).pack(side="left", padx=4)

                # Son zaman
                try:
                    ts = datetime.fromtimestamp(r["last_seen"]).strftime("%d.%m %H:%M:%S")
                except Exception:
                    ts = "—"
                ctk.CTkLabel(
                    row_frame, text=ts, width=130,
                    font=ctk.CTkFont(size=10),
                    text_color=COLORS["text_dim"], anchor="w",
                ).pack(side="left", padx=4)

                # Durum
                status = r["status"]
                if status == "blocked":
                    st_text = self.t("ip_status_blocked")
                    st_color = COLORS["red"]
                elif status == "whitelisted":
                    st_text = self.t("ip_status_whitelisted")
                    st_color = COLORS["green"]
                else:
                    st_text = self.t("ip_status_watching")
                    st_color = COLORS["orange"]
                ctk.CTkLabel(
                    row_frame, text=st_text, width=80,
                    font=ctk.CTkFont(size=10, weight="bold"),
                    text_color=st_color, anchor="w",
                ).pack(side="left", padx=4)

                # Aksiyon butonları — duruma göre dinamik
                ip = r["ip"]
                if status == "blocked":
                    # Engeli kaldır butonu
                    ctk.CTkButton(
                        row_frame, text=self.t("ip_btn_unblock"),
                        width=70, height=20,
                        font=ctk.CTkFont(size=9),
                        fg_color=COLORS["orange"], hover_color=COLORS["orange_hover"],
                        text_color=COLORS["text_bright"], corner_radius=3,
                        command=lambda _ip=ip: self._ip_table_unblock(_ip),
                    ).pack(side="left", padx=2)
                    # Güvenli listeye al
                    ctk.CTkButton(
                        row_frame, text=self.t("ip_btn_whitelist"),
                        width=55, height=20,
                        font=ctk.CTkFont(size=9),
                        fg_color=COLORS["green"], hover_color=COLORS["green_hover"],
                        text_color=COLORS["text_bright"], corner_radius=3,
                        command=lambda _ip=ip: self._ip_table_whitelist(_ip),
                    ).pack(side="left", padx=2)
                elif status == "whitelisted":
                    # Güvenden çıkar butonu
                    ctk.CTkButton(
                        row_frame, text=self.t("ip_btn_remove_whitelist"),
                        width=75, height=20,
                        font=ctk.CTkFont(size=9),
                        fg_color=COLORS["orange"], hover_color=COLORS["orange_hover"],
                        text_color=COLORS["text_bright"], corner_radius=3,
                        command=lambda _ip=ip: self._ip_table_remove_whitelist(_ip),
                    ).pack(side="left", padx=2)
                    # Engelle butonu
                    ctk.CTkButton(
                        row_frame, text=self.t("ip_btn_block"),
                        width=55, height=20,
                        font=ctk.CTkFont(size=9),
                        fg_color=COLORS["red"], hover_color=COLORS["red_hover"],
                        text_color=COLORS["text_bright"], corner_radius=3,
                        command=lambda _ip=ip: self._ip_table_block(_ip),
                    ).pack(side="left", padx=2)
                else:
                    # İzleniyor — Engelle + Güvenli
                    ctk.CTkButton(
                        row_frame, text=self.t("ip_btn_block"),
                        width=55, height=20,
                        font=ctk.CTkFont(size=9),
                        fg_color=COLORS["red"], hover_color=COLORS["red_hover"],
                        text_color=COLORS["text_bright"], corner_radius=3,
                        command=lambda _ip=ip: self._ip_table_block(_ip),
                    ).pack(side="left", padx=2)
                    ctk.CTkButton(
                        row_frame, text=self.t("ip_btn_whitelist"),
                        width=55, height=20,
                        font=ctk.CTkFont(size=9),
                        fg_color=COLORS["green"], hover_color=COLORS["green_hover"],
                        text_color=COLORS["text_bright"], corner_radius=3,
                        command=lambda _ip=ip: self._ip_table_whitelist(_ip),
                    ).pack(side="left", padx=2)

        except Exception as e:
            log(f"[GUI] IP table render error: {e}")

    def _ip_table_block(self, ip: str):
        """IP tablosundan hızlı engelle — firewall + ThreatEngine senkron."""
        auto_response = getattr(self.app, 'auto_response', None)
        threat_engine = getattr(self.app, 'threat_engine', None)
        if not auto_response:
            return

        # Önce whitelist'ten çıkar (varsa)
        if threat_engine:
            threat_engine._whitelist_ips.discard(ip)
        ew = getattr(self.app, 'event_watcher', None)
        if ew and hasattr(ew, 'whitelist_ips'):
            ew.whitelist_ips.discard(ip)
        if auto_response:
            auto_response.whitelist_ips.discard(ip)

        ok = auto_response.block_ip(ip, reason="Manual block from IP table")
        if ok:
            # ThreatEngine durumunu da güncelle
            if threat_engine:
                threat_engine._rule_blocked_ips.add(ip)
                ctx = threat_engine.get_ip_context(ip)
                if ctx:
                    ctx.is_blocked = True
            self.show_toast(self.t("toast_ip_blocked"),
                            self.t("toast_ip_blocked_msg").format(ip=ip), "high")
        else:
            self.show_toast(self.t("toast_block_failed"),
                            self.t("toast_ip_blocked_msg").format(ip=ip), "warning")
        self._refresh_ip_table()

    def _ip_table_unblock(self, ip: str):
        """IP tablosundan engeli kaldır — firewall + ThreatEngine senkron."""
        auto_response = getattr(self.app, 'auto_response', None)
        threat_engine = getattr(self.app, 'threat_engine', None)

        if auto_response:
            auto_response.unblock_ip(ip)
        if threat_engine:
            threat_engine._rule_blocked_ips.discard(ip)
            ctx = threat_engine.get_ip_context(ip)
            if ctx:
                ctx.is_blocked = False
        self.show_toast(self.t("toast_ip_unblocked"),
                        self.t("toast_ip_unblocked_msg").format(ip=ip), "info")
        self._refresh_ip_table()

    def _ip_table_whitelist(self, ip: str):
        """IP tablosundan güvenli listeye ekle — engeli kaldır + whitelist senkron."""
        threat_engine = getattr(self.app, 'threat_engine', None)
        auto_response = getattr(self.app, 'auto_response', None)

        # Engeli varsa önce kaldır
        if auto_response:
            auto_response.unblock_ip(ip)
            auto_response.whitelist_ips.add(ip)
        if threat_engine:
            threat_engine._rule_blocked_ips.discard(ip)
            threat_engine._whitelist_ips.add(ip)
            ctx = threat_engine.get_ip_context(ip)
            if ctx:
                ctx.is_blocked = False
        ew = getattr(self.app, 'event_watcher', None)
        if ew and hasattr(ew, 'whitelist_ips'):
            ew.whitelist_ips.add(ip)

        self.show_toast(self.t("ip_status_whitelisted"),
                        self.t("toast_ip_whitelisted_msg").format(ip=ip), "info")
        self._refresh_ip_table()

    def _ip_table_remove_whitelist(self, ip: str):
        """IP'yi güvenli listeden çıkar."""
        threat_engine = getattr(self.app, 'threat_engine', None)
        auto_response = getattr(self.app, 'auto_response', None)

        if threat_engine:
            threat_engine._whitelist_ips.discard(ip)
        ew = getattr(self.app, 'event_watcher', None)
        if ew and hasattr(ew, 'whitelist_ips'):
            ew.whitelist_ips.discard(ip)
        if auto_response:
            auto_response.whitelist_ips.discard(ip)

        self.show_toast("Whitelist",
                        self.t("toast_ip_removed_whitelist").format(ip=ip), "info")
        self._refresh_ip_table()

    def _create_stat_card(self, parent, emoji: str, label: str, value: str,
                         color: str, on_click=None) -> ctk.CTkFrame:
        """Tek bir istatistik kartı oluşturur. Opsiyonel on_click ile tıklanabilir."""
        card = ctk.CTkFrame(parent, fg_color=COLORS["bg"], corner_radius=10,
                            border_width=1, border_color=COLORS["border"])

        # Tıklanabilirlik — cursor + hover efekti
        if on_click:
            card.configure(cursor="hand2")

            def _on_enter(e):
                card.configure(border_color=COLORS["blue"])
            def _on_leave(e):
                card.configure(border_color=COLORS["border"])
            card.bind("<Enter>", _on_enter)
            card.bind("<Leave>", _on_leave)

        # Emoji
        emoji_lbl = ctk.CTkLabel(
            card, text=emoji, font=ctk.CTkFont(size=20),
        )
        emoji_lbl.pack(anchor="w", padx=12, pady=(10, 0))

        # Değer (büyük rakam)
        value_lbl = ctk.CTkLabel(
            card, text=value,
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=color,
        )
        value_lbl.pack(anchor="w", padx=12, pady=(2, 0))

        # Açıklama
        label_lbl = ctk.CTkLabel(
            card, text=label,
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"],
        )
        label_lbl.pack(anchor="w", padx=12, pady=(0, 2))

        # Tıkla göstergesi
        if on_click:
            hint_lbl = ctk.CTkLabel(
                card, text="🔍 " + self.t("card_click_detail"),
                font=ctk.CTkFont(size=9),
                text_color=COLORS["text_dim"],
            )
            hint_lbl.pack(anchor="w", padx=12, pady=(0, 6))
            # Click bind — card ve tüm child widget'lara
            for widget in [card, emoji_lbl, value_lbl, label_lbl, hint_lbl]:
                widget.bind("<Button-1>", lambda e, cb=on_click: cb())
        else:
            # Alt padding
            ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

        # value_lbl ve label_lbl referansları card objesine ekleniyor
        card._value_lbl = value_lbl  # type: ignore[attr-defined]
        card._label_lbl = label_lbl  # type: ignore[attr-defined]
        return card

    # ═══════════════════════════════════════════════════════════════
    #  DETAIL POPUP SİSTEMİ — Tıklanabilir Kart Detayları
    # ═══════════════════════════════════════════════════════════════

    def _show_detail_window(self, title: str, width: int = 620, height: int = 480) -> ctk.CTkToplevel:
        """Reusable detail popup penceresi oluşturur. İçerik eklenmek üzere döner."""
        popup = ctk.CTkToplevel(self.root)
        popup.title(title)
        popup.geometry(f"{width}x{height}")
        popup.configure(fg_color=COLORS["bg"])
        popup.transient(self.root)
        popup.attributes("-topmost", True)
        popup.grab_set()

        # Başlık bandı
        hdr = ctk.CTkFrame(popup, fg_color=COLORS["accent"], corner_radius=0, height=40)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr, text=f"  {title}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left", padx=8)
        ctk.CTkButton(
            hdr, text="✕", width=32, height=28,
            font=ctk.CTkFont(size=13), fg_color="transparent",
            hover_color=COLORS["red"], text_color=COLORS["text_bright"],
            command=popup.destroy,
        ).pack(side="right", padx=4)

        # Scrollable içerik alanı
        content = ctk.CTkScrollableFrame(popup, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=8, pady=8)
        popup._content = content  # type: ignore[attr-defined]
        return popup

    def _add_detail_table(self, parent, headers: list, rows: list,
                          col_widths: list = None, row_actions: list = None):
        """Detail popup'a tablo ekler. row_actions = [(text, color, callback), ...] per row."""
        if not col_widths:
            col_widths = [max(60, 500 // len(headers))] * len(headers)

        # Başlık satırı
        hdr_frame = ctk.CTkFrame(parent, fg_color=COLORS["accent"], corner_radius=6)
        hdr_frame.pack(fill="x", pady=(0, 4))
        for i, text in enumerate(headers):
            w = col_widths[i] if i < len(col_widths) else 100
            ctk.CTkLabel(
                hdr_frame, text=text, width=w, anchor="w",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=COLORS["text_bright"],
            ).pack(side="left", padx=4, pady=4)

        # Veri satırları
        for idx, row_data in enumerate(rows):
            bg = COLORS["card"] if idx % 2 == 0 else COLORS["bg"]
            row_frame = ctk.CTkFrame(parent, fg_color=bg, corner_radius=4)
            row_frame.pack(fill="x", pady=1)
            for i, cell in enumerate(row_data):
                w = col_widths[i] if i < len(col_widths) else 100
                color = COLORS["text"]
                # Renkli hücreler — özel prefix ile
                if isinstance(cell, tuple):
                    cell, color = cell
                ctk.CTkLabel(
                    row_frame, text=str(cell), width=w, anchor="w",
                    font=ctk.CTkFont(size=11),
                    text_color=color,
                ).pack(side="left", padx=4, pady=3)

            # Aksiyon butonları
            if row_actions and idx < len(row_actions):
                for btn_text, btn_color, btn_cmd in (row_actions[idx] or []):
                    ctk.CTkButton(
                        row_frame, text=btn_text, width=70, height=22,
                        font=ctk.CTkFont(size=9),
                        fg_color=btn_color, hover_color=btn_color,
                        text_color=COLORS["text_bright"], corner_radius=3,
                        command=btn_cmd,
                    ).pack(side="right", padx=2, pady=2)

    # ── Detail: Toplam Saldırılar ── #
    def _detail_total_attacks(self):
        """Toplam saldırı detay popup — threat engine'den en aktif IP'ler."""
        popup = self._show_detail_window(f"🎯 {self.t('dash_total_attacks')}")
        content = popup._content

        total = getattr(self.app, '_last_attack_count', 0) or 0
        ctk.CTkLabel(
            content, text=f"{self.t('dash_total_attacks')}: {total}",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLORS["red"],
        ).pack(anchor="w", padx=4, pady=(0, 8))

        # Top saldırgan IP'leri 
        threat_engine = getattr(self.app, 'threat_engine', None)
        if not threat_engine:
            ctk.CTkLabel(content, text=self.t("detail_no_data"),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return

        contexts = threat_engine.get_all_contexts()
        top_ips = sorted(
            [(ip, ctx) for ip, ctx in contexts.items()
             if ip not in ("local", "", "127.0.0.1", "::1") and ctx.failed_attempts > 0],
            key=lambda x: x[1].failed_attempts, reverse=True,
        )[:25]

        if not top_ips:
            ctk.CTkLabel(content, text=self.t("detail_no_attacks"),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return

        from datetime import datetime
        headers = ["IP", self.t("ip_col_service"), self.t("ip_col_attempts"),
                    self.t("detail_score"), self.t("ip_col_last_time")]
        rows = []
        actions = []
        for ip, ctx in top_ips:
            services = "/".join(list(ctx.services_targeted)[:2]) if ctx.services_targeted else "—"
            try:
                ts = datetime.fromtimestamp(ctx.last_seen).strftime("%d.%m %H:%M:%S")
            except Exception:
                ts = "—"
            score_color = COLORS["red"] if ctx.threat_score >= 80 else (
                COLORS["orange"] if ctx.threat_score >= 40 else COLORS["text_dim"])
            rows.append([ip, services, str(ctx.failed_attempts),
                         (str(ctx.threat_score), score_color), ts])
            # Engelle butonu
            _ip = ip
            actions.append([
                (self.t("ip_btn_block"), COLORS["red"],
                 lambda i=_ip: (self._ip_table_block(i), popup.destroy())),
            ])

        self._add_detail_table(content, headers, rows,
                               col_widths=[130, 70, 65, 55, 110], row_actions=actions)

    # ── Detail: Oturum Saldırıları ── #
    def _detail_session_attacks(self):
        """Oturumdaki saldırı detayları — servis bazlı credential yakalama istatistikleri."""
        popup = self._show_detail_window(f"⚡ {self.t('dash_session_attacks')}")
        content = popup._content

        sm = self.app.service_manager
        sess = sm.session_stats

        total = sess.get("total_credentials", 0)
        ctk.CTkLabel(
            content, text=f"{self.t('dash_session_attacks')}: {total}",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLORS["orange"],
        ).pack(anchor="w", padx=4, pady=(0, 8))

        # Servis bazlı istatistikler
        svc_stats = sess.get("per_service", {})
        if svc_stats:
            headers = [self.t("ip_col_service"), self.t("ip_col_attempts"),
                       self.t("detail_last_user"), self.t("ip_col_last_time")]
            rows = []
            for svc, data in svc_stats.items():
                count = data if isinstance(data, int) else data.get("count", 0)
                last_user = data.get("last_user", "—") if isinstance(data, dict) else "—"
                last_time = data.get("last_time", "—") if isinstance(data, dict) else "—"
                rows.append([svc.upper(), str(count), last_user, str(last_time)])
            self._add_detail_table(content, headers, rows,
                                   col_widths=[100, 80, 140, 130])

        # Son saldırılar listesi — threat feed'den son 20
        last_ip = sess.get("last_attacker_ip", "")
        last_svc = sess.get("last_service", "")
        if last_ip:
            ctk.CTkLabel(
                content,
                text=f"\n{self.t('detail_last_attacker')}: {last_ip} ({last_svc})",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLORS["red"],
            ).pack(anchor="w", padx=4, pady=(8, 4))

    # ── Detail: Aktif Servisler ── #
    def _detail_active_services(self):
        """Aktif honeypot servislerinin detayı."""
        popup = self._show_detail_window(f"🟢 {self.t('dash_active_services')}", height=350)
        content = popup._content

        sm = self.app.service_manager
        running = sm.running_services
        total = len(self.app.PORT_TABLOSU)

        ctk.CTkLabel(
            content,
            text=f"{self.t('dash_active_services')}: {len(running)}/{total}",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLORS["green"],
        ).pack(anchor="w", padx=4, pady=(0, 8))

        headers = [self.t("ip_col_service"), "Port", self.t("detail_status")]
        rows = []
        for port, svc in self.app.PORT_TABLOSU:
            is_active = svc.upper() in [s.upper() for s in running]
            status_text = self.t("status_running") if is_active else self.t("status_stopped")
            status_color = COLORS["green"] if is_active else COLORS["red"]
            rows.append([svc.upper(), str(port), (status_text, status_color)])
        self._add_detail_table(content, headers, rows, col_widths=[150, 80, 120])

    # ── Detail: Son Saldırı ── #
    def _detail_last_attack(self):
        """Son saldırı detayı — en son saldıranın tam profili."""
        popup = self._show_detail_window(f"🕵️ {self.t('dash_last_attack')}", height=400)
        content = popup._content

        threat_engine = getattr(self.app, 'threat_engine', None)
        if not threat_engine:
            ctk.CTkLabel(content, text=self.t("detail_no_data"),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return

        latest = threat_engine.get_last_attacker()
        if not latest:
            ctk.CTkLabel(content, text=self.t("dash_no_attack"),
                         font=ctk.CTkFont(size=14),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return

        from datetime import datetime
        ip = latest.get("ip", "—")
        score = latest.get("threat_score", 0)
        fails = latest.get("failed_attempts", 0)
        logins = latest.get("successful_logins", 0)
        services = ", ".join(latest.get("services", []))
        try:
            ts = datetime.fromtimestamp(latest["last_seen"]).strftime("%d.%m.%Y %H:%M:%S")
        except Exception:
            ts = "—"

        info_lines = [
            (f"IP: {ip}", COLORS["red"]),
            (f"Threat Score: {score}", COLORS["orange"] if score >= 40 else COLORS["text"]),
            (f"{self.t('ip_col_attempts')}: {fails}", COLORS["text"]),
            (f"Successful Logins: {logins}", COLORS["red"] if logins > 0 else COLORS["text"]),
            (f"{self.t('ip_col_service')}: {services}", COLORS["text"]),
            (f"{self.t('ip_col_last_time')}: {ts}", COLORS["text_dim"]),
        ]
        for text, color in info_lines:
            ctk.CTkLabel(
                content, text=text, font=ctk.CTkFont(size=13),
                text_color=color,
            ).pack(anchor="w", padx=8, pady=2)

        # Aksiyon butonları
        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(fill="x", padx=8, pady=(12, 4))
        ctk.CTkButton(
            btn_frame, text=f"🚫 {self.t('ip_btn_block')} {ip}",
            width=160, height=32, font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=COLORS["red"], hover_color=COLORS["red_hover"],
            command=lambda: (self._ip_table_block(ip), popup.destroy()),
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            btn_frame, text=f"✅ {self.t('ip_btn_whitelist')} {ip}",
            width=160, height=32, font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=COLORS["green"], hover_color=COLORS["green_hover"],
            command=lambda: (self._ip_table_whitelist(ip), popup.destroy()),
        ).pack(side="left", padx=4)

    # ── Detail: API Sağlık Durumu ── #
    def _detail_api_health(self):
        """API bağlantı sağlık detayları."""
        popup = self._show_detail_window(f"🌐 {self.t('detail_api_health')}", height=400)
        content = popup._content

        api_ok = getattr(self.app, '_last_api_ok', False)
        status_text = self.t("dash_connected") if api_ok else self.t("dash_disconnected")
        status_color = COLORS["green"] if api_ok else COLORS["red"]

        ctk.CTkLabel(
            content,
            text=f"API: {status_text}",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=status_color,
        ).pack(anchor="w", padx=8, pady=(0, 8))

        # API istatistikleri — client_api istatistikleri
        api_client = getattr(self.app, 'api_client', None)
        base_url = api_client.base_url if api_client else "—"

        info_items = [
            (f"Base URL: {base_url}", COLORS["text"]),
            (f"Token: {self.app.state.get('token', '—')[:20]}...", COLORS["text_dim"]),
        ]

        # Heartbeat durumu
        hb_ok = getattr(self.app, '_last_heartbeat_ok', None)
        if hb_ok is not None:
            hb_text = "✅ OK" if hb_ok else "❌ FAIL"
            hb_color = COLORS["green"] if hb_ok else COLORS["red"]
            info_items.append((f"Heartbeat: {hb_text}", hb_color))

        # Alert pipeline istatistikleri
        alert_pipeline = getattr(self.app, 'alert_pipeline', None)
        if alert_pipeline:
            try:
                al_stats = alert_pipeline.get_stats()
                sent = al_stats.get("total_sent", 0)
                failed = al_stats.get("total_failed", 0)
                dedup = al_stats.get("dedup_table_size", 0)
                info_items.append((f"Alerts Sent: {sent}", COLORS["green"] if sent > 0 else COLORS["text_dim"]))
                info_items.append((f"Alerts Failed: {failed}", COLORS["red"] if failed > 0 else COLORS["text_dim"]))
                info_items.append((f"Dedup Table: {dedup}", COLORS["text_dim"]))
            except Exception:
                pass

        # MemoryGuard
        mem_guard = getattr(self.app, 'memory_guard', None)
        if mem_guard:
            try:
                import psutil
                proc = psutil.Process()
                mem_mb = proc.memory_info().rss / (1024 * 1024)
                info_items.append((f"Client RAM: {mem_mb:.0f} MB", 
                                   COLORS["red"] if mem_mb > 500 else COLORS["text"]))
            except Exception:
                pass

        for text, color in info_items:
            ctk.CTkLabel(
                content, text=text, font=ctk.CTkFont(size=12),
                text_color=color,
            ).pack(anchor="w", padx=8, pady=2)

        # Bağlantı testi butonu
        def _test_api():
            def _do():
                try:
                    ok = api_client.check_connection(max_attempts=1, delay=0) if api_client else False
                    def _show():
                        if ok:
                            self.show_toast("API", self.t("detail_api_ok"), "info")
                        else:
                            self.show_toast("API", self.t("detail_api_fail"), "warning")
                    self._gui_safe(_show)
                except Exception:
                    pass
            threading.Thread(target=_do, daemon=True).start()

        ctk.CTkButton(
            content, text=f"🔄 {self.t('detail_test_connection')}",
            width=200, height=32, font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=COLORS["blue"], hover_color=COLORS["blue_hover"],
            command=_test_api,
        ).pack(anchor="w", padx=8, pady=(12, 4))

    # ── Detail: Ransomware Shield ── #
    def _detail_ransomware(self):
        """Ransomware shield detayları — tespit edilen olaylar + aksiyon butonları."""
        popup = self._show_detail_window(f"🧬 {self.t('card_ransomware')}", height=520)
        content = popup._content

        rs = getattr(self.app, 'ransomware_shield', None)
        if not rs:
            ctk.CTkLabel(content, text=self.t("detail_no_data"),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return

        stats = rs.get_stats()
        running = stats.get("running", False)
        canary_alerts = stats.get("canary_alerts", 0)
        fs_alerts = stats.get("fs_alerts", 0)
        process_alerts = stats.get("process_alerts", 0)
        vss_alerts = stats.get("vss_alerts", 0)
        total_alerts = stats.get("alerts_total", 0)
        canary_files = stats.get("canary_files", 0)

        status_text = "🟢 ACTIVE" if running else "🔴 OFF"
        status_color = COLORS["green"] if running else COLORS["red"]

        ctk.CTkLabel(
            content, text=f"Ransomware Shield: {status_text}",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=status_color,
        ).pack(anchor="w", padx=8, pady=(0, 4))

        # Özet istatistikler
        summary_items = [
            (f"📁 Canary Files: {canary_files}", COLORS["text"]),
            (f"🚨 {self.t('detail_rs_canary')}: {canary_alerts}",
             COLORS["red"] if canary_alerts > 0 else COLORS["text_dim"]),
            (f"📂 {self.t('detail_rs_filesystem')}: {fs_alerts}",
             COLORS["red"] if fs_alerts > 0 else COLORS["text_dim"]),
            (f"⚙️ {self.t('detail_rs_process')}: {process_alerts}",
             COLORS["red"] if process_alerts > 0 else COLORS["text_dim"]),
            (f"💾 {self.t('detail_rs_vss')}: {vss_alerts}",
             COLORS["red"] if vss_alerts > 0 else COLORS["text_dim"]),
            (f"📊 {self.t('detail_rs_total')}: {total_alerts}",
             COLORS["orange"] if total_alerts > 0 else COLORS["text_dim"]),
        ]
        for text, color in summary_items:
            ctk.CTkLabel(content, text=text, font=ctk.CTkFont(size=12),
                         text_color=color).pack(anchor="w", padx=8, pady=1)

        # Tespit edilen olaylar — detay tablosu
        detections = rs.get_detections()
        if detections:
            ctk.CTkLabel(
                content,
                text=f"\n🔍 {self.t('detail_rs_detections')} ({len(detections)}):",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=COLORS["orange"],
            ).pack(anchor="w", padx=8, pady=(8, 4))

            for det in detections[-20:]:  # Son 20 tespit
                det_type = det.get("type", "unknown")
                ts = det.get("timestamp", "—")
                score = det.get("threat_score", 0)
                score_color = COLORS["red"] if score >= 80 else (
                    COLORS["orange"] if score >= 50 else COLORS["text_dim"])

                det_frame = ctk.CTkFrame(content, fg_color=COLORS["card"], corner_radius=6)
                det_frame.pack(fill="x", padx=8, pady=2)

                if det_type == "canary_triggered":
                    file_path = det.get("file", "—")
                    change = det.get("change", "—")
                    text = f"🚨 CANARY: {os.path.basename(file_path)} — {change}"
                elif det_type == "suspicious_process":
                    pname = det.get("process", "—")
                    pid = det.get("pid", 0)
                    reason = det.get("reason", "—")
                    text = f"⚙️ PROCESS: {pname} (PID {pid}) — {reason}"
                elif det_type == "vss_deletion":
                    text = f"💾 VSS: {det.get('details', 'Shadow copy deletion detected')}"
                else:
                    text = f"📂 {det_type}: {det.get('details', str(det))}"

                ctk.CTkLabel(
                    det_frame, text=text, font=ctk.CTkFont(size=11),
                    text_color=COLORS["text"], wraplength=550,
                ).pack(side="left", anchor="w", padx=8, pady=4, fill="x", expand=True)

                ctk.CTkLabel(
                    det_frame, text=f"Score: {score}",
                    font=ctk.CTkFont(size=10, weight="bold"),
                    text_color=score_color, width=65,
                ).pack(side="right", padx=4)

                # Süreç durdurma butonu (process tespitleri için)
                if det_type == "suspicious_process" and det.get("pid"):
                    pid = det["pid"]
                    pname = det.get("process", "")
                    ctk.CTkButton(
                        det_frame, text=self.t("detail_kill_process"),
                        width=70, height=20, font=ctk.CTkFont(size=9),
                        fg_color=COLORS["red"], hover_color=COLORS["red_hover"],
                        command=lambda p=pid, n=pname: self._kill_process(p, n),
                    ).pack(side="right", padx=2)
        else:
            ctk.CTkLabel(
                content,
                text=f"\n✅ {self.t('detail_rs_no_detections')}",
                font=ctk.CTkFont(size=13),
                text_color=COLORS["green"],
            ).pack(anchor="w", padx=8, pady=(8, 4))

    # ── Detail: CPU / RAM ── #
    def _detail_cpu_ram(self):
        """CPU ve RAM kullanım detayları + en çok kaynak kullanan süreçler."""
        popup = self._show_detail_window(f"💻 {self.t('card_cpu_ram')}", height=480)
        content = popup._content

        import psutil

        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("C:\\")

        ctk.CTkLabel(
            content,
            text=f"CPU: {cpu:.1f}%  |  RAM: {mem.percent:.1f}%  |  Disk: {disk.percent:.1f}%",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLORS["orange"] if cpu > 70 or mem.percent > 80 else COLORS["green"],
        ).pack(anchor="w", padx=8, pady=(0, 4))

        info = [
            (f"RAM: {mem.used / (1024**3):.1f} GB / {mem.total / (1024**3):.1f} GB", COLORS["text"]),
            (f"Disk: {disk.used / (1024**3):.0f} GB / {disk.total / (1024**3):.0f} GB", COLORS["text"]),
            (f"CPU Cores: {psutil.cpu_count(logical=True)}", COLORS["text_dim"]),
        ]
        for text, color in info:
            ctk.CTkLabel(content, text=text, font=ctk.CTkFont(size=12),
                         text_color=color).pack(anchor="w", padx=8, pady=1)

        # Client process memory
        proc = psutil.Process()
        client_mem = proc.memory_info().rss / (1024 * 1024)
        client_color = COLORS["red"] if client_mem > 500 else (
            COLORS["orange"] if client_mem > 200 else COLORS["green"])
        ctk.CTkLabel(
            content,
            text=f"Honeypot Client RAM: {client_mem:.0f} MB",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=client_color,
        ).pack(anchor="w", padx=8, pady=(4, 8))

        # Top süreçler
        ctk.CTkLabel(
            content,
            text=f"🔝 {self.t('detail_top_processes')}:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=8, pady=(4, 4))

        processes = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
            try:
                pinfo = p.info
                mem_mb = pinfo['memory_info'].rss / (1024 * 1024) if pinfo.get('memory_info') else 0
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'] or '—',
                    'cpu': pinfo.get('cpu_percent', 0) or 0,
                    'mem_mb': mem_mb,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # RAM'e göre sırala
        top_procs = sorted(processes, key=lambda p: p['mem_mb'], reverse=True)[:15]

        headers = ["PID", self.t("detail_process_name"), "CPU %", "RAM (MB)"]
        rows = []
        actions = []
        for p in top_procs:
            cpu_color = COLORS["red"] if p['cpu'] > 50 else COLORS["text"]
            mem_color = COLORS["orange"] if p['mem_mb'] > 200 else COLORS["text"]
            rows.append([
                str(p['pid']), p['name'],
                (f"{p['cpu']:.1f}", cpu_color),
                (f"{p['mem_mb']:.0f}", mem_color),
            ])
            actions.append([
                (self.t("detail_kill_process"), COLORS["red"],
                 lambda pid=p['pid'], name=p['name']: self._kill_process(pid, name)),
            ])

        self._add_detail_table(content, headers, rows,
                               col_widths=[60, 200, 65, 80], row_actions=actions)

    # ── Detail: Self-Protection ── #
    def _detail_self_protect(self):
        """Self-protection durumu detayları."""
        popup = self._show_detail_window(f"🔒 {self.t('card_protection')}", height=300)
        content = popup._content

        pp = getattr(self.app, 'process_protection', None)
        if pp:
            ctk.CTkLabel(content, text=f"🔒 {self.t('card_protection')}: ACTIVE",
                         font=ctk.CTkFont(size=16, weight="bold"),
                         text_color=COLORS["green"]).pack(anchor="w", padx=8, pady=(0, 4))
            ctk.CTkLabel(content, text=self.t("detail_sp_desc"),
                         font=ctk.CTkFont(size=12),
                         text_color=COLORS["text"]).pack(anchor="w", padx=8, pady=2)
        else:
            ctk.CTkLabel(content, text=f"🔒 {self.t('card_protection')}: OFF",
                         font=ctk.CTkFont(size=16, weight="bold"),
                         text_color=COLORS["red"]).pack(anchor="w", padx=8, pady=(0, 4))

        # MemoryGuard durumu
        mg = getattr(self.app, 'memory_guard', None)
        if mg:
            ctk.CTkLabel(content, text=f"\n🧠 MemoryGuard: ACTIVE",
                         font=ctk.CTkFont(size=13, weight="bold"),
                         text_color=COLORS["green"]).pack(anchor="w", padx=8, pady=(4, 2))
            try:
                import psutil
                client_mem = psutil.Process().memory_info().rss / (1024 * 1024)
                ctk.CTkLabel(content, text=f"Current: {client_mem:.0f} MB",
                             font=ctk.CTkFont(size=12),
                             text_color=COLORS["text"]).pack(anchor="w", padx=8, pady=1)
            except Exception:
                pass

    # ── Detail: Threat Level ── #
    def _detail_threat_level(self):
        """Tehdit seviyesi detayı — en yüksek skorlu IP'ler."""
        popup = self._show_detail_window(f"🛡️ {self.t('card_threat_level')}")
        content = popup._content

        threat_engine = getattr(self.app, 'threat_engine', None)
        if not threat_engine:
            ctk.CTkLabel(content, text=self.t("detail_no_data"),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return

        level, level_color = threat_engine.get_threat_level()
        ctk.CTkLabel(
            content,
            text=f"{self.t('card_threat_level')}: {level}",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=level_color,
        ).pack(anchor="w", padx=8, pady=(0, 8))

        # Son tehditler (yüksek skor)
        recent = threat_engine.get_recent_threats(max_age_seconds=3600, min_score=20)
        if recent:
            from datetime import datetime
            headers = ["IP", self.t("detail_score"), self.t("ip_col_attempts"),
                       self.t("ip_col_service"), self.t("ip_col_last_time")]
            rows = []
            actions = []
            for t in recent[:20]:
                score_color = COLORS["red"] if t["threat_score"] >= 80 else (
                    COLORS["orange"] if t["threat_score"] >= 40 else COLORS["text_dim"])
                services = "/".join(t.get("services", [])[:2])
                try:
                    ts = datetime.fromtimestamp(t["last_seen"]).strftime("%d.%m %H:%M")
                except Exception:
                    ts = "—"
                rows.append([t["ip"], (str(t["threat_score"]), score_color),
                             str(t["failed_attempts"]), services, ts])
                _ip = t["ip"]
                actions.append([
                    (self.t("ip_btn_block"), COLORS["red"],
                     lambda i=_ip: (self._ip_table_block(i), popup.destroy())),
                ])
            self._add_detail_table(content, headers, rows,
                                   col_widths=[130, 55, 65, 80, 100], row_actions=actions)
        else:
            ctk.CTkLabel(content, text=f"✅ {self.t('detail_no_threats')}",
                         font=ctk.CTkFont(size=13),
                         text_color=COLORS["green"]).pack(anchor="w", padx=8, pady=8)

    # ── Detail: Olaylar/Saat ── #
    def _detail_events_per_hour(self):
        """Olay/saat detayı — ThreatEngine istatistikleri."""
        popup = self._show_detail_window(f"📊 {self.t('card_events_per_hour')}", height=350)
        content = popup._content

        threat_engine = getattr(self.app, 'threat_engine', None)
        if not threat_engine:
            ctk.CTkLabel(content, text=self.t("detail_no_data"),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return

        stats = threat_engine.get_stats()
        events_scored = stats.get("events_scored", 0)
        uptime_sec = int(time.time() - self._start_time) or 1
        eph = int(events_scored / (uptime_sec / 3600)) if uptime_sec > 60 else 0

        ctk.CTkLabel(
            content,
            text=f"{self.t('card_events_per_hour')}: {eph}",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=COLORS["orange"] if eph > 100 else COLORS["text"],
        ).pack(anchor="w", padx=8, pady=(0, 8))

        info = [
            (f"{self.t('detail_events_total')}: {events_scored}", COLORS["text"]),
            (f"{self.t('detail_events_blocked')}: {stats.get('ips_blocked', 0)}", COLORS["red"]),
            (f"Uptime: {self._format_uptime(uptime_sec)}", COLORS["text_dim"]),
            (f"Active IPs: {stats.get('active_ips', 0)}", COLORS["text"]),
        ]
        for text, color in info:
            ctk.CTkLabel(content, text=text, font=ctk.CTkFont(size=12),
                         text_color=color).pack(anchor="w", padx=8, pady=2)

    # ── Detail: Engellenen IP'ler ── #
    def _detail_blocked_ips(self):
        """Engellenen/takip edilen IP detayları — tam liste."""
        popup = self._show_detail_window(f"🚫 {self.t('card_tracked_ips')}", height=520)
        content = popup._content

        threat_engine = getattr(self.app, 'threat_engine', None)
        if not threat_engine:
            ctk.CTkLabel(content, text=self.t("detail_no_data"),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=4)
            return

        contexts = threat_engine.get_all_contexts()
        blocked = getattr(threat_engine, '_rule_blocked_ips', set())

        active_ips = [(ip, ctx) for ip, ctx in contexts.items()
                      if ip not in ("local", "", "127.0.0.1", "::1")
                      and (ctx.threat_score > 0 or ctx.failed_attempts > 0)]

        blocked_count = sum(1 for ip, ctx in active_ips if ip in blocked or ctx.is_blocked)
        watching_count = len(active_ips) - blocked_count

        ctk.CTkLabel(
            content,
            text=f"{self.t('detail_blocked_count')}: {blocked_count}  |  "
                 f"{self.t('detail_watching_count')}: {watching_count}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["orange"],
        ).pack(anchor="w", padx=8, pady=(0, 8))

        if not active_ips:
            ctk.CTkLabel(content, text=self.t("ip_no_activity"),
                         text_color=COLORS["text_dim"]).pack(anchor="w", padx=8)
            return

        from datetime import datetime
        sorted_ips = sorted(active_ips, key=lambda x: x[1].last_seen, reverse=True)[:30]

        headers = ["IP", self.t("ip_col_status"), self.t("detail_score"),
                    self.t("ip_col_attempts"), self.t("ip_col_last_time")]
        rows = []
        actions = []
        for ip, ctx in sorted_ips:
            is_blocked = ip in blocked or ctx.is_blocked
            status = (self.t("ip_status_blocked"), COLORS["red"]) if is_blocked else \
                     (self.t("ip_status_watching"), COLORS["orange"])
            score_color = COLORS["red"] if ctx.threat_score >= 80 else (
                COLORS["orange"] if ctx.threat_score >= 40 else COLORS["text_dim"])
            try:
                ts = datetime.fromtimestamp(ctx.last_seen).strftime("%d.%m %H:%M")
            except Exception:
                ts = "—"
            rows.append([ip, status, (str(ctx.threat_score), score_color),
                         str(ctx.failed_attempts), ts])
            _ip = ip
            if is_blocked:
                actions.append([
                    (self.t("ip_btn_unblock"), COLORS["orange"],
                     lambda i=_ip: (self._ip_table_unblock(i), popup.destroy())),
                ])
            else:
                actions.append([
                    (self.t("ip_btn_block"), COLORS["red"],
                     lambda i=_ip: (self._ip_table_block(i), popup.destroy())),
                ])

        self._add_detail_table(content, headers, rows,
                               col_widths=[130, 80, 55, 65, 90], row_actions=actions)

    # ── Süreç Durdurma (Process Kill) ── #
    def _kill_process(self, pid: int, name: str = ""):
        """Belirtilen PID'li süreci durdur."""
        import tkinter.messagebox as mbox
        ok = mbox.askyesno(
            self.t("detail_kill_confirm_title"),
            self.t("detail_kill_confirm_msg").format(name=name, pid=pid),
        )
        if not ok:
            return
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.terminate()
            # 3 saniye bekle, hala yaşıyorsa kill
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
            self.show_toast(
                self.t("detail_process_killed"),
                self.t("detail_process_killed_msg").format(name=name, pid=pid),
                "high",
            )
        except psutil.NoSuchProcess:
            self.show_toast(self.t("detail_process_not_found"),
                            f"PID {pid}", "warning")
        except psutil.AccessDenied:
            self.show_toast(self.t("detail_process_access_denied"),
                            f"{name} (PID {pid})", "warning")
        except Exception as e:
            self.show_toast(self.t("error"), str(e), "warning")

    # ─── Command History Panel (v4.0 Faz 4) ─── #
    def _build_command_history(self, parent):
        """Scrollable command execution history — last 50 remote commands & results."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            sec, text=self.t("section_command_history"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=16, pady=(12, 4))

        self._cmd_history_box = ctk.CTkTextbox(
            sec, height=100, fg_color=COLORS["bg"],
            border_width=1, border_color=COLORS["border"],
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS["text_dim"],
            state="disabled", wrap="word",
        )
        self._cmd_history_box.pack(fill="x", padx=16, pady=(0, 12))

        # Placeholder
        self._cmd_history_box.configure(state="normal")
        self._cmd_history_box.insert("1.0", self.t("placeholder_command_history"))
        self._cmd_history_box.configure(state="disabled")
        self._cmd_history_has_data = False

    def append_command_history(self, text: str):
        """Append a line to command history (thread-safe)."""
        def _do():
            try:
                if not hasattr(self, '_cmd_history_box'):
                    return
                self._cmd_history_box.configure(state="normal")
                # İlk gerçek veri geldiğinde placeholder'ı temizle
                if not getattr(self, '_cmd_history_has_data', False):
                    self._cmd_history_box.delete("1.0", "end")
                    self._cmd_history_has_data = True
                self._cmd_history_box.insert("end", text + "\n")
                self._cmd_history_box.see("end")
                content = self._cmd_history_box.get("1.0", "end")
                lines = content.splitlines()
                if len(lines) > 50:
                    self._cmd_history_box.delete("1.0", f"{len(lines)-50}.0")
                self._cmd_history_box.configure(state="disabled")
            except Exception:
                pass
        if self.root:
            self.root.after(0, _do)

    # ─── Active Sessions Panel (v4.0 Faz 4) ─── #
    def _build_active_sessions(self, parent):
        """Active RDP/console sessions display with refresh button."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        hdr = ctk.CTkFrame(sec, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            hdr, text=self.t("section_active_sessions"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(side="left")

        ctk.CTkButton(
            hdr, text="🔄", width=28, height=22,
            font=ctk.CTkFont(size=11),
            fg_color=COLORS.get("bg", "#1a1b2e"),
            border_width=1, border_color=COLORS["border"],
            hover_color="#2a2b3e",
            command=self._refresh_active_sessions,
        ).pack(side="right")

        self._sessions_box = ctk.CTkTextbox(
            sec, height=80, fg_color=COLORS["bg"],
            border_width=1, border_color=COLORS["border"],
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS["text_dim"],
            state="disabled", wrap="word",
        )
        self._sessions_box.pack(fill="x", padx=16, pady=(0, 12))

        # Placeholder + otomatik yükle
        self._sessions_box.configure(state="normal")
        self._sessions_box.insert("1.0", self.t("loading_sessions"))
        self._sessions_box.configure(state="disabled")
        # Başlangıçta otomatik yükle
        self._refresh_active_sessions()

    def _refresh_active_sessions(self):
        """Fetch and display active sessions via 'query user' + 'query session'."""
        import subprocess
        CREATE_NW = 0x08000000

        def _do():
            lines = []
            try:
                # query user — RDP/console oturumlarını gösterir
                r1 = subprocess.run(
                    ["query", "user"],
                    capture_output=True, text=True, timeout=5,
                    creationflags=CREATE_NW,
                )
                raw = (r1.stdout or "").strip()
                if raw:
                    # Parse query user output into Turkish-friendly format
                    for line in raw.splitlines():
                        parts = line.split()
                        if not parts:
                            continue
                        # Header line
                        if parts[0].upper() in ("USERNAME", "KULLANICI"):
                            lines.append("  " + self.t("sessions_header"))
                            lines.append("  " + "─" * 60)
                            continue
                        # Data line — may start with > for current user
                        marker = ""
                        if parts[0].startswith(">"):
                            parts[0] = parts[0][1:]
                            marker = "► "
                        username = parts[0] if len(parts) > 0 else ""
                        session = parts[1] if len(parts) > 1 else ""
                        sess_id = parts[2] if len(parts) > 2 else ""
                        state = parts[3] if len(parts) > 3 else ""
                        # Logon time is typically the last 2 parts
                        logon = " ".join(parts[-2:]) if len(parts) >= 6 else ""
                        state_tr = self.t("session_active") if state.lower() == "active" else (
                            self.t("session_disconnected") if state.lower() == "disc" else state)
                        icon = "🟢" if state.lower() == "active" else "🔴"
                        lines.append(
                            f"  {marker}{icon} {username:<18} {session:<13} {state_tr:<12} {logon}"
                        )
            except Exception:
                pass

            if not lines:
                # Fallback: query session
                try:
                    r2 = subprocess.run(
                        ["query", "session"],
                        capture_output=True, text=True, timeout=5,
                        creationflags=CREATE_NW,
                    )
                    if (r2.stdout or "").strip():
                        lines = ["  " + l for l in r2.stdout.strip().splitlines()]
                except Exception:
                    pass

            output = "\n".join(lines) if lines else self.t("sessions_none")

            def _update():
                try:
                    if hasattr(self, '_sessions_box'):
                        self._sessions_box.configure(state="normal")
                        self._sessions_box.delete("1.0", "end")
                        self._sessions_box.insert("1.0", output)
                        self._sessions_box.configure(state="disabled")
                except Exception:
                    pass
            if self.root:
                self.root.after(0, _update)

        import threading as _th
        _th.Thread(target=_do, daemon=True).start()

    # ─── Trend Mini-Charts (v4.0 Faz 4) ─── #
    def _build_trend_panel(self, parent):
        """ASCII-style trend mini-charts for CPU, events/hour, and threat score."""
        sec = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12)
        sec.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(
            sec, text=self.t("section_trends"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_bright"],
        ).pack(anchor="w", padx=16, pady=(12, 4))

        self._trend_box = ctk.CTkTextbox(
            sec, height=80, fg_color=COLORS["bg"],
            border_width=1, border_color=COLORS["border"],
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS["text_dim"],
            state="disabled", wrap="none",
        )
        self._trend_box.pack(fill="x", padx=16, pady=(0, 12))

    def _refresh_trend_panel(self):
        """Update trend mini-charts with ASCII sparklines."""
        try:
            perf = getattr(self.app, 'perf_optimizer', None)
            if not perf or not hasattr(perf, 'get_trend_data'):
                return

            data = perf.get_trend_data(30)
            if not data:
                return

            # Build ASCII sparklines
            bars = " ▁▂▃▄▅▆▇█"

            def sparkline(values, max_val=None):
                if not values:
                    return ""
                if max_val is None:
                    max_val = max(values) if max(values) > 0 else 1
                return "".join(bars[min(8, int(v / max_val * 8))] for v in values)

            cpus = [d["cpu"] for d in data]
            mems = [d["mem"] for d in data]
            eps_vals = [d["eps"] for d in data]

            cpu_spark = sparkline(cpus, 100)
            mem_spark = sparkline(mems, 100)
            eps_spark = sparkline(eps_vals)

            cpu_now = f"{cpus[-1]:.0f}%" if cpus else "—"
            mem_now = f"{mems[-1]:.0f}%" if mems else "—"
            eps_now = f"{eps_vals[-1]:.1f}" if eps_vals else "—"

            text = (
                f"CPU  {cpu_spark}  {cpu_now}\n"
                f"RAM  {mem_spark}  {mem_now}\n"
                f"E/s  {eps_spark}  {eps_now}"
            )

            if hasattr(self, '_trend_box'):
                self._trend_box.configure(state="normal")
                self._trend_box.delete("1.0", "end")
                self._trend_box.insert("1.0", text)
                self._trend_box.configure(state="disabled")

        except Exception:
            pass

    # ─── Dashboard Refresh ─── #
    def _schedule_dashboard_refresh(self):
        """Her 5 saniyede bir dashboard kartlarını günceller."""
        self._refresh_dashboard()

        # IP tablosunu her 10 saniyede bir güncelle (2 × 5s)
        if not hasattr(self, '_ip_table_tick'):
            self._ip_table_tick = 0
        self._ip_table_tick += 1
        if self._ip_table_tick >= 2:
            self._ip_table_tick = 0
            self._refresh_ip_table()

        # Security intel panellerini her 60 saniyede bir güncelle (12 × 5s)
        if not hasattr(self, '_security_tick'):
            self._security_tick = 0
        self._security_tick += 1
        if self._security_tick >= 12:
            self._security_tick = 0
            self._refresh_security_intel()

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

            # 5) Son saldırı zamanı — honeypot credential + threat engine birleştir
            last_ts = sess.get("last_attack_ts")
            last_ip = sess.get("last_attacker_ip", "")
            last_svc = sess.get("last_service", "")

            # Threat Engine'den en son saldıranı al
            threat_engine = getattr(self.app, 'threat_engine', None)
            if threat_engine:
                try:
                    latest = threat_engine.get_last_attacker()
                    if latest:
                        te_ts = latest.get("last_seen", 0)
                        if not last_ts or te_ts > last_ts:
                            last_ts = te_ts
                            last_ip = latest.get("ip", "")
                            svcs = latest.get("services", [])
                            last_svc = svcs[0] if svcs else "SCAN"
                except Exception:
                    pass

            if last_ts:
                ago_sec = time.time() - last_ts
                ago = self._format_ago(ago_sec)
                if last_ip:
                    display = f"{last_ip} ({last_svc})"
                else:
                    display = ago
                color = COLORS["red"] if ago_sec < 300 else (
                    COLORS["orange"] if ago_sec < 3600 else COLORS["text_dim"])
                self._update_card("last_attack", display, color,
                                  label=f"{self.t('dash_last_attack')} — {ago}")
            else:
                self._update_card("last_attack", self.t("dash_no_attack"), COLORS["text_dim"])

            # 6) API bağlantı durumu (gerçek zamanlı kontrol)
            api_ok = getattr(self.app, '_last_api_ok', False)
            if api_ok:
                self._update_card("connection", self.t("dash_connected"), COLORS["green"])
            else:
                self._update_card("connection", self.t("dash_disconnected"), COLORS["red"])

            # 7) Threat Detection cards (v4.0)
            threat_engine = getattr(self.app, 'threat_engine', None)
            if threat_engine:
                try:
                    level, level_color = threat_engine.get_threat_level()
                    self._update_card("threat_level", level, level_color)

                    engine_stats = threat_engine.get_stats()
                    events_scored = engine_stats.get("events_scored", 0)
                    uptime_sec = int(time.time() - self._start_time) or 1
                    events_per_hour = int(events_scored / (uptime_sec / 3600)) if uptime_sec > 60 else 0
                    eph_color = COLORS["red"] if events_per_hour > 100 else (
                        COLORS["orange"] if events_per_hour > 20 else COLORS["text_dim"])
                    self._update_card("events_per_hour", str(events_per_hour), eph_color)

                    active_ips = engine_stats.get("active_ips", 0)
                    blocked_color = COLORS["red"] if active_ips > 5 else (
                        COLORS["orange"] if active_ips > 0 else COLORS["text_dim"])
                    self._update_card("blocked_ips", str(active_ips), blocked_color)
                except Exception:
                    pass

            # 8) Silent Hours status (v4.0 Faz 2)
            sh_guard = getattr(self.app, 'silent_hours_guard', None)
            if sh_guard and hasattr(self, '_silent_hours_label'):
                try:
                    if sh_guard.is_silent_now():
                        self._silent_hours_label.configure(
                            text=self.t("status_silent_hours_active"),
                            text_color=COLORS["orange"],
                        )
                    else:
                        self._silent_hours_label.configure(
                            text=self.t("status_normal_hours"),
                            text_color=COLORS["text_dim"],
                        )
                except Exception:
                    pass

            # 9) Ransomware Shield status (v4.0 Faz 3)
            rs = getattr(self.app, 'ransomware_shield', None)
            if rs:
                try:
                    rs_stats = rs.get_stats() if hasattr(rs, 'get_stats') else {}
                    rs_running = rs_stats.get("running", False)
                    rs_alerts = rs_stats.get("alerts_total", 0)
                    if rs_alerts > 0:
                        self._update_card("ransomware", f"⚠ {rs_alerts}", COLORS["red"])
                    elif rs_running:
                        self._update_card("ransomware", "SAFE", COLORS["green"])
                    else:
                        self._update_card("ransomware", "OFF", COLORS["text_dim"])
                except Exception:
                    pass

            # 10) CPU / RAM usage (v4.0 Faz 3)
            hm = getattr(self.app, 'health_monitor', None)
            if hm:
                try:
                    snap = hm.get_snapshot() if hasattr(hm, 'get_snapshot') else {}
                    cpu = snap.get("cpu_percent", 0)
                    ram = snap.get("memory_percent", 0)
                    cpu_color = COLORS["red"] if cpu > 90 else (
                        COLORS["orange"] if cpu > 70 else COLORS["text_dim"])
                    self._update_card("cpu_usage", f"{cpu:.0f}% / {ram:.0f}%", cpu_color)
                except Exception:
                    pass

            # 11) Self-Protection status (v4.0 Faz 3)
            pp = getattr(self.app, 'process_protection', None)
            if pp:
                try:
                    self._update_card("self_protect", "ACTIVE", COLORS["green"])
                except Exception:
                    pass
            else:
                self._update_card("self_protect", "OFF", COLORS["text_dim"])

            # 12) Trend mini-charts (v4.0 Faz 4)
            self._refresh_trend_panel()

            # 13) Performance throttle info (v4.0 Faz 4)
            perf = getattr(self.app, 'perf_optimizer', None)
            if perf:
                try:
                    ps = perf.get_stats()
                    mode = ps.get("throttle_mode", "NORMAL")
                    if mode == "CRITICAL":
                        self.append_threat_feed(
                            f"⚠️ PERF: Throttle mode CRITICAL — CPU/RAM high"
                        )
                except Exception:
                    pass

            # Header badge senkronizasyonu
            self.update_header_status(active_count > 0)

        except Exception:
            pass

    # _update_tab_badges kaldırıldı — CTkTabview tab isimlerini runtime'da
    # değiştirmek (rename, dict key update vb.) segmented button click
    # callback'lerini bozuyor. Tab isimleri artık sabit.

    def _start_pulse_blink(self):
        """Header pulse dot'u 800ms aralıkla yanıp söndürür."""
        def _blink():
            try:
                if not self.root or not self.root.winfo_exists():
                    return
                self._pulse_visible = not self._pulse_visible
                if hasattr(self, '_pulse_dot'):
                    any_active = len(getattr(self.app, 'service_manager', None) and
                                     self.app.service_manager.running_services or []) > 0
                    pulse_color = COLORS["green"] if any_active else COLORS["text_dim"]
                    self._pulse_dot.configure(
                        text_color=pulse_color if self._pulse_visible else COLORS["card"]
                    )
                self.root.after(800, _blink)
            except Exception:
                pass
        _blink()

    def _update_card(self, key: str, value: str, color: str, label: str = ""):
        """Bir dashboard kartının değerini (ve opsiyonel alt yazısını) güncelle."""
        card = self._dash_cards.get(key)
        if card and hasattr(card, '_value_lbl'):
            try:
                card._value_lbl.configure(text=value, text_color=color)
                if label and hasattr(card, '_label_lbl'):
                    card._label_lbl.configure(text=label)
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

    # ─── Toast Notification (v4.0) ─── #
    def show_toast(self, title: str, message: str, severity: str = "info",
                   duration_ms: int = 5000):
        """
        Show a temporary toast notification at the bottom-right of the window.
        Severity: info (blue), warning (orange), high (red), critical (pulsing red).
        """
        self._gui_safe(lambda: self._render_toast(title, message, severity, duration_ms))

    def _render_toast(self, title: str, message: str, severity: str, duration_ms: int):
        """Render toast on the GUI thread."""
        try:
            if not self.root or not self.root.winfo_exists():
                return

            severity_colors = {
                "info":     COLORS["blue"],
                "warning":  COLORS["orange"],
                "high":     COLORS["red"],
                "critical": "#FF0000",
            }
            bg_color = severity_colors.get(severity, COLORS["blue"])
            severity_icons = {
                "info": "ℹ️", "warning": "⚠️", "high": "🚨", "critical": "💀",
            }
            icon = severity_icons.get(severity, "ℹ️")

            toast = ctk.CTkFrame(
                self.root, fg_color=COLORS["card"], corner_radius=12,
                border_width=2, border_color=bg_color,
            )
            toast.place(relx=1.0, rely=1.0, x=-16, y=-16, anchor="se")

            # Title row
            title_lbl = ctk.CTkLabel(
                toast, text=f"{icon}  {title}",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=bg_color,
            )
            title_lbl.pack(anchor="w", padx=12, pady=(10, 2))

            # Message
            msg_lbl = ctk.CTkLabel(
                toast, text=message,
                font=ctk.CTkFont(size=11),
                text_color=COLORS["text"],
                wraplength=280,
            )
            msg_lbl.pack(anchor="w", padx=12, pady=(0, 10))

            # Auto-dismiss
            def _dismiss():
                try:
                    toast.destroy()
                except Exception:
                    pass

            self.root.after(duration_ms, _dismiss)

        except Exception as e:
            log(f"Toast render error: {e}")

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

        # İlk açılışta header durumunu doğru set et
        any_active = len(running_names) > 0
        self.update_header_status(any_active)

        # Hızlı blink timer başlat (800ms)
        self._start_pulse_blink()

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
            text_color=COLORS["text_bright"], width=30, anchor="center",
        ).pack(side="left", padx=(0, 8))

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

    def _rebuild_gui(self):
        """Tüm widget'ları yıkıp GUI'yi yeniden oluşturur (dil değişimi vb.)."""
        try:
            # Mevcut dashboard refresh / pulse timer'ları widget yıkılınca
            # winfo_exists() == False olacak ve doğal olarak duracak.
            # Tüm root children'ları yık
            for child in list(self.root.winfo_children()):
                try:
                    child.destroy()
                except Exception:
                    pass
            # Dahili referansları temizle
            self._dash_cards = {}
            self.row_controls = {}
            self.app.row_controls = {}
            self._active_popup = None
            self._tabview = None
            # Yeniden oluştur (mevcut modda — görünürse gui, gizliyse minimized)
            mode = "minimized" if self.app._tray_mode.is_set() else "gui"
            self.build(self.root, mode)
            log("[GUI] GUI rebuilt successfully (hot-reload)")
        except Exception as e:
            log(f"[GUI] Rebuild error: {e}")

    def _set_lang(self, code: str):
        try:
            update_language_config(code, True)
            log(f"[CONFIG] Language changed to: {code}")
        except Exception as e:
            log(f"[CONFIG] Language change error: {e}")
        # Dili anında değiştir ve GUI'yi yeniden oluştur (restart gerekmez)
        self.app.lang = code
        self._rebuild_gui()

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
