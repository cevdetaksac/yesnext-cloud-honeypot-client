#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Design tokens for Cloud Honeypot Client v4.4 UI."""

# Modern dark theme — slate + emerald accent
COLORS = {
    "bg":           "#0b1120",
    "sidebar":      "#0f172a",
    "card":         "#1e293b",
    "card_hover":   "#243044",
    "card_active":  "#1d3a2f",
    "accent":       "#134e4a",
    "accent_soft":  "#115e59",
    "green":        "#10b981",
    "green_hover":  "#34d399",
    "red":          "#f43f5e",
    "red_hover":    "#fb7185",
    "orange":       "#f59e0b",
    "orange_hover": "#fbbf24",
    "blue":         "#3b82f6",
    "blue_hover":   "#60a5fa",
    "purple":       "#a78bfa",
    "text":         "#cbd5e1",
    "text_dim":     "#64748b",
    "text_bright":  "#f8fafc",
    "border":       "#334155",
    "entry_bg":     "#0f172a",
    "status_dot_on":  "#34d399",
    "status_dot_off": "#f43f5e",
    "nav_active":   "#1e3a5f",
    "nav_hover":    "#1e293b",
}

FONTS = {
    "title": ("Segoe UI", 20, "bold"),
    "heading": ("Segoe UI", 14, "bold"),
    "body": ("Segoe UI", 12),
    "small": ("Segoe UI", 11),
    "mono": ("Cascadia Mono", 11),
}

SERVICE_ICONS = {
    "RDP":   "🖥",
    "MSSQL": "🗃",
    "MYSQL": "🐬",
    "FTP":   "📁",
    "SSH":   "🔐",
    "HTTP":  "🌐",
    "SMB":   "📂",
}

SIDEBAR_WIDTH = 220
CORNER_RADIUS = 14
