#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import messagebox
import sys

# Simulated admin dialog test
def test_admin_dialog():
    root = tk.Tk()
    root.withdraw()  # Hide main window
    
    result = messagebox.askyesnocancel(
        title="Yönetici Yetkileri Gerekli",
        message=(
            "Cloud Honeypot Client'ın tam işlevselliği için yönetici yetkileri gereklidir.\n\n"
            "• Güvenlik duvarı kuralları yönetimi\n"
            "• Sistem portları yapılandırması\n"
            "• Servis yönetimi\n"
            "• Registry değişiklikleri\n\n"
            "Yönetici yetkileriyle yeniden başlatmak istiyor musunuz?\n\n"
            "EVET = Yönetici olarak yeniden başlat\n"
            "HAYIR = Sınırlı modda devam et\n"
            "İPTAL = Uygulamayı kapat"
        )
    )
    
    root.destroy()
    
    if result is True:
        return "admin"
    elif result is False:
        return "limited"
    else:
        return "cancel"

if __name__ == "__main__":
    print("Admin privilege dialog test")
    choice = test_admin_dialog()
    print(f"User choice: {choice}")
    
    if choice == "admin":
        print("User wants admin restart")
    elif choice == "limited":
        print("User wants limited mode")
    elif choice == "cancel":
        print("User wants to exit")
