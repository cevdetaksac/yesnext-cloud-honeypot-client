"""
Cloud Honeypot Client - GUI Components Module  
GUI bileşenleri ve dialog yönetimi modülü
"""

import tkinter as tk
from tkinter import messagebox, ttk
import threading
import time
from typing import Dict, Optional, Callable, Any

class LoadingScreen:
    """Loading ekranı sınıfı"""
    
    def __init__(self, i18n: Dict, theme: str = "dark"):
        self.i18n = i18n
        self.theme = theme
        self.window = None
        self.progress_var = None
        self.status_var = None
        self.progress_bar = None
        self.running = False
    
    def create(self):
        """Loading ekranı oluştur"""
        self.window = tk.Tk()
        self.window.title(self.i18n.get('loading_title', 'Loading...'))
        self.window.geometry('400x150')
        self.window.resizable(False, False)
        
        # Ekranı ortala
        self.window.eval('tk::PlaceWindow . center')
        
        # Tema ayarları
        if self.theme == "dark":
            bg_color = "#2b2b2b"
            fg_color = "#ffffff"
        else:
            bg_color = "#ffffff"
            fg_color = "#000000"
        
        self.window.configure(bg=bg_color)
        
        # Ana frame
        main_frame = tk.Frame(self.window, bg=bg_color, padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)
        
        # Başlık
        title_label = tk.Label(
            main_frame,
            text=self.i18n.get('loading_title', 'Loading...'),
            bg=bg_color,
            fg=fg_color,
            font=('Arial', 12, 'bold')
        )
        title_label.pack(pady=(0, 10))
        
        # Durum metni
        self.status_var = tk.StringVar(value=self.i18n.get('loading_initializing', 'Initializing...'))
        status_label = tk.Label(
            main_frame,
            textvariable=self.status_var,
            bg=bg_color,
            fg=fg_color,
            font=('Arial', 9)
        )
        status_label.pack(pady=(0, 10))
        
        # Progress bar
        self.progress_var = tk.IntVar(value=0)
        self.progress_bar = ttk.Progressbar(
            main_frame,
            length=350,
            mode='determinate',
            variable=self.progress_var,
            maximum=100
        )
        self.progress_bar.pack(pady=(0, 10))
        
        # İlerleme metni
        progress_label = tk.Label(
            main_frame,
            text="0%",
            bg=bg_color,
            fg=fg_color,
            font=('Arial', 8)
        )
        self.progress_label = progress_label
        progress_label.pack()
        
        self.window.update()
        self.running = True
    
    def update_progress(self, percentage: int, status_text: str = ""):
        """İlerleme güncelle"""
        if not self.running or not self.window:
            return
            
        try:
            self.progress_var.set(percentage)
            self.progress_label.config(text=f"{percentage}%")
            
            if status_text:
                self.status_var.set(status_text)
            
            self.window.update()
        except tk.TclError:
            pass
    
    def close(self):
        """Loading ekranını kapat"""
        if self.window:
            try:
                self.running = False
                self.window.destroy()
                self.window = None
            except tk.TclError:
                pass

class LanguageDialog:
    """Estetik dil seçim dialog'u - Orijinal tasarıma benzer"""
    
    def __init__(self, theme: str = "dark"):
        self.theme = theme
        self.selected_language = None
        self.window = None
    
    def show(self) -> Optional[str]:
        """Dil seçim dialog'unu göster"""
        self.window = tk.Tk()
        self.window.title("Dil Seçimi / Language Selection")
        self.window.geometry('400x280')
        self.window.resizable(False, False)
        
        # Pencereyi ekranın ortasına yerleştir
        self.window.eval('tk::PlaceWindow . center')
        
        # Tema ayarları (koyu tema)
        bg_color = "#2b2b2b"
        fg_color = "#ffffff"
        self.window.configure(bg=bg_color)
        
        # Ana frame
        main_frame = tk.Frame(self.window, bg=bg_color, padx=30, pady=30)
        main_frame.pack(fill='both', expand=True)
        
        # Üst başlık
        title_label = tk.Label(
            main_frame,
            text="Lütfen Dilinizi Seçin",
            bg=bg_color,
            fg=fg_color,
            font=('Segoe UI', 14, 'bold'),
            justify='center'
        )
        title_label.pack(pady=(0, 5))
        
        # Alt başlık (İngilizce)
        subtitle_label = tk.Label(
            main_frame,
            text="Please Select Your Language",
            bg=bg_color,
            fg="#cccccc",
            font=('Segoe UI', 11),
            justify='center'
        )
        subtitle_label.pack(pady=(0, 30))
        
        # Buton frame (yan yana yerleştirme için)
        button_frame = tk.Frame(main_frame, bg=bg_color)
        button_frame.pack(pady=(0, 20))
        
        # Türkçe butonu (Kırmızı)
        tr_button = tk.Button(
            button_frame,
            text="🇹🇷  Türkçe",
            command=lambda: self._select_language_with_log('tr'),
            font=('Segoe UI', 12, 'bold'),
            width=15,
            height=2,
            bg="#dc3545",  # Kırmızı
            fg="white",
            activebackground="#c82333",
            activeforeground="white",
            relief="flat",
            cursor="hand2"
        )
        tr_button.pack(side='left', padx=(0, 10))
        
        # English butonu (Mavi)
        en_button = tk.Button(
            button_frame,
            text="🇺🇸  English",
            command=lambda: self._select_language_with_log('en'),
            font=('Segoe UI', 12, 'bold'),
            width=15,
            height=2,
            bg="#007bff",  # Mavi
            fg="white",
            activebackground="#0056b3",
            activeforeground="white",
            relief="flat",
            cursor="hand2"
        )
        en_button.pack(side='left', padx=(10, 0))
        
        # Alt bilgi
        info_label = tk.Label(
            main_frame,
            text="Dil, uygulama yeniden başlatıldığında değiştirilebilir",
            bg=bg_color,
            fg="#999999",
            font=('Segoe UI', 9),
            justify='center'
        )
        info_label.pack(pady=(10, 0))
        
        # Pencere odakla
        self.window.focus_force()
        self.window.lift()
        self.window.attributes('-topmost', True)
        
        # Modal dialog
        self.window.transient()
        self.window.grab_set()
        
        # Kapatma kontrolü
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)
        
        # Ana loop - wait_window kullan mainloop yerine
        try:
            self.window.wait_window()
        except Exception as e:
            print(f"Language dialog error: {e}")
            self.selected_language = 'tr'
        
        return self.selected_language
    
    def _select_language_with_log(self, lang: str):
        """Dil seç ve logla"""
        print(f"[LANGUAGE_DIALOG] Language selected: {lang}")
        self._select_language(lang)
    
    def _select_language(self, lang: str):
        """Dil seç"""
        self.selected_language = lang
        if self.window:
            self.window.destroy()
    
    def _on_close(self):
        """Dialog kapatıldığında"""
        print("[LANGUAGE_DIALOG] Dialog closed without selection, defaulting to 'tr'")
        self.selected_language = 'tr'  # Default Türkçe
        if self.window:
            self.window.destroy()

class AdminPrivilegeDialog:
    """Estetik yönetici yetki dialog'u"""
    
    def __init__(self, i18n: Dict):
        self.i18n = i18n
        self.result = None
        self.window = None
    
    def show(self) -> str:
        """Admin yetki dialog'unu göster"""
        self.window = tk.Tk()
        self.window.title("Yönetici Yetkileri Gerekli")
        self.window.geometry('500x400')  # Boyutu artırdım
        self.window.resizable(False, False)
        
        # Pencereyi ekranın ortasına yerleştir
        self.window.eval('tk::PlaceWindow . center')
        
        # Tema ayarları
        bg_color = "#2b2b2b"
        fg_color = "#ffffff"
        self.window.configure(bg=bg_color)
        
        # Ana frame - padding artırıldı
        main_frame = tk.Frame(self.window, bg=bg_color, padx=30, pady=30)
        main_frame.pack(fill='both', expand=True)
        
        # Uyarı ikonu ve başlık frame
        header_frame = tk.Frame(main_frame, bg=bg_color)
        header_frame.pack(fill='x', pady=(0, 20))
        
        # Uyarı ikonu (emoji)
        icon_label = tk.Label(
            header_frame,
            text="⚠️",
            bg=bg_color,
            fg="#ffc107",
            font=('Segoe UI', 24)
        )
        icon_label.pack()
        
        # Başlık
        title_label = tk.Label(
            header_frame,
            text="Yönetici Yetkileri Gerekli",
            bg=bg_color,
            fg=fg_color,
            font=('Segoe UI', 14, 'bold'),
            justify='center'
        )
        title_label.pack(pady=(10, 0))
        
        # Açıklama metni
        message_text = """Bu uygulama sistem seviyesinde işlemler yapmak için
yönetici yetkileri gerektiriyor.

• Ağ bağlantılarını yönetmek
• Güvenlik duvarı ayarları
• Sistem servislerini kontrol etmek

Uygulama güvenli bir şekilde çalıştırılacaktır."""
        
        message_label = tk.Label(
            main_frame,
            text=message_text,
            bg=bg_color,
            fg="#cccccc",
            font=('Segoe UI', 10),
            justify='left',
            wraplength=380
        )
        message_label.pack(pady=(0, 25))
        
        # Buton frame - padding ve spacing artırıldı
        button_frame = tk.Frame(main_frame, bg=bg_color)
        button_frame.pack(fill='x', pady=(20, 0))
        
        # Evet butonu (Yeşil) - Daha büyük
        yes_button = tk.Button(
            button_frame,
            text="✓ Evet, Yönetici Olarak Çalıştır",
            command=lambda: self._set_result_with_log('yes'),
            font=('Segoe UI', 11, 'bold'),
            width=25,
            height=3,
            bg="#28a745",  # Yeşil
            fg="white",
            activebackground="#218838",
            activeforeground="white",
            relief="raised",
            bd=2,
            cursor="hand2"
        )
        yes_button.pack(pady=(0, 15), fill='x')
        
        # Hayır butonu (Gri) - Daha büyük
        no_button = tk.Button(
            button_frame,
            text="Sınırlı Modda Devam Et",
            command=lambda: self._set_result_with_log('no'),
            font=('Segoe UI', 11),
            width=25,
            height=3,
            bg="#6c757d",  # Gri
            fg="white",
            activebackground="#5a6268",
            activeforeground="white",
            relief="raised",
            bd=2,
            cursor="hand2"
        )
        no_button.pack(pady=(0, 15), fill='x')
        
        # İptal butonu (Kırmızı) - Daha büyük
        cancel_button = tk.Button(
            button_frame,
            text="✕ İptal Et ve Çık",
            command=lambda: self._set_result_with_log('cancel'),
            font=('Segoe UI', 11),
            width=25,
            height=3,
            bg="#dc3545",  # Kırmızı
            fg="white",
            activebackground="#c82333",
            activeforeground="white",
            relief="raised",
            bd=2,
            cursor="hand2"
        )
        cancel_button.pack(fill='x')
        
        # Pencere odakla
        self.window.focus_force()
        self.window.lift()
        self.window.attributes('-topmost', True)
        
        # Modal dialog
        self.window.transient()
        self.window.grab_set()
        
        # Kapatma kontrolü
        self.window.protocol("WM_DELETE_WINDOW", lambda: self._set_result_with_log('cancel'))
        
        # Ana loop - wait_window kullan mainloop yerine
        try:
            self.window.wait_window()
        except Exception as e:
            print(f"Admin dialog error: {e}")
            self.result = 'cancel'
        
        return self.result or 'cancel'
    
    def _set_result_with_log(self, result: str):
        """Sonucu logla ve ayarla"""
        print(f"[ADMIN_DIALOG] Button clicked: {result}")
        self._set_result(result)
    
    def _set_result(self, result: str):
        """Sonucu ayarla ve dialog'u kapat"""
        self.result = result
        if self.window:
            self.window.destroy()

class ConsentDialog:
    """Güvenlik onay dialog'u"""
    
    def __init__(self, i18n: Dict, theme: str = "dark"):
        self.i18n = i18n
        self.theme = theme
        self.result = None
        self.rdp_consent = False
        self.auto_consent = False
        self.window = None
    
    def show(self) -> Dict:
        """Onay dialog'unu göster"""
        self.window = tk.Tk()
        self.window.title(self.i18n.get('consent_title', 'Security Consent'))
        self.window.geometry('500x350')
        self.window.resizable(False, False)
        
        # Ekranı ortala
        self.window.eval('tk::PlaceWindow . center')
        
        # Tema ayarları
        if self.theme == "dark":
            bg_color = "#2b2b2b"
            fg_color = "#ffffff"
        else:
            bg_color = "#ffffff"
            fg_color = "#000000"
        
        self.window.configure(bg=bg_color)
        
        # Ana frame
        main_frame = tk.Frame(self.window, bg=bg_color, padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)
        
        # Başlık
        title_label = tk.Label(
            main_frame,
            text=self.i18n.get('consent_title', 'Security Consent'),
            bg=bg_color,
            fg=fg_color,
            font=('Arial', 14, 'bold')
        )
        title_label.pack(pady=(0, 15))
        
        # Açıklama
        consent_text = self.i18n.get('consent_msg', 'This app may perform various operations.')
        text_widget = tk.Text(
            main_frame,
            height=8,
            bg=bg_color,
            fg=fg_color,
            font=('Arial', 9),
            wrap='word',
            state='disabled'
        )
        text_widget.config(state='normal')
        text_widget.insert('1.0', consent_text)
        text_widget.config(state='disabled')
        text_widget.pack(pady=(0, 15), fill='both', expand=True)
        
        # Checkbox frame
        checkbox_frame = tk.Frame(main_frame, bg=bg_color)
        checkbox_frame.pack(pady=(0, 15), fill='x')
        
        # RDP checkbox
        self.rdp_var = tk.BooleanVar()
        rdp_check = tk.Checkbutton(
            checkbox_frame,
            text=self.i18n.get('consent_rdp', 'Move RDP to 53389 and manage service'),
            variable=self.rdp_var,
            bg=bg_color,
            fg=fg_color,
            font=('Arial', 9),
            selectcolor=bg_color
        )
        rdp_check.pack(anchor='w')
        
        # Auto checkbox
        self.auto_var = tk.BooleanVar()
        auto_check = tk.Checkbutton(
            checkbox_frame,
            text=self.i18n.get('consent_auto', 'Autostart on boot/logon'),
            variable=self.auto_var,
            bg=bg_color,
            fg=fg_color,
            font=('Arial', 9),
            selectcolor=bg_color
        )
        auto_check.pack(anchor='w')
        
        # Buton frame
        button_frame = tk.Frame(main_frame, bg=bg_color)
        button_frame.pack(pady=(10, 0))
        
        # Accept butonu
        accept_button = tk.Button(
            button_frame,
            text=self.i18n.get('consent_accept', 'Accept & Continue'),
            command=self._accept,
            font=('Arial', 10),
            width=15
        )
        accept_button.pack(side='left', padx=(0, 10))
        
        # Cancel butonu
        cancel_button = tk.Button(
            button_frame,
            text=self.i18n.get('consent_cancel', 'Cancel'),
            command=self._cancel,
            font=('Arial', 10),
            width=15
        )
        cancel_button.pack(side='right')
        
        # Modal dialog
        self.window.transient()
        self.window.grab_set()
        self.window.focus_force()
        
        # Kapatma kontrolü
        self.window.protocol("WM_DELETE_WINDOW", self._cancel)
        
        self.window.mainloop()
        
        return {
            'accepted': self.result,
            'rdp_consent': self.rdp_consent,
            'auto_consent': self.auto_consent
        }
    
    def _accept(self):
        """Onayla"""
        self.result = True
        self.rdp_consent = self.rdp_var.get()
        self.auto_consent = self.auto_var.get()
        self.window.destroy()
    
    def _cancel(self):
        """İptal"""
        self.result = False
        self.rdp_consent = False
        self.auto_consent = False
        self.window.destroy()

def show_startup_notice(i18n: Dict) -> bool:
    """Başlangıç bildirimini göster"""
    title = i18n.get('startup_title', 'Notice')
    message = i18n.get('startup_notice', 'This application requires network access.')
    
    result = messagebox.showinfo(title, message)
    return True

def show_error_message(i18n: Dict, title_key: str, message_key: str, **kwargs) -> None:
    """Hata mesajı göster"""
    title = i18n.get(title_key, 'Error')
    message = i18n.get(message_key, 'An error occurred.')
    
    # Format string varsa
    if kwargs:
        try:
            message = message.format(**kwargs)
        except (KeyError, ValueError):
            pass
    
    messagebox.showerror(title, message)

def show_info_message(i18n: Dict, title_key: str, message_key: str, **kwargs) -> None:
    """Bilgi mesajı göster"""
    title = i18n.get(title_key, 'Info')
    message = i18n.get(message_key, 'Information.')
    
    # Format string varsa
    if kwargs:
        try:
            message = message.format(**kwargs)
        except (KeyError, ValueError):
            pass
    
    messagebox.showinfo(title, message)

def show_warning_message(i18n: Dict, title_key: str, message_key: str, **kwargs) -> None:
    """Uyarı mesajı göster"""
    title = i18n.get(title_key, 'Warning')
    message = i18n.get(message_key, 'Warning.')
    
    # Format string varsa
    if kwargs:
        try:
            message = message.format(**kwargs)
        except (KeyError, ValueError):
            pass
    
    messagebox.showwarning(title, message)

def show_question_message(i18n: Dict, title_key: str, message_key: str, **kwargs) -> bool:
    """Soru mesajı göster"""
    title = i18n.get(title_key, 'Question')
    message = i18n.get(message_key, 'Question?')
    
    # Format string varsa
    if kwargs:
        try:
            message = message.format(**kwargs)
        except (KeyError, ValueError):
            pass
    
    result = messagebox.askyesno(title, message)
    return result

class SystemTrayManager:
    """Sistem tepsisi yönetimi"""
    
    def __init__(self, i18n: Dict, app_instance=None):
        self.i18n = i18n
        self.app = app_instance
        self.tray_icon = None
    
    def create_tray_menu(self):
        """Tepsi menüsü oluştur"""
        try:
            import pystray
            from PIL import Image, ImageDraw
            
            # Basit ikon oluştur
            def create_icon():
                width = height = 64
                image = Image.new('RGB', (width, height), color='red')
                draw = ImageDraw.Draw(image)
                draw.rectangle([16, 16, 48, 48], fill='white')
                return image
            
            # Menü öğeleri
            menu_items = [
                pystray.MenuItem(
                    self.i18n.get('tray_show', 'Show'),
                    self._show_window
                ),
                pystray.MenuItem(
                    self.i18n.get('tray_exit', 'Exit'),
                    self._exit_app
                )
            ]
            
            # Tray icon oluştur
            self.tray_icon = pystray.Icon(
                "HoneypotClient",
                create_icon(),
                menu=pystray.Menu(*menu_items)
            )
            
        except ImportError:
            # pystray yoksa sistem tepsisi kullanılmaz
            pass
    
    def _show_window(self, icon, item):
        """Pencereyi göster"""
        if self.app and hasattr(self.app, 'root'):
            self.app.root.deiconify()
            self.app.root.lift()
    
    def _exit_app(self, icon, item):
        """Uygulamayı kapat"""
        if self.app:
            self.app.on_closing()

if __name__ == "__main__":
    # Test
    test_i18n = {
        'loading_title': 'Test Loading',
        'loading_initializing': 'Test initializing...',
        'admin_required_title': 'Admin Required',
        'admin_required_message': 'Admin privileges required for testing.'
    }
    
    print("Testing GUI components...")
    
    # Test language dialog
    lang_dialog = LanguageDialog()
    print("Language dialog created ✅")
    
    # Test loading screen
    loading = LoadingScreen(test_i18n)
    print("Loading screen created ✅")
    
    print("All GUI components tested successfully ✅")
