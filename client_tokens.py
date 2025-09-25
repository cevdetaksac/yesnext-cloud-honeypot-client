#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Token Management Module - Cloud Honeypot Client
Handles token storage, loading, client registration and authentication
"""

import os
from typing import Optional
import tkinter.messagebox as messagebox
from client_helpers import ClientHelpers, log
from client_utils import TokenStore
from client_api import register_client_api


def get_token_file_paths(app_dir: str) -> tuple:
    """Get token file paths"""
    token_file_new = os.path.join(app_dir, "token.dat")
    token_file_old = "token.txt"
    return token_file_new, token_file_old


class TokenManager:
    """Token yönetimi için merkezi sınıf"""
    
    def __init__(self, api_url: str, server_name: str, token_file_new: str, token_file_old: str):
        self.api_url = api_url
        self.server_name = server_name
        self.token_file_new = token_file_new
        self.token_file_old = token_file_old
    
    def get_token(self) -> Optional[str]:
        """Kaydedilmiş token'ı yükler"""
        # Önce eski plain text token'ı kontrol et ve migrate et
        TokenStore.migrate_from_plain(self.token_file_old, self.token_file_new)
        # DPAPI ile şifrelenmiş token'ı yükle
        return TokenStore.load(self.token_file_new)
    
    def register_client(self, root_window=None, t_func=None) -> Optional[str]:
        """Register client with API and get token"""
        for attempt in range(3):
            try:
                ip = ClientHelpers.get_public_ip()
                
                def save_token(tok):
                    TokenStore.save(tok, self.token_file_new)
                
                token = register_client_api(self.api_url, self.server_name, ip, save_token, log)
                if token:
                    return token
                
                msg = "API kaydı başarısız. Tekrar deneniyor..."
                if root_window:
                    messagebox.showwarning("Uyarı", msg)
                log(msg)
                
            except Exception as e:
                msg = f"API kaydı başarısız: {e}. Tekrar deneniyor..."
                if root_window:
                    messagebox.showwarning("Uyarı", msg)
                log(msg)
            
            import time
            time.sleep(5)
        
        if root_window and t_func:
            messagebox.showwarning(t_func("warn"), t_func("api_registration_warning"))
        return None
    
    def load_token(self, root_window=None, t_func=None) -> Optional[str]:
        """Load token from storage or register new client"""
        TokenStore.migrate_from_plain(self.token_file_old, self.token_file_new)
        return TokenStore.load(self.token_file_new) or self.register_client(root_window, t_func)


def create_token_manager(api_url: str, server_name: str, token_file_new: str, token_file_old: str) -> TokenManager:
    """Factory function to create TokenManager instance"""
    return TokenManager(api_url, server_name, token_file_new, token_file_old)