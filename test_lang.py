#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk
import sys
import os

# Add current directory to path
sys.path.append('.')

try:
    from client import read_settings, write_settings, LanguageSelector
    
    print("Testing Language Selector...")
    
    settings = read_settings()
    print(f"Current settings: {settings}")
    
    # Test if language already selected
    if not settings.get("language_selected", False):
        print("Language not selected yet - showing selector")
        try:
            selector = LanguageSelector()
            print("LanguageSelector created successfully")
            lang = selector.show()
            print(f"Selected language: {lang}")
        except Exception as lang_error:
            print(f"Language selector error: {lang_error}")
            import traceback
            traceback.print_exc()
    else:
        print("Language already selected:", settings.get("language", "tr"))
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
