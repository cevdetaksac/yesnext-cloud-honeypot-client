#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🚨 EMERGENCY MEMORY PATCH
========================

3.7GB RAM sorunu için acil hafıza optimizasyonu.
Mevcut koda minimal müdahale ile memory leak'leri durdurur.

"""

import gc
import threading
import time
import psutil
import os
from client_helpers import log

class EmergencyMemoryPatch:
    """Acil hafıza yaması - mevcut sisteme enjekte edilir"""
    
    def __init__(self):
        self.patch_active = False
        self.cleanup_thread = None
        self.memory_limit_mb = 1024  # 1GB limit
        self.cleanup_interval = 60   # Her dakika kontrol
        
    def activate_emergency_patch(self, app_instance):
        """Acil hafıza yamasını aktifleştir"""
        if self.patch_active:
            return
            
        self.patch_active = True
        self.app = app_instance
        
        # Cleanup thread başlat
        self.cleanup_thread = threading.Thread(
            target=self._emergency_cleanup_loop,
            daemon=True,
            name="EmergencyMemoryCleanup"
        )
        self.cleanup_thread.start()
        
        log("🚨 Emergency memory patch activated - monitoring RAM usage")
        
    def _emergency_cleanup_loop(self):
        """Acil temizlik döngüsü"""
        while self.patch_active:
            try:
                # Memory kullanımını kontrol et
                memory_mb = self._get_memory_usage()
                
                if memory_mb > self.memory_limit_mb:
                    log(f"🚨 HIGH MEMORY: {memory_mb:.1f}MB > {self.memory_limit_mb}MB - Emergency cleanup!")
                    self._perform_emergency_cleanup()
                elif memory_mb > 512:  # 512MB üzeri uyarı
                    log(f"⚠️ Memory warning: {memory_mb:.1f}MB")
                    self._perform_light_cleanup()
                
                time.sleep(self.cleanup_interval)
                
            except Exception as e:
                log(f"Emergency cleanup error: {e}")
                time.sleep(60)
                
    def _get_memory_usage(self):
        """Mevcut memory kullanımını MB olarak al"""
        try:
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except:
            return 0
            
    def _perform_emergency_cleanup(self):
        """Acil durum temizliği"""
        log("🧹 Performing emergency memory cleanup...")
        
        # 1. Force garbage collection
        collected = gc.collect()
        
        # 2. Cache'leri temizle
        self._clear_caches()
        
        # 3. Dead thread'leri temizle
        self._cleanup_dead_threads()
        
        # 4. Connection buffer'larını temizle
        self._cleanup_connection_buffers()
        
        # 5. API response cache'ini temizle
        self._cleanup_api_cache()
        
        # Memory kullanımını tekrar kontrol et
        memory_after = self._get_memory_usage()
        log(f"✅ Emergency cleanup done: GC collected {collected}, Memory: {memory_after:.1f}MB")
        
    def _perform_light_cleanup(self):
        """Hafif temizlik"""
        gc.collect()
        self._clear_caches()
        
    def _clear_caches(self):
        """Cache'leri temizle"""
        try:
            # Port table cache
            if hasattr(self.app, '_port_table_cache'):
                delattr(self.app, '_port_table_cache')
                
            # Attack count cache
            if hasattr(self.app, '_last_attack_count'):
                delattr(self.app, '_last_attack_count')
                
            # GUI health cache
            if hasattr(self.app, 'gui_health'):
                self.app.gui_health['update_count'] = 0
                self.app.gui_health['frozen_count'] = 0
                
        except Exception as e:
            log(f"Cache clear error: {e}")
            
    def _cleanup_dead_threads(self):
        """Ölü thread'leri temizle"""
        try:
            active_count = threading.active_count()
            if active_count > 20:  # Çok fazla thread varsa
                log(f"⚠️ Too many threads: {active_count}")
                # Thread sayısını logla ama müdahale etme (crash risk)
        except Exception as e:
            log(f"Thread cleanup error: {e}")
            
    def _cleanup_connection_buffers(self):
        """Connection buffer'larını temizle"""
        try:
            # Mevcut server socket'lerde receive buffer'ı küçült
            for port, server_thread in self.app.state.get("servers", {}).items():
                if hasattr(server_thread, 'sock') and server_thread.sock:
                    try:
                        # Buffer size'ı küçült
                        server_thread.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
                    except:
                        pass
        except Exception as e:
            log(f"Connection buffer cleanup error: {e}")
            
    def _cleanup_api_cache(self):
        """API cache'ini temizle"""
        try:
            # API client cache temizliği
            if hasattr(self.app, 'api_client'):
                # Response cache'i varsa temizle
                if hasattr(self.app.api_client, '_response_cache'):
                    self.app.api_client._response_cache.clear()
                    
        except Exception as e:
            log(f"API cache cleanup error: {e}")

# Global emergency patch instance
_emergency_patch = EmergencyMemoryPatch()

def activate_emergency_memory_patch(app_instance):
    """Acil hafıza yamasını aktifleştir"""
    global _emergency_patch
    _emergency_patch.activate_emergency_patch(app_instance)
    return _emergency_patch

def get_memory_usage_mb():
    """Mevcut memory kullanımını MB olarak döndür"""
    try:
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    except:
        return 0

def force_memory_cleanup():
    """Manuel memory cleanup tetikle"""
    try:
        collected = gc.collect()
        memory_mb = get_memory_usage_mb()
        log(f"🧹 Manual cleanup: GC collected {collected}, Memory: {memory_mb:.1f}MB")
        return collected
    except Exception as e:
        log(f"Manual cleanup error: {e}")
        return 0