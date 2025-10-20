#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔄 AUTO RESTART SCHEDULER
========================

3.7GB RAM sorunu için en basit çözüm: Belirli aralıklarla uygulamayı restart et.
Memory leak'ler birikse bile restart ile temizlenir.

"""

import os
import time
import threading
import subprocess
import signal
import socket
from datetime import datetime, timedelta
from client_helpers import log

class AutoRestartScheduler:
    """Otomatik restart zamanlayıcısı"""
    
    def __init__(self):
        self.restart_enabled = False
        self.restart_thread = None
        self.restart_interval_hours = 8  # Her 8 saatte bir restart
        self.memory_threshold_mb = 2048  # 2GB üzeri restart
        self.check_interval_minutes = 30  # Her 30 dakikada kontrol
        
    def enable_auto_restart(self, app_instance, restart_hours=8, memory_threshold=2048):
        """Otomatik restart'ı aktifleştir"""
        if self.restart_enabled:
            return False
            
        self.app = app_instance
        self.restart_interval_hours = restart_hours
        self.memory_threshold_mb = memory_threshold
        self.restart_enabled = True
        
        # Restart thread başlat
        self.restart_thread = threading.Thread(
            target=self._restart_monitor_loop,
            daemon=True,
            name="AutoRestartMonitor"
        )
        self.restart_thread.start()
        
        # İlk restart zamanını hesapla
        next_restart = datetime.now() + timedelta(hours=restart_hours)
        log(f"🔄 Auto-restart scheduled every {restart_hours}h or if memory > {memory_threshold}MB")
        log(f"📅 Next scheduled restart: {next_restart.strftime('%Y-%m-%d %H:%M:%S')}")
        
        return True
        
    def disable_auto_restart(self):
        """Otomatik restart'ı deaktifleştir"""
        self.restart_enabled = False
        log("⏹️ Auto-restart disabled")
        
    def _restart_monitor_loop(self):
        """Restart monitor döngüsü"""
        last_restart_time = time.time()
        
        while self.restart_enabled:
            try:
                current_time = time.time()
                
                # Zaman bazlı restart kontrolü
                hours_elapsed = (current_time - last_restart_time) / 3600
                if hours_elapsed >= self.restart_interval_hours:
                    log(f"⏰ Scheduled restart time reached ({hours_elapsed:.1f}h elapsed)")
                    self._perform_graceful_restart("Scheduled restart")
                    return
                
                # Memory bazlı restart kontrolü
                memory_mb = self._get_memory_usage()
                if memory_mb > self.memory_threshold_mb:
                    log(f"🚨 Memory threshold exceeded: {memory_mb:.1f}MB > {self.memory_threshold_mb}MB")
                    self._perform_graceful_restart(f"Memory threshold ({memory_mb:.1f}MB)")
                    return
                
                # Durum raporu
                remaining_hours = self.restart_interval_hours - hours_elapsed
                log(f"📊 Memory: {memory_mb:.1f}MB, Next restart in: {remaining_hours:.1f}h")
                
                # Check interval kadar bekle
                time.sleep(self.check_interval_minutes * 60)
                
            except Exception as e:
                log(f"❌ Restart monitor error: {e}")
                time.sleep(300)  # 5 dakika bekle
                
    def _get_memory_usage(self):
        """Memory kullanımını MB olarak al"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except Exception:
            return 0
            
    def _perform_graceful_restart(self, reason="Unknown"):
        """Graceful restart işlemi"""
        log(f"🔄 Initiating graceful restart - Reason: {reason}")
        
        try:
            # 1. Tunnel'ları temiz şekilde kapat
            self._shutdown_tunnels()
            
            # 2. State'i kaydet
            self._save_application_state()
            
            # 3. Heartbeat'i durdur
            self._cleanup_heartbeat()
            
            # 4. Yeni instance başlat
            self._start_new_instance()
            
            # 5. Mevcut process'i sonlandır
            log("✅ Graceful restart initiated - terminating current process")
            time.sleep(2)
            os._exit(0)
            
        except Exception as e:
            log(f"❌ Graceful restart failed: {e}")
            # Fallback: Force restart
            self._force_restart()
            
    def _shutdown_tunnels(self):
        """Tunnel'ları temiz şekilde kapat"""
        try:
            if hasattr(self.app, 'remove_tunnels'):
                log("🔌 Shutting down tunnels...")
                self.app.remove_tunnels()
                time.sleep(1)
        except Exception as e:
            log(f"Tunnel shutdown error: {e}")
            
    def _save_application_state(self):
        """Uygulama durumunu kaydet"""
        try:
            if hasattr(self.app, 'write_status'):
                active_rows = self.app._active_rows_from_servers()
                self.app.write_status(active_rows, running=False)
                log("💾 Application state saved")
        except Exception as e:
            log(f"State save error: {e}")
            
    def _cleanup_heartbeat(self):
        """Heartbeat'i temizle"""
        try:
            if hasattr(self.app, 'monitoring_manager'):
                self.app.monitoring_manager.stop_heartbeat_system()
        except Exception as e:
            log(f"Heartbeat cleanup error: {e}")
            
    def _start_new_instance(self):
        """Yeni instance başlat"""
        try:
            import sys
            
            # Executable path
            if getattr(sys, 'frozen', False):
                # PyInstaller binary
                exe_path = sys.executable
                cmd = [exe_path, "--daemon"]
            else:
                # Python script
                exe_path = sys.executable
                script_path = os.path.abspath(sys.argv[0])
                cmd = [exe_path, script_path, "--daemon"]
            
            # Yeni process başlat
            subprocess.Popen(
                cmd,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            )
            
            log(f"🚀 New instance started: {' '.join(cmd)}")
            
        except Exception as e:
            log(f"❌ Failed to start new instance: {e}")
            
    def _force_restart(self):
        """Force restart (son çare)"""
        try:
            log("🚨 Performing force restart...")
            
            # Mevcut process'i kill et
            import psutil
            current_process = psutil.Process()
            current_process.terminate()
            
            time.sleep(5)
            
            # Hala yaşıyorsa kill
            if current_process.is_running():
                current_process.kill()
                
        except Exception as e:
            log(f"Force restart error: {e}")
            os._exit(1)

class MemoryWatchdog:
    """Basit memory watchdog - sadece log tutar"""
    
    def __init__(self):
        self.watching = False
        self.watch_thread = None
        
    def start_watching(self, check_interval_minutes=10):
        """Memory watching başlat"""
        if self.watching:
            return
            
        self.watching = True
        self.watch_thread = threading.Thread(
            target=self._watch_loop,
            args=(check_interval_minutes,),
            daemon=True,
            name="MemoryWatchdog"
        )
        self.watch_thread.start()
        log(f"👁️ Memory watchdog started (check every {check_interval_minutes}min)")
        
    def stop_watching(self):
        """Memory watching durdur"""
        self.watching = False
        
    def _watch_loop(self, check_interval_minutes):
        """Memory watch döngüsü"""
        while self.watching:
            try:
                memory_mb = self._get_memory_usage()
                thread_count = threading.active_count()
                
                # Log level'ını memory'ye göre ayarla
                if memory_mb > 3000:  # 3GB+
                    log(f"🚨 CRITICAL MEMORY: {memory_mb:.1f}MB, Threads: {thread_count}")
                elif memory_mb > 2000:  # 2GB+
                    log(f"⚠️ HIGH MEMORY: {memory_mb:.1f}MB, Threads: {thread_count}")
                elif memory_mb > 1000:  # 1GB+
                    log(f"📊 Memory: {memory_mb:.1f}MB, Threads: {thread_count}")
                # 1GB altı log'lama
                
                time.sleep(check_interval_minutes * 60)
                
            except Exception as e:
                log(f"Memory watchdog error: {e}")
                time.sleep(300)
                
    def _get_memory_usage(self):
        """Memory kullanımını al"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except:
            return 0

# Global instances
_auto_restart_scheduler = AutoRestartScheduler()
_memory_watchdog = MemoryWatchdog()

def enable_auto_restart(app_instance, restart_hours=8, memory_threshold_mb=2048):
    """Auto restart'ı aktifleştir"""
    return _auto_restart_scheduler.enable_auto_restart(app_instance, restart_hours, memory_threshold_mb)

def disable_auto_restart():
    """Auto restart'ı deaktifleştir"""
    _auto_restart_scheduler.disable_auto_restart()

def start_memory_watchdog(check_interval_minutes=10):
    """Memory watchdog başlat"""
    _memory_watchdog.start_watching(check_interval_minutes)

def stop_memory_watchdog():
    """Memory watchdog durdur"""
    _memory_watchdog.stop_watching()

def get_current_memory_mb():
    """Mevcut memory kullanımını döndür"""
    try:
        import psutil
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    except:
        return 0