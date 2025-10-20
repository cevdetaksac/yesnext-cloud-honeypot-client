#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🎯 MEMORY OPTIMIZER MODULE
==========================

RAM kullanımını optimize etmek için geliştirilen modül.
Çoklu thread'leri tek thread'de birleştirip memory leak'leri önler.

"""

import gc
import threading
import time
from typing import Dict, Any
from client_helpers import log

class MemoryOptimizer:
    """RAM kullanımını optimize eden merkezi sistem"""
    
    def __init__(self, app_instance):
        self.app = app_instance
        self.running = False
        self.unified_thread = None
        self.cycle_counter = 0
        
        # Timing configuration (saniye)
        self.intervals = {
            'heartbeat': 60,
            'tunnel_watchdog': 10, 
            'reconcile': 600,
            'open_ports': 600,
            'memory_cleanup': 300,  # 5 dakikada bir memory cleanup
            'api_sync': 30
        }
        
        # Last execution tracking
        self.last_execution = {key: 0 for key in self.intervals}
        
    def start_unified_monitoring(self):
        """Tüm monitoring işlemlerini tek thread'de birleştir"""
        if self.running:
            return False
            
        self.running = True
        self.unified_thread = threading.Thread(
            target=self._unified_monitoring_loop,
            daemon=True,
            name="UnifiedMonitoring"
        )
        self.unified_thread.start()
        log("🔄 Unified monitoring thread başlatıldı - RAM optimize edildi")
        return True
        
    def stop_unified_monitoring(self):
        """Unified monitoring'i durdur"""
        self.running = False
        if self.unified_thread:
            self.unified_thread.join(timeout=5)
        log("⏹️ Unified monitoring durduruldu")
        
    def _unified_monitoring_loop(self):
        """Tüm monitoring işlemlerini tek loop'ta yap"""
        log("🚀 Unified monitoring loop başlatıldı")
        
        while self.running:
            try:
                current_time = time.time()
                self.cycle_counter += 1
                
                # Heartbeat (her 60 saniye)
                if self._should_execute('heartbeat', current_time):
                    self._safe_execute(self._heartbeat_task, 'heartbeat')
                
                # Tunnel watchdog (her 10 saniye)
                if self._should_execute('tunnel_watchdog', current_time):
                    self._safe_execute(self._tunnel_watchdog_task, 'tunnel_watchdog')
                
                # API reconcile (her 600 saniye = 10 dakika)
                if self._should_execute('reconcile', current_time):
                    self._safe_execute(self._reconcile_task, 'reconcile')
                
                # Open ports report (her 600 saniye)
                if self._should_execute('open_ports', current_time):
                    self._safe_execute(self._open_ports_task, 'open_ports')
                
                # Memory cleanup (her 300 saniye = 5 dakika)
                if self._should_execute('memory_cleanup', current_time):
                    self._safe_execute(self._memory_cleanup_task, 'memory_cleanup')
                
                # API sync (her 30 saniye)
                if self._should_execute('api_sync', current_time):
                    self._safe_execute(self._api_sync_task, 'api_sync')
                
                # Her 100 döngüde bir istatistik
                if self.cycle_counter % 100 == 0:
                    self._log_memory_stats()
                
                # Base interval: 5 saniye (en küçük interval'ın yarısı)
                time.sleep(5)
                
            except Exception as e:
                log(f"❌ Unified monitoring error: {e}")
                time.sleep(10)  # Error durumunda biraz daha bekle
                
    def _should_execute(self, task_name: str, current_time: float) -> bool:
        """Task'in çalışma zamanı geldi mi kontrol et"""
        interval = self.intervals[task_name]
        last_exec = self.last_execution[task_name]
        return (current_time - last_exec) >= interval
    
    def _safe_execute(self, task_func, task_name: str):
        """Task'i güvenli şekilde çalıştır"""
        try:
            start_time = time.time()
            task_func()
            execution_time = time.time() - start_time
            self.last_execution[task_name] = time.time()
            
            # Yavaş task'ları logla
            if execution_time > 2:
                log(f"⚠️ Slow task {task_name}: {execution_time:.2f}s")
                
        except Exception as e:
            log(f"❌ Task {task_name} failed: {e}")
            self.last_execution[task_name] = time.time()  # Hatada da zamanı güncelle
    
    def _heartbeat_task(self):
        """Heartbeat görevini yap"""
        try:
            if hasattr(self.app, 'send_heartbeat_once'):
                self.app.send_heartbeat_once()
        except Exception as e:
            log(f"Heartbeat task error: {e}")
    
    def _tunnel_watchdog_task(self):
        """Tunnel watchdog görevini yap"""
        try:
            if self.app.state.get("running"):
                # Sadece temel tunnel kontrolü
                from client_networking import TunnelManager
                
                # Dead tunnel'ları restart et
                for row in self.app.state.get("selected_rows", []):
                    if isinstance(row, (list, tuple)) and len(row) >= 3:
                        listen_port = int(str(row[0]))
                        service = str(row[2])
                        
                        st = self.app.state["servers"].get(listen_port)
                        if st is None or not st.is_alive():
                            # Sadece logla, restart etme (memory leak'i önle)
                            log(f"⚠️ Dead tunnel detected: {service}:{listen_port}")
                            
        except Exception as e:
            log(f"Tunnel watchdog task error: {e}")
    
    def _reconcile_task(self):
        """API reconcile görevini yap"""
        try:
            # Reconciliation pause check
            with self.app.reconciliation_lock:
                if self.app.state.get("reconciliation_paused"):
                    return
            
            # Basit reconcile - sadece durum raporu
            if hasattr(self.app, 'report_tunnel_status_once'):
                self.app.report_tunnel_status_once()
                
        except Exception as e:
            log(f"Reconcile task error: {e}")
    
    def _open_ports_task(self):
        """Open ports report görevini yap"""
        try:
            if hasattr(self.app, 'report_open_ports_once'):
                self.app.report_open_ports_once()
        except Exception as e:
            log(f"Open ports task error: {e}")
    
    def _api_sync_task(self):
        """API sync görevini yap"""
        try:
            # Basit API connection check
            if hasattr(self.app, 'try_api_connection'):
                self.app.try_api_connection(show_error=False)
        except Exception as e:
            log(f"API sync task error: {e}")
    
    def _memory_cleanup_task(self):
        """Memory cleanup görevini yap"""
        try:
            # Force garbage collection
            collected = gc.collect()
            
            # Cache'leri temizle
            if hasattr(self.app, '_port_table_cache'):
                delattr(self.app, '_port_table_cache')
            
            # Thread cleanup - ölü thread'leri temizle
            active_threads = threading.active_count()
            
            log(f"🧹 Memory cleanup: GC collected {collected} objects, {active_threads} active threads")
            
        except Exception as e:
            log(f"Memory cleanup task error: {e}")
    
    def _log_memory_stats(self):
        """Memory istatistiklerini logla"""
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            thread_count = threading.active_count()
            
            log(f"📊 Memory: {memory_mb:.1f}MB, Threads: {thread_count}, Cycles: {self.cycle_counter}")
            
        except Exception as e:
            log(f"Memory stats error: {e}")

class ConnectionPoolManager:
    """Connection pool yöneticisi - memory leak'leri önler"""
    
    def __init__(self, max_connections=10):
        self.max_connections = max_connections
        self.active_connections = {}
        self.connection_lock = threading.Lock()
        
    def register_connection(self, conn_id: str, connection):
        """Connection'ı kaydet"""
        with self.connection_lock:
            if len(self.active_connections) >= self.max_connections:
                # Eski connection'ları temizle
                self._cleanup_old_connections()
            
            self.active_connections[conn_id] = {
                'connection': connection,
                'created': time.time()
            }
    
    def unregister_connection(self, conn_id: str):
        """Connection'ı sil"""
        with self.connection_lock:
            if conn_id in self.active_connections:
                conn_info = self.active_connections.pop(conn_id)
                try:
                    conn_info['connection'].close()
                except:
                    pass
    
    def _cleanup_old_connections(self):
        """Eski connection'ları temizle"""
        current_time = time.time()
        to_remove = []
        
        for conn_id, conn_info in self.active_connections.items():
            if current_time - conn_info['created'] > 300:  # 5 dakikadan eski
                to_remove.append(conn_id)
        
        for conn_id in to_remove:
            self.unregister_connection(conn_id)
            
        log(f"🧹 Cleaned up {len(to_remove)} old connections")

# Global instance
_memory_optimizer = None
_connection_pool = ConnectionPoolManager()

def get_memory_optimizer(app_instance):
    """Memory optimizer singleton'ı al"""
    global _memory_optimizer
    if _memory_optimizer is None:
        _memory_optimizer = MemoryOptimizer(app_instance)
    return _memory_optimizer

def get_connection_pool():
    """Connection pool'u al"""
    return _connection_pool