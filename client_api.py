"""
Cloud Honeypot Client - API Management Module
API bağlantı yönetimi ve veri transferi modülü
"""

import json
import requests
import threading
import time
from typing import Dict, Optional, Any
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# SSL uyarılarını gizle
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HoneypotAPIClient:
    """Honeypot API bağlantı yönetimi sınıfı"""
    
    def __init__(self, base_url: str, log_func=None):
        self.base_url = base_url.rstrip('/')
        self.session = self._create_session()
        self.log = log_func if log_func else print
        
    def _create_session(self) -> requests.Session:
        """HTTP session oluştur"""
        session = requests.Session()
        
        # Retry stratejisi
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "OPTIONS"],
            backoff_factor=1
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Default headers
        session.headers.update({
            'User-Agent': 'Cloud-Honeypot-Client/1.0',
            'Content-Type': 'application/json'
        })
        
        return session
    
    def api_request(self, method: str, endpoint: str, data: Dict = None,
                   params: Dict = None, timeout: int = 10) -> Optional[Dict]:
        """API isteği gönder"""
        try:
            url = f"{self.base_url}/{endpoint.lstrip('/')}"
            self.log(f"[API] {method.upper()} isteği: {url}")
            
            if params:
                self.log(f"[API] Params: {params}")
            
            if data:
                self.log(f"[API] JSON: {data}")
            
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=timeout,
                verify=False
            )
            
            self.log(f"[API] Yanıt: HTTP {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                self.log(f"[API] Başarılı yanıt: {result}")
                return result
            else:
                self.log(f"[API] Hata yanıtı: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.log(f"[API] İstek hatası: {e}")
            return None
        except json.JSONDecodeError as e:
            self.log(f"[API] JSON parse hatası: {e}")
            return None
        except Exception as e:
            self.log(f"[API] Beklenmeyen hata: {e}")
            return None
    
    def check_connection(self, max_attempts: int = 5, delay: int = 5) -> bool:
        """API bağlantısını kontrol et - orijinal try_api_connection mantığına uygun"""
        for attempt in range(1, max_attempts + 1):
            self.log(f"[API] Bağlantı kontrol denemesi {attempt}/{max_attempts}")
            
            try:
                # Strip any trailing slash from base_url (orijinal koddan)
                base_url = self.base_url.rstrip('/')
                health_url = f"{base_url.rsplit('/api', 1)[0]}/healthz"
                self.log(f"Checking API health at {health_url}...")
                
                response = self.session.get(
                    health_url,
                    timeout=15,  # Orijinal kodda 15 saniye
                    verify=False
                )
                
                if response.status_code == 200:
                    try:
                        health_data = response.json()
                        if health_data.get("status") == "ok":
                            client_count = health_data.get("clients", 0)
                            self.log(f"API connection successful - {client_count} clients registered")
                            return True
                    except ValueError:
                        self.log("API health check succeeded but returned invalid JSON")
                
                if response.status_code in [401, 403]:  # API çalışıyor ama token gerekiyor
                    self.log("API connection successful but requires authentication")
                    return True
                    
                self.log(f"API connection failed: HTTP {response.status_code}")
                    
            except Exception as e:
                self.log(f"[API] Bağlantı denemesi {attempt} başarısız: {e}")
            
            if attempt < max_attempts:
                self.log(f"[API] {delay} saniye bekleyip tekrar deneniyor...")
                time.sleep(delay)
        
        self.log("[API] Bağlantı kurulamadı!")
        return False
    
    def register_client(self, token: str) -> bool:
        """Client'ı API'ye kaydet"""
        try:
            data = {'token': token}
            result = self.api_request('POST', 'agent/register', data=data)
            return result is not None
        except Exception as e:
            self.log(f"[API] Kayıt hatası: {e}")
            return False
    
    def get_tunnel_statuses(self, token: str) -> Optional[Dict]:
        """Tünel durumlarını al"""
        try:
            params = {'token': token}
            return self.api_request('GET', 'premium/tunnel-status', params=params)
        except Exception as e:
            self.log(f"[API] Tünel durumu alma hatası: {e}")
            return None
    
    def update_tunnel_statuses(self, token: str, statuses: list) -> bool:
        """Tünel durumlarını güncelle"""
        try:
            data = {
                'token': token,
                'statuses': statuses
            }
            result = self.api_request('POST', 'agent/tunnel-status', data=data)
            return result is not None
        except Exception as e:
            self.log(f"[API] Tünel durumu güncelleme hatası: {e}")
            return False
    
    def get_attack_count(self, token: str) -> Optional[int]:
        """Saldırı sayısını al"""
        try:
            self.log("[API] Saldırı sayısı sorgulanıyor...")
            params = {'token': token}
            result = self.api_request('GET', 'attack-count', params=params)
            
            if result and 'count' in result:
                count = int(result['count'])
                self.log(f"[API] Toplam saldırı sayısı: {count}")
                return count
            
            return None
        except Exception as e:
            self.log(f"[API] Saldırı sayısı alma hatası: {e}")
            return None
    
    def notify_rdp_status(self, token: str, is_active: bool) -> bool:
        """RDP durumunu bildir"""
        try:
            data = {
                'token': token,
                'rdp_active': is_active
            }
            result = self.api_request('POST', 'agent/rdp-status', data=data)
            return result is not None
        except Exception as e:
            self.log(f"[API] RDP durumu bildirme hatası: {e}")
            return False

class AsyncAttackCounter:
    """Asenkron saldırı sayacı"""
    
    def __init__(self, api_client: HoneypotAPIClient, token: str, 
                 update_callback=None, log_func=None):
        self.api_client = api_client
        self.token = token
        self.update_callback = update_callback
        self.log = log_func if log_func else print
        self.running = False
        self.thread = None
        self.last_count = 0
    
    def start(self, interval: int = 10):
        """Sayaç başlat"""
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._counter_loop, args=(interval,))
        self.thread.daemon = True
        self.thread.start()
        self.log("[GUI] Asenkron saldırı sayacı başlatıldı")
    
    def stop(self):
        """Sayaç durdur"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
        self.log("[GUI] Asenkron saldırı sayacı durduruldu")
    
    def _counter_loop(self, interval: int):
        """Sayaç döngüsü"""
        while self.running:
            try:
                self.log("[API] Saldırı sayısı sorgulanıyor...")
                self.log("[GUI] Asenkron saldırı sayacı güncelleme başlatıldı")
                
                count = self.api_client.get_attack_count(self.token)
                
                if count is not None and count != self.last_count:
                    self.last_count = count
                    if self.update_callback:
                        self.update_callback(count)
                    self.log(f"[GUI] Saldırı sayacı güncellendi: {count}")
                
            except Exception as e:
                self.log(f"[API] Saldırı sayacı hatası: {e}")
            
            # Interval kadar bekle veya durdurulana kadar
            for _ in range(interval * 10):  # 0.1 saniye aralıklarla
                if not self.running:
                    break
                time.sleep(0.1)

def test_api_connection(base_url: str, log_func=None) -> bool:
    """API bağlantısını test et"""
    client = HoneypotAPIClient(base_url, log_func)
    return client.check_connection()

if __name__ == "__main__":
    # Test
    import logging
    logging.basicConfig(level=logging.INFO)
    
    def test_log(msg):
        print(f"[TEST] {msg}")
    
    # Test API client
    client = HoneypotAPIClient("https://honeypot.yesnext.com.tr", test_log)
    
    # Test connection
    if client.check_connection():
        print("✅ API bağlantısı başarılı")
    else:
        print("❌ API bağlantısı başarısız")
