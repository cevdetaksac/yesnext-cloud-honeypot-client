# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client - API Management Module

Bu modül, Cloud Honeypot sunucusu ile olan tüm API iletişimini yönetir.
İstemci kaydı, IP güncellemeleri, heartbeat gönderimi, tünel durumu raporlama
ve saldırı sayısı sorgulama gibi işlemleri merkezileştirir.

Sınıflar:
    - HoneypotAPIClient: API ile etkileşim kurmak için ana sınıf.
    - AsyncAttackCounter: Saldırı sayacını asenkron olarak günceller.

Fonksiyonlar:
    - test_api_connection: API bağlantısını test eder.
"""

# Import constants for timeout values
try:
    from client_constants import API_REQUEST_TIMEOUT
except ImportError:
    API_REQUEST_TIMEOUT = 8

import json
import requests
import threading
import time
from typing import Dict, Optional, Any, Union
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
    
    def api_request(self, method: str, endpoint: str, data: Optional[Dict] = None,
                   params: Optional[Dict] = None, timeout: int = API_REQUEST_TIMEOUT, verbose_logging: bool = True) -> Optional[Dict]:
        """API isteği gönder"""
        try:
            url = f"{self.base_url}/{endpoint.lstrip('/')}"
            
            # Sık çağrılan endpointler için sessiz mod
            from client_constants import VERBOSE_LOGGING
            is_frequent_endpoint = endpoint in ['attack-count', 'agent/heartbeat', 'agent/tunnel-status']
            show_logs = (verbose_logging or VERBOSE_LOGGING) and not is_frequent_endpoint
            
            if show_logs:
                self.log(f"[API] {method.upper()} isteği: {url}")
            
            if params and show_logs:
                self.log(f"[API] Params: {params}")
            
            if data and show_logs:
                self.log(f"[API] JSON: {data}")
            
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=timeout,
                verify=False
            )
            
            if show_logs or response.status_code != 200:
                self.log(f"[API] Yanıt: HTTP {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                if show_logs:
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

    def register_client(self, server_name: str, ip_address: str) -> Optional[str]:
        """İstemciyi API'ye kaydeder ve bir token alır."""
        try:
            payload = {"server_name": server_name, "ip": ip_address}
            response = self.api_request("POST", "register", data=payload)
            if response and "token" in response:
                token = response["token"]
                self.log(f"İstemci başarıyla kaydedildi, token alındı: {token[:8]}...")
                return token
            self.log("İstemci kaydı başarısız oldu veya token alınamadı.")
            return None
        except Exception as e:
            self.log(f"[API] İstemci kaydı sırasında hata: {e}")
            return None

    def update_client_ip(self, token: str, new_ip: str) -> bool:
        """İstemcinin genel IP adresini API'de günceller."""
        try:
            payload = {"token": token, "ip": new_ip}
            response = self.api_request("POST", "update-ip", data=payload)
            if response:
                self.log(f"IP adresi başarıyla güncellendi: {new_ip}")
                return True
            self.log(f"IP adresi güncellemesi başarısız oldu.")
            return False
        except Exception as e:
            self.log(f"[API] IP güncelleme hatası: {e}")
            return False

    def send_heartbeat(self, token: str, ip: str, hostname: str, running: bool, status: str) -> bool:
        """API'ye bir heartbeat sinyali gönderir."""
        try:
            payload = {
                "token": token, "ip": ip, "hostname": hostname,
                "running": running, "status": status
            }
            response = self.api_request("POST", "heartbeat", data=payload)
            return response is not None
        except Exception as e:
            self.log(f"[API] Heartbeat gönderme hatası: {e}")
            return False

    def report_open_ports(self, token: str, ports: list) -> bool:
        """İstemcideki açık portları API'ye raporlar."""
        try:
            payload = {"token": token, "ports": ports}
            response = self.api_request("POST", "agent/open-ports", data=payload)
            return response is not None
        except Exception as e:
            self.log(f"[API] Açık portları raporlama hatası: {e}")
            return False

    def report_tunnel_action(self, token: str, service: str, action: str, new_port: Optional[int] = None) -> bool:
        """Bir tünel eylemini (başlatma/durdurma) API'ye bildirir."""
        try:
            payload = {
                "token": token,
                "service": str(service or "").upper(),
                "action": "start" if action == "start" else "stop",
            }
            if new_port and str(new_port) != '-':
                payload["new_port"] = int(str(new_port))

            response = self.api_request("POST", "premium/tunnel-set", data=payload)
            if isinstance(response, dict) and response.get("status") in ("queued", "ok", "success"):
                self.log(f"Tünel eylemi bildirildi: {payload}")
                return True
            
            self.log(f"Tünel eylemi bildirimi başarısız: {response}")
            return False
        except Exception as e:
            self.log(f"Tünel eylemi raporlama hatası: {e}")
            return False
    
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
                            
                            # OpenCanary servis durumunu da kontrol et
                            canary_status = health_data.get("opencanary_status", "unknown")
                            self.log(f"API connection successful - {client_count} clients registered, OpenCanary: {canary_status}")
                            
                            # Eğer OpenCanary çalışmıyorsa uyarı ver
                            if canary_status != "running":
                                self.log(f"⚠️ WARNING: OpenCanary service is not running! Status: {canary_status}")
                                
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
            params = {'token': token}
            result = self.api_request('GET', 'attack-count', params=params, verbose_logging=False)
            
            if result and 'count' in result:
                count = int(result['count'])
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

# ===================== API WRAPPER FUNCTIONS ===================== #
# Purpose: High-level API request functions for client integration

def api_request_with_token(api_client, token: str, method: str, endpoint: str, 
                          data: Optional[Dict] = None, params: Optional[Dict] = None, timeout: int = API_REQUEST_TIMEOUT, 
                          json: Optional[Dict] = None) -> Optional[Dict]:
    """API request wrapper with token authentication"""
    try:
        if token:
            params = params or {}
            params['token'] = token
        
        return api_client.api_request(
            method=method, endpoint=endpoint,
            data=json if json else data, params=params, timeout=timeout
        )
    except Exception as e:
        if hasattr(api_client, 'log') and api_client.log:
            api_client.log(f"[API] Wrapper hatası: {e}")
        return None

# ===================== HEARTBEAT & IP MANAGEMENT ===================== #
# Purpose: Client IP tracking and heartbeat communication

def update_client_ip_api(api_url: str, token: str, new_ip: str, log_func=None):
    """Update client IP address via API with improved error handling"""
    import requests
    import requests.exceptions
    
    try:
        if not token: 
            if log_func: log_func("IP update skipped: no token")
            return False
        
        response = requests.post(f"{api_url}/update-ip", 
                               json={"token": token, "ip": new_ip}, timeout=API_REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            # IP güncelleme sadece değişim oldğunda loglanacak
            if log_func: log_func(f"IP updated to: {new_ip}")
            return True
        else:
            if log_func: log_func(f"IP update server error: HTTP {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError as e:
        if log_func: log_func(f"IP update network error: {e}")
        return False
    except requests.exceptions.Timeout as e:
        if log_func: log_func(f"IP update timeout error: {e}")
        return False
    except requests.exceptions.RequestException as e:
        if log_func: log_func(f"IP update request error: {e}")
        return False
    except Exception as e:
        if log_func: log_func(f"IP update unexpected error: {e}")
        return False

def send_heartbeat_api(api_url: str, token: str, ip: str, hostname: str, 
                      running: bool, status_override: Optional[str] = None, log_func=None):
    """Send single heartbeat to API with improved error handling"""
    import requests
    import requests.exceptions
    
    try:
        if not token:
            if log_func: log_func("heartbeat skipped: no token")
            return False
        
        # Support for new idle status and intelligent status detection
        if status_override in ("online", "idle", "offline", "error"):
            status = status_override
        else:
            status = "online" if running else "offline"
        
        payload = {
            "token": token, "ip": ip, "hostname": hostname,
            "running": running, "status": status
        }
        
        # Increased timeout and better error handling  
        response = requests.post(f"{api_url}/heartbeat", json=payload, timeout=API_REQUEST_TIMEOUT)
        
        # Check response status
        if response.status_code == 200:
            # Sadece önemli durumlarda logla (status değişiminde vs.)
            return True
        else:
            if log_func: log_func(f"heartbeat server error: HTTP {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError as e:
        if log_func: log_func(f"heartbeat network error: {e}")
        return False
    except requests.exceptions.Timeout as e:
        if log_func: log_func(f"heartbeat timeout error: {e}")
        return False
    except requests.exceptions.RequestException as e:
        if log_func: log_func(f"heartbeat request error: {e}")
        return False
    except Exception as e:
        if log_func: log_func(f"heartbeat unexpected error: {e}")
        return False

# ===================== TUNNEL ACTION REPORTING ===================== #
# Purpose: Report tunnel state changes to honeypot server

def report_tunnel_action_api(api_request_func, token: str, service: str, action: str,
                           new_port: Optional[Union[str, int]] = None, log_func=None) -> bool:
    """Report tunnel action to API using provided api_request function"""
    try:
        if not token:
            if log_func: log_func("Token yok; eylem bildirilemedi")
            return False

        payload: Dict[str, Any] = {
            "token": token,
            "service": str(service or "").upper(),
            "action": action if action in ("start", "stop") else "stop",
        }
        if new_port and str(new_port) != '-':
            payload["new_port"] = int(str(new_port))

        resp = api_request_func("POST", "premium/tunnel-set", json=payload)
        if isinstance(resp, dict) and resp.get("status") in ("queued", "ok", "success"):
            if log_func: log_func(f"Tünel eylemi bildirildi: {payload}")
            return True

        if log_func: log_func(f"Tünel eylemi bildirimi başarısız: {resp}")
        return False
    except Exception as e:
        if log_func: log_func(f"Tünel eylemi raporlanırken hata: {e}")
        return False

# ===================== CLIENT REGISTRATION & PORT REPORTING ===================== #
# Purpose: Client registration and port status reporting

def register_client_api(api_url: str, server_name: str, ip: str, token_save_func=None, log_func=None) -> Optional[str]:
    """Register client with API and get token - improved error handling"""
    import requests
    import requests.exceptions
    
    try:
        payload = {"server_name": f"{server_name} ({ip})", "ip": ip}
        response = requests.post(f"{api_url}/register", json=payload, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            token = data.get("token")
            if token:
                if token_save_func:
                    token_save_func(token)
                if log_func: log_func(f"Client registration successful: {server_name}")
                return token
            else:
                if log_func: log_func("Registration failed: no token in response")
                return None
        else:
            if log_func: log_func(f"Registration server error: HTTP {response.status_code}")
            return None
            
    except requests.exceptions.ConnectionError as e:
        if log_func: log_func(f"Registration network error: {e}")
        return None
    except requests.exceptions.Timeout as e:
        if log_func: log_func(f"Registration timeout error: {e}")
        return None
    except requests.exceptions.RequestException as e:
        if log_func: log_func(f"Registration request error: {e}")
        return None
    except Exception as e:
        if log_func: log_func(f"Registration unexpected error: {e}")
        return None

def report_open_ports_api(api_url: str, token: str, ports: list, log_func=None) -> bool:
    """Report open ports to API with improved error handling"""
    import requests
    import requests.exceptions
    
    try:
        if not token:
            if log_func: log_func("Open ports report skipped: no token")
            return False
        
        payload = {"token": token, "ports": ports}
        response = requests.post(f"{api_url}/agent/open-ports", json=payload, timeout=API_REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            if log_func: log_func(f"Open ports reported successfully: {len(ports)} ports")
            return True
        else:
            if log_func: log_func(f"Open ports server error: HTTP {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError as e:
        if log_func: log_func(f"Open ports network error: {e}")
        return False
    except requests.exceptions.Timeout as e:
        if log_func: log_func(f"Open ports timeout error: {e}")
        return False
    except requests.exceptions.RequestException as e:
        if log_func: log_func(f"Open ports request error: {e}")
        return False
    except Exception as e:
        if log_func: log_func(f"Open ports unexpected error: {e}")
        return False
