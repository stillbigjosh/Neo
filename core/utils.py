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
import json
import random
import string
import base64
import hashlib
from datetime import datetime, timedelta

def generate_random_string(length=8):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def generate_random_filename(extension=""):
    return f"{generate_random_string(12)}{extension}"

def generate_domain(length=12):
    tld = random.choice(['com', 'net', 'org', 'io', 'co'])
    return f"{generate_random_string(length)}.{tld}"

def generate_user_agent():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    ]
    return random.choice(user_agents)

def get_file_hash(file_path, algorithm="sha256"):
    hash_func = getattr(hashlib, algorithm)()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

def encode_base64(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('utf-8')

def decode_base64(encoded_data):
    if isinstance(encoded_data, str):
        encoded_data = encoded_data.encode('utf-8')
    return base64.b64decode(encoded_data)

def timestamp_to_datetime(timestamp):
    return datetime.fromtimestamp(timestamp)

def datetime_to_timestamp(dt):
    return dt.timestamp()

def is_expired(timestamp, expiration_seconds):
    return (datetime.now() - timestamp_to_datetime(timestamp)).total_seconds() > expiration_seconds

def get_file_size(file_path):
    return os.path.getsize(file_path)

def create_directory_if_not_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def read_file(file_path):
    with open(file_path, 'r') as f:
        return f.read()

def write_file(file_path, content):
    with open(file_path, 'w') as f:
        f.write(content)

def append_file(file_path, content):
    with open(file_path, 'a') as f:
        f.write(content)

def load_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def save_json(file_path, data):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

def validate_ip_address(ip_address):
    parts = ip_address.split('.')
    if len(parts) != 4:
        return False
    
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def validate_domain(domain):
    if len(domain) > 253:
        return False
    
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    
    for part in parts:
        if not part or len(part) > 63:
            return False
        if not all(c.isalnum() or c == '-' for c in part):
            return False
        if part.startswith('-') or part.endswith('-'):
            return False
    
    return True

def generate_sleep_time(base_time, jitter_percent):
    jitter = base_time * (jitter_percent / 100)
    min_sleep = base_time - jitter
    max_sleep = base_time + jitter
    return random.uniform(min_sleep, max_sleep)

def format_datetime(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def format_bytes(bytes_value):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def truncate_string(s, length=50, suffix='...'):
    if len(s) <= length:
        return s
    return s[:length-len(suffix)] + suffix
