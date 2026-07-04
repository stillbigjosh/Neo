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
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class EncryptionManager:
    def __init__(self, config):
        self.config = config
        self.encryption_key = self._load_or_generate_key()
        self.fernet = Fernet(self.encryption_key)
    
    def _load_or_generate_key(self):
        key_file = "encryption.key"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(key)
            return key
    
    def encrypt_data(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return self.fernet.encrypt(data)
    
    def decrypt_data(self, encrypted_data):
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode('utf-8')
        return self.fernet.decrypt(encrypted_data).decode('utf-8')
    
    def generate_aes_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        return key, salt
    
    def encrypt_aes(self, data, key):
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        iv = os.urandom(16)

        cipher = Cipher(
            algorithms.AES(key),
            modes.CFB(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        encrypted_data = encryptor.update(data) + encryptor.finalize()

        return iv + encrypted_data
    
    def decrypt_aes(self, encrypted_data, key):
        iv = encrypted_data[:16]
        data = encrypted_data[16:]

        cipher = Cipher(
            algorithms.AES(key),
            modes.CFB(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(data) + decryptor.finalize()

        return decrypted_data
    
    def generate_rsa_key_pair(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem
    
    def encrypt_rsa(self, data, public_key):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        pub_key = serialization.load_pem_public_key(
            public_key,
            backend=default_backend()
        )

        encrypted_data = pub_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_data
    
    def decrypt_rsa(self, encrypted_data, private_key):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        priv_key = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )

        decrypted_data = priv_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted_data
    
    def generate_hmac(self, data, key):
        import hmac
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return hmac.new(key, data, hashlib.sha256).digest()
    
    def verify_hmac(self, data, key, hmac_value):
        import hmac
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        expected_hmac = hmac.new(key, data, hashlib.sha256).digest()
        return hmac.compare_digest(expected_hmac, hmac_value)
    
    def generate_xor_key(self, length=32):
        return os.urandom(length)
    
    def xor_encrypt(self, data, key):
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        repeated_key = (key * ((len(data) // len(key)) + 1))[:len(data)]

        encrypted_data = bytes([data[i] ^ repeated_key[i] for i in range(len(data))])

        return encrypted_data
    
    def xor_decrypt(self, encrypted_data, key):
        return self.xor_encrypt(encrypted_data, key)
    
    def generate_steganography_key(self):
        return os.urandom(16)
    
    def hide_data_in_image(self, image_path, data, output_path, key):
        from PIL import Image
        import numpy as np
        
        image = Image.open(image_path)
        pixels = np.array(image)

        if isinstance(data, str):
            data = data.encode('utf-8')
        data_binary = ''.join(format(byte, '08b') for byte in data)

        data_length = len(data_binary)
        data_binary = format(data_length, '032b') + data_binary

        max_capacity = pixels.size // 8
        if len(data_binary) > max_capacity:
            raise ValueError("Image too small to hold the data")

        flat_pixels = pixels.flatten()
        for i in range(len(data_binary)):
            flat_pixels[i] = flat_pixels[i] & ~1
            flat_pixels[i] |= int(data_binary[i])

        stego_pixels = flat_pixels.reshape(pixels.shape)

        stego_image = Image.fromarray(stego_pixels)
        stego_image.save(output_path)

        return True
    
    def extract_data_from_image(self, image_path, key):
        from PIL import Image
        import numpy as np
        
        image = Image.open(image_path)
        pixels = np.array(image)

        flat_pixels = pixels.flatten()
        extracted_bits = [str(pixel & 1) for pixel in flat_pixels]

        data_length = int(''.join(extracted_bits[:32]), 2)

        data_binary = ''.join(extracted_bits[32:32+data_length])

        data = bytes(int(data_binary[i:i+8], 2) for i in range(0, len(data_binary), 8))

        return data.decode('utf-8')
