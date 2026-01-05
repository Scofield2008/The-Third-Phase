#!/usr/bin/env python3
"""
SecureShare CLI - Command line tool for encrypted file sharing
"""
import requests
import argparse
import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import secrets
import getpass

# Configuration
API_BASE_URL = os.environ.get('SECURESHARE_URL', 'http://localhost:5000')

def generate_random_password(length=32):
    """Generate a cryptographically secure random password"""
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def encrypt_file_password(file_path, password):
    """Encrypt file with password using AES-GCM"""
    # Generate salt and IV
    salt = os.urandom(16)
    iv = os.urandom(12)
    
    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    # Encrypt file
    aesgcm = AESGCM(key)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    
    return ciphertext, salt, iv

def encrypt_file_rsa(file_path):
    """Encrypt file with RSA key exchange"""
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Export public key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Export private key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Generate AES key
    aes_key = os.urandom(32)
    
    # Encrypt AES key with RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Encrypt file with AES
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    
    return ciphertext, iv, pem_public, encrypted_aes_key, pem_private

def decrypt_file_password(encrypted_data, salt, iv, password):
    """Decrypt file with password"""
    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    # Decrypt
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, encrypted_data, None)
    return plaintext

def decrypt_file_rsa(encrypted_data, iv, encrypted_aes_key, private_key_pem):
    """Decrypt file with RSA private key"""
    # Import private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem,
        password=None,
        backend=default_backend()
    )
    
    # Decrypt AES key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt file
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(iv, encrypted_data, None)
    return plaintext

def upload_file(file_path, expiry_hours=24, max_downloads=1, password=None, use_rsa=False):
    """Upload and encrypt a file"""
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found")
        return False
    
    file_size = os.path.getsize(file_path)
    if file_size > 500 * 1024 * 1024:
        print("Error: File size exceeds 500MB limit")
        return False
    
    print(f"Encrypting {os.path.basename(file_path)} ({file_size} bytes)...")
    
    try:
        if use_rsa:
            # RSA mode
            encrypted, iv, pem_public, encrypted_aes_key, pem_private = encrypt_file_rsa(file_path)
            
            files = {
                'encrypted': (os.path.basename(file_path) + '.enc', encrypted)
            }
            data = {
                'expiry_hours': expiry_hours,
                'max_downloads': max_downloads,
                'salt': '',
                'iv': base64.b64encode(iv).decode(),
                'password_protected': 'false',
                'rsa_public_key': base64.b64encode(pem_public).decode(),
                'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode(),
                'rsa_private_key': base64.b64encode(pem_private).decode()
            }
            
            generated_password = None
            private_key_b64 = base64.b64encode(pem_private).decode()
        else:
            # Password mode
            if not password:
                password = generate_random_password(32)
                generated_password = password
                print(f"Generated password: {password}")
            else:
                generated_password = None
            
            encrypted, salt, iv = encrypt_file_password(file_path, password)
            
            files = {
                'encrypted': (os.path.basename(file_path) + '.enc', encrypted)
            }
            data = {
                'expiry_hours': expiry_hours,
                'max_downloads': max_downloads,
                'salt': base64.b64encode(salt).decode(),
                'iv': base64.b64encode(iv).decode(),
                'password_protected': 'true'
            }
            private_key_b64 = None
        
        print(f"Uploading to {API_BASE_URL}...")
        response = requests.post(f'{API_BASE_URL}/api/upload', files=files, data=data)
        result = response.json()
        
        if response.status_code == 200 and result.get('success'):
            print("\n✓ Upload successful!")
            print(f"\nDownload URL: {result['download_url']}")
            print(f"Expires: {result['expiry_time']}")
            print(f"Max downloads: {result['max_downloads']}")
            
            if use_rsa:
                print(f"\n⚠️  CRITICAL: Save this RSA private key (Base64):")
                print(f"{private_key_b64}")
                
                # Optionally save to file
                key_file = file_path + '.rsa_key'
                with open(key_file, 'w') as f:
                    f.write(private_key_b64)
                print(f"\nPrivate key saved to: {key_file}")
            elif generated_password:
                print(f"\nPassword: {generated_password}")
            
            return True
        else:
            print(f"\n✗ Upload failed: {result.get('error', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"\n✗ Error: {str(e)}")
        return False

def download_file(file_id, output_path=None, password=None, rsa_private_key=None):
    """Download and decrypt a file"""
    try:
        print(f"Downloading file {file_id}...")
        
        response = requests.get(f'{API_BASE_URL}/api/file/{file_id}')
        result = response.json()
        
        if response.status_code != 200 or not result.get('success'):
            print(f"✗ Download failed: {result.get('error', 'Unknown error')}")
            return False
        
        # Parse response
        encrypted_hex = result['encrypted']
        encrypted = bytes.fromhex(encrypted_hex)
        salt = base64.b64decode(result['salt']) if result['salt'] else b''
        iv = base64.b64decode(result['iv'])
        filename = result['filename'].replace('.enc', '')
        
        if not output_path:
            output_path = filename
        
        print(f"Decrypting {filename}...")
        
        # Determine decryption method
        if result.get('rsa_public_key'):
            # RSA mode
            if not rsa_private_key:
                rsa_private_key = input("Enter RSA private key (Base64): ")
            
            encrypted_aes_key = base64.b64decode(result['encrypted_aes_key'])
            private_key_bytes = base64.b64decode(rsa_private_key)
            
            plaintext = decrypt_file_rsa(encrypted, iv, encrypted_aes_key, private_key_bytes)
        else:
            # Password mode
            if not password:
                password = getpass.getpass("Enter password: ")
            
            plaintext = decrypt_file_password(encrypted, salt, iv, password)
        
        # Save decrypted file
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        print(f"✓ File saved to: {output_path}")
        return True
        
    except Exception as e:
        print(f"✗ Error: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='SecureShare CLI - Encrypted file sharing')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Upload command
    upload_parser = subparsers.add_parser('upload', help='Upload and encrypt a file')
    upload_parser.add_argument('file', help='File to upload')
    upload_parser.add_argument('--expiry', type=int, default=24, help='Expiry time in hours (default: 24)')
    upload_parser.add_argument('--max-downloads', type=int, default=1, help='Max downloads (default: 1)')
    upload_parser.add_argument('--password', help='Custom password (auto-generated if not provided)')
    upload_parser.add_argument('--rsa', action='store_true', help='Use RSA key exchange')
    
    # Download command
    download_parser = subparsers.add_parser('download', help='Download and decrypt a file')
    download_parser.add_argument('file_id', help='File ID from download URL')
    download_parser.add_argument('--output', help='Output file path')
    download_parser.add_argument('--password', help='Password for decryption')
    download_parser.add_argument('--rsa-key', help='RSA private key (Base64) for decryption')
    
    args = parser.parse_args()
    
    if args.command == 'upload':
        success = upload_file(
            args.file,
            expiry_hours=args.expiry,
            max_downloads=args.max_downloads,
            password=args.password,
            use_rsa=args.rsa
        )
        sys.exit(0 if success else 1)
        
    elif args.command == 'download':
        success = download_file(
            args.file_id,
            output_path=args.output,
            password=args.password,
            rsa_private_key=args.rsa_key
        )
        sys.exit(0 if success else 1)
        
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()