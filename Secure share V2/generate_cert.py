#!/usr/bin/env python3
"""
Generate self-signed SSL certificate for local HTTPS testing
"""
from OpenSSL import crypto
import socket

def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "192.168.1.100"

def generate_self_signed_cert(hostname=None):
    """Generate a self-signed SSL certificate"""
    
    if hostname is None:
        hostname = get_local_ip()
    
    print(f"\n{'='*60}")
    print("Generating Self-Signed SSL Certificate")
    print(f"{'='*60}\n")
    print(f"Hostname: {hostname}")
    
    # Create key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    
    # Create certificate
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "SecureShare"
    cert.get_subject().OU = "Development"
    cert.get_subject().CN = hostname
    
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for 1 year
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    
    # Add Subject Alternative Name (SAN) for IP
    san_list = [
        f"IP:{hostname}",
        "DNS:localhost",
        "IP:127.0.0.1"
    ]
    
    cert.add_extensions([
        crypto.X509Extension(
            b"subjectAltName",
            False,
            ", ".join(san_list).encode()
        ),
        crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
        crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
        crypto.X509Extension(b"extendedKeyUsage", True, b"serverAuth"),
    ])
    
    cert.sign(k, 'sha256')
    
    # Save certificate
    with open("cert.pem", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    # Save private key
    with open("key.pem", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    
    print(f"\n✓ Certificate generated successfully!")
    print(f"✓ Files created: cert.pem, key.pem")
    print(f"\n{'='*60}")
    print("IMPORTANT: Accept Security Warning")
    print(f"{'='*60}")
    print("When accessing the site, you'll see a security warning")
    print("because this is a self-signed certificate.\n")
    print("To proceed:")
    print("  1. Click 'Advanced' or 'Show details'")
    print("  2. Click 'Proceed to [your-ip]' or 'Accept risk'")
    print("  3. On iPhone: Tap 'Show Details' > 'visit this website'")
    print("  4. On Android: Tap 'Advanced' > 'Proceed to [your-ip]'")
    print(f"\n{'='*60}")
    print(f"Access your site at: https://{hostname}:5000")
    print(f"{'='*60}\n")

if __name__ == '__main__':
    try:
        generate_self_signed_cert()
    except ImportError:
        print("\n✗ Error: pyOpenSSL not installed")
        print("\nInstall it with:")
        print("  pip install pyopenssl")
    except Exception as e:
        print(f"\n✗ Error: {e}")