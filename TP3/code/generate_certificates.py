#!/usr/bin/env python3
import os
import subprocess
import argparse
from pathlib import Path

def run_command(cmd, cwd=None):
    """Execute a shell command and return its output"""
    print(f"Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        raise Exception(f"Command failed with exit code {result.returncode}")
    return result.stdout

def create_directory(path):
    """Create directory if it doesn't exist"""
    if not os.path.exists(path):
        os.makedirs(path)
        print(f"Created directory: {path}")

def generate_ca_certificate(cert_dir):
    """Generate CA private key and certificate"""
    print("\n=== Generating CA Certificate ===")
    ca_key = os.path.join(cert_dir, "ca.key")
    ca_cert = os.path.join(cert_dir, "ca.crt")
    
    # Generate CA private key
    run_command([
        "openssl", "genrsa", 
        "-out", ca_key, 
        "4096"
    ])
    
    # Generate CA certificate
    run_command([
        "openssl", "req", 
        "-new", "-x509", 
        "-key", ca_key, 
        "-out", ca_cert,
        "-days", "3650",
        "-subj", "/CN=BLP-Model CA"
    ])
    
    print(f"CA certificate generated: {ca_cert}")
    print(f"CA private key generated: {ca_key}")
    return ca_key, ca_cert

def generate_server_certificate(cert_dir, ca_key, ca_cert):
    """Generate server private key and certificate"""
    print("\n=== Generating Server Certificate ===")
    server_key = os.path.join(cert_dir, "server.key")
    server_csr = os.path.join(cert_dir, "server.csr")
    server_cert = os.path.join(cert_dir, "server.crt")
    server_ext = os.path.join(cert_dir, "server.ext")
    
    # Create server extension file for SAN
    with open(server_ext, "w") as f:
        f.write("""
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
        """)
    
    # Generate server private key
    run_command([
        "openssl", "genrsa", 
        "-out", server_key, 
        "2048"
    ])
    
    # Generate server CSR
    run_command([
        "openssl", "req", 
        "-new", 
        "-key", server_key, 
        "-out", server_csr,
        "-subj", "/CN=BLP-Model Server"
    ])
    
    # Sign server certificate with CA
    run_command([
        "openssl", "x509", 
        "-req", 
        "-in", server_csr, 
        "-CA", ca_cert, 
        "-CAkey", ca_key,
        "-CAcreateserial",
        "-out", server_cert,
        "-days", "365",
        "-extfile", server_ext,
        "-extensions", "v3_req"
    ])
    
    print(f"Server certificate generated: {server_cert}")
    print(f"Server private key generated: {server_key}")
    return server_key, server_cert

def generate_client_certificate(cert_dir, ca_key, ca_cert, client_name="client"):
    """Generate client private key and certificate"""
    print(f"\n=== Generating Client Certificate ({client_name}) ===")
    client_key = os.path.join(cert_dir, f"{client_name}.key")
    client_csr = os.path.join(cert_dir, f"{client_name}.csr")
    client_cert = os.path.join(cert_dir, f"{client_name}.crt")
    
    # Generate client private key
    run_command([
        "openssl", "genrsa", 
        "-out", client_key, 
        "2048"
    ])
    
    # Generate client CSR
    run_command([
        "openssl", "req", 
        "-new", 
        "-key", client_key, 
        "-out", client_csr,
        "-subj", f"/CN=BLP-Model {client_name.capitalize()}"
    ])
    
    # Sign client certificate with CA
    run_command([
        "openssl", "x509", 
        "-req", 
        "-in", client_csr, 
        "-CA", ca_cert, 
        "-CAkey", ca_key,
        "-CAcreateserial",
        "-out", client_cert,
        "-days", "365"
    ])
    
    print(f"Client certificate generated: {client_cert}")
    print(f"Client private key generated: {client_key}")
    return client_key, client_cert

def main():
    parser = argparse.ArgumentParser(description="Generate certificates for TLS with mutual authentication")
    parser.add_argument("--cert-dir", default="./certs", help="Directory to store certificates")
    parser.add_argument("--client-name", default="client", help="Name for the client certificate")
    args = parser.parse_args()
    
    cert_dir = os.path.abspath(args.cert_dir)
    create_directory(cert_dir)
    
    ca_key, ca_cert = generate_ca_certificate(cert_dir)
    server_key, server_cert = generate_server_certificate(cert_dir, ca_key, ca_cert)
    client_key, client_cert = generate_client_certificate(cert_dir, ca_key, ca_cert, args.client_name)
    
    print("\n=== Certificate Generation Complete ===")
    print(f"All certificates and keys are stored in: {cert_dir}")
    print("\nFor server configuration:")
    print(f"  CA Certificate: {os.path.basename(ca_cert)}")
    print(f"  Server Certificate: {os.path.basename(server_cert)}")
    print(f"  Server Private Key: {os.path.basename(server_key)}")
    print("\nFor client configuration:")
    print(f"  CA Certificate: {os.path.basename(ca_cert)}")
    print(f"  Client Certificate: {os.path.basename(client_cert)}")
    print(f"  Client Private Key: {os.path.basename(client_key)}")

if __name__ == "__main__":
    main()
