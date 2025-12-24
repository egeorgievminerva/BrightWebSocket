#!/usr/bin/env python3
"""
RSA Public Key Encryption Web Server (Native HTTP Server)

A lightweight web server using Python's built-in http.server module
that provides RSA public key encryption services via HTTP REST API.
Accepts text data via HTTP requests and returns encrypted results.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
import json
import base64
import logging
import sys
import os
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global variables for RSA key pair
private_key = None
public_key = None

def load_private_key_from_pem(pem_file_path: str) -> rsa.RSAPrivateKey:
    """Load RSA private key from PEM file."""
    try:
        if not os.path.exists(pem_file_path):
            raise FileNotFoundError(f"Private key file not found: {pem_file_path}")

        with open(pem_file_path, 'rb') as f:
            pem_data = f.read()

        private_key = serialization.load_pem_private_key(
            pem_data,
            password=None  # Assumes no password protection
        )

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError(f"File {pem_file_path} does not contain an RSA private key")

        logger.info(f"Loaded RSA private key from {pem_file_path} ({private_key.key_size} bits)")
        return private_key

    except Exception as e:
        logger.error(f"Failed to load private key from {pem_file_path}: {e}")
        raise


def load_public_key_from_certificate(cert_file_path: str) -> rsa.RSAPublicKey:
    """Load RSA public key from PEM certificate file."""
    try:
        if not os.path.exists(cert_file_path):
            raise FileNotFoundError(f"Certificate file not found: {cert_file_path}")

        with open(cert_file_path, 'rb') as f:
            pem_data = f.read()

        # Load the certificate
        cert = x509.load_pem_x509_certificate(pem_data)
        
        # Extract the public key from the certificate
        public_key = cert.public_key()

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError(f"Certificate {cert_file_path} does not contain an RSA public key")

        logger.info(f"Loaded RSA public key from certificate {cert_file_path} ({public_key.key_size} bits)")
        return public_key

    except Exception as e:
        logger.error(f"Failed to load public key from certificate {cert_file_path}: {e}")
        raise


def load_keys_from_files(cert_path: str = None, private_key_path: str = None) -> tuple:
    """Load RSA keys from certificate or private key PEM files."""
    global private_key, public_key

    loaded_private_key = None
    loaded_public_key = None

    # Load private key if provided
    if private_key_path:
        loaded_private_key = load_private_key_from_pem(private_key_path)
        # Extract public key from private key
        loaded_public_key = loaded_private_key.public_key()
        logger.info("Derived public key from private key")

    # Load certificate if provided (encrypt-only mode)
    if cert_path:
        loaded_public_key = load_public_key_from_certificate(cert_path)

    # Set global variables
    private_key = loaded_private_key
    public_key = loaded_public_key

    if private_key and public_key:
        logger.info(f"Running in FULL mode (encrypt and decrypt) - {public_key.key_size} bits")
    elif public_key:
        logger.info(f"Running in ENCRYPT-ONLY mode - {public_key.key_size} bits")
    else:
        raise ValueError("No keys loaded. Must specify either --certificate or --private-key-pem")

    return private_key, public_key




def encrypt_data(dataInHexStr: str, pub_key) -> str:
    """Encrypt dataInHexStr using RSA public key and return hex encoded result."""
    try:
        # Decode the hex encoded string into original data bytes
        data_bytes = bytes.fromhex(dataInHexStr)

        # Encrypt using PKCS1v15 padding (same as C implementation)
        encrypted = pub_key.encrypt(
            data_bytes,
            padding.PKCS1v15()
        )

        # Return hex encoded encrypted data
        result = encrypted.hex()
        logger.info(f"encrypt_data (input: {dataInHexStr}) (output: {result})")
        return result

    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise


def decrypt_data(encrypted_data: str, priv_key) -> str:
    """Decrypt hex encoded data using RSA private key."""
    try:
        # Decode from hex
        encrypted_bytes = bytes.fromhex(encrypted_data)

        # Decrypt using PKCS1v15 padding (same as C implementation)
        decrypted = priv_key.decrypt(
            encrypted_bytes,
            padding.PKCS1v15()
        )

        # Return hex encoded string of the decrypted data
        result = decrypted.hex()
        logger.info(f"decrypt_data (input: {encrypted_data}) (output: {result})")
        return result

    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Thread per request HTTP Server"""
    allow_reuse_address = True
    daemon_threads = True


class RSAServerHandler(BaseHTTPRequestHandler):
    """HTTP request handler for RSA encryption server."""

    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        logger.info(f"{self.address_string()} - {format % args}")

    def send_json_response(self, data: Dict[str, Any], status_code: int = 200):
        """Send JSON response with proper headers."""
        response_body = json.dumps(data, indent=2).encode('utf-8')

        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

        if self.command != 'HEAD':
            self.wfile.write(response_body)

    def send_error_response(self, message: str, status_code: int = 400):
        """Send error response."""
        self.send_json_response({'error': message}, status_code)

    def get_request_body(self) -> Optional[Dict[str, Any]]:
        """Parse JSON request body."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                return {}

            body = self.rfile.read(content_length).decode('utf-8')
            return json.loads(body)
        except (ValueError, json.JSONDecodeError) as e:
            logger.error(f"Failed to parse request body: {e}")
            return None

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        """Handle GET requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == '/health':
            self.handle_health()
        else:
            self.send_error_response('Endpoint not found', 404)

    def do_POST(self):
        """Handle POST requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        logger.info(f"do_POST headers: {self.headers}")


        if path == '/encrypt':
            self.handle_encrypt()
        elif path == '/decrypt':
            self.handle_decrypt()
        else:
            self.send_error_response('Endpoint not found', 404)

    def handle_health(self):
        """Handle health check endpoint."""
        # Determine server mode
        if private_key is not None and public_key is not None:
            key_mode = 'full' # Both encrypt and decrypt
        elif public_key is not None:
            key_mode = 'encrypt-only' # Only encrypt
        else:
            key_mode = 'no-keys'

        response = {
            'status': 'healthy',
            'service': 'RSA Encryption Server (Native)',
            'key_size': public_key.key_size if public_key else None
        }
        self.send_json_response(response)


    def handle_encrypt(self):
        """Handle text encryption endpoint."""
        if public_key is None:
            self.send_error_response('No public key available. Must specify --certificate or --private-key-pem.', 412)
            return

        # Check content type
        content_type = self.headers.get('Content-Type', '')
        if not content_type.startswith('application/json'):
            self.send_error_response('Content-Type must be application/json', 400)
            return

        # Parse request body
        data = self.get_request_body()
        if data is None:
            self.send_error_response('Invalid JSON in request body', 400)
            return

        if 'data' not in data:
            self.send_error_response('Missing "data" field in request body', 400)
            return

        text_to_encrypt = data['data']
        if not isinstance(text_to_encrypt, str):
            self.send_error_response('"data" field must be a string', 400)
            return

        # Check data length (RSA has size limits)
        max_length = (public_key.key_size // 8) - 11  # PKCS1v15 padding overhead
        try:
            data_bytes = bytes.fromhex(text_to_encrypt)
        except ValueError:
            self.send_error_response('"data" field must be a valid hex string', 400)
            return

        if len(data_bytes) > max_length:
            self.send_error_response(
                f'Data too long. Maximum length is {max_length} bytes for {public_key.key_size}-bit key',
                400
            )
            return

        try:
            # Encrypt the data
            encrypted_data = encrypt_data(text_to_encrypt, public_key)

            response = {
                'encrypted_data': encrypted_data,
                'original_length': len(text_to_encrypt),
                'encrypted_length': len(encrypted_data),
                'encoding': 'hex'
            }
            self.send_json_response(response)

        except Exception as e:
            logger.error(f"Encryption request failed: {str(e)}")
            self.send_error_response('Encryption failed', 500)

    def handle_decrypt(self):
        """Handle text decryption endpoint."""
        if private_key is None:
            if public_key is not None:
                self.send_error_response('Decryption not available in encrypt-only mode (no private key loaded)', 403)
            else:
                self.send_error_response('No private key available. Must specify --private-key-pem.', 412)
            return

        # Check content type
        content_type = self.headers.get('Content-Type', '')
        if not content_type.startswith('application/json'):
            self.send_error_response('Content-Type must be application/json', 400)
            return

        # Parse request body
        data = self.get_request_body()
        if data is None:
            self.send_error_response('Invalid JSON in request body', 400)
            return

        if 'encrypted_data' not in data:
            self.send_error_response('Missing "encrypted_data" field in request body', 400)
            return

        encrypted_data = data['encrypted_data']
        if not isinstance(encrypted_data, str):
            self.send_error_response('"encrypted_data" field must be a string', 400)
            return

        try:
            # Decrypt the data
            decrypted_data = decrypt_data(encrypted_data, private_key)

            response = {
                'decrypted_data': decrypted_data,
                'decrypted_length': len(decrypted_data)
            }
            self.send_json_response(response)

        except Exception as e:
            errMsg = f"Decryption request failed: {str(e)}"
            logger.error(errMsg)
            self.send_error_response(errMsg, 500)



def run_server(host: str = '0.0.0.0', port: int = 5000):
    """Run the RSA encryption server."""
    server_address = (host, port)

    try:
        httpd = ThreadedHTTPServer(server_address, RSAServerHandler)
        logger.info(f"RSA Encryption Server starting on http://{host}:{port}")
        logger.info("Available endpoints:")
        logger.info("  GET  /health      - Server health check")
        logger.info("  POST /encrypt     - Encrypt text data")
        logger.info("  POST /decrypt     - Decrypt encrypted data (if private key loaded)")
        logger.info("Press Ctrl+C to stop the server")

        httpd.serve_forever()

    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        if 'httpd' in locals():
            httpd.server_close()
        logger.info("Server stopped")


def main():
    """Main function."""
    import argparse

    parser = argparse.ArgumentParser(
        description='RSA Encryption Server',
        epilog="""Key loading modes:
  - Only --certificate: Encrypt-only mode (no decryption)
  - Only --private-key-pem: Full mode (public key derived from private key)
  
Examples:
  %(prog)s --certificate server.cer --port 8080
  %(prog)s --host 127.0.0.1 --private-key-pem private.key
  %(prog)s --host 192.168.1.100 --certificate cert.pem""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to (default: 5000)')
    parser.add_argument('--certificate', type=str,
                       help='Path to PEM certificate file (encrypt-only mode)')
    parser.add_argument('--private-key-pem', type=str,
                       help='Path to PEM file containing RSA private key (full mode)')

    args = parser.parse_args()

    # Validate arguments
    if not args.certificate and not args.private_key_pem:
        parser.error("Must specify either --certificate or --private-key-pem")
    
    if args.certificate and args.private_key_pem:
        parser.error("Cannot specify both --certificate and --private-key-pem")

    try:
        # Load keys from files
        logger.info("Loading RSA keys...")
        load_keys_from_files(args.certificate, args.private_key_pem)

    except Exception as e:
        logger.error(f"Failed to load keys: {e}")
        sys.exit(1)

    # Start the server
    run_server(args.host, args.port)


if __name__ == '__main__':
    main()
