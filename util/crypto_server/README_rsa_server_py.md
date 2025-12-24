# Python RSA Public Key Encryption Web Server

A lightweight web server using Python's built-in http.server module that provides RSA public key encryption services via HTTP REST API. The server accepts hex-encoded data and returns encrypted results using RSA encryption with PKCS1v15 padding.

## Features

- **Certificate Support**: Load public key from X.509 PEM certificate for encrypt-only mode
- **Private Key Support**: Load private key for full mode (encrypt and decrypt)
- **Hex Encoding**: Uses hex encoding for data (compatible with C implementation)
- **Text Encryption**: Encrypt hex-encoded data using RSA public key with PKCS1v15 padding
- **Text Decryption**: Decrypt encrypted data (only in full mode)
- **REST API**: Clean JSON-based HTTP API for all operations
- **Security**: Uses PKCS1v15 padding (compatible with Roku BrightScript)
- **Error Handling**: Comprehensive error handling and validation
- **Signal Handling**: Graceful shutdown on SIGTERM/SIGINT

## Quick Start

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Start the server:
```bash
# Encrypt-only mode (using certificate)
python rsa_server.py --certificate server.cer

# Full mode (encrypt and decrypt with private key)
python rsa_server.py --private-key-pem private.key

# Custom host and port
python rsa_server.py --host 127.0.0.1 --port 8080 --certificate server.cer

# Bind to specific IP
python rsa_server.py --host 192.168.1.100 --private-key-pem private.key
```

The server will start on `http://0.0.0.0:5000` by default.

**Note:** You MUST specify either `--certificate` (encrypt-only) or `--private-key-pem` (full mode). You cannot specify both.

### Basic Usage

**Encrypt hex-encoded data:**
```bash
# Data must be hex-encoded string
curl -X POST http://localhost:5000/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "48656c6c6f"}'
```

**Decrypt encrypted data (full mode only):**
```bash
curl -X POST http://localhost:5000/decrypt \
  -H "Content-Type: application/json" \
  -d '{"encrypted_data": "<hex-encoded-encrypted-data>"}'
```

**Check server health:**
```bash
curl http://localhost:5000/health
```

## API Documentation

### Endpoints

#### GET `/health`
Check if the server is running and healthy.

**Response:**
```json
{
  "status": "healthy",
  "service": "RSA Encryption Server (Native)",
  "key_size": 2048
}
```

#### POST `/encrypt`
Encrypt hex-encoded data using the server's RSA public key.

**Request Body:**
```json
{
  "data": "48656c6c6f"  // hex-encoded data
}
```

**Response:**
```json
{
  "encrypted_data": "a1b2c3d4...",  // hex-encoded encrypted data
  "original_length": 10,
  "encrypted_length": 512,
  "encoding": "hex"
}
```

**Error Response (400 - Data too long):**
```json
{
  "error": "Data too long. Maximum length is 245 bytes for 2048-bit key"
}
```

#### POST `/decrypt`
Decrypt RSA encrypted data (only available in full mode with private key).

**Request Body:**
```json
{
  "encrypted_data": "a1b2c3d4..."  // hex-encoded encrypted data
}
```

**Response:**
```json
{
  "decrypted_data": "48656c6c6f",  // hex-encoded decrypted data
  "decrypted_length": 10
}
```

**Error Response (403 - Encrypt-only mode):**
```json
{
  "error": "Decryption not available in encrypt-only mode (no private key loaded)"
}
```

## Command-Line Options

```
usage: rsa_server.py [-h] [--host HOST] [--port PORT] [--certificate CERTIFICATE]
                     [--private-key-pem PRIVATE_KEY_PEM]

RSA Encryption Server

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           Host to bind to (default: 0.0.0.0)
  --port PORT           Port to bind to (default: 5000)
  --certificate CERTIFICATE
                        Path to PEM certificate file (encrypt-only mode)
  --private-key-pem PRIVATE_KEY_PEM
                        Path to PEM file containing RSA private key (full mode)
```

## Data Limits

RSA encryption has inherent size limits based on the key size and padding scheme:

| Key Size | Max Plaintext (bytes) |
|----------|----------------------|
| 1024-bit | 117 bytes           |
| 2048-bit | 245 bytes           |
| 3072-bit | 373 bytes           |
| 4096-bit | 501 bytes           |

*Limits are for PKCS1v15 padding*

## Security Considerations

- **Padding**: Uses PKCS1v15 padding (compatible with Roku BrightScript implementation)
- **Private Key**: Kept server-side and never exposed via API (in full mode)
- **Certificate**: Public key extracted from X.509 certificate (in encrypt-only mode)
- **Production Use**: For production, consider:
  - Using HTTPS/TLS for transport encryption
  - Storing keys securely (HSM, key vault)
  - Rate limiting and authentication
  - Logging and monitoring
  - Firewall rules to restrict access

## Running as a Service

The server can be run as a background service:

**Using nohup:**
```bash
nohup python rsa_server.py --certificate server.cer > /var/log/rsa-server.log 2>&1 &
```

**Stopping the service:**
```bash
# Find the process
ps aux | grep rsa_server.py

# Send SIGTERM for graceful shutdown
kill -TERM <PID>
```

## Example Client Code

```python
import requests

# Initialize client
base_url = "http://localhost:5000"

# Convert text to hex
message = "Hello, World!"
hex_data = message.encode('utf-8').hex()

# Encrypt hex-encoded data
payload = {"data": hex_data}
response = requests.post(f"{base_url}/encrypt", json=payload)
encrypted_result = response.json()

print(f"Encrypted: {encrypted_result['encrypted_data']}")

# Decrypt (only works in full mode with private key)
decrypt_payload = {"encrypted_data": encrypted_result['encrypted_data']}
response = requests.post(f"{base_url}/decrypt", json=decrypt_payload)
decrypted_result = response.json()

# Convert hex back to text
decrypted_hex = decrypted_result['decrypted_data']
decrypted_text = bytes.fromhex(decrypted_hex).decode('utf-8')

print(f"Decrypted: {decrypted_text}")
```

## Command Line Examples

### Using curl

**Encrypt hex-encoded data:**
```bash
# Convert text to hex first
echo -n "Hello" | xxd -p  # Outputs: 48656c6c6f

curl -X POST http://localhost:5000/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "48656c6c6f"}'
```

**Decrypt encrypted data:**
```bash
curl -X POST http://localhost:5000/decrypt \
  -H "Content-Type: application/json" \
  -d '{"encrypted_data": "a1b2c3d4..."}'
```

**Check health:**
```bash
curl http://localhost:5000/health | jq
```

## Development

### Project Structure
```
.
├── rsa_server.py              # Main server application (Python)
├── rsa_service.c              # C implementation
├── requirements.txt           # Python dependencies
├── README_rsa_server_py.md    # Python server documentation
└── README.md                  # General documentation
```

### Testing

Test individual endpoints:
```bash
# Test health
curl http://localhost:5000/health

# Test encryption with hex data
curl -X POST http://localhost:5000/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "74657374"}'

# Test decryption (full mode only)
curl -X POST http://localhost:5000/decrypt \
  -H "Content-Type: application/json" \
  -d '{"encrypted_data": "<hex-encrypted-data>"}'
```

## Troubleshooting

### Common Issues

**Server won't start:**
- Check if port is available: `lsof -i :5000`
- Verify Python version (3.7+): `python --version`
- Install missing dependencies: `pip install -r requirements.txt`
- Ensure you specified either `--certificate` or `--private-key-pem`

**Encryption fails with "Data too long":**
- Data must be hex-encoded
- Check data size limits based on key size (245 bytes for 2048-bit)
- For larger data, consider hybrid encryption (RSA + AES)

**Invalid hex string error:**
- Ensure data is properly hex-encoded
- Use `echo -n "text" | xxd -p` to convert text to hex

**Decryption not available:**
- Decryption only works in full mode
- Restart server with `--private-key-pem` instead of `--certificate`

**Client connection errors:**
- Verify server is running: `curl http://localhost:5000/health`
- Check firewall settings
- Ensure correct server URL and port

### Logging

The server logs all requests and errors. Check console output for debugging information.

## License

This project is provided as-is for educational and development purposes.

## Contributing

Feel free to submit issues and enhancement requests!
