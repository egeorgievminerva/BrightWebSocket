# rsa_service.c
RSA Public Key Encryption Web Server written in C
Dependencies: libmicrohttpd jansson openssl
- OS X: brew install libmicrohttpd jansson
- Linux: sudo apt-get install libmicrohttpd-dev libjansson-dev libssl-dev

To build the app type:
```
make rsa_service
```

To start rsa_service as a demon read the respective guide:
 Linux - README_rsa_service_systemd.md
 OS X - README_rsa_service_launchd.md

# rsa_server.py
RSA Public Key Encryption Web Server written in python
See README_RSA_Server.md

