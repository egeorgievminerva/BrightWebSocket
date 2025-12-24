.PHONY: all

all: rsa_service

rsa_service: rsa_service.c
	gcc rsa_service.c -o rsa_service -lmicrohttpd -lssl -lcrypto -ljansson -I/opt/homebrew/include -L/opt/homebrew/lib


run-server:
	openssl s_server -accept 8447 -cert server.cer -cert_chain fullchain.cer -key server.key -tls1_2 -cipher AES256-SHA256 -www -msg -state
