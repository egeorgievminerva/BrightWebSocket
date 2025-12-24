#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// For libmicrohttpd
#include <microhttpd.h>

// For OpenSSL
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>

// For Jansson
#include <jansson.h>

// --- Global Variable ---
// In a real multi-threaded application, this should be handled with care
// (e.g., read-only after initialization, or using mutexes if the key could change).
// For this example, a simple global is sufficient.
EVP_PKEY *private_key = NULL;
EVP_PKEY *public_key = NULL;    // Used when running in encrypt-only mode with certificate
int rsa_key_size_bits = 0;      // Store key size for the health endpoint
int encrypt_only_mode = 0;      // Flag: 1 if running with certificate (no private key)
int server_port = 5000;         // Default port, can be changed with --port option
const char *server_host = NULL; // Host to bind to (NULL = all interfaces)

// Signal handling
volatile sig_atomic_t keep_running = 1;

// --- Hex String Helper Functions ---

// Encodes a byte array into a newly allocated hex string.
// The caller is responsible for freeing the returned string.
char *hex_encode(const unsigned char *input, int length)
{
    if (input == NULL || length <= 0)
        return NULL;

    char *hex_string = malloc(length * 2 + 1);
    if (hex_string == NULL)
        return NULL;

    for (int i = 0; i < length; i++)
    {
        sprintf(hex_string + (i * 2), "%02x", input[i]);
    }
    hex_string[length * 2] = '\0';

    return hex_string;
}

// Decodes a hex string into a newly allocated byte array.
// The caller is responsible for freeing the returned buffer.
unsigned char *hex_decode(const char *input, int *out_len)
{
    int len = strlen(input);
    if (len % 2 != 0)
    { // Hex strings must have an even number of characters
        return NULL;
    }

    *out_len = len / 2;
    unsigned char *decoded_data = malloc(*out_len);
    if (decoded_data == NULL)
        return NULL;

    for (int i = 0; i < *out_len; i++)
    {
        char byte_str[3] = {input[i * 2], input[i * 2 + 1], '\0'};
        if (!isxdigit(byte_str[0]) || !isxdigit(byte_str[1]))
        {
            free(decoded_data);
            return NULL; // Invalid hex character
        }
        decoded_data[i] = (unsigned char)strtol(byte_str, NULL, 16);
    }

    return decoded_data;
}
// --- API Logic Functions ---

// Creates a JSON error response string
char *create_error_response(const char *message)
{
    json_t *root = json_object();
    json_object_set_new(root, "error", json_string(message));
    char *response_str = json_dumps(root, 0);
    json_decref(root);
    return response_str;
}

// Handles the /health endpoint logic
enum MHD_Result handle_health(char **response_str, int *http_status)
{
    json_t *root = json_object();
    json_object_set_new(root, "status", json_string("healthy"));
    json_object_set_new(root, "service", json_string("RSA Encryption Server"));
    json_object_set_new(root, "key_size", json_integer(rsa_key_size_bits));

    *response_str = json_dumps(root, JSON_INDENT(2)); // Pretty-print the JSON
    json_decref(root);

    *http_status = MHD_HTTP_OK;
    return MHD_YES;
}

// Handles the /encrypt endpoint logic
enum MHD_Result handle_encrypt(const char *post_data, char **response_str, int *http_status)
{
    json_error_t error;
    json_t *root = json_loads(post_data, 0, &error);
    if (!root)
    {
        *response_str = create_error_response("Invalid JSON format.");
        *http_status = MHD_HTTP_BAD_REQUEST;
        return MHD_YES;
    }

    json_t *data_node = json_object_get(root, "data");
    if (!json_is_string(data_node))
    {
        *response_str = create_error_response("Missing or invalid 'data' field in JSON.");
        *http_status = MHD_HTTP_BAD_REQUEST;
        json_decref(root);
        return MHD_YES;
    }

    const char *hex_input = json_string_value(data_node);
    int decoded_len = 0;
    unsigned char *decoded_data = hex_decode(hex_input, &decoded_len);

    if (!decoded_data)
    {
        json_decref(root);
        *response_str = create_error_response("Invalid Hex data.");
        *http_status = MHD_HTTP_BAD_REQUEST;
        return MHD_YES;
    }

    // Perform RSA Public Key Encryption
    // Use public_key in encrypt-only mode, otherwise extract from private_key
    EVP_PKEY *key_for_encryption = encrypt_only_mode ? public_key : private_key;
    RSA *rsa = EVP_PKEY_get1_RSA(key_for_encryption);
    int rsa_size = RSA_size(rsa);
    unsigned char *encrypted_data = malloc(rsa_size);

    int encrypted_len = RSA_public_encrypt(decoded_len, decoded_data, encrypted_data, rsa, RSA_PKCS1_PADDING);
    free(decoded_data);
    RSA_free(rsa);

    if (encrypted_len == -1)
    {
        *response_str = create_error_response("RSA encryption failed.");
        *http_status = MHD_HTTP_INTERNAL_SERVER_ERROR;
        free(encrypted_data);
        json_decref(root);
        return MHD_YES;
    }

    // Hex encode the result and create the JSON response
    char *hex_output = hex_encode(encrypted_data, encrypted_len);
    free(encrypted_data);

    printf("encrypt_data (input: %s) (output: %s)\n", hex_input, hex_output);
    json_decref(root);

    json_t *response_json = json_object();
    json_object_set_new(response_json, "encrypted_data", json_string(hex_output));
    json_object_set_new(response_json, "original_length", json_integer(decoded_len));
    json_object_set_new(response_json, "encrypted_length", json_integer(encrypted_len));
    *response_str = json_dumps(response_json, 0);
    free(hex_output);
    json_decref(response_json);
    *http_status = MHD_HTTP_OK;

    return MHD_YES;
}

// Handles the /decrypt endpoint logic
enum MHD_Result handle_decrypt(const char *post_data, char **response_str, int *http_status)
{
    // Check if running in encrypt-only mode
    if (encrypt_only_mode)
    {
        *response_str = create_error_response("Decryption not available in encrypt-only mode (no private key loaded)");
        *http_status = MHD_HTTP_FORBIDDEN;
        return MHD_YES;
    }

    json_error_t error;
    json_t *root = json_loads(post_data, 0, &error);
    if (!root)
    {
        *response_str = create_error_response("Invalid JSON format.");
        *http_status = MHD_HTTP_BAD_REQUEST;
        return MHD_YES;
    }

    json_t *data_node = json_object_get(root, "encrypted_data");
    if (!json_is_string(data_node))
    {
        *response_str = create_error_response("Missing or invalid 'encrypted_data' field in JSON.");
        *http_status = MHD_HTTP_BAD_REQUEST;
        json_decref(root);
        return MHD_YES;
    }

    const char *hex_input = json_string_value(data_node);
    int decoded_len = 0;
    unsigned char *decoded_data = hex_decode(hex_input, &decoded_len);

    if (!decoded_data)
    {
        json_decref(root);
        *response_str = create_error_response("Invalid Hex data.");
        *http_status = MHD_HTTP_BAD_REQUEST;
        return MHD_YES;
    }

    // Perform RSA Private Key Decryption
    RSA *rsa = EVP_PKEY_get1_RSA(private_key);
    int rsa_size = RSA_size(rsa);
    unsigned char *decrypted_data = malloc(rsa_size * 2);

    int decrypted_len = RSA_private_decrypt(decoded_len, decoded_data, decrypted_data, rsa, RSA_PKCS1_PADDING);
    free(decoded_data);
    RSA_free(rsa);

    if (decrypted_len == -1)
    {
        *response_str = create_error_response("RSA decryption failed. Data might be invalid.");
        fprintf(stderr, "ERROR: %s hex_input: %s\n", *response_str, hex_input);
        ERR_print_errors_fp(stderr);
        json_decref(root);
        *http_status = MHD_HTTP_BAD_REQUEST; // Treat as a client error
        free(decrypted_data);
        return MHD_YES;
    }

    // Hex encode the result and create JSON response
    char *hex_output = hex_encode(decrypted_data, decrypted_len);
    printf("decrypt_data (input: %s) (output: %s)\n", hex_input, hex_output);
    json_decref(root);
    free(decrypted_data);

    json_t *response_json = json_object();
    json_object_set_new(response_json, "decrypted_data", json_string(hex_output));

    *response_str = json_dumps(response_json, 0);
    free(hex_output);
    json_decref(response_json);
    *http_status = MHD_HTTP_OK;

    return MHD_YES;
}

// --- Signal Handler ---

void signal_handler(int signum)
{
    if (signum == SIGTERM || signum == SIGINT)
    {
        printf("\nReceived signal %d, shutting down gracefully...\n", signum);
        keep_running = 0;
    }
}

// --- HTTP Server (libmicrohttpd) Callback ---

enum MHD_Result answer_to_connection(void *cls, struct MHD_Connection *connection,
                                     const char *url, const char *method,
                                     const char *version, const char *upload_data,
                                     size_t *upload_data_size, void **con_cls)
{

    char *response_str = NULL;
    int http_status = MHD_HTTP_NOT_FOUND;

    // --- Routing ---
    if (0 == strcmp(url, "/health") && 0 == strcmp(method, "GET"))
    {
        handle_health(&response_str, &http_status);
    }
    else if (0 == strcmp(method, "POST"))
    {
        // Handle POST requests, which require a body
        if (NULL == *con_cls)
        {
            char *post_buffer = malloc(1);
            post_buffer[0] = '\0';
            *con_cls = post_buffer;
            return MHD_YES;
        }

        if (*upload_data_size != 0)
        {
            char *post_buffer = *con_cls;
            size_t current_size = strlen(post_buffer);
            post_buffer = realloc(post_buffer, current_size + *upload_data_size + 1);
            if (!post_buffer)
                return MHD_NO;

            memcpy(post_buffer + current_size, upload_data, *upload_data_size);
            post_buffer[current_size + *upload_data_size] = '\0';
            *con_cls = post_buffer;
            *upload_data_size = 0;
            return MHD_YES;
        }

        // Full POST body received
        char *post_body = *con_cls;
        if (0 == strcmp(url, "/encrypt"))
        {
            handle_encrypt(post_body, &response_str, &http_status);
        }
        else if (0 == strcmp(url, "/decrypt"))
        {
            handle_decrypt(post_body, &response_str, &http_status);
        }
        else
        {
            response_str = create_error_response("Endpoint not found for POST method.");
        }

        // Cleanup POST buffer
        free(post_body);
        *con_cls = NULL;
    }
    else
    {
        // Any other method/URL combo
        response_str = create_error_response("Method not allowed or endpoint not found.");
        http_status = MHD_HTTP_METHOD_NOT_ALLOWED;
    }

    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_str),
                                                                    (void *)response_str,
                                                                    MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(response, "Content-Type", "application/json");

    enum MHD_Result ret = MHD_queue_response(connection, http_status, response);
    MHD_destroy_response(response);

    return ret;
}

// --- Main Entry Point ---

int main(int argc, char *argv[])
{
    // Parse command line arguments in any order
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s [OPTIONS]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Required (one of):\n");
        fprintf(stderr, "  --private-key-pem FILE    Use private key (enables both encrypt and decrypt)\n");
        fprintf(stderr, "  --certificate FILE        Use certificate (encrypt-only mode)\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Optional:\n");
        fprintf(stderr, "  --host HOST               Host/IP to bind to (default: 0.0.0.0 - all interfaces)\n");
        fprintf(stderr, "  --port PORT               TCP port to listen on (default: 5000)\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  %s --certificate cert.pem --port 8080\n", argv[0]);
        fprintf(stderr, "  %s --host 127.0.0.1 --port 3000 --private-key-pem private.key\n", argv[0]);
        fprintf(stderr, "  %s --host 192.168.1.100 --certificate cert.pem\n", argv[0]);
        return 1;
    }

    // Variables to store parsed options
    const char *key_file_path = NULL;
    const char *cert_file_path = NULL;
    int port_specified = 0;
    int host_specified = 0;

    // Parse all arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--private-key-pem") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: --private-key-pem requires a file path\n");
                return 1;
            }
            if (key_file_path != NULL)
            {
                fprintf(stderr, "Error: --private-key-pem specified multiple times\n");
                return 1;
            }
            if (cert_file_path != NULL)
            {
                fprintf(stderr, "Error: Cannot specify both --private-key-pem and --certificate\n");
                return 1;
            }
            key_file_path = argv[i + 1];
            i++; // Skip the file path in next iteration
        }
        else if (strcmp(argv[i], "--certificate") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: --certificate requires a file path\n");
                return 1;
            }
            if (cert_file_path != NULL)
            {
                fprintf(stderr, "Error: --certificate specified multiple times\n");
                return 1;
            }
            if (key_file_path != NULL)
            {
                fprintf(stderr, "Error: Cannot specify both --private-key-pem and --certificate\n");
                return 1;
            }
            cert_file_path = argv[i + 1];
            i++; // Skip the file path in next iteration
        }
        else if (strcmp(argv[i], "--port") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: --port requires a port number\n");
                return 1;
            }
            if (port_specified)
            {
                fprintf(stderr, "Error: --port specified multiple times\n");
                return 1;
            }

            char *endptr;
            long port_long = strtol(argv[i + 1], &endptr, 10);

            if (*endptr != '\0' || port_long < 1 || port_long > 65535)
            {
                fprintf(stderr, "Error: Invalid port number '%s'. Must be between 1 and 65535.\n", argv[i + 1]);
                return 1;
            }

            server_port = (int)port_long;
            port_specified = 1;
            i++; // Skip the port value in next iteration
        }
        else if (strcmp(argv[i], "--host") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: --host requires a hostname or IP address\n");
                return 1;
            }
            if (host_specified)
            {
                fprintf(stderr, "Error: --host specified multiple times\n");
                return 1;
            }

            server_host = argv[i + 1];
            host_specified = 1;
            i++; // Skip the host value in next iteration
        }
        else
        {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            fprintf(stderr, "Use '%s' without arguments to see usage information\n", argv[0]);
            return 1;
        }
    }

    // Validate that exactly one of --private-key-pem or --certificate was provided
    if (key_file_path == NULL && cert_file_path == NULL)
    {
        fprintf(stderr, "Error: Must specify either --private-key-pem or --certificate\n");
        fprintf(stderr, "Use '%s' without arguments to see usage information\n", argv[0]);
        return 1;
    }

    // Load the key or certificate
    if (cert_file_path != NULL)
    {
        // Load certificate and extract public key
        FILE *cert_file = fopen(cert_file_path, "r");
        if (!cert_file)
        {
            perror("Failed to open certificate file");
            return 1;
        }

        X509 *cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
        fclose(cert_file);

        if (!cert)
        {
            fprintf(stderr, "Failed to read certificate from %s\n", cert_file_path);
            ERR_print_errors_fp(stderr);
            return 1;
        }

        public_key = X509_get_pubkey(cert);
        X509_free(cert);

        if (!public_key)
        {
            fprintf(stderr, "Failed to extract public key from certificate %s\n", cert_file_path);
            ERR_print_errors_fp(stderr);
            return 1;
        }

        rsa_key_size_bits = EVP_PKEY_bits(public_key);
        encrypt_only_mode = 1;
        printf("Loaded public key from certificate %s (%d bits)\n", cert_file_path, rsa_key_size_bits);
        printf("Running in ENCRYPT-ONLY mode\n");
    }
    else // key_file_path != NULL
    {
        FILE *key_file = fopen(key_file_path, "r");
        if (!key_file)
        {
            perror("Failed to open private key file");
            return 1;
        }

        private_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
        fclose(key_file);

        if (!private_key)
        {
            fprintf(stderr, "Failed to read private key from %s\n", key_file_path);
            ERR_print_errors_fp(stderr);
            return 1;
        }

        rsa_key_size_bits = EVP_PKEY_bits(private_key);
        encrypt_only_mode = 0;
        printf("Loaded private key from %s (%d bits)\n", key_file_path, rsa_key_size_bits);
        printf("Running in FULL mode (encrypt and decrypt)\n");
    }

    // Set up signal handlers for graceful shutdown
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGTERM, &sa, NULL) == -1)
    {
        perror("Failed to set up SIGTERM handler");
        if (private_key)
            EVP_PKEY_free(private_key);
        if (public_key)
            EVP_PKEY_free(public_key);
        return 1;
    }

    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("Failed to set up SIGINT handler");
        if (private_key)
            EVP_PKEY_free(private_key);
        if (public_key)
            EVP_PKEY_free(public_key);
        return 1;
    }

    // Prepare socket address if specific host is requested
    struct sockaddr_in addr;
    struct MHD_Daemon *daemon;

    if (server_host != NULL)
    {
        // Bind to specific address
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(server_port);

        if (inet_pton(AF_INET, server_host, &addr.sin_addr) != 1)
        {
            fprintf(stderr, "Error: Invalid IP address '%s'\n", server_host);
            if (private_key)
                EVP_PKEY_free(private_key);
            if (public_key)
                EVP_PKEY_free(public_key);
            return 1;
        }

        daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, server_port, NULL, NULL,
                                  &answer_to_connection, NULL,
                                  MHD_OPTION_SOCK_ADDR, (struct sockaddr *)&addr,
                                  MHD_OPTION_END);
    }
    else
    {
        // Bind to all interfaces (default)
        daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, server_port, NULL, NULL,
                                  &answer_to_connection, NULL, MHD_OPTION_END);
    }

    if (NULL == daemon)
    {
        fprintf(stderr, "Failed to start HTTP server daemon on %s:%d.\n",
                server_host ? server_host : "0.0.0.0", server_port);
        if (private_key)
            EVP_PKEY_free(private_key);
        if (public_key)
            EVP_PKEY_free(public_key);
        return 1;
    }

    printf("RSA service started on %s:%d (PID: %d)\n",
           server_host ? server_host : "0.0.0.0", server_port, getpid());
    if (encrypt_only_mode)
    {
        printf("Endpoints available: POST /encrypt (decrypt disabled in encrypt-only mode)\n");
    }
    else
    {
        printf("Endpoints available: POST /encrypt, POST /decrypt\n");
    }
    printf("Server running. Send SIGTERM or SIGINT to stop gracefully.\n");

    // Main loop - wait for signal
    while (keep_running)
    {
        sleep(1);
    }

    printf("Stopping server...\n");
    MHD_stop_daemon(daemon);
    if (private_key)
        EVP_PKEY_free(private_key);
    if (public_key)
        EVP_PKEY_free(public_key);

    return 0;
}
