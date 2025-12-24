' WebSocketClient.brs
' Copyright (C) 2018 Rolando Islas
' Released under the MIT license
'
' Utilities for operating with the Transport Layer Security (TLS) protocol
' Follows RFC 5246

' TlsUtil object
' Requires pkg:/components/WebSocket/ByteUtil.brs

function TlsUtil() as object
    tls_util = {}

    ' Configure server for RSA encryption
    tls_util._rsa_service_info = {
        url: "",
        headers: {},
    }

    ' Constants
    tls_util.STATE_DISCONNECTED = 0
    tls_util.STATE_CONNECTING = 1
    tls_util.STATE_FINISHED = 2
    tls_util._BUFFER_SIZE = cint(1024 * 1024 * 1)
    tls_util._TLS_VERSION = [3, 3]
    ' TLS Constants
    tls_util._TLS_FRAGMENT_MAX_LENGTH = 2 ^ 14
    tls_util._HANDSHAKE_TYPE = {
        HELLO_REQUEST: 0,
        CLIENT_HELLO: 1,
        SERVER_HELLO: 2,
        CERTIFICATE: 11,
        SERVER_KEY_EXCHANGE: 12,
        CERTIFICATE_REQUEST: 13,
        SERVER_HELLO_DONE: 14,
        CERTIFICATE_VERIFY: 15,
        CLIENT_KEY_EXCHANGE: 16,
        FINISHED: 20
    }
    tls_util._RECORD_TYPE = {
        CHANGE_CIPHER_SPEC: 20,
        ALERT: 21,
        HANDSHAKE: 22,
        APPLICATION_DATA: 23
    }
    tls_util._EXTENSION_TYPE = {
        SERVER_NAME: 0,
        SUPPORTED_GROUPS: 10,
        EC_POINT_FORMATS: 11
    }
    tls_util._ALERT_LEVEL = {
        WARNING: 1,
        FATAL: 2
    }
    tls_util._ALERT_TYPE = {
        CLOSE_NOTIFY: 0,
        UNEXPECTED_MESSAGE: 10,
        HANDSHAKE_FAILURE: 40,
        BAD_CERTIFICATE: 42,
        PROTOCOL_VERSION: 70,
        UNSUPPORTED_EXTENSION: 110
    }
    tls_util._COMPRESSION_METHODS = {
        NULL: 0
    }
    tls_util._SUPPORTED_GROUPS = {
        SECP256R1: 23,
        SECP384R1: 24,
        SECP521R1: 25
    }
    tls_util._EC_POINT_FORMATS = {
        UNCOMPRESSED: 0
    }
    ' Variables
    tls_util._logger = Logger("TlsUtil")
    tls_util._data = createObject("roByteArray")
    tls_util._date_time_object = createObject("roDateTime")
    tls_util._data[tls_util._BUFFER_SIZE] = 0
    tls_util._data_size = 0
    tls_util.websocket_ready_state = tls_util.STATE_DISCONNECTED
    tls_util._hostname = invalid
    tls_util._client_hello_random = invalid
    tls_util._server_hello_random = invalid
    tls_util._cipher_suite = invalid
    tls_util._supported_extensions = []
    tls_util._server_extensions = [] ' Extensions negotiated by server
    tls_util._handshake_start_time = 0
    tls_util._certificates = []
    tls_util._server_public_key = invalid
    tls_util._bypass_tls = false
    tls_util._premaster_secret = invalid
    tls_util._master_secret = invalid
    tls_util._client_keys = invalid

    tls_util.session_keys = {}
    tls_util.client_seq_num = 0&
    tls_util.server_seq_num = 0&

    ' TLS Constants
    tls_util.TLS1_2_VERSION = &h0303
    tls_util.CIPHER_SUITE = &h003D ' TLS_RSA_WITH_AES_256_CBC_SHA256
    ' tls_util._NL = chr(13) + chr(10)

    tls_util.two_chars_regex = CreateObject("roRegex", "([a-z0-9]{2})", "i")
    tls_util._connect_timeout_seconds = 30

    ' Decode TLS bytes
    ' This function buffers data if it does not have enough bytes to decode
    ' @param input roByteArray
    ' @param size integer size of usable data in the input array starting from
    '                     index 0
    ' @return roByteArray of decoded data. The returned array may have a count
    '         of zero. May return invalid on error
    tls_util.read = function(input as object, size as integer) as object
        if m.websocket_ready_state = m.STATE_DISCONNECTED
            m._logger.printl(m._logger.DEBUG, "TlsUtil: Read failed: state is disconnected")
            return invalid
        end if
        if m._has_handshake_timed_out()
            m._logger.printl(m._logger.DEBUG, "TlsUtil: Handshake timed out")
            return invalid
        end if
        decoded_app_data = createObject("roByteArray")
        ' TLS Record Frame
        if size >= 0
            ' Save to buffer
            for byte_index = m._data_size to m._data_size + size - 1
                m._data[byte_index] = input[byte_index - m._data_size]
            end for
            m._data_size += size
            input = invalid
            ' Wait for frame size
            fragment_start_index = 5
            if m._data_size < fragment_start_index
                return decoded_app_data
            end if
            ' Record
            record_type = m._data[0]
            version_major = m._data[1]
            version_minor = m._data[2]
            fragment_length = bytes_to_short(m._data[3], m._data[4])
            ' Check version
            if m._TLS_VERSION[0] <> version_major or m._TLS_VERSION[1] <> version_minor
                m._error(m._ALERT_TYPE.PROTOCOL_VERSION, "Received a frame with an an unsupported version defined")
                return invalid
            end if
            ' Wait for fragment
            if m._data_size < fragment_start_index + fragment_length
                return decoded_app_data
            end if
            ' Fragment
            fragment = createObject("roByteArray")
            for byte_index = fragment_start_index to fragment_start_index + fragment_length - 1
                fragment.push(m._data[byte_index])
            end for

            handled_fragment = m._handle_fragment(record_type, fragment)
            if handled_fragment = invalid
                return invalid
            else
                decoded_app_data.append(handled_fragment)
            end if
            ' Delete fragment from buffer
            m._data = byte_array_sub(m._data, fragment_start_index + fragment_length, m._data_size - 1)
            m._data_size = m._data.count()
            m._data[m._BUFFER_SIZE] = 0
        end if
        return decoded_app_data
    end function

    ' Check if the handshake has timed out
    ' @return if the handshake has not completed before a timed out
    tls_util._has_handshake_timed_out = function() as boolean
        return uptime(0) - m._handshake_start_time >= 30 and m._handshake_start_time > -1
    end function

    ' Send a fatal alert and optionally log a debug message and set the state to disconnected if fatal
    ' @param alert_type integer type
    ' @param message string optional message to log
    ' @param fatal boolean set the alert type to fatal and disconnect
    tls_util._error = sub(alert_type as integer, message = "" as string, fatal = true as boolean) as void
        level = m._ALERT_LEVEL.FATAL
        if not fatal
            level = m._ALERT_LEVEL.WARNING
        end if
        m._send_alert(level, alert_type)
        if message <> ""
            m._logger.printl(m._logger.DEBUG, "TlsUtil: Error: " + message)
        end if
        if fatal
            m.websocket_ready_state = m.STATE_DISCONNECTED
        end if
    end sub

    ' Send an alert
    ' @param alert_level integer level of alert
    ' @param alert_type integer alert description
    tls_util._send_alert = sub(alert_level as integer, alert_type as integer)
        alert = createObject("roByteArray")
        alert.push(alert_level)
        alert.push(alert_type)
        m._sendRecord(m._RECORD_TYPE.ALERT, alert)
    end sub

    ' Handle opaque fragment data
    ' @param record_type type of frame
    ' @param frame roByteArray frame
    ' @return potentially empty roByteArray or invalid on error. disconnect state is handled on error
    tls_util._handle_fragment = function(record_type as integer, fragment as object) as object
        m._logger.printl(m._logger.VERBOSE, "Received fragment of type " + record_type.toStr() + ": " + m.format_hex_bytes(fragment))
        decoded_app_data = createObject("roByteArray")
        while fragment.count() > 0
            ' Handshake
            if record_type = m._RECORD_TYPE.HANDSHAKE
                fragment_header_size = 4
                ' Invalid data
                if fragment.count() < fragment_header_size
                    m._error_handshake()
                    return invalid
                    ' Handle handshake data
                else
                    if m.changeCipherSpecReceived = true
                        m._logger.printl(m._logger.DEBUG, "Received Server Finished (Encrypted)")
                        m._logger.printl(m._logger.DEBUG, "TlsClient", "*** TLS 1.2 HANDSHAKE SUCCESSFUL ***")
                        m._logger.printl(m._logger.DEBUG, "TlsUtil: Received Finished: " + m.format_hex_bytes(fragment))
                        ' Server has sent Finished message, handshake is complete
                        m.websocket_ready_state = m.STATE_FINISHED
                        m._logger.printl(m._logger.DEBUG, "TlsUtil: TLS handshake completed successfully")
                        m.server_seq_num++ ' CRITICAL: Account for this encrypted record
                        return decoded_app_data
                    end if

                    handshake_type = m._readChar(fragment, 0)
                    handshake_len = m._readInt24(fragment, 1)

                    if fragment.count() < fragment_header_size + handshake_len
                        m._logger.printl(m._logger.DEBUG, "Incomplete handshake fragment received. Needs to be :" + handshake_len.ToStr() + " but it is: " + fragment.count().ToStr())
                        return invalid
                    end if

                    ' Only hash the current handshake message, not the entire fragment
                    current_handshake_msg = fragment.slice(0, fragment_header_size + handshake_len)
                    m.sha256_update(current_handshake_msg)

                    handshake_data = fragment.slice(fragment_header_size, fragment_header_size + handshake_len)

                    ' Debug: Log handshake message received
                    #if DEBUG_LOG_WEBSOCKET
                        print "*** HANDSHAKE RECEIVED: " + m.format_hex_bytes(handshake_data)
                    #end if
                    if not m._handle_handshake(handshake_type, handshake_data)
                        return invalid
                    end if
                    fragment = byte_array_sub(fragment, fragment_header_size + handshake_len, fragment.count() - 1)
                end if
                ' App data
            else if record_type = m._RECORD_TYPE.APPLICATION_DATA
                m._logger.printl(m._logger.DEBUG, "TlsUtil: Received Application Data (Encrypted)")
                decoded_part = m._readAndDecryptRecord(record_type, fragment)
                if decoded_part <> invalid
                    decoded_app_data.append(decoded_part.payload)
                end if
                fragment.clear()
                ' Alert
            else if record_type = m._RECORD_TYPE.ALERT
                alert_level = -1
                alert_description = -1
                ' After TLS handshake completes, alerts are encrypted
                if m.websocket_ready_state = m.STATE_FINISHED
                    m._logger.printl(m._logger.DEBUG, "TlsUtil: Received Alert (Encrypted)")
                    decoded_part = m._readAndDecryptRecord(record_type, fragment)
                    if decoded_part <> invalid and decoded_part.payload.count() >= 2
                        alert_level = decoded_part.payload[0]
                        alert_description = decoded_part.payload[1]
                    end if
                    fragment.clear()
                else
                    ' During handshake, alerts are not encrypted
                    if fragment.count() < 2
                        m._error_handshake()
                        return invalid
                    else
                        alert_level = fragment[0]
                        alert_description = fragment[1]
                        fragment = byte_array_sub(fragment, 2, fragment.count() - 1)
                    end if
                end if
                m._logger.printl(m._logger.DEBUG, "TlsUtil: alert:")
                m._logger.printl(m._logger.DEBUG, "  level: " + alert_level.toStr())
                m._logger.printl(m._logger.DEBUG, "  description: " + alert_description.toStr())
                if alert_level = m._ALERT_LEVEL.FATAL
                    m._error(m._ALERT_TYPE.CLOSE_NOTIFY, "Received fatal alert", true)
                    return invalid
                else if alert_level = m._ALERT_LEVEL.WARNING and alert_description = m._ALERT_TYPE.CLOSE_NOTIFY
                    m._logger.printl(m._logger.DEBUG, "TlsUtil: Received close_notify alert, closing connection")
                    m.websocket_ready_state = m.STATE_DISCONNECTED
                    m._socket.close()
                end if

                ' Cipher spec
            else if record_type = m._RECORD_TYPE.CHANGE_CIPHER_SPEC
                ' Handle ChangeCipherSpec message
                m._logger.printl(m._logger.DEBUG, "TlsUtil: Received ChangeCipherSpec")
                fragment = byte_array_sub(fragment, 1, fragment.count() - 1)
                m.changeCipherSpecReceived = true
            end if
        end while
        return decoded_app_data
    end function

    ' Handle handshake data
    ' @param handshake_type integer type of handshake data
    ' @param handshake roByteArray handshake data
    ' @return false on error
    tls_util._handle_handshake = function(handshake_type as integer, handshake as object) as boolean
        ' HelloRequest
        if handshake_type = m._HANDSHAKE_TYPE.HELLO_REQUEST
            ' Only initiate new handshake if we're truly disconnected and not in progress
            if m.websocket_ready_state = m.STATE_DISCONNECTED
                m._logger.printl(m._logger.DEBUG, "TlsUtil: Received HelloRequest, initiating new handshake")
                m.connect(m._hostname)
            else
                m._logger.printl(m._logger.DEBUG, "TlsUtil: Ignoring HelloRequest during active handshake (state: " + m.websocket_ready_state.toStr() + ")")
            end if
            ' ServerHello
        else if handshake_type = m._HANDSHAKE_TYPE.SERVER_HELLO
            if handshake.count() < 38
                m._error_handshake()
                return false
            end if
            version_major = handshake[0]
            version_minor = handshake[1]
            if version_major <> m._TLS_VERSION[0] or version_minor <> m._TLS_VERSION[1]
                m._error_handshake()
                return false
            end if
            m.server_random = handshake.slice(2, 34) ' Skip version
            session_id = createObject("roByteArray")
            session_id_length = handshake[34]
            for byte_index = 35 to 34 + session_id_length
                session_id.push(handshake[byte_index])
            end for
            cipher_suite = createObject("roByteArray")
            cipher_suite.push(handshake[35 + session_id_length])
            cipher_suite.push(handshake[36 + session_id_length])
            m._cipher_suite = cipher_suite
            compression_method = m._readChar(handshake, 37 + session_id_length)
            if compression_method <> m._COMPRESSION_METHODS.NULL
                m._logger.printl(m._logger.FATAL, "TlsUtil: Unsupported compression method received: " + compression_method.toStr())
                m._error_handshake()
                return false
            end if
            extensions = createObject("roByteArray")
            if handshake.count() > 38 + session_id_length
                extensions_length = bytes_to_short(handshake[38 + session_id_length], handshake[39 + session_id_length])
                m._logger.printl(m._logger.DEBUG, "*** SERVERHELLO DEBUG: handshake.count()=" + handshake.count().toStr() + ", session_id_length=" + session_id_length.toStr())
                m._logger.printl(m._logger.DEBUG, "*** SERVERHELLO DEBUG: extensions_length=" + extensions_length.toStr())
                m._logger.printl(m._logger.DEBUG, "*** SERVERHELLO DEBUG: extensions start at offset " + (40 + session_id_length).toStr())
                ' Extract extensions data (skip the 2-byte length field)
                for byte_index = 40 + session_id_length to 40 + session_id_length + extensions_length - 1
                    extensions.push(handshake[byte_index])
                end for
                print "*** SERVERHELLO DEBUG: extracted " + extensions.count().toStr() + " bytes of extensions data"
                if extensions.count() > 0
                    print "*** SERVERHELLO DEBUG: extensions hex: " + extensions.toHexString()
                end if
            else
                print "*** SERVERHELLO DEBUG: No extensions found (handshake too short)"
            end if
            extension_types = []
            m._server_extensions = [] ' Track server extensions for EMS negotiation
            if extensions.count() > 0
                extension_index = 0
                while extension_index < extensions.count()
                    if extensions.count() - extension_index < 4
                        m._error_handshake()
                        return false
                    end if
                    extension_type = bytes_to_short(extensions[extension_index], extensions[extension_index + 1])
                    extension_length = bytes_to_short(extensions[extension_index + 2], extensions[extension_index + 3])
                    extension_index += 4 + extension_length
                    extension_types.push(extension_type)
                    m._server_extensions.push(extension_type) ' Store for later use
                end while
            end if

            ' Log server extensions for debugging
            if m._server_extensions.count() > 0
                ext_list = []
                for each ext in m._server_extensions
                    extItem = "0x" + StrI(ext, 16)
                    ext_list.Push(extItem)
                end for
                m._logger.printl(m._logger.DEBUG, "TlsUtil: Server negotiated extensions: [" + ext_list.join(", ") + "]")
                print "*** SERVER EXTENSIONS: [" + ext_list.join(", ") + "]"

                ' Check specifically for Extended Master Secret
                has_ems = false
                for each ext_type in m._server_extensions
                    if ext_type = &h0017
                        has_ems = true
                        exit for
                    end if
                end for
                print "*** EXTENDED MASTER SECRET NEGOTIATED: " + has_ems.toStr()
            else
                print "*** SERVER EXTENSIONS: NONE"
                print "*** EXTENDED MASTER SECRET NEGOTIATED: false"
            end if
            for each extension_type in extension_types
                ' Check if extension was requested
                was_extension_requested = false
                for each supported_extension in m._supported_extensions
                    if supported_extension = extension_type
                        was_extension_requested = true
                    end if
                end for
                if not was_extension_requested
                    m._error(m._ALERT_TYPE.UNSUPPORTED_EXTENSION, "Received invalid extension data", true)
                    return false
                end if
                ' Check if extension has been defined more than once
                extension_definitions = 0
                for each extension_type_loop in extension_types
                    if extension_type = extension_type_loop
                        extension_definitions++
                        if extension_definitions > 1
                            m._error(m._ALERT_TYPE.UNSUPPORTED_EXTENSION, "Received invalid extension data", true)
                            return false
                        end if
                    end if
                end for
            end for
            m._logger.printl(m._logger.DEBUG, "TlsUtil: Received ServerHello:")

            m._logger.printl(m._logger.DEBUG, "  cipher suite: " + cipher_suite.toHexString())

            ' Certificate
        else if handshake_type = m._HANDSHAKE_TYPE.CERTIFICATE
            certificate_list = []
            if handshake.count() < 3
                m._error_handshake()
                return false
            end if
            certificate_list_length = bytes_to_int24(handshake[0], handshake[1], handshake[2])
            if handshake.count() < 2 + certificate_list_length
                m._error_handshake()
                return false
            end if
            certificate_index = 3
            while certificate_index + 1 < handshake.count()
                certificate_size = bytes_to_int24(handshake[certificate_index], handshake[certificate_index + 1], handshake[certificate_index + 2])
                if handshake.count() < certificate_index + certificate_size
                    m._error_handshake()
                    return false
                end if
                certificate = createObject("roByteArray")
                for byte_index = certificate_index + 3 to certificate_index + certificate_size - 1
                    certificate.push(handshake[byte_index])
                end for
                certificate_list.push(certificate)
                certificate_index += 3 + certificate_size
            end while
            m._certificates = certificate_list
            m._logger.printl(m._logger.DEBUG, "TlsUtil: Received Certificate: " + certificate_list.count().toStr() + " certificates")
            ' ServerKeyExchange
        else if handshake_type = m._HANDSHAKE_TYPE.SERVER_KEY_EXCHANGE
            m._logger.printl(m._logger.DEBUG, "TlsUtil: Received ServerKeyExchange: " + handshake.toHexString())
            m._error_handshake()
            return false
            ' Certificate Request
        else if handshake_type = m._HANDSHAKE_TYPE.CERTIFICATE_REQUEST
            m._logger.printl(m._logger.DEBUG, "TlsUtil: Received CertificateRequest: " + handshake.toHexString())
            m._error_handshake()
            return false
            ' ServerHelloDone
        else if handshake_type = m._HANDSHAKE_TYPE.SERVER_HELLO_DONE
            m._handshake_start_time = -1
            m._logger.printl(m._logger.DEBUG, "TlsUtil: Received ServerHelloDone")
            if not m._sendClientKeyExchange()
                return false
            end if
            m._deriveKeys()
            if not m._sendChangeCipherSpecAndFinished()
                m._logger.printl(m._logger.FATAL, "TlsUtil: _sendChangeCipherSpecAndFinished failed")
                return false
            end if
            ' Finished
        else if handshake_type = m._HANDSHAKE_TYPE.FINISHED
            m._logger.printl(m._logger.DEBUG, "TlsUtil: Received Finished: " + handshake.toHexString())
            ' Server has sent Finished message, handshake is complete
            m.websocket_ready_state = m.STATE_FINISHED
            m._logger.printl(m._logger.DEBUG, "TlsUtil: TLS handshake completed successfully")
        end if
        return true
    end function

    tls_util._deriveKeys = sub() as void
        if m.master_secret <> invalid
            return
        end if
        m._logger.printl(m._logger.DEBUG, "--- Deriving Keys ---")

        ' Master Secret
        master_seed = createObject("roByteArray")
        master_seed.append(m.client_random)
        master_seed.append(m.server_random)
        m.master_secret = m.prf_sha256(m.pre_master_secret, "master secret", master_seed, 48)
        m._logger.printl(m._logger.DEBUG, "Master Secret: " + m.format_hex_bytes(m.master_secret))

        ' Session Keys
        key_expansion_seed = m.server_random
        key_expansion_seed.append(m.client_random)

        mac_key_size = 32
        enc_key_size = 32
        key_material_len = (mac_key_size + enc_key_size) * 2

        key_material = m.prf_sha256(m.master_secret, "key expansion", key_expansion_seed, key_material_len)

        offset = 0
        m.session_keys.client_write_MAC_key = key_material.slice(offset, offset + mac_key_size) : offset += mac_key_size
        m.session_keys.server_write_MAC_key = key_material.slice(offset, offset + mac_key_size) : offset += mac_key_size
        m.session_keys.client_write_key = key_material.slice(offset, offset + enc_key_size) : offset += enc_key_size
        m.session_keys.server_write_key = key_material.slice(offset, offset + enc_key_size)

        m._logger.printl(m._logger.DEBUG, "Client Write Key: " + m.format_hex_bytes(m.session_keys.client_write_key))
        m._logger.printl(m._logger.DEBUG, "Client MAC Key: " + m.format_hex_bytes(m.session_keys.client_write_MAC_key))
    end sub


    ' Set the ready state to disconnected and send a fatal alert
    tls_util._error_handshake = sub() as void
        m._error(m._ALERT_TYPE.HANDSHAKE_FAILURE, "Received invalid handshake data", true)
    end sub

    ' Set the internal socket used for sending
    ' @param socket roStreamSocket async TCP socket
    tls_util.set_socket = sub(socket as object) as void
        m._socket = socket
    end sub

    tls_util.set_rsa_service_info = sub(service_info as object) as void
        m._rsa_service_info = service_info
    end sub

    tls_util.set_connect_timeout_seconds = sub(connect_timeout_seconds as dynamic)
        m._connect_timeout_seconds = connect_timeout_seconds
    end sub

    ' Start the TLS handshake with a ClientHello
    ' Should only be called if the client socket is a new connection
    ' @param hostname string hostname
    tls_util.connect = sub(hostname as string) as void
        m._hostname = hostname
        m._cipher_suite = invalid
        m._supported_extensions.clear()
        m._handshake_start_time = uptime(0)
        m._certificates.clear()
        m.websocket_ready_state = m.STATE_CONNECTING
        m._sendClientHello()
    end sub

    ' Send data through the TLS tunnel over the socket
    ' @param payload roByteArray data to send
    ' @return bytes of payload sent. -1 on error
    tls_util.send = function(payload as object) as integer
        if m._sendEncryptedRecord(m._RECORD_TYPE.APPLICATION_DATA, payload)
            m._logger.printl(m._logger.DEBUG, "Sent len:" + payload.count().toStr() + ", string: " + payload.toAsciiString())
            return payload.count()
        else
            m._logger.printl(m._logger.FATAL, "ERROR sending len:" + payload.count().toStr() + ", string: " + payload.toAsciiString())
            return -1
        end if
    end function

    ' Send string through the TLS tunnel over the socket
    ' @return bytes of payload sent
    tls_util.send_str = function(payload as string) as integer
        ba = createObject("roByteArray")
        ba.fromAsciiString(payload)
        return m.send(ba)
    end function

    ' Set internal buffer size
    ' @param size integer
    tls_util.set_buffer_size = sub(size as integer) as void
        if m.websocket_ready_state <> m.STATE_DISCONNECTED
            m._logger.printl(m._logger.WARN, "TlsUtil: Cannot set buffer size while connection is open")
            return
        end if
        m._BUFFER_SIZE = size
    end sub

    ' Set the log level
    tls_util.set_log_level_int = sub(level_int as integer) as void
        m._logger.log_level = level_int
    end sub

    ' Returns a roByteArray that conforms to the Random struct used RFC 5246
    tls_util.RandomByteArray = function(length as integer) as object
        random = createObject("roByteArray")
        time = m._date_time_object
        time.Mark()
        m._pushInt32(random, time.asSeconds())
        for byte = 0 to (length - 5)
            random.push(rnd(256) - 1)
        end for
        return random
    end function

    tls_util._pushBytes = sub(msg as object, number as dynamic, byteCount as integer) as void
        for bit = (byteCount - 1) * 8 to 0 step -8
            msg.push((number >> bit) and &hFF)
        end for
    end sub

    ' Push a 64-bit integer into a byte array
    tls_util._pushLongLong = sub(msg as object, val as longinteger) as void
        m._pushBytes(msg, val, 8)
    end sub

    ' Push a 32-bit integer into a byte array
    tls_util._pushInt32 = sub(msg as object, val as integer) as void
        m._pushBytes(msg, val, 4)
    end sub

    ' Push a 24-bit integer into a byte array
    tls_util._pushInt24 = sub(msg as object, val as integer) as void
        m._pushBytes(msg, val, 3)
    end sub

    ' Push a 16-bit integer into a byte array
    tls_util._pushShort = sub(msg as object, val as integer) as void
        m._pushBytes(msg, val, 2)
    end sub

    ' Push a 8-bit integer into a byte array
    tls_util._pushChar = sub(msg as object, val as integer) as void
        m._pushBytes(msg, val, 1)
    end sub

    tls_util._readChar = function(msg as object, offset as integer) as integer
        return msg[offset]
    end function

    tls_util._readShort = function(msg as object, offset as integer) as integer
        return (m._readChar(msg, offset) << 8) or m._readChar(msg, offset + 1)
    end function

    tls_util._readInt24 = function(msg as object, offset as integer) as integer
        return (m._readChar(msg, offset) << 16) or m._readShort(msg, offset + 1)
    end function

    tls_util._readInt32 = function(msg as object, offset as integer) as integer
        return (m._readChar(msg, offset) << 24) or m._readInt24(msg, offset + 1)
    end function


    ' ----- HANDSHAKE MESSAGE CONSTRUCTION -----

    tls_util._sendClientHello = function() as boolean
        if m.clientHelloResult = invalid
            m.clientHelloResult = false
        else
            return m.clientHelloResult
        end if
        m._logger.printl(m._logger.DEBUG, "--- Sending Client Hello ---")

        ' Generate 32 bytes of random data
        m.client_random = m.RandomByteArray(32)
        m._logger.printl(m._logger.DEBUG, "Client Random: " + m.format_hex_bytes(m.client_random))

        payload = createObject("roByteArray")
        m._pushShort(payload, m.TLS1_2_VERSION)
        payload.append(m.client_random)
        m._pushChar(payload, 0) ' Session ID length
        m._pushShort(payload, 2) ' Cipher suites length
        m._pushShort(payload, m.CIPHER_SUITE)
        m._pushChar(payload, 1) ' Compression methods length
        m._pushChar(payload, 0) ' Null compression

        ' Extensions
        ext = createObject("roByteArray")

        ' Server Name Indication (SNI) Extension - REQUIRED for modern servers
        if m._hostname <> invalid and m._hostname <> ""
            sni_data = createObject("roByteArray")
            hostname_bytes = createObject("roByteArray")
            hostname_bytes.fromAsciiString(m._hostname)

            ' Server Name List Length (2 bytes)
            m._pushShort(sni_data, hostname_bytes.count() + 3)
            ' Server Name Type: host_name (0x00)
            m._pushChar(sni_data, 0)
            ' Server Name Length (2 bytes)
            m._pushShort(sni_data, hostname_bytes.count())
            ' Server Name
            sni_data.append(hostname_bytes)

            ' Add SNI extension
            m._pushShort(ext, &h0000) ' Extension type: server_name
            m._pushShort(ext, sni_data.count()) ' Extension length
            ext.append(sni_data)
            m._supported_extensions.push(&h0000)
            m._logger.printl(m._logger.DEBUG, "Added SNI extension for hostname: " + m._hostname)
        end if

        ' Signature Algorithms Extension
        m._pushShort(ext, &h000d) ' Extension type: signature_algorithms
        m._pushShort(ext, &h000a) ' Extension length
        m._pushShort(ext, &h0008) ' List length
        m._pushShort(ext, &h0401) ' rsa_pkcs1_sha256
        m._pushShort(ext, &h0501) ' rsa_pkcs1_sha384
        m._pushShort(ext, &h0601) ' rsa_pkcs1_sha512
        m._pushShort(ext, &h0201) ' rsa_pkcs1_sha1
        m._supported_extensions.push(&h000d)

        ' Add extensions length and data to payload
        m._pushShort(payload, ext.Count())
        payload.append(ext)

        m.clientHelloResult = m._sendHandshakeMessage(m._HANDSHAKE_TYPE.CLIENT_HELLO, payload)
        return m.clientHelloResult
    end function

    tls_util._sendClientKeyExchange = function() as boolean
        if m.clientKeyExchangeResult = invalid
            m.clientKeyExchangeResult = false
        else
            return m.clientKeyExchangeResult
        end if
        m._logger.printl(m._logger.DEBUG, "--- Sending Client Key Exchange ---")

        ' Generate Pre-Master Secret
        m.pre_master_secret = createObject("roByteArray")
        m._pushShort(m.pre_master_secret, m.TLS1_2_VERSION)
        pms_random = m.RandomByteArray(46)
        m.pre_master_secret.append(pms_random)
        m._logger.printl(m._logger.DEBUG, "Pre-Master Secret: " + m.format_hex_bytes(m.pre_master_secret))

        ' Encrypt with server's public key via web service
        encrypted_pms = m.rsa_encrypt_premaster(m.pre_master_secret)
        if encrypted_pms = invalid
            m._logger.printl(m._logger.FATAL, "Failed to encrypt Pre-Master Secret with server's public key.")
            m.clientKeyExchangeResult = false
            return m.clientKeyExchangeResult
        end if

        payload = createObject("roByteArray")
        m._pushShort(payload, encrypted_pms.count())
        payload.append(encrypted_pms)

        m.clientKeyExchangeResult = m._sendHandshakeMessage(m._HANDSHAKE_TYPE.CLIENT_KEY_EXCHANGE, payload)
        return m.clientKeyExchangeResult

    end function

    tls_util._sendChangeCipherSpecAndFinished = function() as boolean
        if m.clientChangeCipherSent = invalid
            m.clientChangeCipherSent = false
        else
            return m.clientChangeCipherSent
        end if
        m._logger.printl(m._logger.DEBUG, "--- Sending Change Cipher Spec & Finished ---")

        ' Send Change Cipher Spec (unencrypted)
        ccs = createObject("roByteArray")
        m._pushChar(ccs, 1)
        if not m._sendRecord(m._RECORD_TYPE.CHANGE_CIPHER_SPEC, ccs)
            return false
        end if

        ' Construct Finished message
        hexResult = m.sha256_final() ' Finalizes and resets context
        handshake_hash = createObject("roByteArray")
        handshake_hash.fromHexString(hexResult)

        m._logger.printl(m._logger.DEBUG, "Final Handshake Hash (len:" + strI(handshake_hash.Count()) + "): " + m.format_hex_bytes(handshake_hash))

        verify_data = m.prf_sha256(m.master_secret, "client finished", handshake_hash, 12)
        m._logger.printl(m._logger.DEBUG, "Finished Verify Data    (len: " + StrI(verify_data.Count()) + "): " + m.format_hex_bytes(verify_data))

        finished_payload = verify_data

        ' Build the handshake message structure
        finished_hs_msg = createObject("roByteArray")
        m._pushChar(finished_hs_msg, m._HANDSHAKE_TYPE.FINISHED)
        m._pushInt24(finished_hs_msg, finished_payload.count())
        finished_hs_msg.append(finished_payload)

        ' Send the Finished message (ENCRYPTED)
        m.clientChangeCipherSent = m._sendEncryptedRecord(m._RECORD_TYPE.HANDSHAKE, finished_hs_msg)
        return m.clientChangeCipherSent
    end function

    tls_util._sendHandshakeMessage = function(hs_type as integer, payload as object) as boolean
        msg = createObject("roByteArray")
        m._pushChar(msg, hs_type)
        m._pushInt24(msg, payload.count())
        msg.append(payload)

        m.sha256_update(msg)
        return m._sendRecord(m._RECORD_TYPE.HANDSHAKE, msg)
    end function

    tls_util._sendRecord = function(rec_type as integer, data as object) as boolean
        header = createObject("roByteArray")
        m._pushChar(header, rec_type)
        m._pushShort(header, m.TLS1_2_VERSION)
        m._pushShort(header, data.count())

        bytes_sent = m._socket.send(header, 0, header.count())
        bytes_sent += m._socket.send(data, 0, data.count())

        result = bytes_sent = header.count() + data.count()
        m._logger.printl(m._logger.DEBUG, "_sendRecord type: " + stri(rec_type) + ", len: " + stri(data.count()) + ", result: " + result.toStr())
        m._logger.printl(m._logger.DEBUG, "_sendRecord payload: " + m.format_hex_bytes(data) + ", data string: " + data.toAsciiString())
        return result
    end function

    tls_util._sendEncryptedRecord = function(rec_type as integer, data as object) as boolean
        AES_BLOCK_SIZE = 16

        ' 1. Calculate HMAC
        hmac_input = createObject("roByteArray")
        m._pushLongLong(hmac_input, m.client_seq_num)
        m._pushChar(hmac_input, rec_type)
        m._pushShort(hmac_input, m.TLS1_2_VERSION)
        m._pushShort(hmac_input, data.count())
        hmac_input.append(data)

        hmac = m.hmac_sha256(m.session_keys.client_write_MAC_key, hmac_input)

        ' 2. Construct plaintext: data + HMAC + padding
        plaintext = data
        plaintext.append(hmac)

        padding_len = AES_BLOCK_SIZE - (plaintext.count() mod AES_BLOCK_SIZE)
        padding_val = padding_len - 1

        for i = 1 to padding_len
            m._pushChar(plaintext, padding_val)
        end for

        ' 3. Generate IV and Encrypt
        iv = m.RandomByteArray(AES_BLOCK_SIZE)

        ciphertext = m.aes_256_cbc_encrypt(m.session_keys.client_write_key, iv, plaintext)
        if ciphertext = invalid
            return false
        end if

        ' 4. Construct final payload: IV + ciphertext and send
        final_payload = iv
        final_payload.append(ciphertext)

        m.client_seq_num++
        return m._sendRecord(rec_type, final_payload)
    end function

    ' Compute HMAC-SHA256 hash
    tls_util.hmac_sha256 = function(key as object, data as object) as object
        hmac = createObject("roHMAC")
        if hmac = invalid
            m._logger.printl(m._logger.FATAL, "roHMAC not available for HMAC-SHA256")
            return invalid
        end if
        if hmac.setup("sha256", key) <> 0
            m._logger.printl(m._logger.FATAL, "Failed to setup HMAC-SHA256")
            return invalid
        end if
        return hmac.Process(data)
    end function

    ' Update a running SHA256 context
    tls_util.sha256_update = sub(data as object)
        if m.sha256_context = invalid
            m.sha256_context = createObject("roEVPDigest")
            if m.sha256_context.setup("sha256") <> 0
                m._logger.printl(m._logger.FATAL, "Failed to initialize SHA256 context")
                m.sha256_context = invalid
                return
            end if
        end if
        m._logger.printl(m._logger.DEBUG, "sha256_update with data of length: " + stri(data.count()))
        m.sha256_context.update(data)
    end sub

    ' Finalize the running SHA256 hash and return the result
    tls_util.sha256_final = function() as string
        if m.sha256_context = invalid
            m._logger.printl(m._logger.FATAL, "SHA256 context not initialized before final()")
            return invalid
        end if

        sha256_result = m.sha256_context.final()

        ' Create a new context for the next handshake
        m.sha256_context = invalid

        return sha256_result
    end function

    ' Implements the TLS 1.2 PRF (Pseudo-Random Function) using P_SHA256
    tls_util.prf_sha256 = function(secret as object, label as string, seed as object, out_len as integer) as object
        ' Combine label and seed
        labelBA = createObject("roByteArray")
        labelBA.fromAsciiString(label)

        m._logger.printl(m._logger.DEBUG, "prf_sha256 secret (len:" + StrI(secret.Count()) + ") " + m.format_hex_bytes(secret))
        m._logger.printl(m._logger.DEBUG, "prf_sha256 label (len:" + StrI(labelBA.Count()) + ") '" + label + "' - " + m.format_hex_bytes(labelBA))
        m._logger.printl(m._logger.DEBUG, "prf_sha256 seed (len:" + StrI(seed.Count()) + ") " + m.format_hex_bytes(seed))

        full_seed = labelBA
        full_seed.append(seed)

        m._logger.printl(m._logger.DEBUG, "p_hash seed (len:" + StrI(full_seed.Count()) + ") " + m.format_hex_bytes(full_seed))

        ' P_hash implementation
        result = createObject("roByteArray")
        a = m.hmac_sha256(secret, full_seed) ' A(1)

        while result.count() < out_len
            ' HMAC(secret, A(i) + seed)
            hmac_input = createObject("roByteArray")
            hmac_input.append(a)
            hmac_input.append(full_seed)
            hmac_out = m.hmac_sha256(secret, hmac_input)
            result.append(hmac_out)

            if result.count() < out_len
                ' A(i+1) = HMAC(secret, A(i))
                a = m.hmac_sha256(secret, a)
            end if
        end while

        ' Truncate to the desired length
        return result.slice(0, out_len)
    end function

    ' Encrypt with AES-256-CBC
    tls_util.aes_256_cbc_encrypt = function(key as object, iv as object, plaintext as object) as object
        cipher = createObject("roEVPCipher")
        if cipher.setup(true, "aes-256-cbc", key.toHexString(), iv.toHexString(), 0) <> 0 ' true for encryption, 0 for no padding
            m._logger.printl(m._logger.FATAL, "Failed to setup AES-256-CBC for encryption")
            return invalid
        end if

        result = cipher.Process(plaintext)
        return result
    end function

    tls_util._readAndDecryptRecord = function(rec_type as integer, payload as object) as object
        AES_BLOCK_SIZE = 16
        SHA256_DIGEST_LENGTH = 32

        ' 1. Separate IV and ciphertext
        if payload.count() < AES_BLOCK_SIZE
            return invalid
        end if
        iv = payload.slice(0, AES_BLOCK_SIZE)
        ciphertext = payload.slice(AES_BLOCK_SIZE)

        ' 2. Decrypt
        decrypted = m.aes_256_cbc_decrypt(m.session_keys.server_write_key, iv, ciphertext)
        if decrypted = invalid
            return invalid
        end if

        ' 3. Strip padding
        padding_len = decrypted[decrypted.count() - 1] + 1
        if padding_len > decrypted.count()
            return invalid
        end if

        data_and_mac = decrypted.slice(0, decrypted.count() - padding_len)

        ' 4. Separate MAC and original data
        if data_and_mac.count() < SHA256_DIGEST_LENGTH
            return invalid
        end if
        original_data_len = data_and_mac.count() - SHA256_DIGEST_LENGTH
        original_data = data_and_mac.slice(0, original_data_len)
        received_hmac = data_and_mac.slice(original_data_len)

        ' 5. Verify HMAC
        hmac_input = createObject("roByteArray")
        m._pushLongLong(hmac_input, m.server_seq_num)
        m._pushChar(hmac_input, rec_type)
        m._pushShort(hmac_input, m.TLS1_2_VERSION)
        m._pushShort(hmac_input, original_data.count())
        hmac_input.append(original_data)

        calculated_hmac = m.hmac_sha256(m.session_keys.server_write_MAC_key, hmac_input)

        if received_hmac.toHexString() <> calculated_hmac.toHexString()
            m.logger.printl(m.logger.FATAL, "HMAC verification failed! Message has been tampered with.")
            return invalid
        end if

        ' 6. Success
        data = original_data
        data_len = original_data_len
        m._logger.printl(m._logger.DEBUG, "_readAndDecryptRecord decrypted data len: " + stri(data_len) + ", rec_type: " + stri(rec_type) + ", data hex: " + m.format_hex_bytes(data) + ", data string: " + data.toAsciiString())
        m.server_seq_num++
        return {
            rec_type: rec_type,
            payload: data,
            payload_len: data_len
        } ' Success
    end function
    ' Decrypt with AES-256-CBC
    tls_util.aes_256_cbc_decrypt = function(key as object, iv as object, ciphertext as object) as object
        cipher = createObject("roEVPCipher")
        if cipher.setup(false, "aes-256-cbc", key.toHexString(), iv.toHexString(), 0) <> 0 ' false for decryption, 0 for no padding
            m._logger.printl(m._logger.FATAL, "Failed to setup AES-256-CBC for decryption")
            return invalid
        end if

        result = cipher.Process(ciphertext)
        return result
    end function

    ' Encrypt premaster secret with RSA public key using an external Web service
    tls_util.rsa_encrypt_premaster = function(premaster_secret as object) as object
        m._logger.printl(m._logger.DEBUG, "TlsUtil", "Attempting RSA encryption via web service")
        response = m.rsa_encrypt_service(premaster_secret)

        if (response <> invalid) and (response.status = 200) and (type(response.body) = "roAssociativeArray") and m.isString(response.body.encrypted_data)
            ba = createObject("roByteArray")
            ba.fromHexString(response.body.encrypted_data)
            if ba.count() > 0
                m._logger.printl(m._logger.DEBUG, "TlsUtil", "RSA encryption successful via web service: " + stri(ba.count()) + " bytes returned: " + m.format_hex_bytes(ba))

                return ba
            end if
        end if

        m._logger.printl(m._logger.FATAL, "RSA encryption via web service failed: " + FormatJson(response))
        return invalid
    end function

    ' Makes the HTTP POST call to the crypto service
    tls_util.rsa_encrypt_service = function(premaster_secret as object) as object

        response = { body: {}, headers: invalid, status: -1 }

        if (m._rsa_service_info.url = invalid) or m._rsa_service_info.url.IsEmpty()
            response.body.message = "ERROR: WebSocketClient.rsa_service_info.url is not configured!"
            return response
        end if

        http = createObject("roUrlTransfer")
        http.setPort(createObject("roMessagePort"))
        http.setUrl(m._rsa_service_info.url)
        http.setRequest("POST")
        http.retainBodyOnError(true)
        http.enableEncodings(true)
        headers = {
            "Content-Type": "application/json; charset=UTF-8"
        }
        if getInterface(m._rsa_service_info.headers, "ifAssociativeArray") <> invalid
            headers.Append(m._rsa_service_info.headers)
        end if
        http.SetHeaders(headers)
        hexPremaster = premaster_secret.toHexString()
        postData = "{ ""data"": """ + hexPremaster + """ }"

        #if DEBUG_LOG_WEBSOCKET
            m._logger.printl(3, "TlsUtil", "RSA service request URL: " + m._rsa_service_info.url + Chr(10) + "HEADERS: " + FormatJson(m._rsa_service_info.headers) + Chr(10) + "BODY: " + postData)
        #end if

        didRequest = http.asyncPostFromString(postData)

        if not didRequest
            m._logger.printl(3, "TlsUtil", "RSA service request was not sent to url: " + m._rsa_service_info.url)
            return invalid
        end if

        msg = wait(m._connect_timeout_seconds * 1000, http.getMessagePort())

        if type(msg) = "roUrlEvent"
            if msg.getInt() = 1 ' Complete
                response.body = parseJson(msg.getString())
                response.headers = msg.getResponseHeaders()
                response.status = msg.getResponseCode()
                response.url = m._rsa_service_info.url
                #if DEBUG_LOG_WEBSOCKET
                    m._logger.printl(m._logger.DEBUG, "TlsUtil", "RSA service request completed " + formatJson(response))
                #end if
            else
                m._logger.printl(m._logger.FATAL, "RSA service request failed with code: " + stri(msg.getInt()))
            end if
        else if msg = invalid
            m._logger.printl(m._logger.FATAL, "RSA service request timed out.")
        end if

        return response
    end function

    tls_util.isString = function(value as dynamic) as boolean
        return value <> invalid and getInterface(value, "ifString") <> invalid
    end function

    tls_util.format_hex_bytes = function(data as object) as string
        return m.two_chars_regex.replaceAll(data.toHexString(), "\1 ")
    end function

    return tls_util
end function
