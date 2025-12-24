' WebSocketClient.brs
' Copyright (C) 2018 Rolando Islas
' Released under the MIT license
'
' BrightScript web socket client (RFC 6455)

' Create a new WebSocketClient instance

function WebSocketClient() as object
    ws = {}
    ' Constants
    ws.STATE = {
        CONNECTING: 0,
        OPEN: 1,
        CLOSING: 2,
        CLOSED: 3
    }
    ws.OPCODE = {
        CONTINUATION: 0,
        TEXT: 1,
        BINARY: 2,
        CLOSE: 8,
        PING: 9,
        PONG: 10
    }
    ws._REGEX_URL = createObject("roRegex", "(\w+):\/\/([^/:]+)(?::(\d+))?(.*)?", "")
    ws._CHARS = "0123456789abcdefghijklmnopqrstuvwxyz".split("")
    ws._NL = chr(13) + chr(10)
    ws._HTTP_STATUS_LINE_REGEX = createObject("roRegex", "(HTTP\/\d+(?:.\d)?)\s(\d{3})\s(.*)", "")
    ws._HTTP_HEADER_REGEX = createObject("roRegex", "(\w+):\s?(.*)", "")
    ws._WS_ACCEPT_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    ws._FRAME_SIZE = 1024
    ws._CLOSING_DELAY = 30
    ws._BUFFER_SOCKET_SIZE = 4096 ' we allow 4times higher amount in buffer as max limit without waiting to clear it, figured out the last amount of buffer is about 13000 before it overload
    ws._BUFFER_SLEEP = 10
    ws._BUFFER_LOOP_LIMIT = 5000 / ws._BUFFER_SLEEP ' max waiting time till try to push another value into buffer, _BUFFER_SLEEP * _BUFFER_LOOP_LIMIT
    ' Variables
    ws._logger = Logger("WebSocketClient")
    ws._ready_state = ws.state.CLOSED
    ws._log_timestamp = uptime(0)
    ws._protocols = []
    ws._headers = []
    ws._secure = false
    ws._tls = invalid
    ws._socket = invalid
    ws._sec_ws_key = invalid
    ws._handshake = invalid
    ws._sent_handshake = false
    ws._has_received_handshake = false
    ws._socket_open_time = 0
    ws._buffer_size = cint(1024 * 1024 * 0.5)
    ws._data = createObject("roByteArray")
    ws._data[ws._buffer_size] = 0
    ws._data_size = 0
    ws._frame_data = createObject("roByteArray")
    ws._started_closing = 0
    ws._hostname = ""
    ws._ws_port = createObject("roMessagePort")
    ws._message_port = invalid
    ws._connect_timeout_seconds = 0
    ws._ping_interval_seconds = 0
    ws._pong_max_missed = 3
    ws._pong_timeout_seconds = 5
    ws._pong_missed_count = 0
    ws._rsa_service_info = {
        url: "",
        headers: {},
    }

    ' ========== Getters ==========

    ' Get web socket ready state
    ' @see WebSocketClient.STATE for values
    ' @param self WebSocketClient
    ' @return integer ready state
    ws.get_ready_state = function() as integer
        return m._ready_state
    end function

    ' Get web socket protocols sent on initial handshake
    ' @param self WebSocketClient
    ' @return roArray web socket protocols
    ws.get_protocols = function() as object
        return m._protocols
    end function

    ' Get HTTP headers sent on initial HTTP request
    ' @param self WebSocketClient
    ' @return roArray HTTP headers - even indices are the header keys, the odd
    '         indices are the header values
    ws.get_headers = function() as object
        return m._headers
    end function

    ' Get the status of a secure web socket connection having been used
    ' @param self WebSocketClient
    ' @return boolean true if a TLS connection should be attempted before
    '         attempting a web socket handshake
    ws.get_secure = function() as boolean
        return m._secure
    end function

    ' Get the maximum buffer size for data sent to the websocket
    ' @param self WebSocketClient
    ' @return integer max buffer size in bytes
    ws.get_buffer_size = function() as integer
        return m._buffer_size
    end function

    ' ========== Setters ==========

    ' Set the web socket protocols to request from the web socket server
    ' @param self WebSocketClient
    ' @param roArray of protocol strings
    ws.set_protocols = sub(protocols as object) as void
        m._protocols = protocols
        m._post_message("protocols", m._protocols)
    end sub

    ' Set the headers to send on the initial HTTP request for a web socket
    ' @param self WebSocketClient
    ' @param roArray of header strings - The even indices should be the header
    '        keys and the odd are the header values
    ws.set_headers = sub(headers as object) as void
        m._headers = headers
        m._post_message("headers", m._headers)
    end sub

    ' Set if a TLS connection should be attempted before the web socket
    ' connection
    ' @param self WebSocketClient
    ' @param secure boolean should a secure connetion be attempted
    ws.set_secure = sub(secure as boolean) as void
        m._secure = secure
        m._post_message("secure", m._secure)
    end sub

    ' Set the buffer size for web socket data
    ' @param self WebSocketClient
    ' @param size integer max size of buffer in bytes
    ws.set_buffer_size = sub(size as integer) as void
        if m._ready_state <> m.STATE.CLOSED
            m._logger.printl(m._logger.WARN, "Cannot resize buffer on a socket that is not closed")
            return
        else if size < m._FRAME_SIZE
            m._logger.printl(m._logger.WARN, "Cannot set buffer to a size smaller than " + m._FRAME_SIZE.toStr() + " bytes")
            return
        end if
        m._buffer_size = size
        m._buffer = createObject("roByteArray")
        m._buffer[m._buffer_size] = 0
        m._data_size = 0
        m._post_message("buffer_size", m._buffer_size)
    end sub

    ' Set the message port that should be used to relay web socket events and
    ' field change updates
    ' @param self WebSocketClient
    ' @param port roMessagePort
    ws.set_message_port = sub(port as object) as void
        m._message_port = port
    end sub

    ' Set the log level
    ws.set_log_level = sub(log_level as string) as void
        m._logger.set_log_level(log_level)
    end sub

    ws.set_connect_timeout = sub(connect_timeout as integer) as void
        m._connect_timeout_seconds = connect_timeout
    end sub

    ws.set_close_timeout = sub(close_timeout as integer) as void
        m._CLOSING_DELAY = close_timeout
    end sub

    ws.set_ping_interval = sub(ping_interval as integer) as void
        m._ping_interval_seconds = ping_interval
    end sub

    ws.set_pong_max_missed = sub(pong_max_missed as integer) as void
        m._pong_max_missed = pong_max_missed
    end sub

    ws.set_pong_timeout = sub(pong_timeout as integer) as void
        m._pong_timeout_seconds = pong_timeout
    end sub

    ws.set_rsa_service_info = sub(service_info as object) as void
        m._rsa_service_info = service_info
        if m._tls <> invalid
            m._tls.set_rsa_service_info(m._rsa_service_info)
        end if
    end sub

    ' ========== Main ==========

    ' Parses one websocket frame or HTTP message, if one is available
    ' @param self WebSocketClient
    ws.run = sub() as void
        msg = wait(300, m._ws_port)
        ' Socket event
        if type(msg) = "roSocketEvent"
            m._send_handshake()
            m._read_socket_data()
        end if
        m._try_force_close()
        m._check_pinger()
    end sub

    ' Force close a connection after the close frame has been sent and no
    ' response was given, after a timeout
    ' @param self WebSocketClient
    ws._try_force_close = sub() as void
        if (m._ready_state = m.STATE.CLOSING) and ((uptime(0) - m._started_closing) >= m._CLOSING_DELAY)
            m._close()
        end if
        if (m._ready_state = m.STATE.OPEN) and m._secure and (m._tls.websocket_ready_state = m._tls.STATE_DISCONNECTED)
            m._state(m.STATE.CLOSING) ' Skip trying to send close frame
            m.close([1011, "Internal error: TLS disconnected"])
        end if

        ' Check if open connection is
        ' If we've been stuck for too long, reset and retry
        if (m._ready_state = m.STATE.CONNECTING) and ((uptime(0) - m._socket_open_time) >= m._connect_timeout_seconds)
            #if DEBUG_LOG_WEBSOCKET
                m._logger.printl(m._logger.DEBUG, "WebSocket connect timed out, resetting connection")
            #end if
            m._close(1006, "WebSocket connect timed out")
        end if
    end sub

    ' Sends data through the socket
    ' @param self WebSocketClient
    ' @param message array - should contain one element of type roString or roArray
    '                        cannot exceed 125 bytes if the the specified opcode
    '                        is for a control frame
    ' @param _opcode int - define a **control** opcode data opcodes are determined
    '                      by the type of the passed message
    ' @param silent boolean - does not send on_websocket_error event
    ' @param do_close boolean - if true, a close frame will be sent on errors
    ' @return integer amount of bytes sent
    ws.send = function(message as dynamic, _opcode = -1 as integer, silent = false as boolean, do_close = true as boolean) as integer
        if m._socket = invalid or not m.rawSocketConected
            m._logger.printl(m._logger.DEBUG, "Failed to send data: socket is closed")
            return -1
        end if
        if m._ready_state <> m.STATE.OPEN
            m._logger.printl(m._logger.DEBUG, "Failed to send data: connection not open")
            return -1
        end if
        if type(message) = "roString" or type(message) = "String" or type(message) = "roByteArray"
            message = [message]
        end if
        if message.count() <> 1
            m._logger.printl(m._logger.DEBUG, "Failed to send data: too many parameters")
            return -1
        end if
        bytes = createObject("roByteArray")
        opcode = 0
        if type(message[0]) = "roString" or type(message[0]) = "String"
            bytes.fromAsciiString(message[0])
            opcode = m.OPCODE.TEXT
        else if type(message[0]) = "roArray" or type(message[0]) = "roByteArray"
            for each byte in message[0]
                bytes.push(byte)
            end for
            opcode = m.OPCODE.BINARY
        else
            m._logger.printl(m._logger.DEBUG, "Failed to send data: invalid parameter type")
            return -1
        end if
        if _opcode > -1 and (_opcode >> 3) <> 1
            m._logger.printl(m._logger.DEBUG, "Failed to send data: specified opcode was not a control opcode")
            return -1
        else if _opcode > -1
            if bytes.count() > 125
                m._logger.printl(m._logger.DEBUG, "Failed to send data: control frames cannot have a payload larger than 125 bytes")
                return -1
            end if
            opcode = _opcode
        end if
        ' Frame message
        frame_count = bytes.count() \ m._FRAME_SIZE
        if ((bytes.count() mod m._FRAME_SIZE) <> 0) or (frame_count = 0)
            frame_count++
        end if
        total_sent = 0
        for frame_index = 0 to (frame_count - 1)
            ' Get sub array of payload bytes
            payload = createObject("roByteArray")
            max = bytes.count() - 1
            if (frame_index + 1) * m._FRAME_SIZE - 1 < max
                max = (frame_index + 1) * m._FRAME_SIZE - 1
            end if
            for byte_index = frame_index * m._FRAME_SIZE to max
                payload.push(bytes[byte_index])
            end for
            ' Construct frame
            frame = createObject("roByteArray")
            ' FIN(1) RSV1(1) RSV2(1) RSV3(1) opcode(4)
            final = 0
            if frame_index = frame_count - 1
                final = &h80
            end if
            opcode_frame = m.OPCODE.CONTINUATION
            if frame_index = 0
                opcode_frame = opcode
            end if
            frame.push(final or opcode_frame)
            ' mask(1) payload_length(7)
            length_7 = payload.count()
            if payload.count() > &hffff
                length_7 = 127
            else if payload.count() > 125
                length_7 = 126
            end if
            frame.push(&h80 or length_7)
            ' payload_length_continuation(64)
            ' 16 bit uint
            if length_7 = 126
                frame.append(short_to_bytes(payload.count()))
                ' 64 bit uint
            else if length_7 = 127
                frame.append(long_to_bytes(payload.count()))
            end if
            ' masking key(32)
            mask = rnd(&hffff)
            mask_bytes = int_to_bytes(mask)
            frame.append(mask_bytes)
            ' Mask payload
            masked_payload = createObject("roByteArray")
            for byte_index = 0 to payload.count() - 1
                masking_key = mask_bytes[byte_index mod 4]
                byte = payload[byte_index]
                masked_byte = xor(byte, masking_key)
                masked_payload.push(masked_byte)
            end for
            frame.append(masked_payload)
            ' Send frame
            if _opcode <> m.OPCODE.PING
                m._logger.printl(m._logger.VERBOSE, "Sending frame (" + (frame_index + 1).ToStr() + " of " + frame_count.ToStr() + "): " + frame.toHexString() + ", data string: " + payload.toAsciiString())
            end if
            sent = 0
            if m._secure
                sent = m._tls.send(frame)
            else
                sent = m._socket.send(frame, 0, frame.count())
            end if
            if _opcode <> m.OPCODE.PING
                m._logger.printl(m._logger.VERBOSE, "Sent " + sent.toStr() + " bytes")
                loop_wait = 0
                while m._socket.GetCountSendBuf() > m._BUFFER_SOCKET_SIZE
                    m._logger.printl(m._logger.VERBOSE, "Sleeping " + m._BUFFER_SLEEP.toStr() + "ms to reduce buffer")
                    sleep(m._BUFFER_SLEEP)
                    if loop_wait > m._BUFFER_LOOP_LIMIT
                        exit while
                    end if
                    loop_wait++
                end while
            end if
            total_sent += sent
            if sent <> frame.count()
                if do_close
                    m._close()
                end if
                if not silent
                    m._error(14, "Failed to send data")
                end if
                return total_sent
            end if
        end for
        return total_sent
    end function

    ' Send the initial websocket handshake if it has not been sent
    ' @param self WebSocketClient
    ws._send_handshake = sub() as void
        if m._ready_state = m.STATE.OPEN
            return
        end if
        #if DEBUG_LOG_WEBSOCKET
            now = uptime(0)
            doRepetitiveLog = (m._log_timestamp + 1.0) < now
            if doRepetitiveLog
                m._log_timestamp = now
                m._logger.printl(m._logger.DEBUG, "_send_handshake socket: " + (m._socket <> invalid).toStr() + ", rawSocketConected=" + m.rawSocketConected.toStr() + ", secure=" + m._secure.toStr() + ", sent_handshake=" + m._sent_handshake.toStr() + ", handshake=" + (m._handshake <> invalid).toStr() + ", tls_state=" + m._tls?.websocket_ready_state.toStr())
            end if
        #end if

        if m._socket = invalid or not m.rawSocketConected or m._sent_handshake or m._handshake = invalid or (m._secure and m._tls.websocket_ready_state = m._tls.STATE_CONNECTING)
            #if DEBUG_LOG_WEBSOCKET
                if doRepetitiveLog
                    m._logger.printl(m._logger.DEBUG, "Not ready for handshake socket: " + (m._socket <> invalid).toStr() + ", rawSocketConected=" + m.rawSocketConected.toStr() + ", sent_handshake=" + m._sent_handshake.toStr() + ", handshake=" + (m._handshake <> invalid).toStr() + ", tls_state=" + m._tls?.websocket_ready_state.toStr())
                end if
            #end if
            return
        end if
        if m._secure and m._tls.websocket_ready_state = m._tls.STATE_DISCONNECTED
            #if DEBUG_LOG_WEBSOCKET
                m._logger.printl(m._logger.DEBUG, "Establshing TLS ...")
            #end if
            m._tls.connect(m._hostname)
        else
            m._logger.printl(m._logger.VERBOSE, m._handshake)
            sent = 0
            if m._secure
                sent = m._tls.send_str(m._handshake)
            else
                sent = m._socket.sendStr(m._handshake)
            end if
            m._logger.printl(m._logger.VERBOSE, "Sent " + sent.toStr() + " bytes")
            if sent = -1
                m._close()
                m._error(4, "Failed to send data: " + m._socket.status().toStr())
                return
            end if
            m._sent_handshake = true
        end if
    end sub

    ' Read socket data
    ' @param self WebSocketClient
    ws._read_socket_data = sub() as void
        if m._socket = invalid or m._ready_state = m.STATE.CLOSED or (m._secure and m._tls.websocket_ready_state = m._tls.STATE_DISCONNECTED)
            return
        end if
        buffer = createObject("roByteArray")
        buffer[1024] = 0
        bytes_received = 0
        if m._socket.isReadable() and m._socket.getCountRcvBuf() > 0
            bytes_received = m._socket.receive(buffer, 0, 1024)
        end if
        if bytes_received < 0
            m._close()
            m._error(15, "Failed to read from socket")
            return
        end if
        if m._secure
            buffer = m._tls.read(buffer, bytes_received)
            if buffer = invalid
                m._close()
                m._error(17, "TLS error")
                return
            end if
            bytes_received = buffer.count()
        end if
        buffer_index = 0
        for byte_index = m._data_size to m._data_size + bytes_received - 1
            m._data[byte_index] = buffer[buffer_index]
            buffer_index++
        end for
        m._data_size += bytes_received
        m._data[m._data_size] = 0
        ' WebSocket frames
        if m._has_received_handshake
            ' Wait for at least the payload 7-bit size
            if m._data_size < 2
                return
            end if
            final = (m._data[0] >> 7) = 1
            opcode = (m._data[0] and &hf)
            control = (opcode >> 3) = 1
            masked = (m._data[1] >> 7) = 1
            payload_size_7 = m._data[1] and &h7f
            payload_size = payload_size_7
            payload_index = 2
            mask = 0
            if payload_size_7 = 126
                ' Wait for the 16-bit payload size
                if m._data_size < 4
                    return
                end if
                payload_size = bytes_to_short(m._data[2], m._data[3])
                payload_index += 2
            else if payload_size_7 = 127
                ' Wait for the 64-bit payload size
                if m._data_size < 10
                    return
                end if
                payload_size = bytes_to_long(m._data[2], m._data[3], m._data[4], m._data[5], m._data[6], m._data[7], m._data[8], m._data[9])
                payload_index += 8
            end if
            if masked
                ' Wait for mask int
                if m._data_size < payload_index
                    return
                end if
                mask = bytes_to_int(m._data[payload_index], m._data[payload_index + 1], m._data[payload_index + 2], m._data[payload_index + 3])
                payload_index += 4
            end if
            ' Wait for payload
            if m._data_size < payload_index + payload_size
                return
            end if
            payload = createObject("roByteArray")
            for byte_index = payload_index to payload_index + payload_size - 1
                payload.push(m._data[byte_index])
            end for
            ' Handle control frame
            if control
                m._handle_frame(opcode, payload)
                ' Handle data frame
            else if final
                full_payload = createObject("roByteArray")
                full_payload.append(m._frame_data)
                full_payload.append(payload)
                m._handle_frame(opcode, full_payload)
                m._frame_data.clear()
                ' Check for continuation frame
            else
                m._frame_data.append(payload)
            end if
            ' Save start of next frame
            if m._data_size > payload_index + payload_size
                data = createObject("roByteArray")
                data.append(m._data)
                m._data.clear()
                for byte_index = payload_index + payload_size to m._data_size - 1
                    m._data.push(data[byte_index])
                end for
            else
                m._data.clear()
            end if
            ' HTTP/Handshake
        else
            data = m._data.toAsciiString()
            http_delimiter = m._NL + m._NL
            if data.len() <> data.replace(http_delimiter, "").len()
                split = data.split(http_delimiter)
                message = split[0]
                data = ""
                for split_index = 1 to split.count() - 1
                    data += split[split_index]
                    if split_index < split.count() - 1 or split[split_index].right(4) = m._NL + m._NL
                        data += m._NL + m._NL
                    end if
                end for
                ' Handle the message
                m._logger.printl(m._logger.VERBOSE, "Message: " + message)
                m._handle_handshake_response(message)
            end if
            m._data.fromAsciiString(data)
        end if
        m._data_size = m._data.count()
        m._data[m._buffer_size] = 0
    end sub

    ' Handle the handshake message or die trying
    ' @param self WebSocketClient
    ' @param string http response header
    ws._handle_handshake_response = sub(message as string) as void
        lines = message.split(m._NL)
        if lines.count() = 0
            m._close()
            m._error(5, "Invalid handshake: Missing status line")
            return
        end if
        ' Check status line
        if not m._HTTP_STATUS_LINE_REGEX.isMatch(lines[0])
            m._close()
            m._error(6, "Invalid handshake: Status line malformed")
            return
        end if
        status_line = m._HTTP_STATUS_LINE_REGEX.match(lines[0])
        if status_line[1] <> "HTTP/1.1"
            m._close()
            m._error(7, "Invalid handshake: Response version mismatch.  Expected HTTP/1.1, got " + status_line[0])
            return
        end if
        if status_line[2] <> "101"
            m._close()
            m._error(8, "Invalid handshake: HTTP status code is not 101: Received " + status_line[2])
            return
        end if
        ' Search headers
        protocol = ""
        for header_line_index = 1 to lines.count() - 1:
            if m._HTTP_HEADER_REGEX.isMatch(lines[header_line_index])
                header = m._HTTP_HEADER_REGEX.match(lines[header_line_index])
                ' Upgrade
                if ucase(header[1]) = "UPGRADE" and ucase(header[2]) <> "WEBSOCKET"
                    m._close()
                    m._error(9, "Invalid handshake: invalid upgrade header: " + header[2])
                    return
                    ' Connection
                else if ucase(header[1]) = "CONNECTION" and ucase(header[2]) <> "UPGRADE"
                    m._close()
                    m._error(10, "Invalid handshake: invalid connection header: " + header[2])
                    return
                    ' Sec-WebSocket-Accept
                else if ucase(header[1]) = "SEC-WEBSOCKET-ACCEPT"
                    expected_array = createObject("roByteArray")
                    expected_array.fromAsciiString(m._sec_ws_key + m._WS_ACCEPT_GUID)
                    digest = createObject("roEVPDigest")
                    digest.setup("sha1")
                    expected = digest.process(expected_array)
                    if expected <> header[2].trim()
                        m._close()
                        m._error(11, "Invalid handshake: Sec-WebSocket-Accept value is invalid: " + header[2])
                        return
                    end if
                    ' Sec-WebSocket-Extensions
                else if ucase(header[1]) = "SEC-WEBSOCKET-EXTENSIONS" and header[2] <> ""
                    m._close()
                    m._error(12, "Invalid handshake: Sec-WebSocket-Extensions value is invalid: " + header[2])
                    return
                    ' Sec-WebSocket-Protocol
                else if ucase(header[1]) = "SEC-WEBSOCKET-PROTOCOL"
                    p = header[2].trim()
                    was_requested = false
                    for each requested_protocol in m._protocols
                        if requested_protocol = p
                            was_requested = true
                        end if
                    end for
                    if not was_requested
                        m._close()
                        m._error(13, "Invalid handshake: Sec-WebSocket-Protocol contains a protocol that was not requested: " + p)
                        return
                    end if
                    protocol = p
                end if
            end if
        end for
        m._has_received_handshake = true
        m._state(m.STATE.OPEN)
        m._post_message("on_websocket_open", {
            protocol: protocol
        })
        m._start_pinger()
    end sub

    ' Post a message to the message port
    ' @param self WebSocketClient
    ' @param id string message event id
    ' @param data dynamic message data
    ws._post_message = sub(id as string, data as dynamic) as void
        if m._message_port <> invalid
            m._message_port.postMessage({
                id: id,
                data: data
            })
        end if
    end sub

    ' Handle a web socket frame
    ' @param self WebSocketClient
    ' @param opcode int opcode
    ' @param payload roByteArray payload data
    ws._handle_frame = sub(opcode as integer, payload as object) as void
        if opcode <> m.OPCODE.PONG
            frame_print = "" + "Received frame:" + m._NL
            frame_print += "  Opcode: " + opcode.toStr() + m._NL
            frame_print += "  Payload: " + payload.toHexString()
            m._logger.printl(m._logger.VERBOSE, frame_print)
        end if

        if m._is_ping_enabled() and (not m._is_ping_sent)
            m._mark_ping_pong_time() ' delay next ping since the channel is active
        end if

        ' Close
        if opcode = m.OPCODE.CLOSE
            m._close()
            return
            ' Ping
        else if opcode = m.OPCODE.PING
            m.send("", m.OPCODE.PONG)
            return
            ' Pong
        else if opcode = m.OPCODE.PONG
            if m._is_ping_enabled()
                m._on_pong_received(payload)
            end if
            return
            ' Text
        else if opcode = m.OPCODE.TEXT
            m._post_message("on_websocket_message", {
                type: 0,
                message: payload.toAsciiString()
            })
            return
            ' Data
        else if opcode = m.OPCODE.BINARY
            payload_array = []
            for each byte in payload
                payload_array.push(byte)
            end for
            m._post_message("on_websocket_message", {
                type: 1,
                message: payload_array
            })
            return
        end if
    end sub

    ' Generate a 20 character [A-Za-z0-9] random string and base64 encode it
    ' @param self WebSocketClient
    ' @return string random 20 character base64 encoded string
    ws._generate_sec_ws_key = function() as string
        sec_ws_key = ""
        for char_index = 0 to 19
            char = m._CHARS[rnd(m._CHARS.count()) - 1]
            if rnd(2) = 1
                char = ucase(char)
            end if
            sec_ws_key += char
        end for
        ba = createObject("roByteArray")
        ba.fromAsciiString(sec_ws_key)
        return ba.toBase64String()
    end function

    ' Connect to the specified URL
    ' @param self WebSocketClient
    ' @param url_string web socket url to connect
    '                   Format: ws://example.org:80/
    '                   If the port is not specified the port will be assumed
    '                   from the protocol (ws: 80, wss: 443).
    ws.open = sub(url as string) as void
        if m._ready_state <> m.STATE.CLOSED
            m._logger.printl(m._logger.DEBUG, "Tried to open a web socket that was already open")
            return
        end if
        #if DEBUG_LOG_WEBSOCKET
            m._logger.printl(m._logger.DEBUG, "Opening URL: " + url)
        #end if
        if m._REGEX_URL.isMatch(url)
            match = m._REGEX_URL.match(url)
            ws_type = lcase(match[1])
            host = lcase(match[2])
            port = match[3]
            path = match[4]
            #if DEBUG_LOG_WEBSOCKET
                m._logger.printl(m._logger.DEBUG, "Parsed URL: " + FormatJson({
                    ws_type: ws_type,
                    host: host,
                    port: port,
                    path: path,
                }))
            #end if
            m._hostname = host
            ' Port
            if ws_type = "wss"
                m.set_secure(true)
            else if ws_type = "ws"
                m.set_secure(false)
            else
                m._close()
                m._error(0, "Invalid web socket type specified: " + ws_type)
                return
            end if
            if port <> ""
                port = val(port, 10)
            else if m._secure
                port = 443
            else
                port = 80
            end if
            ' Path
            if path = ""
                path = "/"
            end if
            ' Construct handshake
            m._sec_ws_key = m._generate_sec_ws_key()
            protocols = ""
            for each proto in m._protocols
                protocols += proto + ", "
            end for
            if protocols <> ""
                protocols = protocols.left(len(protocols) - 2)
            end if
            handshake = "GET " + path + " HTTP/1.1" + m._NL
            handshake += "Host: " + host + ":" + port.toStr() + m._NL
            handshake += "Upgrade: websocket" + m._NL
            handshake += "Connection: Upgrade" + m._NL
            handshake += "Sec-WebSocket-Key: " + m._sec_ws_key + m._NL
            if protocols <> ""
                handshake += "Sec-WebSocket-Protocol: " + protocols + m._NL
            end if
            ' handshake += "Sec-WebSocket-Extensions: " + m._NL
            handshake += "Sec-WebSocket-Version: 13" + m._NL
            handshake += m._get_parsed_user_headers()
            handshake += m._NL
            m._handshake = handshake
            ' Create socket
            m.rawSocketConected = false
            m._state(m.STATE.CONNECTING)
            address = createObject("roSocketAddress")
            address.setHostName(host)
            address.setPort(port)

            if not address.isAddressValid()
                m._logger.printl(m._logger.FATAL, "Invalid hostname: " + host + ":" + port.ToStr())
                m._close()
                m._error(2, "Invalid hostname")
                return
            end if
            m._data_size = 0
            m._socket = createObject("roStreamSocket")
            m._socket.notifyReadable(true)
            m._socket.notifyWritable(true)
            m._socket.notifyException(true)
            ' set up segmentation on 576 which is lowest value of MTU speed up
            ' transmition around 15%-22%, tested on 4660X - Roku Ultra and
            ' 3500EU - Roku Stick
            m._socket.setMaxSeg(576)
            m._socket.setMessagePort(m._ws_port)
            m._socket.setSendToAddress(address)
            m._sent_handshake = false
            m._has_received_handshake = false
            m._tls = TlsUtil()
            m._tls.set_log_level_int(m._logger.log_level)
            m._tls.set_socket(m._socket)
            m._tls.set_buffer_size(m._buffer_size)
            m._tls.set_rsa_service_info(m._rsa_service_info)
            m._tls.set_connect_timeout_seconds(m._connect_timeout_seconds)
            if not m._socket.connect()
                m._close()
                errMsg = "Socket failed to connect: " + m._socket.status().toStr()
                m._logger.printl(m._logger.FATAL, "" + errMsg)
                m._error(3, errMsg)
                return
            end if
            m.rawSocketConected = true
            m._socket_open_time = uptime(0) ' Record when Web-Socket as open
            #if DEBUG_LOG_WEBSOCKET
                m._logger.printl(m._logger.DEBUG, "WebSocketClient open success: " + FormatJson({
                    ws_type: ws_type,
                    host: host,
                    port: port,
                    path: path,
                }))
            #end if
        else
            m._close()
            m._error(1, "Invalid URL specified")
        end if
    end sub

    ' Parse header array and return a string of headers delimited by CRLF
    ' @param self WebSocketClient
    ws._get_parsed_user_headers = function() as string
        if m._headers = invalid or m._headers.count() = 0 or (m._headers.count() mod 2) = 1
            return ""
        end if
        header_string = ""
        for header_index = 0 to m._headers.count() - 1 step 2
            header = m._headers[header_index]
            value = m._headers[header_index + 1]
            header_string += header + ": " + value + m._NL
        end for
        return header_string
    end function

    ' Set ready state
    ' @param self WebSocketClient
    ' @param state
    ws._state = sub(_state as integer) as void
        m._ready_state = _state
        m._post_message("websocket_ready_state", _state)
    end sub

    ' Send an error event
    ' Posts an on_websocket_error message to the message port
    ' @param self WebSocketClient
    ' @param code integer error code
    ' @param message string error message
    ws._error = sub(code as integer, message as string) as void
        m._logger.printl(m._logger.EXTRA, "Error: " + message)
        m._post_message("on_websocket_error", {
            code: code,
            message: message
        })
    end sub

    ' Close the socket
    ' @param WebSocketClient
    ' @param code integer -  status code
    ' @param reason roByteArray - reason
    ws._close = sub(code = 1000 as integer, reason = invalid as object) as void
        if m._socket <> invalid
            ' Send the closing frame
            if m._ready_state = m.STATE.OPEN
                m._send_close_frame(code, reason)
                m._started_closing = uptime(0)
                m._state(m.STATE.CLOSING)
            else
                m._state(m.STATE.CLOSED)
                m._post_message("on_websocket_close", {
                    code: code,
                    reason: reason
                })
                m._socket.close()
            end if
        else if m._ready_state <> m.STATE.CLOSED
            m._state(m.STATE.CLOSED)
        end if
    end sub

    ' Send a close frame to the server to initiate a close
    ' @param self WebSocketClient
    ' @param code integer -  status code
    ' @param reason roByteArray - reason
    ws._send_close_frame = sub(code as integer, reason as dynamic) as void
        message = createObject("roByteArray")
        message.push(code >> 8)
        message.push(code)
        if reason <> invalid
            message.append(reason)
        end if
        m.send(message, m.OPCODE.CLOSE, true, false)
    end sub

    ' Close the socket
    ' @self WebSocketClient
    ' @param reason array - array [code as integer, message as roString]
    ws.close = sub(params as object) as void
        #if DEBUG_LOG_WEBSOCKET
            m._logger.printl(m._logger.DEBUG, "close params: " + FormatJson(params))
        #end if
        code = 1000
        reason = createObject("roByteArray")
        if params.count() > 0
            code = params[0]
            if (getInterface(code, "ifInt") = invalid) or code > &hffff
                m._logger.printl(m._logger.DEBUG, "close expects value at array index 0 to be a 16-bit integer")
            end if
        end if
        if params.count() > 1
            message = params[1]
            if getInterface(message, "ifString") <> invalid
                reason.fromAsciiString(message)
            else
                m._logger.printl(m._logger.DEBUG, "close expects value at array index 1 to be a string")
            end if
        end if
        m._close(code, reason)
    end sub

    ws._is_ping_enabled = function() as boolean
        return m._ping_interval_seconds > 0
    end function

    ws._start_pinger = sub() as void
        if not (m._is_ping_enabled() and (m._ready_state = m.STATE.OPEN))
            return
        end if

        m._logger.printl(m._logger.DEBUG, "starting pinger with interval: " + m._ping_interval_seconds.ToStr() + " seconds")
        m._is_ping_sent = false
        m._pong_missed_count = 0
        m._ping_pong_timestamp = 0
        m._mark_ping_pong_time()
    end sub

    ws._check_pinger = sub() as void
        if not (m._is_ping_enabled() and (m._ready_state = m.STATE.OPEN))
            return
        end if

        seconds_since = uptime(0) - m._ping_pong_timestamp
        if m._is_ping_sent and (seconds_since >= m._pong_timeout_seconds)
            m._pong_missed_count += 1
            m._is_ping_sent = false
            seconds_since = m._ping_interval_seconds ' Force send ping
            m._logger.printl(m._logger.DEBUG, "pinger missed " + m._pong_missed_count.ToStr() + " from " + m._pong_max_missed.ToStr())
        end if

        if m._pong_missed_count >= m._pong_max_missed
            message = "pinger: ping timeout after " + m._pong_missed_count.ToStr() + " PONG message"
            m._logger.printl(m._logger.WARN, "" + message)
            m.close([1011, message])
        else if (not m._is_ping_sent) and (seconds_since >= m._ping_interval_seconds)
            m._is_ping_sent = true
            m._mark_ping_pong_time()
            m._logger.printl(m._logger.DEBUG, "pinger sending PING " + (m._pong_missed_count + 1).ToStr() + " of " + m._pong_max_missed.ToStr())
            m.send("", m.OPCODE.PING)
        end if

    end sub

    ws._on_pong_received = sub(payload as object) as void
        if m._is_ping_sent
            m._is_ping_sent = false
            m._mark_ping_pong_time()
            m._logger.printl(m._logger.DEBUG, "pinger PONG received")
        end if
    end sub

    ws._mark_ping_pong_time = sub() as void
        m._ping_pong_timestamp = uptime(0)
    end sub

    ' Return constructed instance
    return ws
end function
