' WebSocketClientTask.brs
' Copyright (C) 2018 Rolando Islas
' Released under the MIT license
'
' BrightScript, SceneGraph Task wrapper for the web socket client

' Entry point
sub init() as void
    ' Task init
    m.port = createObject("roMessagePort")
    ' Event listeners
    m.top.observeField("open", m.port)
    m.top.observeField("send", m.port)
    m.top.observeField("close", m.port)
    m.top.observeField("buffer_size", m.port)
    m.top.observeField("protocols", m.port)
    m.top.observeField("headers", m.port)
    m.top.observeField("secure", m.port)
    m.top.observeField("log_level", m.port)
    m.top.observeField("ping_interval", m.port)
    m.top.observeField("rsa_service_info", m.port)

    m.ws = WebSocketClient()
    m.ws.set_message_port(m.port)

    m.ws.set_connect_timeout(m.top.connect_timeout)
    m.ws.set_close_timeout(m.top.close_timeout)
    m.ws.set_ping_interval(m.top.ping_interval)
    m.ws.set_pong_max_missed(m.top.pong_max_missed)
    m.ws.set_pong_timeout(m.top.pong_timeout)
    m.ws.set_rsa_service_info(m.top.rsa_service_info)

    ' Fields
    m.top.STATE_CONNECTING = m.ws.STATE.CONNECTING
    m.top.STATE_OPEN = m.ws.STATE.OPEN
    m.top.STATE_CLOSING = m.ws.STATE.CLOSING
    m.top.STATE_CLOSED = m.ws.STATE.CLOSED
    m.top.websocket_ready_state = m.ws.get_ready_state()
    m.top.protocols = m.ws.get_protocols()
    m.top.headers = m.ws.get_headers()
    m.top.secure = m.ws.get_secure()
    m.top.buffer_size = m.ws.get_buffer_size()

    m.top.functionName = "WebSocketLoop"
    m.top.control = "RUN"
end sub

' Main task loop
sub WebSocketLoop() as void
    while true
        ' Check task messages
        msg = wait(25, m.port)
        ' Field event
        if type(msg) = "roSGNodeEvent"
            #if DEBUG_LOG_WEBSOCKET
                m.ws._logger.printl(m.ws._logger.DEBUG, "WebSocketLoop: roSGNodeEvent for " + msg.getNode().ToStr() + ", field: " + msg.getField() + ", data: " + FormatJson(msg.getData()))
            #end if
            if msg.getField() = "open"
                m.ws.open(msg.getData())
            else if msg.getField() = "send"
                m.ws.send(msg.getData())
            else if msg.getField() = "close"
                m.ws.close(msg.getData())
            else if msg.getField() = "buffer_size"
                m.ws.set_buffer_size(msg.getData())
            else if msg.getField() = "protocols"
                m.ws.set_protocols(msg.getData())
            else if msg.getField() = "headers"
                m.ws.set_headers(msg.getData())
            else if msg.getField() = "secure"
                m.ws.set_secure(msg.getData())
            else if msg.getField() = "log_level"
                m.ws.set_log_level(msg.getData())
            else if msg.getField() = "connect_timeout"
                m.ws.set_connect_timeout(msg.getData())
            else if msg.getField() = "close_timeout"
                m.ws.set_close_timeout(msg.getData())
            else if msg.getField() = "ping_interval"
                m.ws.set_ping_interval(msg.getData())
            else if msg.getField() = "pong_max_missed>"
                m.ws.set_pong_max_missed(msg.getData())
            else if msg.getField() = "pong_timeout"
                m.ws.set_pong_timeout(msg.getData())
            else if msg.getField() = "rsa_service_info"
                m.ws.set_rsa_service_info(msg.getData())
            end if
            ' WebSocket event
        else if type(msg) = "roAssociativeArray"
            #if DEBUG_LOG_WEBSOCKET
                m.ws._logger.printl(m.ws._logger.DEBUG, "WebSocketLoop: roSGNodeEvent for " + msg.id + ", data: " + FormatJson(msg.data))
            #end if
            if msg.id = "on_websocket_open"
                m.top.on_websocket_open = msg.data
            else if msg.id = "on_websocket_close"
                m.top.on_websocket_close = msg.data
            else if msg.id = "on_websocket_message"
                m.top.on_websocket_message = msg.data
            else if msg.id = "on_websocket_error"
                m.top.on_websocket_error = msg.data
            else if msg.id = "websocket_ready_state"
                m.top.websocket_ready_state = msg.data
            else if msg.id = "buffer_size"
                m.top.unobserveField("buffer_size")
                m.top.buffer_size = msg.data
                m.top.observeField("buffer_size", m.task_port)
            else if msg.id = "protocols"
                m.top.unobserveField("protocols")
                m.top.protocols = msg.data
                m.top.observeField("protocols", m.task_port)
            else if msg.id = "headers"
                m.top.unobserveField("headers")
                m.top.headers = msg.data
                m.top.observeField("headers", m.task_port)
            else if msg.id = "secure"
                m.top.unobserveField("secure")
                m.top.secure = msg.data
                m.top.observeField("secure", m.task_port)
            end if
        end if
        if msg = invalid
            m.ws.run()
        end if
    end while
end sub
