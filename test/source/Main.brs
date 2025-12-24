' This source file is the entry point for the application and is not required
' to use the library. See readme.md for more info.

' Entry point for the application
function main(args as dynamic) as void
    screen = createObject("roSGScreen")
    port = createObject("roMessagePort")
    screen.setMessagePort(port)
    scene = screen.createScene("Main")
    screen.show()
    scene.setFocus(true)
    scene.backExitsScene = false
    while true
        msg = wait(0, port)
        if type(msg) = "roSGScreenEvent" and msg.isScreenClosed()
            return
        end if
    end while
end function

' Entry point for the main scene
function init() as void
    m.ws = createObject("roSGNode", "WebSocketClient")
    m.ws.observeField("on_websocket_open", "on_open")
    m.ws.observeField("on_websocket_close", "on_close")
    m.ws.observeField("on_websocket_message", "on_message")
    m.ws.observeField("on_websocket_error", "on_error")
    m.ws.protocols = []
    m.ws.headers = []
    #if DEBUG_LOG_WEBSOCKET
        m.ws.log_level = "VERBOSE"
    #else
        m.ws.log_level = "INFO"
    #end if

    ' Plain-text WebSocket server, e.g. util/echo/websocket_echo_server.js
    ' m.SERVER = "ws://10.42.0.1:5000/"

    ' Secure WebSocket server, e.g. util/echo/websocket_echo_server_ssl.js server.key server.cer 5001
    ' rsa_service must also be started
    '```
    ' python util/crypto_server/rsa_server.py --port 5002 --certificate server.cer
    '````
    ' Configure server for RSA encryption of the pre-master secret
    m.SERVER = "wss://10.42.0.1:5001/"
    m.ws.rsa_service_info = {
        url: "http://10.42.0.1:5002/encrypt",
        headers: {},
    }
    m.ws.open = m.SERVER
    m.reinitialize = false
    m._date_time_object = createObject("roDateTime")
    m._new_line_regex = CreateObject("roRegex", "\n", "")
end function

' Key events
function onKeyEvent(key as string, press as boolean) as boolean
    if key = "back" and press
        print "Closing websocket"
        m.ws.close = [1000, "optional"]
        return true
    else if key = "OK" and press
        print "Reinitializing websocket"
        if m.ws.ready_state <> m.ws.STATE_CLOSED
            m.ws.close = []
            m.reinitialize = true
        else
            m.ws.open = m.SERVER
        end if
        return true
    end if
    return false
end function

' Socket open event
function on_open(event as object) as void
    show_message("WebSocket opened")
    show_message("Protocol: " + FormatJson(event.getData()))
    send_test_data()
end function

' Send test data to the websocket
function send_test_data() as void
    test_string = "test string"
    show_message("Sending string: " + test_string)
    m.ws.send = [test_string]
    test_binary = []
    for bin = 0 to 3
        test_binary.push(bin)
    end for
    show_message("Sending binary data: 00010203")
    m.ws.send = [test_binary]
end function

' Socket close event
function on_close(event as object) as void
    show_message("WebSocket closed")

    if m.reinitialize
        m.ws.open = m.SERVER
        m.reinitialize = false
    end if
end function

' Socket message event
function on_message(event as object) as void
    message = event.getData().message
    if type(message) = "roString"
        show_message("<-- WebSocket text message: " + message)
    else
        ba = createObject("roByteArray")
        for each byte in message
            ba.push(byte)
        end for
        show_message("<-- WebSocket binary message: " + ba.toHexString())
    end if
end function

' Socket Error event
function on_error(event as object) as void
    show_message("WebSocket error: " + FormatJson(event.GetData()))
end function

function curent_timestamp() as string
    dateTime = m._date_time_object
    dateTime.Mark()
    dateTime.ToLocalTime()

    hours = dateTime.GetHours().ToStr("%02d")
    minutes = dateTime.GetMinutes().ToStr("%02d")
    seconds = dateTime.GetSeconds().ToStr("%02d")
    milliseconds = dateTime.GetMilliseconds().ToStr("%03d")

    return "[" + hours + ":" + minutes + ":" + seconds + "." + milliseconds + "]"
end function

sub show_message(message as string)
    message = curent_timestamp() + "  " + message
    print message
    message = message.Replace(Chr(10), " ")
    currentMessage = m.top.message
    fullMessage = currentMessage + (Chr(10) + message)
    lines = m._new_line_regex.Split(fullMessage)
    maxLines = 3
    if (lines.Count() > maxLines)
        fewLines = []
        for i = (lines.Count() - maxLines) to (lines.Count() - 1)
            fewLines.Push(lines[i])
        end for
        lines = fewLines
        fullMessage = lines.Join(Chr(10))
    end if

    m.top.message = currentMessage + (Chr(10) + message)
end sub
