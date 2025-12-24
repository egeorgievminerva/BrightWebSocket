# WebSocket Echo Server

Tiny node script to create a websocket echo server

# Running

Install the node "ws" library

1. `npm install` from the echo folder root

Run plain WebSocket server

   `node websocket_echo_server.js`

    The plain WebSocket server is started on port 5000.

Run secure WebSocket server

    `node websocket_echo_server_ssl.js server.key server.cer [PORT]`

    Default port for secure WebSocket server is 5001.

The WebSocket servers echo both binary and text frames.
