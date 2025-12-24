const fs = require("fs");
const https = require("https");
const WebSocketServer = require("ws").Server;

// process.argv mapping:
// 2: key path, 3: cert path, 4: port
const keyPath = process.argv[2];
const certPath = process.argv[3];
const port = process.argv[4] || 5001; // Default to 5001 if not provided

// Basic error checking for required arguments
if (!keyPath || !certPath) {
    console.error("Usage: node script.js <key-file> <cert-file> [port]");
    console.error("Example: node script.js key.pem cert.pem 8443");
    process.exit(1);
}

try {
    const serverConfig = {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath)
    };

    // 1. Create the HTTPS server
    const httpsServer = https.createServer(serverConfig, (req, res) => {
        res.writeHead(200);
        res.end("WSS server is running\n");
    });

    // 2. Attach WebSocket server
    const wss = new WebSocketServer({ server: httpsServer });

    wss.on("connection", function (socket) {
        console.log("Client connected");

        socket.on("message", function (message) {
            // Convert buffer to string for logging
            console.log("Received: " + message.toString());
            socket.send(message);
        });

        socket.on("error", function (error) {
            console.error("Socket Error: ", error);
        });

        socket.on("close", () => console.log("Client disconnected"));
    });

    // 3. Start the server
    httpsServer.listen(port, () => {
        console.log(`-----------------------------------------------`);
        console.log(`Secure WebSocket Server (WSS) started`);
        console.log(`Port: ${port}`);
        console.log(`Key:  ${keyPath}`);
        console.log(`Cert: ${certPath}`);
        console.log(`-----------------------------------------------`);
    });

} catch (err) {
    console.error("Error starting server:");
    console.error(err.message);
    process.exit(1);
}