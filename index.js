const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const dotenv = require("dotenv")
const url = require("node:url");
const e = require("express");
const {Client} = require("ssh2")

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

dotenv.config()

app.use(express.json())
app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
    res.send("Rcon");
});

app.post("/auth", async (req,res)=>{
    const {type,rover_id,rover_secret,webapp_id, webapp_secret} = req.body

    if (type === "rover"){
        if(rover_id !== process.env.ROVER_ID){
            return res.status(401).json({error: "Unauthorized"})
        }

        if(!bcrypt.compare(rover_secret, process.env.DEVICE_SECRET_HASH)){
            return res.status(401).json({error: "Unauthorized!"})
        }

        const token = jwt.sign(
            {
                sub: rover_id,
                role: "rover"
            },
            process.env.JWT_SECRET_KEY,
            {expiresIn: "60m", issuer: "Rcon-api"}
        )

        return res.json({ access_token: token, expires_in: 300 });
    }

    if (type === "webapp"){
        if(webapp_id !== process.env.WEBAPP_ID){
            return res.status(401).json({error: "Unauthorized"})
        }

        if(!bcrypt.compare(webapp_secret, process.env.WEBAPP_SECRET_HASH)){
            return res.status(401).json({error: "Unauthorized!"})
        }

        const token = jwt.sign(
            {
                sub: webapp_id,
                role: "webapp"
            },
            process.env.JWT_SECRET_KEY,
            {expiresIn: "6h", issuer: "Rcon-api"}
        )

        return res.json({ access_token: token, expires_in: 3600 * 6 });
    }

    res.status(400).json({ error: "Invalid auth type" });
})

let wsClients = [];

wss.on("connection", (ws, req) => {
    const params = new URLSearchParams(req.url.replace(/^.*\?/, ''));
    const token = params.get('token');

    jwt.verify(token, process.env.JWT_SECRET_KEY, (err) => {
        if (err) {
            ws.close(1008, "Unauthorized!");
            return;
        }

        if (wsClients[token] && wsClients[token] !== ws) {
            try { wsClients[token].close(); } catch (e) {}
        }
        wsClients[token] = ws;
    });

    console.log("WebSocket connected");

    let sshConn = null;
    let sshStream = null;

    ws.on("message", (msg) => {
        let packet;
        try {
            packet = JSON.parse(msg.toString());
        } catch {
            console.error("Invalid JSON");
            return;
        }

        if (packet.type === "ssh_init") {
            if (sshConn) {
                try { sshConn.end(); } catch (e) {}
                sshConn = null;
                sshStream = null;
            }

            sshConn = new Client();

            sshConn.on("ready", () => {
                console.log("SSH :: connected");
                ws.send(JSON.stringify({ type: "ssh_status", status: "connected" }));

                sshConn.shell({ term: 'xterm', cols: 80, rows: 24 }, (err, stream) => {
                    if (err) {
                        ws.send(JSON.stringify({ type: "ssh_error", data: err.message }));
                        return;
                    }
                    sshStream = stream;


                    stream.on("data", (data) => {
                        if (ws.readyState === WebSocket.OPEN) {
                            console.log(data.toString())
                            ws.send(JSON.stringify({ type: "ssh_output", data: data.toString() }));
                        }
                    })

                    stream.on("close", () => {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ type: "ssh_status", status: "closed" }));
                        }
                        sshConn.end();
                    });
                });
            }).on("error", (err) => {
                console.error("SSH :: error", err.message);
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: "ssh_error", data: err.message }));
                }
            }).connect({
                host: process.env.SSH_HOST,
                port: process.env.SSH_PORT,
                username: process.env.SSH_USER,
                password: process.env.SSH_PASS,
            });
            return;
        }

        if (packet.type === "ssh_input" && sshStream) {
            sshStream.write(packet.data);
            console.log(packet.data)
            return;
        }

      if (packet.type === "ssh_close") {
        if (sshStream) {
          try {
            sshStream.destroy()
          } catch (e) { }
            sshStream = null
        }

        if (sshConn) {
          try {
            sshConn.end()
            sshConn.destroy()
          } catch (e) { }
            sshConn = null;
        }

          ws.send(JSON.stringify({ type: "ssh_output", data: {close: true} }));
      }

        if (packet.type === "telemetry" || packet.type === "navcam" || packet.type === "exec") {
            const message = JSON.stringify(packet);
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(message);
                }
            });
        }
    });

    ws.on("close", () => {
        if (sshConn) {
            sshConn.end();
        }

        const msg = JSON.stringify({ connection: "closed" });
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(msg);
            }
        });
        console.log("WebSocket disconnected");
    });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, "0.0.0.0", () => {
    console.log("Server running on", PORT);
});
