const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const dotenv = require("dotenv")
const url = require("node:url");
const e = require("express");

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
            {expiresIn: "60m", issuer: "Rcon-api"}
        )

        return res.json({ access_token: token, expires_in: 300 });
    }

    res.status(400).json({ error: "Invalid auth type" });
})

let wsClients = [];

wss.on("connection", (ws, req) => {

    const params = new URLSearchParams(req.url.replace(/^.*\?/, ''));
    const token = params.get('token');
    console.log(token)


    jwt.verify(token, process.env.JWT_SECRET_KEY, (err)=>{
        if(err){
            ws.close(1008, "Unauthorized!")
        }else{
            wsClients[token] = ws
        }
    })


    console.log("WebSocket connected");
    console.log(wsClients)



    ws.currentCamera = null;

    ws.on("message", (msg) => {
        let packet;
        try {
            packet = JSON.parse(msg.toString());
        } catch {
            console.error("Invalid JSON");
            return;
        }

        if (packet.type === "telemetry" || packet.type === "navcam") {
            const message = JSON.stringify(packet);
            console.log(JSON.parse(message))

            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(message);
                }
            });
        }
    });

    ws.on("close", () => {
        const msg = JSON.stringify({connection: "closed"})
        wss.clients.forEach(client=>{
            if(client.readyState === WebSocket.OPEN){
                client.send(msg)
            }
        })
        console.log("WebSocket disconnected");
    });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, "0.0.0.0",() => {
    console.log("Server running on", PORT);
});