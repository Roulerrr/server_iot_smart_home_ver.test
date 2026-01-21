require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const http = require('http'); // Create HTTP server command
const Websocket = require('ws'); // WebSocket library
// Setup Express app
const app = express();
const server = http.createServer(app); // Create HTTP server (app)
const wss = new Websocket.Server({ server }); // Create WebSocket server
const PORT = process.env.PORT || 3000;

// Database connection
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT
});

// Middleware
app.use(cors());
app.use(express.json());


const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) res.status(401).json({ error: 'Access denied' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    })
}

// Route to register a new user
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;

    try {
        // Hash the password
        const saltRounds = 10;
        const password_hash = await bcrypt.hash(password, saltRounds);
        const result = await pool.query('INSERT INTO user_data(username, email, password_hash) VALUES ($1,$2,$3) RETURNING id, username',
            [username, email, password_hash]
        );

        res.status(201).json({
            message: 'Register user Success',
            user: result.rows[0]
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: 'Error'
        });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM user_data WHERE email =$1', [email]);
        if (result.rows.length === 0) {
            return res.status(401).json({
                error: 'Email or password falied'
            });
        }

        const user = result.rows[0];

        const isMath = await bcrypt.compare(password, user.password_hash);
        if (!isMath) {
            return res.status(401).json({
                error: 'Password failed'
            });
        }

        const token = jwt.sign(
            { userId: user.id, username: user.username },
            process.env.JWT_SECRET,
            {
                expiresIn: process.env.JWT_EXPIRES_IN || '1h'
            });
        res.status(200).json({
            message: 'Login success',
            token: token,
            user: {
                id: user.id,
                username: user.username
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Invalid email or password' });
    }
});

app.post('/api/device/register', authenticateToken, async (req, res) => {
    const { device_name, device_type , device_token} = req.body;

    const ownerId = req.user.userId;

    try {
        const result = await pool.query(
            'INSERT INTO data_device (user_id, device_name, device_type, device_token) VALUES ($1, $2, $3, $4) RETURNING*',
            [ownerId, device_name, device_type, device_token]
        );
        res.status(201).json({
            message: 'Device registered successfully',
            device: result.rows[0]
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: 'Error registering device'                                                       
        });
    }
});

app.post('/add-device', authenticateToken, async (req, res) => {

    const {device_name, device_type, device_token} = req.body;


    const ownerId = req.user.userId;
    try {
        const queryText = `
            INSERT INTO data_device (user_id, device_name, device_type, device_token)
            VALUES ($1, $2, $3, $4)
            RETURNING *;
        `;
        const values = [ownerId, device_name, device_type, device_token];
        const result =  await pool.query(queryText, values);
        res.status(201).json({
            message: 'Device added successfully',
            device: result.rows[0]
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({  
            error: 'Error adding device'
        });
    }
});

//  WebSocket for ESP32 ---
wss.on('connection', (ws) => { 
    console.log('ESP32 connected to WebSocket');

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);

            if (data.type === 'auth') {
                const result = await pool.query(
                    'SELECT id FROM data_device WHERE device_token = $1', 
                    [data.device_token]
                );
                
                if (result.rows.length > 0) {
                    ws.deviceId = result.rows[0].id; 
                    ws.send(JSON.stringify({ status: 'Authorized', deviceId: ws.deviceId }));
                    console.log(`Device ID ${ws.deviceId} Authorized`);
                } else {
                    ws.send(JSON.stringify({ status: 'Unauthorized' }));
                    ws.close(); 
                }
            }

            if (data.type === 'sensor_reading' && ws.deviceId) {
                const { 
                    temperature, humidity, light_level, 
                    soil_moisture, co2_ppm, rain_analog 
                } = data;

                const queryText = `
                    INSERT INTO sensor_data (
                        device_id, temperature, humidity, light_level, 
                        soil_moisture, co2_ppm, rain_analog
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                `;
                
                const values = [
                    ws.deviceId, temperature, humidity, light_level, 
                    soil_moisture, co2_ppm, rain_analog
                ];

                await pool.query(queryText, values);
                console.log(`Saved full sensor set from Device ${ws.deviceId}`);
            }

        } catch (err) {
            console.error('Error processing data:', err);
            ws.send(JSON.stringify({ error: 'Invalid JSON format' }));
        }
    });

    ws.on('close', () => {
        console.log(`Device ${ws.deviceId || 'Unknown'} disconnected`);
    });
});
server.listen(PORT, () => {
    console.log(`Server & WebSocket is running on port: ${PORT}`);
});
// Start Server
// app.listen(PORT, () => {
//     console.log('Server is running', PORT);
// })