require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


const app = express();

// Middleware
const PORT = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());

// Database connection
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT
});

// Route to register a new user
app.post('/register', async (req, res) => {

    const { username, password, email } = req.body;

    try {
        // Hash the password
        const saltRounds = 10;
        const password_hash = await bcrypt.hash(password, saltRounds);

        const result = await pool.query(
            'INSERT INTO user_data (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
            [username, email, password_hash]
        );

        const token = jwt.sign(
            {userId: result.rows[0].id, username: result.rows[0].username},
            process.env.JWT_SECRET,
            {expiresIn: process.env.JWT_EXPIRES_IN || '1h'}
        )

        res.status(201).json({
            message: 'User registered successfuly',
            user: result.rows[0]
        });

    }
    catch (err) {
        console.error('Error registering user:', err);
        res.status(500).json({ error: 'Internal server error' });
    }

}
);

// Route login a user
// app.post('/login', async (req, res) => {

//     const { email, password } = req.body;

//     try {
//         const result = await pool.query(
//             'SELECT * FROM userdb WHERE email = $1',[email]
//         );
//     }
// });


app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query(
            'SELECT * FROM user_data WHERE email = $1', [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        const user = result.rows[0];
        const isMath = await bcrypt.compare(password, user.password_hash);

        if (!isMath) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        res.status(200).json({
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username
            }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: ' Invalid email or password' });
    }
});

// Start then server
app.listen(PORT, () => {
    console.log('Server is running on port', PORT);
})