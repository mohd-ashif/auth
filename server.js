const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const mysql = require('mysql');

const app = express();
const port = 3000;

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'my_database'
});

app.use(bodyParser.json());

app.post('/register', (req, res) => {
    try {
        const { username, password, name, bio } = req.body;

        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error('Error hashing password:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            const sql = 'INSERT INTO users (username, password, name, bio) VALUES (?, ?, ?, ?)';
            connection.query(sql, [username, hashedPassword, name, bio], (err, result) => {
                if (err) {
                    console.error('Error registering user:', err);
                    return res.status(500).json({ error: 'Failed to register user' });
                }
                console.log('User registered successfully');
                res.status(200).json({ message: 'User registered successfully' });
            });
        });
    } catch (error) {
        console.error('Error parsing JSON:', error);
        res.status(400).json({ error: 'Invalid JSON data' });
    }
});


app.post('/login', (req, res) => {
    const { username, password } = req.body;

    
    connection.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            console.error('Error retrieving user from database:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (results.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const user = results[0];

     
        bcrypt.compare(password, user.password, (err, result) => {
            if (err || !result) {
                return res.status(401).json({ error: 'Invalid username or password' });
            }

            
            const token = jwt.sign({ id: user.id, username: user.username }, 'my_key', { expiresIn: '1h' });
            res.json({ token });
        });
    });
});


function authMiddleware(req, res, next) {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized: Missing token' });
    }

    jwt.verify(token, 'my_key', (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Unauthorized: Invalid token' });
        }

        req.user = decoded;
        next();
    });
}


app.get('/protected', authMiddleware, (req, res) => {
    res.json({ message: 'Protected route successfully', user: req.user });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
