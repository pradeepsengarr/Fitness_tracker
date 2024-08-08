const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const port = 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '', // Replace with your MySQL password
  database: 'fitness_tracker' // Replace with your MySQL database name
});

// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error('Database connection error:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

// Register
app.post('/signup', (req, res) => {
  console.log('Signup request received:', req.body);
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    console.error('Missing required fields');
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  const hashedPassword = bcrypt.hashSync(password, 8);

  const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
  db.query(sql, [username, email, hashedPassword], (err, result) => {
    if (err) {
      console.error('Error executing SQL query:', err);
      return res.status(500).json({ success: false, message: 'Failed to register user', error: err.message });
    }
    console.log('User registered successfully:', result.insertId);
    res.status(201).json({ success: true, message: 'User registered successfully' });
  });
});

// Login
app.post('/login', (req, res) => {
  console.log('Login request received:', req.body);
  const { email, password } = req.body;

  if (!email || !password) {
    console.error('Missing required fields');
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  const sql = 'SELECT * FROM users WHERE email = ?';
  db.query(sql, [email], (err, result) => {
    if (err) {
      console.error('Error executing SQL query:', err);
      return res.status(500).json({ success: false, message: 'Server error', error: err.message });
    }
    if (result.length === 0) {
      console.error('User not found:', email);
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const user = result[0];
    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
      console.error('Invalid password for user:', email);
      return res.status(401).json({ success: false, message: 'Invalid password' });
    }

    const token = jwt.sign({ id: user.id }, 'your_secret_key', { expiresIn: '24h' });

    console.log('Login successful for user:', email);
    res.status(200).json({ success: true, auth: true, token, userId: user.username });
  });
});

// Log Workout
app.post('/log-workout', (req, res) => {
  console.log('Log workout request received:', req.body);
  const { userId, exercise, duration, date, weight } = req.body;

  if (!userId || !exercise || !duration || !date || weight === undefined) {
    console.error('Missing required fields');
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  // Get user ID from username
  const userQuery = 'SELECT id FROM users WHERE username = ?';
  db.query(userQuery, [userId], (err, results) => {
    if (err) {
      console.error('Error executing SQL query:', err);
      return res.status(500).json({ success: false, message: 'Failed to fetch user ID', error: err.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    const user_id = results[0].id;

    // Insert workout log
    const sql = 'INSERT INTO log_workout (user_id, exercise, duration, date, weight) VALUES (?, ?, ?, ?, ?)';
    db.query(sql, [user_id, exercise, duration, date, weight], (err, result) => {
      if (err) {
        console.error('Error executing SQL query:', err);
        return res.status(500).json({ success: false, message: 'Failed to log workout', error: err.message });
      }
      console.log('Workout logged successfully for user:', userId);
      res.status(201).json({ success: true, message: 'Workout logged successfully' });
    });
  });
});

// Log Nutrition
app.post('/log-nutrition', (req, res) => {
  console.log('Log nutrition request received:', req.body);
  const { userId, date, calories, proteins, fats, carbohydrates } = req.body;

  if (!userId || !date || !calories || !proteins || !fats || !carbohydrates) {
    console.error('Missing required fields');
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  // Get user ID from username
  const userQuery = 'SELECT id FROM users WHERE username = ?';
  db.query(userQuery, [userId], (err, results) => {
    if (err) {
      console.error('Error executing SQL query:', err);
      return res.status(500).json({ success: false, message: 'Failed to fetch user ID', error: err.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    const user_id = results[0].id;

    // Insert nutrition log
    const sql = 'INSERT INTO nutrition (user_id, date, calories, proteins, fats, carbohydrates) VALUES (?, ?, ?, ?, ?, ?)';
    db.query(sql, [user_id, date, calories, proteins, fats, carbohydrates], (err, result) => {
      if (err) {
        console.error('Error executing SQL query:', err);
        return res.status(500).json({ success: false, message: 'Failed to log nutrition', error: err.message });
      }
      console.log('Nutrition logged successfully for user:', userId);
      res.status(201).json({ success: true, message: 'Nutrition logged successfully' });
    });
  });
});

// Get Workouts for a User
app.get('/workouts/:userId', (req, res) => {
  const { userId } = req.params;
  // Get user ID from username
  const userQuery = 'SELECT id FROM users WHERE username = ?';
  db.query(userQuery, [userId], (err, results) => {
    if (err) {
      console.error('Error executing SQL query:', err);
      return res.status(500).json({ success: false, message: 'Failed to fetch user ID', error: err.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    const user_id = results[0].id;

    // Fetch workouts
    const sql = 'SELECT * FROM log_workout WHERE user_id = ?';
    db.query(sql, [user_id], (err, results) => {
      if (err) {
        console.error('Error executing SQL query:', err);
        return res.status(500).json({ success: false, message: 'Failed to fetch workouts', error: err.message });
      }
      res.status(200).json({ success: true, data: results });
    });
  });
});

// Get Nutrition for a User
app.get('/nutrition/:userId', (req, res) => {
  const { userId } = req.params;
  // Get user ID from username
  const userQuery = 'SELECT id FROM users WHERE username = ?';
  db.query(userQuery, [userId], (err, results) => {
    if (err) {
      console.error('Error executing SQL query:', err);
      return res.status(500).json({ success: false, message: 'Failed to fetch user ID', error: err.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    const user_id = results[0].id;

    // Fetch nutrition data
    const sql = 'SELECT * FROM nutrition WHERE user_id = ?';
    db.query(sql, [user_id], (err, results) => {
      if (err) {
        console.error('Error executing SQL query:', err);
        return res.status(500).json({ success: false, message: 'Failed to fetch nutrition data', error: err.message });
      }
      res.status(200).json({ success: true, data: results });
    });
  });
});

// Get User Profile
app.get('/profile/:userId', (req, res) => {
  const { userId } = req.params;
  const sql = 'SELECT * FROM users WHERE username = ?';
  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error('Error executing SQL query:', err);
      return res.status(500).json({ success: false, message: 'Failed to fetch profile data', error: err.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    res.status(200).json({ success: true, data: results[0] });
  });
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(403).json({ success: false, message: 'No token provided' });

  jwt.verify(token, 'your_secret_key', (err, decoded) => {
    if (err) return res.status(401).json({ success: false, message: 'Failed to authenticate token' });
    req.userId = decoded.id;
    next();
  });
};

// Apply token verification to protected routes
app.use('/log-workout', verifyToken);
app.use('/log-nutrition', verifyToken);

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
