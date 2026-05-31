require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// DEBUG: Log all requests
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// Connect to Neon Database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';

// Google OAuth Client
const GOOGLE_CLIENT_ID = '816021523687-bjk1hqap09aak1bl9rb3tk60q8qr4q1b.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// ================= ERROR HANDLING =================
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// ================= AUTHENTICATION ROUTES =================

// 1. REGISTER - Email/Password
app.post('/api/auth/register', async (req, res) => {
  try {
    console.log('📝 Register attempt:', req.body.email);
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) return res.status(409).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, role',
      [email, hashedPassword]
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '30d' });

    console.log('✅ User registered:', user.email);
    res.status(201).json({ message: 'User registered successfully', token, user: { id: user.id, email: user.email, role: user.role } });
  } catch (err) {
    console.error('❌ Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// 2. LOGIN - Email/Password
app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('🔐 Login attempt:', req.body.email);
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    console.log('✅ Login successful:', user.email);
    res.json({ message: 'Login successful', token, user: { id: user.id, email: user.email, role: user.role } });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// 3. GOOGLE SIGN-IN
app.post('/api/auth/google', async (req, res) => {
  try {
    console.log('🔵 Google sign-in attempt');
    const { credential } = req.body;
    
    if (!credential) {
      console.log('❌ No credential provided');
      return res.status(400).json({ error: 'No Google credential provided' });
    }
    
    console.log('Verifying Google token...');
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    const { email, name, picture, sub: googleId } = payload;
    console.log('✅ Google token verified for:', email);

    let user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (user.rows.length === 0) {
      console.log('Creating new user:', email);
      const result = await pool.query(
        `INSERT INTO users (email, google_id, name, avatar_url, role) 
         VALUES ($1, $2, $3, $4, 'user') RETURNING id, email, name, role, avatar_url`,
        [email, googleId, name, picture]
      );
      user = result.rows[0];
    } else {
      console.log('Existing user found:', email);
      user = user.rows[0];
      await pool.query('UPDATE users SET google_id = $1, avatar_url = $2 WHERE email = $3', [googleId, picture, email]);
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, google: true },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    console.log('✅ Google sign-in complete:', user.email);
    res.json({
      message: 'Google sign-in successful',
      token,
      user: { id: user.id, email: user.email, name: user.name, role: user.role, avatar: user.avatar_url }
    });

  } catch (err) {
    console.error('❌ Google auth error:', err.message);
    res.status(401).json({ error: 'Google authentication failed: ' + err.message });
  }
});

// 4. GET CURRENT USER
app.get('/api/auth/me', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT id, email, role, created_at, name, avatar_url FROM users WHERE id = $1', [decoded.id]);
    
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('Auth error:', err);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ================= MIDDLEWARE =================
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ================= MISSING PERSONS ROUTES =================
app.get('/api/missing-persons', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM missing_persons ORDER BY date_missing DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/missing-persons', authenticateToken, async (req, res) => {
  try {
    const { name, age, gender, last_seen_location, photo_urls, description, notes, residence, police_station, date_missing } = req.body;
    const userId = req.user.id;
    
    const result = await pool.query(
      `INSERT INTO missing_persons (name, age, gender, last_seen_location, photo_urls, description, notes, residence, police_station, date_missing, user_id) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [name, age, gender, last_seen_location, JSON.stringify(photo_urls), description, notes, residence, police_station, date_missing, userId]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error saving person' });
  }
});

app.delete('/api/missing-persons/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    const { id } = req.params;
    await pool.query('DELETE FROM missing_persons WHERE id = $1', [id]);
    res.json({ message: 'Deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

// ================= SIGHTINGS ROUTES =================
app.get('/api/sightings', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM sightings ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/sightings', authenticateToken, async (req, res) => {
  try {
    const { missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, photo_url } = req.body;
    const userId = req.user.id;
    
    // IMPORTANT: This now includes photo_url in the INSERT
    const result = await pool.query(
      `INSERT INTO sightings (missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, photo_url, user_id) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, photo_url, userId]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error saving sighting' });
  }
});

app.delete('/api/sightings/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    const { id } = req.params;
    await pool.query('DELETE FROM sightings WHERE id = $1', [id]);
    res.json({ message: 'Deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

// ================= USERS (Admin Only) =================
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    const result = await pool.query('SELECT id, email, role, created_at, name, avatar_url FROM users ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Test route
app.get('/', (req, res) => {
  res.send('✅ Locate Me Backend is Running!');
});

// TEST ROUTE
app.get('/api/test', (req, res) => {
  console.log('✅ TEST ROUTE HIT!');
  res.json({ message: 'Server is working!', time: new Date() });
});

// ================= START SERVER =================
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  
  // Test database connection
  try {
    await pool.query('SELECT NOW()');
    console.log('✅ Database connected');
  } catch (err) {
    console.error('❌ Database connection failed:', err.message);
  }
});

// Handle server errors
server.on('error', (err) => {
  console.error('❌ Server error:', err);
});