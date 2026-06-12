require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Connect to Neon Database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
const GOOGLE_CLIENT_ID = '384124217618-38rde3tgblslp1s9u3e1fn5tn7h971uk.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Email Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const generateVerificationCode = () => Math.floor(100000 + Math.random() * 900000).toString();

// REGISTER - with email verification
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) return res.status(409).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationCode = generateVerificationCode();

    const result = await pool.query(
      'INSERT INTO users (email, password, verification_token, is_verified, role) VALUES ($1, $2, $3, false, $4) RETURNING id, email, role',
      [email, hashedPassword, verificationCode, 'user']
    );

    const mailOptions = {
      from: `"Locate Me" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Verify your Locate Me Account',
      text: `Your verification code is: ${verificationCode}. Please enter this in the app to activate your account.`
    };
    
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) console.error('Email send error:', error);
      else console.log('Verification email sent:', info.response);
    });

    res.status(201).json({ message: 'Account created. Please check your email for the verification code.' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// VERIFY EMAIL
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { email, code } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND verification_token = $2', [email, code]);
    
    if (result.rows.length === 0) return res.status(400).json({ error: 'Invalid code or email' });

    await pool.query('UPDATE users SET is_verified = true, verification_token = NULL WHERE email = $1', [email]);
    
    res.json({ message: 'Email verified successfully! You can now log in.' });
  } catch (err) {
    console.error('Verify error:', err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// LOGIN - checks verification
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

    const user = result.rows[0];
    
    if (!user.is_verified) return res.status(403).json({ error: 'Please verify your email before logging in.' });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ message: 'Login successful', token, user: { id: user.id, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// GOOGLE SIGN-IN
app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const { email, name, picture, sub: googleId } = payload;

    let user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      const result = await pool.query(
        `INSERT INTO users (email, google_id, name, avatar_url, role, is_verified) VALUES ($1, $2, $3, $4, 'user', true) RETURNING id, email, role`,
        [email, googleId, name, picture]
      );
      user = result.rows[0];
    } else {
      user = user.rows[0];
      if (!user.is_verified) {
          await pool.query('UPDATE users SET is_verified = true WHERE email = $1', [email]);
          user.is_verified = true;
      }
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ message: 'Google sign-in successful', token, user: { id: user.id, email: user.email, role: user.role, name: user.name, avatar: user.avatar_url } });
  } catch (err) {
    console.error('Google auth error:', err);
    res.status(401).json({ error: 'Google authentication failed' });
  }
});

// Middleware
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

// GET ALL MISSING PERSONS
app.get('/api/missing-persons', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM missing_persons ORDER BY date_missing DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// CREATE MISSING PERSON
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

// GET MY POSTS
app.get('/api/users/my-posts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM missing_persons WHERE user_id = $1 ORDER BY date_missing DESC', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

// UPDATE POST (Edit)
app.put('/api/missing-persons/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, age, gender, last_seen_location, description, notes, residence, police_station } = req.body;
    
    const check = await pool.query('SELECT user_id FROM missing_persons WHERE id = $1', [id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Post not found' });
    
    if (check.rows[0].user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized to edit this post' });
    }

    await pool.query(
      `UPDATE missing_persons SET name=$1, age=$2, gender=$3, last_seen_location=$4, description=$5, notes=$6, residence=$7, police_station=$8 WHERE id=$9`,
      [name, age, gender, last_seen_location, description, notes, residence, police_station, id]
    );
    res.json({ message: 'Post updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Update failed' });
  }
});

// DELETE POST
app.delete('/api/missing-persons/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;
    
    const check = await pool.query('SELECT user_id FROM missing_persons WHERE id = $1', [id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Post not found' });
    
    if (check.rows[0].user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized to delete this post' });
    }

    console.log(`Post ${id} deleted by user ${req.user.id}. Reason: ${reason}`);
    await pool.query('DELETE FROM missing_persons WHERE id = $1', [id]);
    res.json({ message: 'Deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

// SIGHTINGS
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
    const result = await pool.query(
      `INSERT INTO sightings (missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, photo_url, user_id) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, photo_url, req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error saving sighting' });
  }
});

// ADMIN ROUTE
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  const result = await pool.query('SELECT id, email, role, created_at, is_verified FROM users ORDER BY created_at DESC');
  res.json(result.rows);
});

app.get('/', (req, res) => res.send('✅ Locate Me Backend is Running!'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  pool.query('SELECT NOW()').then(() => console.log('✅ Database connected')).catch(err => console.error('❌ DB connection failed:', err.message));
});