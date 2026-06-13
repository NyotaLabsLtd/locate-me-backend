require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const { Resend } = require('resend'); // ✅ Using Resend now
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = '384124217618-38rde3tgblslp1s9u3e1fn5tn7h971uk.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// ✅ Initialize Resend with your API key
const resend = new Resend(process.env.RESEND_API_KEY);

// RATE LIMITING
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const generateVerificationToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// ==========================================
// REGISTER with Resend
// ==========================================

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    console.log('📩 Registration attempt for:', req.body.email);
    
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (existingUser.rows.length > 0 && !existingUser.rows[0].is_verified) {
      await pool.query('DELETE FROM users WHERE email = $1', [email]);
      console.log('️ Deleted unverified user:', email);
    } 
    else if (existingUser.rows.length > 0 && existingUser.rows[0].is_verified) {
      return res.status(409).json({ error: 'Email already registered. Please log in.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = generateVerificationToken();

    const result = await pool.query(
      'INSERT INTO users (email, password, verification_token, is_verified, role) VALUES ($1, $2, $3, false, $4) RETURNING id, email, role',
      [email, hashedPassword, verificationToken, 'user']
    );
    console.log('✅ User created in database');

    const verificationLink = `https://locate-me-app.vercel.app/?verify=${verificationToken}`;
    
    // ✅ Send email using Resend
    const { data, error } = await resend.emails.send({
      from: 'Locate Me <onboarding@resend.dev>', // Resend's default test domain
      to: [email],
      subject: 'Verify your Locate Me Account',
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; background: #f4f4f4;">
          <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px;">
            <h2 style="color: #fbbf24; text-align: center;">🔍 Locate Me</h2>
            <p style="font-size: 16px; color: #333;">Welcome to Locate Me!</p>
            <p style="font-size: 16px; color: #333;">Please verify your email address by clicking the button below:</p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${verificationLink}" 
                 style="background: #fbbf24; color: #0f172a; padding: 14px 32px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">
                Verify Email Address
              </a>
            </div>
            <p style="font-size: 14px; color: #666;">If you didn't create this account, please ignore this email.</p>
          </div>
        </div>
      `
    });

    if (error) {
      console.error('❌ Resend error:', error);
    } else {
      console.log('✅ Email sent via Resend:', data);
    }

    res.status(201).json({ 
      message: 'Account created! Please check your email for the verification link.' 
    });
  } catch (err) {
    console.error('❌ Registration error:', err);
    res.status(500).json({ error: 'Registration failed: ' + err.message });
  }
});

// VERIFY EMAIL
app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const result = await pool.query('SELECT * FROM users WHERE verification_token = $1', [token]);
    
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired verification link' });
    }

    const user = result.rows[0];
    
    if (user.is_verified) {
      return res.json({ message: 'Email already verified! You can now log in.', alreadyVerified: true });
    }

    await pool.query(
      'UPDATE users SET is_verified = true, verification_token = NULL WHERE id = $1', 
      [user.id]
    );
    
    res.json({ message: 'Email verified successfully! You can now log in.', verified: true });
  } catch (err) {
    console.error('Verify error:', err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// LOGIN
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

    const user = result.rows[0];
    
    if (!user.is_verified) {
      return res.status(403).json({ 
        error: 'Please verify your email before logging in.',
        unverified: true 
      });
    }

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
app.post('/api/auth/google', authLimiter, async (req, res) => {
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
app.get('/api/missing-persons', generalLimiter, async (req, res) => {
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

// UPDATE POST
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
app.get('/api/sightings', generalLimiter, async (req, res) => {
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