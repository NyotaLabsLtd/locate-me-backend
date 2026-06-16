require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const cookieParser = require('cookie-parser');

const app = express();

// ==========================================
// MIDDLEWARE & CONFIGURATION
// ==========================================
app.set('trust proxy', 1); // Required for Render to get correct IP for rate limiting

// CORS: Allow frontend to send cookies and make requests
app.use(cors({
  origin: ['https://locate-me-app.vercel.app', 'http://localhost:3000'],
  credentials: true 
}));

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser()); // Reads HttpOnly cookies from incoming requests

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = '384124217618-38rde3tgblslp1s9u3e1fn5tn7h971uk.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer configuration for file uploads (stored in memory temporarily)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG, and WebP are allowed.'));
    }
  }
});

// ==========================================
// RATE LIMITING
// ==========================================
const loginLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 7, message: { error: 'Too many login attempts. Please try again after 10 minutes.' }, standardHeaders: true, legacyHeaders: false });
const signupLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 3, message: { error: 'Too many signup attempts. Please try again after 10 minutes.' }, standardHeaders: true, legacyHeaders: false });
const postLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: { error: 'You have reached the maximum limit of 5 posts per hour.' }, standardHeaders: true, legacyHeaders: false, keyGenerator: (req) => req.user?.id || req.ip });
const sightingLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: { error: 'You have reached the maximum limit of 5 sighting reports per hour.' }, standardHeaders: true, legacyHeaders: false, keyGenerator: (req) => req.user?.id || req.ip });
const dailyUploadLimiter = rateLimit({ windowMs: 24 * 60 * 60 * 1000, max: 50, message: { error: 'You have reached the daily upload limit of 50 images.' }, standardHeaders: true, legacyHeaders: false, keyGenerator: (req) => req.user?.id || req.ip });
const hourlyUploadLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, message: { error: 'You have reached the hourly upload limit of 10 images.' }, standardHeaders: true, legacyHeaders: false, keyGenerator: (req) => req.user?.id || req.ip });
const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: 'Too many requests. Please slow down.' }, standardHeaders: true, legacyHeaders: false });

const generateVerificationToken = () => crypto.randomBytes(32).toString('hex');

// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================
const authenticateToken = (req, res, next) => {
  // Read token from HttpOnly cookie instead of headers
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.clearCookie('token');
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ==========================================
// AUTH ROUTES
// ==========================================

// Register
app.post('/api/auth/register', signupLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0 && !existingUser.rows[0].is_verified) {
      await pool.query('DELETE FROM users WHERE email = $1', [email]);
    } else if (existingUser.rows.length > 0 && existingUser.rows[0].is_verified) {
      return res.status(409).json({ error: 'Email already registered. Please log in.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = generateVerificationToken();
    
    await pool.query(
      'INSERT INTO users (email, password, verification_token, is_verified, role) VALUES ($1, $2, $3, false, $4)', 
      [email, hashedPassword, verificationToken, 'user']
    );
    
    res.status(201).json({ message: 'Account created!', token: verificationToken });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed: ' + err.message });
  }
});

// Verify Email
app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const result = await pool.query('SELECT * FROM users WHERE verification_token = $1', [token]);
    if (result.rows.length === 0) return res.status(400).json({ error: 'Invalid or expired verification link' });
    
    const user = result.rows[0];
    if (user.is_verified) return res.json({ message: 'Email already verified!', alreadyVerified: true });
    
    await pool.query('UPDATE users SET is_verified = true, verification_token = NULL WHERE id = $1', [user.id]);
    res.json({ message: 'Email verified successfully!', verified: true });
  } catch (err) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Login
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid email or password' });
    
    const user = result.rows[0];
    if (!user.is_verified) return res.status(403).json({ error: 'Please verify your email before logging in.', unverified: true });
    
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    
    // Set secure HttpOnly cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // true in production (HTTPS)
      sameSite: 'none', // Required for cross-origin requests (Vercel -> Render)
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });
    
    res.json({ message: 'Login successful', user: { id: user.id, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Google Login
app.post('/api/auth/google', loginLimiter, async (req, res) => {
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
    
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'none',
      maxAge: 30 * 24 * 60 * 60 * 1000
    });
    
    res.json({ message: 'Google sign-in successful', user: { id: user.id, email: user.email, role: user.role, name: user.name, avatar: user.avatar_url } });
  } catch (err) {
    console.error('Google auth error:', err);
    res.status(401).json({ error: 'Google authentication failed' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

// ==========================================
// UPLOAD ROUTE
// ==========================================
app.post('/api/upload', authenticateToken, dailyUploadLimiter, hourlyUploadLimiter, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    
    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        { folder: 'locate-me/missing-persons', resource_type: 'image', transformation: [{ quality: 'auto', fetch_format: 'auto' }] },
        (error, result) => { if (error) reject(error); else resolve(result); }
      );
      uploadStream.end(req.file.buffer);
    });
    
    res.json({ secure_url: result.secure_url, public_id: result.public_id });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed: ' + err.message });
  }
});

// ==========================================
// MISSING PERSONS ROUTES
// ==========================================

// Get all missing persons (Public)
app.get('/api/missing-persons', generalLimiter, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM missing_persons ORDER BY date_missing DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Create missing person (Protected)
app.post('/api/missing-persons', authenticateToken, postLimiter, async (req, res) => {
  try {
    const { name, age, gender, last_seen_location, photo_urls, description, notes, residence, police_station, date_missing, date_last_seen } = req.body;
    
    const result = await pool.query(
      `INSERT INTO missing_persons (name, age, gender, last_seen_location, photo_urls, description, notes, residence, police_station, date_missing, date_last_seen, user_id) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [name, age, gender, last_seen_location, JSON.stringify(photo_urls), description, notes, residence, police_station, date_missing, date_last_seen, req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error saving person' });
  }
});

// Get current user's posts (Protected)
app.get('/api/users/my-posts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM missing_persons WHERE user_id = $1 ORDER BY date_missing DESC', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

// Update missing person (Protected) - NOW INCLUDES ALL FIELDS INCLUDING DATE LAST SEEN
app.put('/api/missing-persons/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, age, gender, last_seen_location, description, notes, residence, police_station, date_last_seen } = req.body;
    
    // Check ownership
    const check = await pool.query('SELECT user_id FROM missing_persons WHERE id = $1', [id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Post not found' });
    if (check.rows[0].user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized to edit this post' });
    }

    // Update all editable fields
    await pool.query(
      `UPDATE missing_persons 
       SET name=$1, age=$2, gender=$3, last_seen_location=$4, description=$5, notes=$6, residence=$7, police_station=$8, date_last_seen=$9 
       WHERE id=$10`,
      [name, age, gender, last_seen_location, description, notes, residence, police_station, date_last_seen, id]
    );
    res.json({ message: 'Post updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Update failed' });
  }
});

// Delete missing person (Protected)
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

// ==========================================
// SIGHTINGS ROUTES
// ==========================================

app.get('/api/sightings', generalLimiter, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM sightings ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/sightings', authenticateToken, sightingLimiter, async (req, res) => {
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

// ==========================================
// ADMIN ROUTES
// ==========================================

app.get('/api/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  const result = await pool.query('SELECT id, email, role, created_at, is_verified FROM users ORDER BY created_at DESC');
  res.json(result.rows);
});

app.get('/api/admin/missing-persons', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  try {
    const result = await pool.query(`SELECT mp.*, u.email as poster_email FROM missing_persons mp LEFT JOIN users u ON mp.user_id = u.id ORDER BY mp.date_missing DESC`);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch missing persons' });
  }
});

app.get('/api/admin/sightings-full', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  try {
    const result = await pool.query(`SELECT s.*, u.email as reporter_email FROM sightings s LEFT JOIN users u ON s.user_id = u.id ORDER BY s.created_at DESC`);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch sightings' });
  }
});

// ==========================================
// ERROR HANDLING & SERVER START
// ==========================================

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'File too large. Maximum size is 5MB.' });
    return res.status(400).json({ error: err.message });
  }
  if (err.message === 'Invalid file type. Only JPEG, PNG, and WebP are allowed.') return res.status(400).json({ error: err.message });
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.get('/', (req, res) => res.send('✅ Locate Me Backend is Running!'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  pool.query('SELECT NOW()').then(() => console.log('✅ Database connected')).catch(err => console.error('❌ DB connection failed:', err.message));
});