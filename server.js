require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const rateLimit = require('express-rate-limit');

const app = express();

// ==========================================
// 1. CONFIGURATION & MIDDLEWARE
// ==========================================

// CORS: Allow requests from your Vercel frontend
app.use(cors({
    origin: ['https://locate-me-app.vercel.app', 'http://localhost:3000'],
    credentials: true
}));

app.use(express.json({ limit: '10mb' }));

// Database Connection (Neon PostgreSQL)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Cloudinary Configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer for file uploads (memory storage)
const upload = multer({ storage: multer.memoryStorage() });

// ==========================================
// 2. SECURITY MIDDLEWARE
// ==========================================

// Rate Limiters to prevent spam/brute force
const loginLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 7, message: { error: 'Too many login attempts. Try again in 10 minutes.' } });
const registerLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 3, message: { error: 'Too many signup attempts. Try again in 10 minutes.' } });
const postLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: { error: 'Too many posts. Try again in 1 hour.' } });
const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { error: 'Too many requests.' } });

app.use('/api/auth/login', loginLimiter);
app.use('/api/auth/register', registerLimiter);
app.use('/api/missing-persons', postLimiter);
app.use(generalLimiter);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified; // Contains { id, email, role }
        next();
    } catch (err) {
        res.status(403).json({ error: 'Invalid or expired token.' });
    }
};

// Admin Middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required.' });
    }
    next();
};

// ==========================================
// 3. AUTH ROUTES
// ==========================================

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

        // Check if user exists
        const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) return res.status(409).json({ error: 'Email already registered' });

        // Hash password and create user
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await pool.query(
            'INSERT INTO users (email, password, role, is_verified) VALUES ($1, $2, $3, $4) RETURNING id, email, role, is_verified',
            [email, hashedPassword, 'user', false]
        );

        // Generate JWT token for email verification
        const token = jwt.sign({ id: newUser.rows[0].id, email: newUser.rows[0].email }, process.env.JWT_SECRET, { expiresIn: '24h' });

        res.status(201).json({ 
            message: 'User created successfully', 
            token: token,
            user: { id: newUser.rows[0].id, email: newUser.rows[0].email, role: newUser.rows[0].role }
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        
        if (user.rows.length === 0) return res.status(400).json({ error: 'Invalid email or password' });
        
        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid email or password' });

        if (!user.rows[0].is_verified) return res.status(403).json({ error: 'Please verify your email first', unverified: true });

        const token = jwt.sign(
            { id: user.rows[0].id, email: user.rows[0].email, role: user.rows[0].role }, 
            process.env.JWT_SECRET, 
            { expiresIn: '30d' }
        );

        res.json({ 
            token, 
            user: { id: user.rows[0].id, email: user.rows[0].email, role: user.rows[0].role } 
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error during login' });
    }
});

// Google Auth
app.post('/api/auth/google', async (req, res) => {
    try {
        const { credential } = req.body;
        // Note: In a real production app, you should verify the Google credential here using google-auth-library.
        // For now, we assume the frontend verified it and we just create/find the user.
        // You would normally decode the JWT from Google here to get the email.
        
        // Placeholder for Google JWT decoding (You can use jsonwebtoken to decode without verification for basic info, 
        // but ideally use google-auth-library).
        const decoded = jwt.decode(credential);
        const email = decoded.email;
        const name = decoded.name;

        let user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        
        if (user.rows.length === 0) {
            // Create new user from Google
            user = await pool.query(
                'INSERT INTO users (email, password, role, is_verified) VALUES ($1, $2, $3, $4) RETURNING id, email, role',
                [email, 'google_auth', 'user', true] // Google users are auto-verified
            );
        }

        const token = jwt.sign(
            { id: user.rows[0].id, email: user.rows[0].email, role: user.rows[0].role }, 
            process.env.JWT_SECRET, 
            { expiresIn: '30d' }
        );

        res.json({ 
            token, 
            user: { id: user.rows[0].id, email: user.rows[0].email, role: user.rows[0].role } 
        });
    } catch (err) {
        console.error('Google auth error:', err);
        res.status(500).json({ error: 'Google authentication failed' });
    }
});

// Verify Email
app.get('/api/auth/verify/:token', async (req, res) => {
    try {
        const verified = jwt.verify(req.params.token, process.env.JWT_SECRET);
        await pool.query('UPDATE users SET is_verified = true WHERE id = $1', [verified.id]);
        res.json({ verified: true, message: 'Email verified successfully' });
    } catch (err) {
        res.status(400).json({ error: 'Invalid or expired verification link' });
    }
});

// ==========================================
// 4. MISSING PERSONS ROUTES
// ==========================================

// Get all missing persons (Public)
app.get('/api/missing-persons', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM missing_persons ORDER BY date_missing DESC');
        res.json(result.rows);
    } catch (err) {
        console.error('Fetch missing persons error:', err);
        res.status(500).json({ error: 'Failed to fetch missing persons' });
    }
});

// Create missing person (Protected)
app.post('/api/missing-persons', authenticateToken, async (req, res) => {
    try {
        const { name, age, gender, description, notes, residence, last_seen_location, date_last_seen, police_station, date_missing, photo_urls } = req.body;
        
        const result = await pool.query(
            `INSERT INTO missing_persons (user_id, name, age, gender, description, notes, residence, last_seen_location, date_last_seen, police_station, date_missing, photo_urls) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
            [req.user.id, name, age, gender, description, notes, residence, last_seen_location, date_last_seen, police_station, date_missing, JSON.stringify(photo_urls)]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Create missing person error:', err);
        res.status(500).json({ error: 'Failed to create missing person report' });
    }
});

// Update missing person (Protected - Owner only)
app.put('/api/missing-persons/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, age, gender, description, notes, residence, last_seen_location, date_last_seen, police_station } = req.body;
        
        // Check ownership
        const post = await pool.query('SELECT * FROM missing_persons WHERE id = $1', [id]);
        if (post.rows.length === 0) return res.status(404).json({ error: 'Post not found' });
        if (post.rows[0].user_id !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Not authorized to edit this post' });
        }

        const result = await pool.query(
            `UPDATE missing_persons SET name=$1, age=$2, gender=$3, description=$4, notes=$5, residence=$6, last_seen_location=$7, date_last_seen=$8, police_station=$9 
             WHERE id=$10 RETURNING *`,
            [name, age, gender, description, notes, residence, last_seen_location, date_last_seen, police_station, id]
        );
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Update missing person error:', err);
        res.status(500).json({ error: 'Failed to update post' });
    }
});

// Delete missing person (Protected - Owner or Admin)
app.delete('/api/missing-persons/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;
        
        const post = await pool.query('SELECT * FROM missing_persons WHERE id = $1', [id]);
        if (post.rows.length === 0) return res.status(404).json({ error: 'Post not found' });
        if (post.rows[0].user_id !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Not authorized to delete this post' });
        }

        await pool.query('DELETE FROM missing_persons WHERE id = $1', [id]);
        res.json({ message: 'Post deleted successfully', reason });
    } catch (err) {
        console.error('Delete missing person error:', err);
        res.status(500).json({ error: 'Failed to delete post' });
    }
});

// ==========================================
// 5. SIGHTINGS ROUTES
// ==========================================

app.post('/api/sightings', authenticateToken, async (req, res) => {
    try {
        const { missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, photo_url } = req.body;
        
        const result = await pool.query(
            `INSERT INTO sightings (user_id, missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, photo_url) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
            [req.user.id, missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, photo_url]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Create sighting error:', err);
        res.status(500).json({ error: 'Failed to report sighting' });
    }
});

app.delete('/api/sightings/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const sighting = await pool.query('SELECT * FROM sightings WHERE id = $1', [id]);
        if (sighting.rows.length === 0) return res.status(404).json({ error: 'Sighting not found' });
        if (sighting.rows[0].user_id !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Not authorized' });
        }
        await pool.query('DELETE FROM sightings WHERE id = $1', [id]);
        res.json({ message: 'Sighting deleted' });
    } catch (err) {
        console.error('Delete sighting error:', err);
        res.status(500).json({ error: 'Failed to delete sighting' });
    }
});

// ==========================================
// 6. USER ROUTES
// ==========================================

app.get('/api/users/my-posts', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM missing_persons WHERE user_id = $1 ORDER BY date_missing DESC', [req.user.id]);
        res.json(result.rows);
    } catch (err) {
        console.error('Fetch my posts error:', err);
        res.status(500).json({ error: 'Failed to fetch your posts' });
    }
});

// ==========================================
// 7. UPLOAD ROUTE
// ==========================================

app.post('/api/upload', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        
        // Upload to Cloudinary
        const result = await new Promise((resolve, reject) => {
            const stream = cloudinary.uploader.upload_stream(
                { folder: 'locate-me-app', resource_type: 'image' },
                (error, result) => {
                    if (error) reject(error);
                    else resolve(result);
                }
            );
            stream.end(req.file.buffer);
        });

        res.json({ secure_url: result.secure_url });
    } catch (err) {
        console.error('Upload error:', err);
        res.status(500).json({ error: 'Failed to upload image' });
    }
});

// ==========================================
// 8. ADMIN ROUTES
// ==========================================

// Get all users
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, email, role, is_verified, created_at FROM users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) {
        console.error('Admin fetch users error:', err);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// 🗑️ DELETE USER (Admin Only) - NEW ROUTE
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        
        // Prevent admin from deleting themselves
        if (userId === req.user.id) {
            return res.status(400).json({ error: 'You cannot delete your own account' });
        }

        // Check if user exists
        const user = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Optional: Delete user's posts and sightings first to maintain database integrity
        await pool.query('DELETE FROM missing_persons WHERE user_id = $1', [userId]);
        await pool.query('DELETE FROM sightings WHERE user_id = $1', [userId]);

        // Delete the user
        await pool.query('DELETE FROM users WHERE id = $1', [userId]);
        
        res.json({ message: 'User and their associated data deleted successfully' });
    } catch (err) {
        console.error('Delete user error:', err);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Get all missing persons (Admin view with poster email)
app.get('/api/admin/missing-persons', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT mp.*, u.email as poster_email 
            FROM missing_persons mp 
            JOIN users u ON mp.user_id = u.id 
            ORDER BY mp.date_missing DESC
        `);
        res.json(result.rows);
    } catch (err) {
        console.error('Admin fetch missing persons error:', err);
        res.status(500).json({ error: 'Failed to fetch missing persons' });
    }
});

// Get all sightings (Admin view with reporter email)
app.get('/api/admin/sightings-full', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT s.*, u.email as reporter_email 
            FROM sightings s 
            JOIN users u ON s.user_id = u.id 
            ORDER BY s.created_at DESC
        `);
        res.json(result.rows);
    } catch (err) {
        console.error('Admin fetch sightings error:', err);
        res.status(500).json({ error: 'Failed to fetch sightings' });
    }
});

// ==========================================
// 9. SERVER START
// ==========================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Locate Me Backend is running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});