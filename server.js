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

// CORS: Allow requests from ALL origins
app.use(cors({
    origin: '*', 
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

// Rate Limiters - ONLY for specific actions (NOT for data fetching)
const loginLimiter = rateLimit({ 
    windowMs: 10 * 60 * 1000, 
    max: 7, 
    message: { error: 'Too many login attempts. Try again in 10 minutes.' } 
});

const registerLimiter = rateLimit({ 
    windowMs: 10 * 60 * 1000, 
    max: 3, 
    message: { error: 'Too many signup attempts. Try again in 10 minutes.' } 
});

const postLimiter = rateLimit({ 
    windowMs: 60 * 60 * 1000, 
    max: 5, 
    message: { error: 'Too many posts. Try again in 1 hour.' } 
});

// Apply limiters ONLY where needed (Auth and Creating Posts)
app.use('/api/auth/login', loginLimiter);
app.use('/api/auth/register', registerLimiter);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(403).json({ error: 'Invalid or expired token.' });
    }
};

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required.' });
    }
    next();
};

// ==========================================
// 3. AUTH ROUTES
// ==========================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

        const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) return res.status(409).json({ error: 'Email already registered' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await pool.query(
            'INSERT INTO users (email, password, role, is_verified) VALUES ($1, $2, $3, $4) RETURNING id, email, role, is_verified',
            [email, hashedPassword, 'user', false]
        );

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

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        
        if (user.rows.length === 0) return res.status(400).json({ error: 'Invalid email or password' });
        
        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid email or password' });

        if (!user.rows[0].is_verified) return res.status(403).json({ error: 'Please verify your email first', unverified: true });

        // UPDATED: Include station_id in the token payload
        const token = jwt.sign(
            { 
                id: user.rows[0].id, 
                email: user.rows[0].email, 
                role: user.rows[0].role,
                station_id: user.rows[0].station_id || 'UNASSIGNED' 
            }, 
            process.env.JWT_SECRET, 
            { expiresIn: '30d' }
        );

        res.json({ 
            token, 
            user: { 
                id: user.rows[0].id, 
                email: user.rows[0].email, 
                role: user.rows[0].role,
                station_id: user.rows[0].station_id 
            } 
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error during login' });
    }
});

app.post('/api/auth/google', async (req, res) => {
    try {
        const { credential } = req.body;
        const decoded = jwt.decode(credential);
        const email = decoded.email;

        let user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        
        if (user.rows.length === 0) {
            user = await pool.query(
                'INSERT INTO users (email, password, role, is_verified) VALUES ($1, $2, $3, $4) RETURNING id, email, role',
                [email, 'google_auth', 'user', true]
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

// Get all missing persons - NO RATE LIMIT, NO AUTH REQUIRED
app.get('/api/missing-persons', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM missing_persons ORDER BY date_missing DESC');
        res.json(result.rows);
    } catch (err) {
        console.error('Fetch missing persons error:', err);
        res.status(500).json({ error: 'Failed to fetch missing persons' });
    }
});

// Get missing persons by police station - AUTHENTICATED
app.get('/api/missing-persons/station/:stationId', authenticateToken, async (req, res) => {
    try {
        const { stationId } = req.params;
        const result = await pool.query(
            'SELECT * FROM missing_persons WHERE police_station = $1 ORDER BY date_missing DESC',
            [stationId]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Fetch station cases error:', err);
        res.status(500).json({ error: 'Failed to fetch cases for this station' });
    }
});

app.get('/api/police-stations', async (req, res) => {
    try {
        const stations = [
            { id: 'RUI-2026-001', name: 'Ruiru Police Station', county: 'Kiambu' },
            { id: 'KAS-2026-001', name: 'Kasarani Police Station', county: 'Nairobi' },
            { id: 'NRB-2026-001', name: 'Central Police Station - Nairobi', county: 'Nairobi' },
            { id: 'KIL-2026-001', name: 'Kilimani Police Station', county: 'Nairobi' },
            { id: 'WES-2026-001', name: 'Westlands Police Station', county: 'Nairobi' },
            { id: 'LAN-2026-001', name: "Lang'ata Police Station", county: 'Nairobi' },
            { id: 'EMB-2026-001', name: 'Embakasi Police Station', county: 'Nairobi' },
            { id: 'RUA-2026-001', name: 'Ruaraka Police Station', county: 'Nairobi' },
            { id: 'DON-2026-001', name: 'Donholm Police Station', county: 'Nairobi' },
            { id: 'KAY-2026-001', name: 'Kayole Police Station', county: 'Nairobi' },
            { id: 'PUM-2026-001', name: 'Pumwani Police Station', county: 'Nairobi' },
            { id: 'KAM-2026-001', name: 'Kamukunji Police Station', county: 'Nairobi' },
            { id: 'STA-2026-001', name: 'Starehe Police Station', county: 'Nairobi' },
            { id: 'MAK-2026-001', name: 'Makadara Police Station', county: 'Nairobi' },
            { id: 'KIB-2026-001', name: 'Kibera Police Station', county: 'Nairobi' },
            { id: 'PAR-2026-001', name: 'Parklands Police Station', county: 'Nairobi' },
            { id: 'THI-2026-001', name: 'Thika Police Station', county: 'Kiambu' },
            { id: 'KIA-2026-001', name: 'Kiambu Town Police Station', county: 'Kiambu' },
            { id: 'LIM-2026-001', name: 'Limuru Police Station', county: 'Kiambu' },
            { id: 'JUJ-2026-001', name: 'Juja Police Station', county: 'Kiambu' },
            { id: 'KAR-2026-001', name: 'Karuri Police Station', county: 'Kiambu' },
            { id: 'KIK-2026-001', name: 'Kikuyu Police Station', county: 'Kiambu' },
            { id: 'MOM-2026-001', name: 'Mombasa Central Police Station', county: 'Mombasa' },
            { id: 'TUD-2026-001', name: 'Tudor Police Station', county: 'Mombasa' },
            { id: 'CHA-2026-001', name: 'Changamwe Police Station', county: 'Mombasa' },
            { id: 'KIS-2026-001', name: 'Kisauni Police Station', county: 'Mombasa' },
            { id: 'LIK-2026-001', name: 'Likoni Police Station', county: 'Mombasa' },
            { id: 'KIS-CEN-001', name: 'Kisumu Central Police Station', county: 'Kisumu' },
            { id: 'KIS-TOW-001', name: 'Kisumu Town Police Station', county: 'Kisumu' },
            { id: 'NYA-2026-001', name: 'Nyando Police Station', county: 'Kisumu' },
            { id: 'MUH-2026-001', name: 'Muhoroni Police Station', county: 'Kisumu' },
            { id: 'NAK-CEN-001', name: 'Nakuru Central Police Station', county: 'Nakuru' },
            { id: 'NAK-TOW-001', name: 'Nakuru Town Police Station', county: 'Nakuru' },
            { id: 'NAI-2026-001', name: 'Naivasha Police Station', county: 'Nakuru' },
            { id: 'GIL-2026-001', name: 'Gilgil Police Station', county: 'Nakuru' },
            { id: 'MOL-2026-001', name: 'Molo Police Station', county: 'Nakuru' },
            { id: 'ELD-2026-001', name: 'Eldoret Police Station', county: 'Uasin Gishu' },
            { id: 'ELD-TOW-001', name: 'Eldoret Town Police Station', county: 'Uasin Gishu' },
            { id: 'TUR-2026-001', name: 'Turbo Police Station', county: 'Uasin Gishu' }
        ];
        res.json(stations);
    } catch (err) {
        console.error('Fetch police stations error:', err);
        res.status(500).json({ error: 'Failed to fetch police stations' });
    }
});

// Create missing person - RATE LIMITED (only 5 per hour)
app.post('/api/missing-persons', authenticateToken, postLimiter, async (req, res) => {
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

app.put('/api/missing-persons/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, age, gender, description, notes, residence, last_seen_location, date_last_seen, police_station } = req.body;
        
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

// Get all sightings - NO RATE LIMIT, NO AUTH REQUIRED
app.get('/api/sightings', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM sightings ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) {
        console.error('Fetch sightings error:', err);
        res.status(500).json({ error: 'Failed to fetch sightings' });
    }
});

app.post('/api/sightings', authenticateToken, async (req, res) => {
    try {
        const { missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, photo_url, police_station } = req.body;
        
        const result = await pool.query(
            `INSERT INTO sightings (user_id, missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, photo_url, police_station) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
            [req.user.id, missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, photo_url, police_station]
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
        
        const result = await new Promise((resolve, reject) => {
            const stream = cloudinary.uploader.upload_stream(
                { 
                    folder: 'locate-me-app', 
                    resource_type: 'image',
                    quality: 'auto',
                    fetch_format: 'auto',
                    width: 800,
                    height: 800,
                    crop: 'limit'
                },
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

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, email, role, is_verified, created_at FROM users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) {
        console.error('Admin fetch users error:', err);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        
        if (userId === req.user.id) {
            return res.status(400).json({ error: 'You cannot delete your own account' });
        }

        const user = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        await pool.query('DELETE FROM missing_persons WHERE user_id = $1', [userId]);
        await pool.query('DELETE FROM sightings WHERE user_id = $1', [userId]);
        await pool.query('DELETE FROM users WHERE id = $1', [userId]);
        
        res.json({ message: 'User and their associated data deleted successfully' });
    } catch (err) {
        console.error('Delete user error:', err);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

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
// 9. POLICE DASHBOARD ROUTES (SECURE)
// ==========================================

app.get('/api/police/cases', authenticateToken, async (req, res) => {
    try {
        // 1. Get the station ID from the logged-in user's token
        const userStationId = req.user.station_id;
        
        if (!userStationId || userStationId === 'UNASSIGNED' || userStationId === 'ADMIN') {
            return res.status(403).json({ error: 'User is not assigned to a police station.' });
        }

        // 2. Map the Station ID to the exact name used in the database
        const stationMap = {
            'RUI-2026-001': 'Ruiru Police Station',
            'KAS-2026-001': 'Kasarani Police Station',
            'NRB-2026-001': 'Central Police Station',
            'KIL-2026-001': 'Kilimani Police Station',
            'WES-2026-001': 'Westlands Police Station',
            'LAN-2026-001': "Lang'ata Police Station",
            'EMB-2026-001': 'Embakasi Police Station',
            'PAR-2026-001': 'Parklands police station',
            'KAR-2026-001': 'Karen Police Station.'
        };

        const exactStationName = stationMap[userStationId];

        if (!exactStationName) {
            return res.status(400).json({ error: 'Unknown station ID.' });
        }

        console.log(`Fetching data for station: ${exactStationName}`);

        // 3. Fetch Missing Persons for this specific station WITH POSTER EMAIL
        const missingResult = await pool.query(
            `SELECT mp.*, u.email as poster_email 
             FROM missing_persons mp 
             LEFT JOIN users u ON mp.user_id = u.id 
             WHERE mp.police_station = $1 
             ORDER BY mp.date_missing DESC`, 
            [exactStationName]
        );

        // 4. Fetch Sightings for this specific station WITH POSTER EMAIL
        const sightingsResult = await pool.query(
            `SELECT s.*, u.email as poster_email 
             FROM sightings s 
             LEFT JOIN users u ON s.user_id = u.id 
             WHERE s.police_station = $1 
             ORDER BY s.created_at DESC`, 
            [exactStationName]
        );

        // 5. Send the filtered data back
        res.json({
            missingPersons: missingResult.rows,
            sightings: sightingsResult.rows,
            stationName: exactStationName
        });

    } catch (err) {
        console.error('Police dashboard fetch error:', err);
        res.status(500).json({ error: 'Failed to fetch police dashboard data' });
    }
});

// ==========================================
// 10. SERVER START
// ==========================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Locate Me Backend is running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});
