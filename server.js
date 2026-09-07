require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const app = express();

// ==========================================
// 1. CONFIGURATION & MIDDLEWARE
// ==========================================

app.use(cors({
    origin: '*', 
    credentials: true
}));

app.use(express.json({ limit: '10mb' }));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const upload = multer({ storage: multer.memoryStorage() });

// ==========================================
// 2. SECURITY MIDDLEWARE
// ==========================================

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

app.use('/api/auth/login', loginLimiter);
app.use('/api/auth/register', registerLimiter);

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
// 2.5. AUDIT LOGGING HELPER
// ==========================================
async function logAudit(userId, action, targetType, targetId, details, ipAddress) {
    try {
        await pool.query(
            `INSERT INTO audit_logs (user_id, action, target_type, target_id, details, ip_address) 
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [userId, action, targetType, targetId, details, ipAddress]
        );
        console.log(`[AUDIT] ${action} by User ${userId}`);
    } catch (err) {
        console.error('Audit log error:', err);
        // We don't throw here so the main action doesn't fail if logging fails
    }
}

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
        const newUserId = uuidv4();
        
        const newUser = await pool.query(
            'INSERT INTO users (id, email, password, role, is_verified) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, role, is_verified',
            [newUserId, email, hashedPassword, 'user', false]
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
        
        if (user.rows.length === 0) {
            await logAudit(null, 'LOGIN_FAILED', 'user', null, `Failed login attempt for ${email}`, req.ip);
            return res.status(400).json({ error: 'Invalid email or password' });
        }
        
        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) {
            await logAudit(user.rows[0].id, 'LOGIN_FAILED', 'user', user.rows[0].id, 'Invalid password', req.ip);
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        if (!user.rows[0].is_verified) return res.status(403).json({ error: 'Please verify your email first', unverified: true });

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

        await logAudit(user.rows[0].id, 'LOGIN', 'user', user.rows[0].id, `Logged in as ${user.rows[0].role}`, req.ip);

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
            const newUserId = uuidv4();
            user = await pool.query(
                'INSERT INTO users (id, email, password, role, is_verified) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, role',
                [newUserId, email, 'google_auth', 'user', true]
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

app.get('/api/missing-persons', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM missing_persons WHERE status = \'active\' ORDER BY date_missing DESC');
        res.json(result.rows);
    } catch (err) {
        console.error('Fetch missing persons error:', err);
        res.status(500).json({ error: 'Failed to fetch missing persons' });
    }
});

// ==========================================
// NEW: BACKEND SEARCH ROUTE (ADDED HERE)
// ==========================================
app.get('/api/missing-persons/search', async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) return res.json([]);
        
        // ILIKE is case-insensitive search in PostgreSQL
        const searchTerm = `%${q}%`;
        
        const result = await pool.query(
            `SELECT * FROM missing_persons 
             WHERE status = 'active' 
             AND (name ILIKE $1 OR last_seen_location ILIKE $1 OR description ILIKE $1) 
             ORDER BY date_missing DESC 
             LIMIT 50`,
            [searchTerm]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Search error:', err);
        res.status(500).json({ error: 'Search failed' });
    }
});

app.get('/api/missing-persons/station/:stationId', authenticateToken, async (req, res) => {
    try {
        const { stationId } = req.params;
        const result = await pool.query(
            'SELECT * FROM missing_persons WHERE police_station = $1 AND status = \'active\' ORDER BY date_missing DESC',
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

app.post('/api/missing-persons', authenticateToken, postLimiter, async (req, res) => {
    try {
        const { name, age, gender, description, notes, residence, last_seen_location, date_last_seen, police_station, date_missing, photo_urls } = req.body;
        const newPostId = uuidv4();
        
        const result = await pool.query(
            `INSERT INTO missing_persons (id, user_id, name, age, gender, description, notes, residence, last_seen_location, date_last_seen, police_station, date_missing, photo_urls, status) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'active') RETURNING *`,
            [newPostId, req.user.id, name, age, gender, description, notes, residence, last_seen_location, date_last_seen, police_station, date_missing, JSON.stringify(photo_urls)]
        );
        
        await logAudit(req.user.id, 'CREATE_POST', 'missing_person', newPostId, `Created post: ${name}`, req.ip);
        
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Create missing person error:', err);
        res.status(500).json({ error: 'Failed to create missing person report' });
    }
});

app.put('/api/missing-persons/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        let { name, age, gender, description, notes, residence, last_seen_location, date_last_seen, police_station } = req.body;
        
        age = age ? parseInt(age) : null;
        if (date_last_seen === '') date_last_seen = null;

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
        
        // --- AUDIT LOG ADDED ---
        await logAudit(req.user.id, 'UPDATE_POST', 'missing_person', id, `Updated post: ${name}`, req.ip);
        
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Update missing person error:', err);
        res.status(500).json({ error: 'Failed to update post' });
    }
});

app.put('/api/missing-persons/:id/mark-found', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { resolution_notes } = req.body;
        
        const result = await pool.query(
            `UPDATE missing_persons SET status = 'resolved', resolved_at = NOW(), resolution_notes = $1 
             WHERE id = $2 RETURNING *`,
            [resolution_notes || 'Case resolved', id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Case not found' });
        }
        
        await logAudit(req.user.id, 'MARK_FOUND', 'missing_person', id, `Resolved: ${resolution_notes || 'No notes'}`, req.ip);
        
        res.json({ message: 'Case marked as found', case: result.rows[0] });
    } catch (err) {
        console.error('Mark as found error:', err);
        res.status(500).json({ error: 'Failed to mark case as found' });
    }
});

app.get('/api/missing-persons/resolved', authenticateToken, async (req, res) => {
    try {
        const userStationId = req.user.station_id;
        
        if (!userStationId || userStationId === 'UNASSIGNED' || userStationId === 'ADMIN') {
            return res.status(403).json({ error: 'User is not assigned to a police station.' });
        }

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

        const result = await pool.query(
            `SELECT mp.*, u.email as poster_email 
             FROM missing_persons mp 
             LEFT JOIN users u ON mp.user_id = u.id 
             WHERE mp.police_station = $1 AND mp.status = 'resolved'
             ORDER BY mp.resolved_at DESC`,
            [exactStationName]
        );
        
        res.json(result.rows);
    } catch (err) {
        console.error('Fetch resolved cases error:', err);
        res.status(500).json({ error: 'Failed to fetch resolved cases' });
    }
});

app.get('/api/missing-persons/resolved-public', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT id, name, age, gender, photo_urls, last_seen_location, 
                   date_missing, date_last_seen, resolved_at, police_station, 
                   description, notes, residence, status
            FROM missing_persons 
            WHERE status = 'resolved' 
            ORDER BY resolved_at DESC
        `);
        
        res.json(result.rows);
    } catch (err) {
        console.error('Fetch resolved public error:', err);
        res.status(500).json({ error: 'Failed to fetch found persons' });
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
        
        await logAudit(req.user.id, 'DELETE_POST', 'missing_person', id, `Reason: ${reason || 'No reason'}`, req.ip);
        
        res.json({ message: 'Post deleted successfully', reason });
    } catch (err) {
        console.error('Delete missing person error:', err);
        res.status(500).json({ error: 'Failed to delete post' });
    }
});

// ==========================================
// 5. SIGHTINGS ROUTES
// ==========================================

app.get('/api/sightings', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM sightings ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) {
        console.error('Fetch sightings error:', err);
        res.status(500).json({ error: 'Failed to fetch sightings' });
    }
});

app.get('/api/sightings/public', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT id, missing_person_name, gender, sighting_location, sighting_time, 
                   photo_url, police_station, description, created_at 
            FROM sightings 
            ORDER BY created_at DESC
        `);
        
        res.json(result.rows);
    } catch (err) {
        console.error('Fetch public sightings error:', err);
        res.status(500).json({ error: 'Failed to fetch sightings' });
    }
});

app.post('/api/sightings', authenticateToken, async (req, res) => {
    try {
        const { missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, photo_url, police_station } = req.body;
        const newSightingId = uuidv4();
        
        const result = await pool.query(
            `INSERT INTO sightings (id, user_id, missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, photo_url, police_station) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
            [newSightingId, req.user.id, missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, photo_url, police_station]
        );
        
        await logAudit(req.user.id, 'CREATE_SIGHTING', 'sighting', newSightingId, `Sighting: ${missing_person_name}`, req.ip);
        
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Create sighting error:', err);
        res.status(500).json({ error: 'Failed to report sighting' });
    }
});

app.put('/api/sightings/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, police_station } = req.body;
        
        const sighting = await pool.query('SELECT * FROM sightings WHERE id = $1', [id]);
        if (sighting.rows.length === 0) return res.status(404).json({ error: 'Sighting not found' });
        if (sighting.rows[0].user_id !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Not authorized' });
        }

        const result = await pool.query(
            `UPDATE sightings SET missing_person_name=$1, gender=$2, sighting_location=$3, sighting_time=$4, description=$5, reporter_name=$6, reporter_contact=$7, police_station=$8 WHERE id=$9 RETURNING *`,
            [missing_person_name, gender, sighting_location, sighting_time, description, reporter_name, reporter_contact, police_station, id]
        );
        
        // --- AUDIT LOG ADDED ---
        await logAudit(req.user.id, 'UPDATE_SIGHTING', 'sighting', id, `Updated sighting: ${missing_person_name}`, req.ip);
        
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Update sighting error:', err);
        res.status(500).json({ error: 'Failed to update sighting' });
    }
});

app.put('/api/sightings/:id/resolve', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            "UPDATE sightings SET status = 'resolved', resolved_at = NOW() WHERE id = $1 RETURNING *", 
            [id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Sighting not found' });
        
        await logAudit(req.user.id, 'RESOLVE_SIGHTING', 'sighting', id, 'Sighting marked as resolved', req.ip);
        
        res.json({ message: 'Sighting resolved', case: result.rows[0] });
    } catch (err) {
        console.error('Resolve sighting error:', err);
        res.status(500).json({ error: 'Failed to resolve sighting' });
    }
});

app.get('/api/sightings/resolved', authenticateToken, async (req, res) => {
    try {
        const userStationId = req.user.station_id;
        if (!userStationId || userStationId === 'UNASSIGNED' || userStationId === 'ADMIN') {
            return res.status(403).json({ error: 'User is not assigned to a police station.' });
        }

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

        const result = await pool.query(
            `SELECT * FROM sightings 
             WHERE police_station = $1 AND status = 'resolved' 
             ORDER BY resolved_at DESC`,
            [exactStationName]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Fetch resolved sightings error:', err);
        res.status(500).json({ error: 'Failed to fetch resolved sightings' });
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
        
        // --- AUDIT LOG ADDED ---
        await logAudit(req.user.id, 'DELETE_SIGHTING', 'sighting', id, 'Deleted sighting report', req.ip);
        
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
        console.log('Fetching posts for user:', req.user.id);
        
        const missingResult = await pool.query(
            'SELECT * FROM missing_persons WHERE user_id = $1 AND status = \'active\' ORDER BY date_missing DESC', 
            [req.user.id]
        );
        
        const sightingsResult = await pool.query(
            'SELECT * FROM sightings WHERE user_id = $1 ORDER BY created_at DESC', 
            [req.user.id]
        );
        
        const combinedPosts = [
            ...missingResult.rows.map(p => ({ ...p, post_type: 'missing' })),
            ...sightingsResult.rows.map(s => ({ ...s, post_type: 'sighting' }))
        ];
        
        combinedPosts.sort((a, b) => {
            const dateA = a.post_type === 'missing' ? new Date(a.date_missing) : new Date(a.created_at);
            const dateB = b.post_type === 'missing' ? new Date(b.date_missing) : new Date(b.created_at);
            return dateB - dateA;
        });
        
        console.log('Total posts returned:', combinedPosts.length);
        res.json(combinedPosts);
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
        const result = await pool.query('SELECT id, email, role, is_verified, created_at, station_id FROM users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) {
        console.error('Admin fetch users error:', err);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.post('/api/admin/create-police-user', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { email, password, station_id } = req.body;
        
        if (!email || !password || !station_id) {
            return res.status(400).json({ error: 'Email, password, and station ID are required' });
        }

        const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUserId = uuidv4();

        const newUser = await pool.query(
            'INSERT INTO users (id, email, password, role, station_id, is_verified) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, role, station_id',
            [newUserId, email, hashedPassword, 'police', station_id, true]
        );

        await logAudit(req.user.id, 'CREATE_POLICE_USER', 'user', newUserId, `Created police user: ${email} for station ${station_id}`, req.ip);

        res.status(201).json({
            message: 'Police user created successfully',
            user: newUser.rows[0]
        });
    } catch (err) {
        console.error('Create police user error:', err);
        res.status(500).json({ error: 'Failed to create user' });
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
        
        await logAudit(req.user.id, 'DELETE_USER', 'user', userId, `Deleted user: ${user.rows[0].email}`, req.ip);
        
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
            WHERE mp.status = 'active'
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
        const userStationId = req.user.station_id;
        
        if (!userStationId || userStationId === 'UNASSIGNED' || userStationId === 'ADMIN') {
            return res.status(403).json({ error: 'User is not assigned to a police station.' });
        }

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

        const missingResult = await pool.query(
            `SELECT mp.*, u.email as poster_email 
             FROM missing_persons mp 
             LEFT JOIN users u ON mp.user_id = u.id 
             WHERE mp.police_station = $1 AND mp.status = 'active'
             ORDER BY mp.date_missing DESC`, 
            [exactStationName]
        );

        const sightingsResult = await pool.query(
            `SELECT s.*, u.email as poster_email 
             FROM sightings s 
             LEFT JOIN users u ON s.user_id = u.id 
             WHERE s.police_station = $1 AND (s.status IS NULL OR s.status = 'pending')
             ORDER BY s.created_at DESC`, 
            [exactStationName]
        );

        const resolvedResult = await pool.query(
            `SELECT COUNT(*) FROM missing_persons 
             WHERE police_station = $1 AND status = 'resolved' AND resolved_at >= NOW() - INTERVAL '30 days'`,
            [exactStationName]
        );

        const criticalResult = await pool.query(
            `SELECT COUNT(*) FROM missing_persons 
             WHERE police_station = $1 AND status = 'active' 
             AND (age <= 18 OR LOWER(description) LIKE '%kidnapped%')`,
            [exactStationName]
        );

        res.json({
            missingPersons: missingResult.rows,
            sightings: sightingsResult.rows,
            stationName: exactStationName,
            resolvedThisMonth: parseInt(resolvedResult.rows[0].count),
            criticalCases: parseInt(criticalResult.rows[0].count)
        });

    } catch (err) {
        console.error('Police dashboard fetch error:', err);
        res.status(500).json({ error: 'Failed to fetch police dashboard data' });
    }
});

// ==========================================
// 10. REPORT GENERATION ROUTES
// ==========================================

app.get('/api/reports/monthly-missing', authenticateToken, async (req, res) => {
    try {
        const userStationId = req.user.station_id;
        if (!userStationId || userStationId === 'UNASSIGNED' || userStationId === 'ADMIN') {
            return res.status(403).json({ error: 'User is not assigned to a police station.' });
        }

        const stationMap = {
            'RUI-2026-001': 'Ruiru Police Station', 'KAS-2026-001': 'Kasarani Police Station',
            'NRB-2026-001': 'Central Police Station', 'KIL-2026-001': 'Kilimani Police Station',
            'WES-2026-001': 'Westlands Police Station', 'LAN-2026-001': "Lang'ata Police Station",
            'EMB-2026-001': 'Embakasi Police Station', 'PAR-2026-001': 'Parklands police station',
            'KAR-2026-001': 'Karen Police Station.'
        };

        const exactStationName = stationMap[userStationId];
        const currentMonth = new Date().getMonth() + 1;
        const currentYear = new Date().getFullYear();

        const result = await pool.query(
            `SELECT mp.*, u.email as poster_email 
             FROM missing_persons mp 
             LEFT JOIN users u ON mp.user_id = u.id 
             WHERE mp.police_station = $1 
             AND EXTRACT(MONTH FROM mp.date_missing) = $2 
             AND EXTRACT(YEAR FROM mp.date_missing) = $3
             ORDER BY mp.date_missing DESC`,
            [exactStationName, currentMonth, currentYear]
        );

        const totalCases = result.rows.length;
        const criticalCases = result.rows.filter(r => parseInt(r.age) <= 18 || (r.description || '').toLowerCase().includes('kidnapped')).length;
        const resolvedCases = result.rows.filter(r => r.status === 'resolved').length;

        res.json({ stationName: exactStationName, month: currentMonth, year: currentYear, totalCases, criticalCases, resolvedCases, cases: result.rows });
    } catch (err) {
        console.error('Monthly report error:', err);
        res.status(500).json({ error: 'Failed to generate monthly report' });
    }
});

app.get('/api/reports/sighting-analysis', authenticateToken, async (req, res) => {
    try {
        const userStationId = req.user.station_id;
        if (!userStationId || userStationId === 'UNASSIGNED' || userStationId === 'ADMIN') return res.status(403).json({ error: 'User is not assigned to a police station.' });

        const stationMap = { 'RUI-2026-001': 'Ruiru Police Station', 'KAS-2026-001': 'Kasarani Police Station', 'NRB-2026-001': 'Central Police Station', 'KIL-2026-001': 'Kilimani Police Station', 'WES-2026-001': 'Westlands Police Station', 'LAN-2026-001': "Lang'ata Police Station", 'EMB-2026-001': 'Embakasi Police Station', 'PAR-2026-001': 'Parklands police station', 'KAR-2026-001': 'Karen Police Station.' };
        const exactStationName = stationMap[userStationId];
        const currentMonth = new Date().getMonth() + 1;
        const currentYear = new Date().getFullYear();

        const result = await pool.query(
            `SELECT s.*, u.email as reporter_email FROM sightings s LEFT JOIN users u ON s.user_id = u.id 
             WHERE s.police_station = $1 AND EXTRACT(MONTH FROM s.created_at) = $2 AND EXTRACT(YEAR FROM s.created_at) = $3 ORDER BY s.created_at DESC`,
            [exactStationName, currentMonth, currentYear]
        );

        const totalSightings = result.rows.length;
        const resolvedSightings = result.rows.filter(r => r.status === 'resolved').length;

        res.json({ stationName: exactStationName, month: currentMonth, year: currentYear, totalSightings, resolvedSightings, pendingSightings: totalSightings - resolvedSightings, sightings: result.rows });
    } catch (err) {
        console.error('Sighting report error:', err);
        res.status(500).json({ error: 'Failed to generate sighting report' });
    }
});

app.get('/api/reports/resolved-summary', authenticateToken, async (req, res) => {
    try {
        const userStationId = req.user.station_id;
        if (!userStationId || userStationId === 'UNASSIGNED' || userStationId === 'ADMIN') return res.status(403).json({ error: 'User is not assigned to a police station.' });

        const stationMap = { 'RUI-2026-001': 'Ruiru Police Station', 'KAS-2026-001': 'Kasarani Police Station', 'NRB-2026-001': 'Central Police Station', 'KIL-2026-001': 'Kilimani Police Station', 'WES-2026-001': 'Westlands Police Station', 'LAN-2026-001': "Lang'ata Police Station", 'EMB-2026-001': 'Embakasi Police Station', 'PAR-2026-001': 'Parklands police station', 'KAR-2026-001': 'Karen Police Station.' };
        const exactStationName = stationMap[userStationId];
        const currentMonth = new Date().getMonth() + 1;
        const currentYear = new Date().getFullYear();

        const result = await pool.query(
            `SELECT mp.*, u.email as poster_email FROM missing_persons mp LEFT JOIN users u ON mp.user_id = u.id 
             WHERE mp.police_station = $1 AND mp.status = 'resolved' AND EXTRACT(MONTH FROM mp.resolved_at) = $2 AND EXTRACT(YEAR FROM mp.resolved_at) = $3 ORDER BY mp.resolved_at DESC`,
            [exactStationName, currentMonth, currentYear]
        );

        const totalResolved = result.rows.length;
        const avgResolutionTime = totalResolved > 0 ? Math.round(result.rows.reduce((acc, row) => {
            const diffDays = Math.ceil(Math.abs(new Date(row.resolved_at) - new Date(row.date_missing)) / (1000 * 60 * 60 * 24));
            return acc + diffDays;
        }, 0) / totalResolved) : 0;

        res.json({ stationName: exactStationName, month: currentMonth, year: currentYear, totalResolved, avgResolutionTime, cases: result.rows });
    } catch (err) {
        console.error('Resolved report error:', err);
        res.status(500).json({ error: 'Failed to generate resolved cases report' });
    }
});

app.get('/api/reports/critical-cases', authenticateToken, async (req, res) => {
    try {
        const userStationId = req.user.station_id;
        if (!userStationId || userStationId === 'UNASSIGNED' || userStationId === 'ADMIN') return res.status(403).json({ error: 'User is not assigned to a police station.' });

        const stationMap = { 'RUI-2026-001': 'Ruiru Police Station', 'KAS-2026-001': 'Kasarani Police Station', 'NRB-2026-001': 'Central Police Station', 'KIL-2026-001': 'Kilimani Police Station', 'WES-2026-001': 'Westlands Police Station', 'LAN-2026-001': "Lang'ata Police Station", 'EMB-2026-001': 'Embakasi Police Station', 'PAR-2026-001': 'Parklands police station', 'KAR-2026-001': 'Karen Police Station.' };
        const exactStationName = stationMap[userStationId];
        const currentMonth = new Date().getMonth() + 1;
        const currentYear = new Date().getFullYear();

        const result = await pool.query(
            `SELECT mp.*, u.email as poster_email FROM missing_persons mp LEFT JOIN users u ON mp.user_id = u.id 
             WHERE mp.police_station = $1 AND mp.status = 'active' AND (mp.age <= 18 OR LOWER(mp.description) LIKE '%kidnapped%')
             AND EXTRACT(MONTH FROM mp.date_missing) = $2 AND EXTRACT(YEAR FROM mp.date_missing) = $3 ORDER BY mp.date_missing DESC`,
            [exactStationName, currentMonth, currentYear]
        );

        res.json({ 
            stationName: exactStationName, month: currentMonth, year: currentYear, 
            totalCritical: result.rows.length,
            minors: result.rows.filter(r => parseInt(r.age) <= 18).length,
            kidnappings: result.rows.filter(r => (r.description || '').toLowerCase().includes('kidnapped')).length,
            cases: result.rows 
        });
    } catch (err) {
        console.error('Critical cases report error:', err);
        res.status(500).json({ error: 'Failed to generate critical cases report' });
    }
});

app.get('/api/reports/station-performance', authenticateToken, async (req, res) => {
    try {
        const userStationId = req.user.station_id;
        if (!userStationId || userStationId === 'UNASSIGNED' || userStationId === 'ADMIN') return res.status(403).json({ error: 'User is not assigned to a police station.' });

        const stationMap = { 'RUI-2026-001': 'Ruiru Police Station', 'KAS-2026-001': 'Kasarani Police Station', 'NRB-2026-001': 'Central Police Station', 'KIL-2026-001': 'Kilimani Police Station', 'WES-2026-001': 'Westlands Police Station', 'LAN-2026-001': "Lang'ata Police Station", 'EMB-2026-001': 'Embakasi Police Station', 'PAR-2026-001': 'Parklands police station', 'KAR-2026-001': 'Karen Police Station.' };
        const exactStationName = stationMap[userStationId];
        const currentMonth = new Date().getMonth() + 1;
        const currentYear = new Date().getFullYear();

        const missingResult = await pool.query(`SELECT * FROM missing_persons WHERE police_station = $1 AND EXTRACT(MONTH FROM date_missing) = $2 AND EXTRACT(YEAR FROM date_missing) = $3`, [exactStationName, currentMonth, currentYear]);
        const sightingResult = await pool.query(`SELECT * FROM sightings WHERE police_station = $1 AND EXTRACT(MONTH FROM created_at) = $2 AND EXTRACT(YEAR FROM created_at) = $3`, [exactStationName, currentMonth, currentYear]);

        const totalCases = missingResult.rows.length;
        const resolvedCases = missingResult.rows.filter(r => r.status === 'resolved').length;
        const resolutionRate = totalCases > 0 ? ((resolvedCases / totalCases) * 100).toFixed(1) : 0;

        res.json({
            stationName: exactStationName, month: currentMonth, year: currentYear,
            totalCases, resolvedCases, activeCases: totalCases - resolvedCases, resolutionRate,
            totalSightings: sightingResult.rows.length,
            resolvedSightings: sightingResult.rows.filter(r => r.status === 'resolved').length
        });
    } catch (err) {
        console.error('Performance report error:', err);
        res.status(500).json({ error: 'Failed to generate performance report' });
    }
});

app.get('/api/reports/weekly-activity', authenticateToken, async (req, res) => {
    try {
        const userStationId = req.user.station_id;
        if (!userStationId || userStationId === 'UNASSIGNED' || userStationId === 'ADMIN') return res.status(403).json({ error: 'User is not assigned to a police station.' });

        const stationMap = { 'RUI-2026-001': 'Ruiru Police Station', 'KAS-2026-001': 'Kasarani Police Station', 'NRB-2026-001': 'Central Police Station', 'KIL-2026-001': 'Kilimani Police Station', 'WES-2026-001': 'Westlands Police Station', 'LAN-2026-001': "Lang'ata Police Station", 'EMB-2026-001': 'Embakasi Police Station', 'PAR-2026-001': 'Parklands police station', 'KAR-2026-001': 'Karen Police Station.' };
        const exactStationName = stationMap[userStationId];
        
        const weekAgo = new Date();
        weekAgo.setDate(weekAgo.getDate() - 7);

        const missingResult = await pool.query(`SELECT * FROM missing_persons WHERE police_station = $1 AND date_missing >= $2 ORDER BY date_missing DESC`, [exactStationName, weekAgo]);
        const sightingResult = await pool.query(`SELECT * FROM sightings WHERE police_station = $1 AND created_at >= $2 ORDER BY created_at DESC`, [exactStationName, weekAgo]);
        const resolvedResult = await pool.query(`SELECT * FROM missing_persons WHERE police_station = $1 AND status = 'resolved' AND resolved_at >= $2`, [exactStationName, weekAgo]);

        res.json({
            stationName: exactStationName,
            weekStart: weekAgo.toISOString().split('T')[0],
            weekEnd: new Date().toISOString().split('T')[0],
            newCases: missingResult.rows.length,
            newSightings: sightingResult.rows.length,
            resolvedCases: resolvedResult.rows.length,
            missingCases: missingResult.rows,
            sightings: sightingResult.rows,
            resolved: resolvedResult.rows
        });
    } catch (err) {
        console.error('Weekly report error:', err);
        res.status(500).json({ error: 'Failed to generate weekly report' });
    }
});

// ==========================================
// 10.5. AUDIT LOGS ROUTE
// ==========================================

app.get('/api/admin/audit-logs', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT al.*, u.email as user_email 
            FROM audit_logs al 
            LEFT JOIN users u ON al.user_id = u.id 
            ORDER BY al.created_at DESC 
            LIMIT 100
        `);
        res.json(result.rows);
    } catch (err) {
        console.error('Fetch audit logs error:', err);
        res.status(500).json({ error: 'Failed to fetch audit logs' });
    }
});

// ==========================================
// 11. SERVER START
// ==========================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Locate Me Backend is running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});
