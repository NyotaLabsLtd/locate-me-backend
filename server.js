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
const { Resend } = require('resend');

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

// Initialize Resend with your API Key
const resend = new Resend(process.env.RESEND_API_KEY);

// ==========================================
// UNIFIED POLICE STATION MAP
// ==========================================
const STATION_ID_TO_NAME = {
    'NBI-CEN': 'Central Police Station', 'NBI-KIL': 'Kilimani Police Station', 'NBI-WES': 'Westlands Police Station',
    'NBI-KAS': 'Kasarani Police Station', 'NBI-LAN': "Lang'ata Police Station", 'NBI-EMB': 'Embakasi Police Station',
    'NBI-RUA': 'Ruaraka Police Station', 'NBI-DON': 'Donholm Police Station', 'NBI-KAY': 'Kayole Police Station',
    'NBI-PUM': 'Pumwani Police Station', 'NBI-KAM': 'Kamukunji Police Station', 'NBI-STA': 'Starehe Police Station',
    'NBI-MAK': 'Makadara Police Station', 'NBI-KIB': 'Kibera Police Station', 'NBI-PAR': 'Parklands Police Station',
    'NBI-KAR': 'Karen Police Station', 'NBI-DAG': 'Dagoretti Police Station', 'NBI-MAT': 'Mathare Police Station',
    'NBI-KAR2': 'Kariobangi Police Station',
    
    'KIA-RUI': 'Ruiru Police Station', 'KIA-GAT': 'Gatundu Police Station', 'KIA-THI': 'Thika Police Station',
    'KIA-KIA': 'Kiambu Town Police Station', 'KIA-LIM': 'Limuru Police Station', 'KIA-JUJ': 'Juja Police Station',
    'KIA-KAR': 'Karuri Police Station', 'KIA-KIK': 'Kikuyu Police Station', 'KIA-KIJ': 'Kijabe Police Station',
    'KIA-LAR': 'Lari Police Station', 'MUR-MUR': "Murang'a Town Police Station", 'MUR-KAN': 'Kangema Police Station',
    'MUR-KIH': 'Kiharu Police Station', 'NYE-NYE': 'Nyeri Central Police Station', 'NYE-OTH': 'Othaya Police Station',
    'NYE-KAR': 'Karatina Police Station', 'NYE-MUK': 'Mukurweini Police Station', 'KIR-KER': 'Kerugoya Police Station',
    'KIR-KUT': 'Kutus Police Station', 'KIR-SAG': 'Sagana Police Station', 'NYA-OLK': 'Ol Kalou Police Station',
    'NYA-NJA': 'Njabini Police Station', 'NYA-KIN': 'Kinangop Police Station',
    
    'MAC-MAC': 'Machakos Town Police Station', 'MAC-MAV': 'Mavoko Police Station (Athi River)', 'MAC-KAN': 'Kangundo Police Station',
    'MAC-MAT': 'Matuu Police Station', 'KIT-KIT': 'Kitui Town Police Station', 'KIT-MWI': 'Mwingi Police Station',
    'MAK-WOT': 'Wote Police Station (Makueni)', 'MAK-MAK': 'Makindu Police Station', 'MAK-MTI': 'Mtito Andei Police Station',
    'EMB-EMB': 'Embu Town Police Station', 'EMB-RUN': 'Runyenjes Police Station', 'EMB-SIA': 'Siakago Police Station',
    'MER-MER': 'Meru Central Police Station', 'MER-MAU': 'Maua Police Station', 'MER-NKU': 'Nkubu Police Station',
    'MER-CHU': 'Chuka Police Station', 'MER-TIM': 'Timau Police Station', 'MAR-MAR': 'Marsabit Town Police Station',
    'MAR-MOY': 'Moyale Police Station', 'MAR-NOR': 'North Horr Police Station', 'GAR-GAR': 'Garissa Town Police Station',
    'GAR-DAD': 'Dadaab Police Station', 'GAR-BAL': 'Balambala Police Station', 'WAJ-WAJ': 'Wajir Town Police Station',
    'WAJ-ELD': 'Eldas Police Station', 'MAN-MAN': 'Mandera Town Police Station', 'MAN-ELW': 'El Wak Police Station',
    'ISI-ISI': 'Isiolo Town Police Station', 'ISI-GAR': 'Garbatulla Police Station',
    
    'MOM-CEN': 'Mombasa Central Police Station', 'MOM-TUD': 'Tudor Police Station', 'MOM-CHA': 'Changamwe Police Station',
    'MOM-KIS': 'Kisauni Police Station', 'MOM-LIK': 'Likoni Police Station', 'MOM-NYA': 'Nyali Police Station',
    'MOM-BAM': 'Bamburi Police Station', 'KIL-KIL': 'Kilifi Town Police Station', 'KIL-MAL': 'Malindi Police Station',
    'KIL-MTW': 'Mtwapa Police Station', 'KIL-VIP': 'Vipingo Police Station', 'KWA-KWA': 'Kwale Town Police Station',
    'KWA-MSA': 'Msambweni Police Station', 'KWA-KIN': 'Kinango Police Station', 'TAN-HOL': 'Hola Police Station (Tana River)',
    'TAN-GAR': 'Garsen Police Station', 'LAM-LAM': 'Lamu Town Police Station', 'LAM-MPE': 'Mpeketoni Police Station',
    
    'NAK-CEN': 'Nakuru Central Police Station', 'NAK-NAI': 'Naivasha Police Station', 'NAK-GIL': 'Gilgil Police Station',
    'NAK-MOL': 'Molo Police Station', 'NAK-NJO': 'Njoro Police Station', 'NAK-RON': 'Rongai Police Station (Nakuru)',
    'UAS-ELD': 'Eldoret Central Police Station', 'UAS-ELT': 'Eldoret Town Police Station', 'UAS-TUR': 'Turbo Police Station',
    'UAS-MOI': "Moi's Bridge Police Station", 'UAS-BUR': 'Burnt Forest Police Station', 'NAN-KAP': 'Kapsabet Police Station',
    'NAN-HIL': 'Nandi Hills Police Station', 'NAN-MOS': 'Mosoriot Police Station', 'KER-KER': 'Kericho Town Police Station',
    'KER-LIT': 'Litein Police Station', 'KER-KIP': 'Kipkelion Police Station', 'KER-LON': 'Londiani Police Station',
    'BOM-BOM': 'Bomet Town Police Station', 'BOM-SOT': 'Sotik Police Station', 'BOM-LON': 'Longisa Police Station',
    'NAR-NAR': 'Narok Town Police Station', 'NAR-KIL': 'Kilgoris Police Station', 'NAR-SUS': 'Suswa Police Station',
    'NAK-MAI': 'Mai Mahiu Police Station', 'KAJ-RON': 'Ongata Rongai Police Station (Kajiado)', 'KAJ-KIT': 'Kitengela Police Station',
    'KAJ-KAJ': 'Kajiado Town Police Station', 'KAJ-NGO': 'Ngong Police Station', 'KAJ-ISI': 'Isinya Police Station',
    'KAJ-NAM': 'Namanga Police Station', 'BAR-KAB': 'Kabarnet Police Station', 'BAR-ELD': 'Eldama Ravine Police Station',
    'BAR-MAR': 'Marigat Police Station', 'LAI-NAN': 'Nanyuki Police Station', 'LAI-RUM': 'Rumuruti Police Station',
    'LAI-DOL': 'Dol Dol Police Station', 'SAM-MAR': 'Maralal Police Station', 'TUR-LOD': 'Lodwar Police Station',
    'TUR-KAK': 'Kakuma Police Station', 'WES-KAP': 'Kapenguria Police Station', 'TRA-KIT': 'Kitale Police Station',
    'TRA-KIM': 'Kiminini Police Station', 'TRA-END': 'Endebess Police Station',
    
    'KAK-KAK': 'Kakamega Central Police Station', 'KAK-MUM': 'Mumias Police Station', 'KAK-BUT': 'Butere Police Station',
    'KAK-MAL': 'Malava Police Station', 'KAK-LUG': 'Lugari Police Station', 'BUN-BUN': 'Bungoma Town Police Station',
    'BUN-WEB': 'Webuye Police Station', 'BUN-KIM': 'Kimilili Police Station', 'BUN-CHW': 'Chwele Police Station',
    'BUS-BUS': 'Busia Town Police Station', 'BUS-MAL': 'Malaba Police Station', 'BUS-NAM': 'Nambale Police Station',
    'VIH-MBA': 'Mbale Police Station', 'VIH-LUA': 'Luanda Police Station', 'VIH-HAM': 'Hamisi Police Station',
    
    'KIS-CEN': 'Kisumu Central Police Station', 'KIS-TOW': 'Kisumu Town Police Station', 'KIS-MAS': 'Maseno Police Station',
    'KIS-MUH': 'Muhoroni Police Station', 'KIS-AHE': 'Ahero Police Station', 'SIA-SIA': 'Siaya Town Police Station',
    'SIA-BON': 'Bondo Police Station', 'SIA-UGU': 'Ugunja Police Station', 'HOM-HOM': 'Homa Bay Town Police Station',
    'HOM-MBI': 'Mbita Police Station', 'HOM-KEN': 'Kendu Bay Police Station', 'MIG-MIG': 'Migori Town Police Station',
    'MIG-RON': 'Rongo Police Station', 'MIG-AWE': 'Awendo Police Station', 'KIS2-KIS': 'Kisii Town Police Station',
    'KIS2-KER': 'Keroka Police Station', 'KIS2-SUN': 'Suneka Police Station', 'NYA-NYA': 'Nyamira Town Police Station'
};

// Helper function to get station name from ID
const getStationName = (id) => STATION_ID_TO_NAME[id] || id;

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
// SEND VERIFICATION EMAIL ROUTE
// ==========================================
app.post('/api/auth/send-verification-email', async (req, res) => {
  try {
    const { email, verificationLink } = req.body;
    
    const { data, error } = await resend.emails.send({
      from: 'Locate Me <info@locate-me.co.ke>',
      to: [email],
      subject: 'Verify Your Email - Locate Me',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #fbbf24;">Welcome to Locate Me!</h2>
          <p style="color: #334155; font-size: 16px; line-height: 1.6;">
            Thank you for signing up. Please verify your email by clicking the button below:
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationLink}" 
               style="display: inline-block; background: #fbbf24; color: #0f172a; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px;">
              Verify Email
            </a>
          </div>
          <p style="color: #64748b; font-size: 14px;">
            Or copy and paste this link into your browser:<br>
            <a href="${verificationLink}" style="color: #2563eb;">${verificationLink}</a>
          </p>
          <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 30px 0;">
          <p style="color: #94a3b8; font-size: 12px; text-align: center;">
            © 2024 Locate Me. All rights reserved.<br>
            If you didn't create this account, you can safely ignore this email.
          </p>
        </div>
      `
    });
    
    if (error) {
      console.error('Resend error:', error);
      return res.status(500).json({ error: 'Failed to send email' });
    }
    
    console.log('Verification email sent to:', email);
    res.json({ success: true });
  } catch (error) {
    console.error('Email error:', error);
    res.status(500).json({ error: 'Failed to send email' });
  }
});

// ==========================================
// FORGOT PASSWORD ROUTES
// ==========================================

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await pool.query('SELECT id, email FROM users WHERE email = $1', [email]);
    
    if (user.rows.length === 0) {
      return res.json({ message: 'If an account exists, a reset link has been sent.' });
    }

    const resetToken = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const resetLink = `https://locate-me.co.ke/?reset=${resetToken}`;

    const { data, error } = await resend.emails.send({
      from: 'Locate Me <info@locate-me.co.ke>',
      to: [email],
      subject: 'Reset Your Password - Locate Me',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #fbbf24;">Reset Your Password</h2>
          <p style="color: #334155; font-size: 16px; line-height: 1.6;">
            You requested a password reset for your Locate Me account. Click the button below to create a new password. This link expires in 15 minutes.
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetLink}" 
               style="display: inline-block; background: #fbbf24; color: #0f172a; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px;">
              Reset Password
            </a>
          </div>
          <p style="color: #64748b; font-size: 14px;">
            If you didn't request this, you can safely ignore this email.
          </p>
        </div>
      `
    });

    if (error) {
      console.error('Resend error:', error);
      return res.status(500).json({ error: 'Failed to send reset email' });
    }

    res.json({ message: 'If an account exists, a reset link has been sent.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, decoded.id]);
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(400).json({ error: 'Reset link has expired. Please request a new one.' });
    }
    console.error('Reset password error:', err);
    res.status(400).json({ error: 'Invalid or expired reset link' });
  }
});

// ==========================================
// 4. MISSING PERSONS ROUTES
// ==========================================

app.get('/api/missing-persons', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT id, user_id, name, age, gender, description, notes, residence, 
                   last_seen_location, date_last_seen, police_station, date_missing, 
                   photo_urls, status, created_at, updated_at 
            FROM missing_persons 
            WHERE status = 'active' 
            ORDER BY date_missing DESC
        `);
        res.json(result.rows);
    } catch (err) {
        console.error('Fetch missing persons error:', err);
        res.status(500).json({ error: 'Failed to fetch missing persons' });
    }
});

app.get('/api/missing-persons/search', async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) return res.json([]);
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

// DYNAMIC POLICE STATIONS ENDPOINT
app.get('/api/police-stations', async (req, res) => {
    try {
        const stations = Object.entries(STATION_ID_TO_NAME).map(([id, name]) => {
            let county = 'Other';
            if (id.startsWith('NBI')) county = 'Nairobi';
            else if (['KIA', 'MUR', 'NYE', 'KIR', 'NYA'].some(p => id.startsWith(p))) county = 'Central';
            else if (['MAC', 'KIT', 'MAK', 'EMB', 'MER', 'MAR', 'GAR', 'WAJ', 'MAN', 'ISI'].some(p => id.startsWith(p))) county = 'Eastern & North Eastern';
            else if (['MOM', 'KIL', 'KWA', 'TAN', 'LAM'].some(p => id.startsWith(p))) county = 'Coast';
            else if (['NAK', 'UAS', 'NAN', 'KER', 'BOM', 'NAR', 'KAJ', 'BAR', 'LAI', 'SAM', 'TUR', 'WES', 'TRA'].some(p => id.startsWith(p))) county = 'Rift Valley';
            else if (['KAK', 'BUN', 'BUS', 'VIH'].some(p => id.startsWith(p))) county = 'Western';
            else if (['KIS', 'SIA', 'HOM', 'MIG', 'KIS2'].some(p => id.startsWith(p))) county = 'Nyanza';
            
            return { id, name, county };
        });
        res.json(stations);
    } catch (err) {
        console.error('Fetch police stations error:', err);
        res.status(500).json({ error: 'Failed to fetch police stations' });
    }
});

app.post('/api/missing-persons', authenticateToken, postLimiter, async (req, res) => {
    try {
        const { name, age, gender, description, notes, residence, last_seen_location, date_last_seen, police_station, date_missing, photo_urls, poster_contact } = req.body;
        const newPostId = uuidv4();
        
        const result = await pool.query(
            `INSERT INTO missing_persons (id, user_id, name, age, gender, description, notes, residence, last_seen_location, date_last_seen, police_station, date_missing, photo_urls, status, poster_contact) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'active', $14) RETURNING *`,
            [newPostId, req.user.id, name, age, gender, description, notes, residence, last_seen_location, date_last_seen, police_station, date_missing, JSON.stringify(photo_urls), poster_contact]
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
            `UPDATE missing_persons SET name=$1, age=$2, gender=$3, description=$4, notes=$5, residence=$6, last_seen_location=$7, date_last_seen=$8, police_station=$9 WHERE id=$10 RETURNING *`,
            [name, age, gender, description, notes, residence, last_seen_location, date_last_seen, police_station, id]
        );
        
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
            `UPDATE missing_persons SET status = 'resolved', resolved_at = NOW(), resolution_notes = $1 WHERE id = $2 RETURNING *`,
            [resolution_notes || 'Case resolved', id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Case not found' });
        
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

        const exactStationName = getStationName(userStationId);

        const result = await pool.query(
            `SELECT mp.*, u.email as poster_email FROM missing_persons mp LEFT JOIN users u ON mp.user_id = u.id 
             WHERE mp.police_station = $1 AND mp.status = 'resolved' ORDER BY mp.resolved_at DESC`,
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
        const result = await pool.query("UPDATE sightings SET status = 'resolved', resolved_at = NOW() WHERE id = $1 RETURNING *", [id]);
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

        const exactStationName = getStationName(userStationId);

        const result = await pool.query(
            `SELECT * FROM sightings WHERE police_station = $1 AND status = 'resolved' ORDER BY resolved_at DESC`,
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
        if (existingUser.rows.length > 0) return res.status(409).json({ error: 'Email already registered' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUserId = uuidv4();

        const newUser = await pool.query(
            'INSERT INTO users (id, email, password, role, station_id, is_verified) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, role, station_id',
            [newUserId, email, hashedPassword, 'police', station_id, true]
        );

        await logAudit(req.user.id, 'CREATE_POLICE_USER', 'user', newUserId, `Created police user: ${email} for station ${station_id}`, req.ip);
        res.status(201).json({ message: 'Police user created successfully', user: newUser.rows[0] });
    } catch (err) {
        console.error('Create police user error:', err);
        res.status(500).json({ error: 'Failed to create user' });
    }
});

app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        if (userId === req.user.id) return res.status(400).json({ error: 'You cannot delete your own account' });

        const user = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        if (user.rows.length === 0) return res.status(404).json({ error: 'User not found' });

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
            SELECT mp.*, u.email as poster_email FROM missing_persons mp JOIN users u ON mp.user_id = u.id 
            WHERE mp.status = 'active' ORDER BY mp.date_missing DESC
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
            SELECT s.*, u.email as reporter_email FROM sightings s JOIN users u ON s.user_id = u.id 
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

        const exactStationName = getStationName(userStationId);
        if (!exactStationName) return res.status(400).json({ error: 'Unknown station ID.' });

        console.log(`Fetching data for station: ${exactStationName}`);

        const missingResult = await pool.query(
            `SELECT mp.*, u.email as poster_email FROM missing_persons mp LEFT JOIN users u ON mp.user_id = u.id 
             WHERE mp.police_station = $1 AND mp.status = 'active' ORDER BY mp.date_missing DESC`, 
            [exactStationName]
        );

        const sightingsResult = await pool.query(
            `SELECT s.*, u.email as poster_email FROM sightings s LEFT JOIN users u ON s.user_id = u.id 
             WHERE s.police_station = $1 AND (s.status IS NULL OR s.status = 'pending') ORDER BY s.created_at DESC`, 
            [exactStationName]
        );

        const resolvedResult = await pool.query(
            `SELECT COUNT(*) FROM missing_persons WHERE police_station = $1 AND status = 'resolved' AND resolved_at >= NOW() - INTERVAL '30 days'`,
            [exactStationName]
        );

        const criticalResult = await pool.query(
            `SELECT COUNT(*) FROM missing_persons WHERE police_station = $1 AND status = 'active' AND (age <= 18 OR LOWER(description) LIKE '%kidnapped%')`,
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

        const exactStationName = getStationName(userStationId);
        const currentMonth = new Date().getMonth() + 1;
        const currentYear = new Date().getFullYear();

        const result = await pool.query(
            `SELECT mp.*, u.email as poster_email FROM missing_persons mp LEFT JOIN users u ON mp.user_id = u.id 
             WHERE mp.police_station = $1 AND EXTRACT(MONTH FROM mp.date_missing) = $2 AND EXTRACT(YEAR FROM mp.date_missing) = $3
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

        const exactStationName = getStationName(userStationId);
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

        const exactStationName = getStationName(userStationId);
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

        const exactStationName = getStationName(userStationId);
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

        const exactStationName = getStationName(userStationId);
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

        const exactStationName = getStationName(userStationId);
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
            SELECT al.*, u.email as user_email FROM audit_logs al LEFT JOIN users u ON al.user_id = u.id 
            ORDER BY al.created_at DESC LIMIT 100
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
