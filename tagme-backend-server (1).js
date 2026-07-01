// TagMe Backend - Express Server
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://user:password@localhost:5432/tagme'
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'tagme-secret-key-change-in-production';

// ==================== AUTHENTICATION ====================

// Register User
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, fullName, company } = req.body;
    
    // Check if user exists
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const result = await pool.query(
      'INSERT INTO users (email, password, full_name, company, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, full_name, role',
      [email, hashedPassword, fullName, company, 'customer']
    );
    
    res.status(201).json({ success: true, user: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    
    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        role: user.role,
        company: user.company
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ==================== ADMIN DASHBOARD ====================

// Get admin dashboard data
app.get('/api/admin/dashboard', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin only' });
    }
    
    // Total customers
    const customers = await pool.query('SELECT COUNT(*) as count FROM users WHERE role = $1', ['customer']);
    const totalCustomers = customers.rows[0].count;
    
    // Total scans (real tag taps, separate from visitors who left details)
    const scans = await pool.query('SELECT COUNT(*) as count FROM scans');
    const totalScans = scans.rows[0].count;
    
    // Total revenue
    const revenue = await pool.query('SELECT SUM(price) as total FROM subscriptions WHERE status = $1', ['active']);
    const totalRevenue = revenue.rows[0].total || 0;
    
    // Monthly revenue
    const monthlyRevenue = await pool.query(
      'SELECT SUM(price) as total FROM subscriptions WHERE status = $1 AND created_at > NOW() - INTERVAL \'30 days\'',
      ['active']
    );
    const monthRevenue = monthlyRevenue.rows[0].total || 0;
    
    // Scans this month
    const scansThisMonth = await pool.query(
      'SELECT COUNT(*) as count FROM scans WHERE scanned_at > NOW() - INTERVAL \'30 days\''
    );
    const monthScans = scansThisMonth.rows[0].count;
    
    // All customers with stats (uses each customer's most recent subscription row)
    const allCustomers = await pool.query(`
      SELECT 
        u.id, 
        u.full_name, 
        u.email, 
        s.tier,
        s.price,
        s.status,
        s.expires_at,
        (SELECT COUNT(*) FROM scans WHERE user_id = u.id) as total_scans
      FROM users u
      LEFT JOIN LATERAL (
        SELECT * FROM subscriptions
        WHERE subscriptions.user_id = u.id
        ORDER BY created_at DESC
        LIMIT 1
      ) s ON true
      WHERE u.role = 'customer'
      ORDER BY u.created_at DESC
    `);
    
    res.json({
      totalCustomers,
      totalScans,
      totalRevenue,
      monthRevenue,
      monthScans,
      customers: allCustomers.rows
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Subscriptions that are expired or expiring within 7 days (for the admin alerts panel)
app.get('/api/admin/subscriptions/alerts', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    // Uses each customer's most recent subscription row, in case of multiple over time
    const latestSubs = `
      SELECT DISTINCT ON (s.user_id) s.id, s.user_id, s.status, s.expires_at, u.full_name, u.email
      FROM subscriptions s
      JOIN users u ON u.id = s.user_id
      ORDER BY s.user_id, s.created_at DESC
    `;

    const expired = await pool.query(
      `SELECT * FROM (${latestSubs}) latest WHERE latest.expires_at < NOW() ORDER BY latest.expires_at ASC`
    );

    const expiringSoon = await pool.query(
      `SELECT * FROM (${latestSubs}) latest WHERE latest.expires_at >= NOW() AND latest.expires_at <= NOW() + INTERVAL '7 days' ORDER BY latest.expires_at ASC`
    );

    res.json({ expired: expired.rows, expiringSoon: expiringSoon.rows });
  } catch (error) {
    console.error('Error fetching subscription alerts:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== CUSTOMER DASHBOARD ====================

// Get customer dashboard
app.get('/api/customer/dashboard', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    // Get user info
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Get subscription info
    const subscription = await pool.query(
      'SELECT * FROM subscriptions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1',
      [userId]
    );
    
    // Total scans (real tag taps)
    const scans = await pool.query(
      'SELECT COUNT(*) as count FROM scans WHERE user_id = $1',
      [userId]
    );
    const totalScans = scans.rows[0].count;
    
    // Scans this month
    const monthScans = await pool.query(
      'SELECT COUNT(*) as count FROM scans WHERE user_id = $1 AND scanned_at > NOW() - INTERVAL \'30 days\'',
      [userId]
    );
    const scansThisMonth = monthScans.rows[0].count;
    
    // Scans this week
    const weekScans = await pool.query(
      'SELECT COUNT(*) as count FROM scans WHERE user_id = $1 AND scanned_at > NOW() - INTERVAL \'7 days\'',
      [userId]
    );
    const scansThisWeek = weekScans.rows[0].count;
    
    // New visitors this week (people who actually left their details)
    const newVisitors = await pool.query(
      'SELECT COUNT(*) as count FROM visitors WHERE user_id = $1 AND created_at > NOW() - INTERVAL \'7 days\'',
      [userId]
    );
    const newVisitorsCount = newVisitors.rows[0].count;
    
    res.json({
      user: user.rows[0],
      subscription: subscription.rows[0] || null,
      stats: {
        totalScans,
        scansThisMonth,
        scansThisWeek,
        newVisitors: newVisitorsCount
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== ANALYTICS ====================

// Get analytics data
app.get('/api/analytics/scans', verifyToken, async (req, res) => {
  try {
    const userId = req.user.role === 'admin' ? null : req.user.userId;
    
    // Last 30 days of actual tag taps (scans), not form-fill visitors
    let query = `
      SELECT 
        DATE(scanned_at) as date,
        COUNT(*) as count
      FROM scans
    `;
    
    if (userId) {
      query += ` WHERE user_id = $1`;
    }
    
    query += ` GROUP BY DATE(scanned_at) ORDER BY date DESC LIMIT 30`;
    
    const result = userId 
      ? await pool.query(query, [userId])
      : await pool.query(query);
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get visitor breakdown
app.get('/api/analytics/visitors', verifyToken, async (req, res) => {
  try {
    const userId = req.user.role === 'admin' ? null : req.user.userId;
    
    let query = 'SELECT * FROM visitors';
    if (userId) {
      query += ` WHERE user_id = $1`;
    }
    query += ` ORDER BY created_at DESC LIMIT 100`;
    
    const result = userId
      ? await pool.query(query, [userId])
      : await pool.query(query);
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== VISITORS ====================

// Get visitor contacts
app.get('/api/visitors', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const result = await pool.query(
      'SELECT * FROM visitors WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );
    
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add visitor (from landing page)
app.post('/api/visitors', async (req, res) => {
  try {
    const { userId, name, email, phone, company } = req.body;
    
    const result = await pool.query(
      'INSERT INTO visitors (user_id, name, email, phone, company) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [userId, name, email, phone, company]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Log a tag tap/scan (called the moment the landing page loads — no form required)
app.post('/api/scan', async (req, res) => {
  try {
    const { userId, latitude, longitude } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'userId is required' });
    }

    const result = await pool.query(
      'INSERT INTO scans (user_id, latitude, longitude) VALUES ($1, $2, $3) RETURNING *',
      [userId, latitude || null, longitude || null]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error logging scan:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get recent scans with location (for the map thumbnails on the dashboard)
app.get('/api/customer/analytics/scans', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const limit = parseInt(req.query.limit) || 10;

    const result = await pool.query(
      'SELECT id, latitude, longitude, scanned_at FROM scans WHERE user_id = $1 ORDER BY scanned_at DESC LIMIT $2',
      [userId, limit]
    );

    res.json({ scans: result.rows });
  } catch (error) {
    console.error('Error fetching scans:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== LANDING PAGE PIN PROTECTION ====================

// Public: check if this person's landing page requires a PIN before showing contact info
app.get('/api/pin-required/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await pool.query('SELECT landing_pin FROM users WHERE id = $1', [userId]);
    if (result.rows.length === 0) {
      return res.json({ required: false });
    }
    res.json({ required: !!result.rows[0].landing_pin });
  } catch (error) {
    console.error('Error checking pin requirement:', error);
    res.json({ required: false }); // fail open so a broken check never locks visitors out
  }
});

// Public: verify a PIN entered on the landing page
app.post('/api/verify-pin', async (req, res) => {
  try {
    const { userId, pin } = req.body;
    if (!userId || !pin) {
      return res.status(400).json({ valid: false, error: 'userId and pin are required' });
    }

    const result = await pool.query('SELECT landing_pin FROM users WHERE id = $1', [userId]);
    if (result.rows.length === 0 || !result.rows[0].landing_pin) {
      // No PIN set for this user - treat as valid so the page never gets stuck
      return res.json({ valid: true });
    }

    const isValid = await bcrypt.compare(pin, result.rows[0].landing_pin);
    res.json({ valid: isValid });
  } catch (error) {
    console.error('Error verifying pin:', error);
    res.status(500).json({ valid: false, error: error.message });
  }
});

// Authenticated: customer sets, changes, or removes their own landing page PIN
// Send { "pin": "1234" } to set/change it, or { "pin": "" } to remove protection entirely
app.put('/api/customer/settings/pin', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { pin } = req.body;

    if (pin === '' || pin === null || pin === undefined) {
      await pool.query('UPDATE users SET landing_pin = NULL WHERE id = $1', [userId]);
      return res.json({ success: true, protected: false });
    }

    if (!/^\d{4,6}$/.test(pin)) {
      return res.status(400).json({ error: 'PIN must be 4-6 digits' });
    }

    const hashedPin = await bcrypt.hash(pin, 10);
    await pool.query('UPDATE users SET landing_pin = $1 WHERE id = $2', [hashedPin, userId]);
    res.json({ success: true, protected: true });
  } catch (error) {
    console.error('Error setting pin:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// PASTE THIS ENTIRE SECTION INTO YOUR tagme-backend-server.js
// USES verifyToken (not authenticateToken) - MATCHES YOUR SERVER
// ============================================================================

/**
 * GET /api/admin/analytics/visitors
 * Get all visitors across all customers with pagination
 */
app.get('/api/admin/analytics/visitors', verifyToken, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    const sort = req.query.sort === 'oldest' ? 'ASC' : 'DESC';
    
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const totalResult = await pool.query(
      'SELECT COUNT(*) as count FROM visitors'
    );
    const total = parseInt(totalResult.rows[0].count);

    const result = await pool.query(
      `SELECT 
        v.id, 
        v.user_id, 
        v.name, 
        v.email, 
        v.phone, 
        v.company,
        v.created_at,
        u.full_name as customer_name
      FROM visitors v
      LEFT JOIN users u ON v.user_id = u.id
      ORDER BY v.created_at ${sort}
      LIMIT $1 OFFSET $2`,
      [limit, offset]
    );

    res.json({
      visitors: result.rows,
      total: total,
      hasMore: offset + limit < total
    });
  } catch (error) {
    console.error('Error fetching visitors:', error);
    res.status(500).json({ error: 'Failed to fetch visitors' });
  }
});

/**
 * GET /api/admin/analytics/visitors/by-date/:date
 */
app.get('/api/admin/analytics/visitors/by-date/:date', verifyToken, async (req, res) => {
  try {
    const { date } = req.params;
    
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
    }

    const result = await pool.query(
      `SELECT 
        v.id,
        v.user_id,
        v.name,
        v.email,
        v.phone,
        v.company,
        v.created_at,
        u.full_name as customer_name
      FROM visitors v
      LEFT JOIN users u ON v.user_id = u.id
      WHERE DATE(v.created_at) = $1
      ORDER BY v.created_at DESC`,
      [date]
    );

    res.json({
      date: date,
      count: result.rows.length,
      visitors: result.rows
    });
  } catch (error) {
    console.error('Error fetching visitors by date:', error);
    res.status(500).json({ error: 'Failed to fetch visitors' });
  }
});

/**
 * GET /api/admin/analytics/new-contacts
 */
app.get('/api/admin/analytics/new-contacts', verifyToken, async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const result = await pool.query(
      `SELECT 
        v.id,
        v.user_id,
        v.name,
        v.email,
        v.phone,
        v.company,
        v.created_at,
        u.full_name as customer_name
      FROM visitors v
      LEFT JOIN users u ON v.user_id = u.id
      WHERE v.created_at >= NOW() - INTERVAL '${days} days'
      ORDER BY v.created_at DESC`,
      []
    );

    res.json({
      contacts: result.rows,
      count: result.rows.length,
      period: `Last ${days} days`
    });
  } catch (error) {
    console.error('Error fetching new contacts:', error);
    res.status(500).json({ error: 'Failed to fetch contacts' });
  }
});

/**
 * GET /api/customer/analytics/visitors
 */
app.get('/api/customer/analytics/visitors', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    const sort = req.query.sort === 'oldest' ? 'ASC' : 'DESC';

    const totalResult = await pool.query(
      'SELECT COUNT(*) as count FROM visitors WHERE user_id = $1',
      [userId]
    );
    const total = parseInt(totalResult.rows[0].count);

    const result = await pool.query(
      `SELECT 
        id,
        name,
        email,
        phone,
        company,
        created_at
      FROM visitors
      WHERE user_id = $1
      ORDER BY created_at ${sort}
      LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );

    res.json({
      visitors: result.rows,
      total: total,
      hasMore: offset + limit < total
    });
  } catch (error) {
    console.error('Error fetching visitors:', error);
    res.status(500).json({ error: 'Failed to fetch visitors' });
  }
});

/**
 * GET /api/customer/analytics/visitors/by-date/:date
 */
app.get('/api/customer/analytics/visitors/by-date/:date', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { date } = req.params;
    
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
    }

    const result = await pool.query(
      `SELECT 
        id,
        name,
        email,
        phone,
        company,
        created_at
      FROM visitors
      WHERE user_id = $1 AND DATE(created_at) = $2
      ORDER BY created_at DESC`,
      [userId, date]
    );

    res.json({
      date: date,
      count: result.rows.length,
      visitors: result.rows
    });
  } catch (error) {
    console.error('Error fetching visitors by date:', error);
    res.status(500).json({ error: 'Failed to fetch visitors' });
  }
});

/**
 * GET /api/customer/analytics/new-contacts
 */
app.get('/api/customer/analytics/new-contacts', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const days = parseInt(req.query.days) || 7;

    const result = await pool.query(
      `SELECT 
        id,
        name,
        email,
        phone,
        company,
        created_at
      FROM visitors
      WHERE user_id = $1 AND created_at >= NOW() - INTERVAL '${days} days'
      ORDER BY created_at DESC`,
      [userId]
    );

    res.json({
      contacts: result.rows,
      count: result.rows.length,
      period: `Last ${days} days`
    });
  } catch (error) {
    console.error('Error fetching new contacts:', error);
    res.status(500).json({ error: 'Failed to fetch contacts' });
  }
});

/**
 * GET /api/customer/visitors/:visitorId
 */
app.get('/api/customer/visitors/:visitorId', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { visitorId } = req.params;

    const result = await pool.query(
      `SELECT 
        id,
        name,
        email,
        phone,
        company,
        created_at
      FROM visitors
      WHERE id = $1 AND user_id = $2`,
      [visitorId, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Visitor not found' });
    }

    res.json({ visitor: result.rows[0] });
  } catch (error) {
    console.error('Error fetching visitor:', error);
    res.status(500).json({ error: 'Failed to fetch visitor' });
  }
});

/**
 * DELETE /api/customer/visitors/:visitorId
 * A customer can only delete visitors that belong to them - scoped by user_id
 */
app.delete('/api/customer/visitors/:visitorId', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { visitorId } = req.params;

    const result = await pool.query(
      'DELETE FROM visitors WHERE id = $1 AND user_id = $2 RETURNING id',
      [visitorId, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Visitor not found' });
    }

    res.json({ success: true, deletedId: result.rows[0].id });
  } catch (error) {
    console.error('Error deleting visitor:', error);
    res.status(500).json({ error: 'Failed to delete visitor' });
  }
});

// ============================================================================
// END OF ENDPOINTS - app.listen() GOES BELOW THIS
// ============================================================================

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ status: 'TagMe Backend Running' });
});

// Start server
app.listen(port, () => {
  console.log(`TagMe Backend running on port ${port}`);
});

module.exports = app;
