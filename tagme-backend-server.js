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
    
    // Total scans
    const scans = await pool.query('SELECT COUNT(*) as count FROM visitors');
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
      'SELECT COUNT(*) as count FROM visitors WHERE created_at > NOW() - INTERVAL \'30 days\''
    );
    const monthScans = scansThisMonth.rows[0].count;
    
    // All customers with stats
    const allCustomers = await pool.query(`
      SELECT 
        u.id, 
        u.full_name, 
        u.email, 
        s.tier,
        s.price,
        s.status,
        (SELECT COUNT(*) FROM visitors WHERE user_id = u.id) as total_scans
      FROM users u
      LEFT JOIN subscriptions s ON u.id = s.user_id
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
    
    // Total scans
    const scans = await pool.query(
      'SELECT COUNT(*) as count FROM visitors WHERE user_id = $1',
      [userId]
    );
    const totalScans = scans.rows[0].count;
    
    // Scans this month
    const monthScans = await pool.query(
      'SELECT COUNT(*) as count FROM visitors WHERE user_id = $1 AND created_at > NOW() - INTERVAL \'30 days\'',
      [userId]
    );
    const scansThisMonth = monthScans.rows[0].count;
    
    // Scans this week
    const weekScans = await pool.query(
      'SELECT COUNT(*) as count FROM visitors WHERE user_id = $1 AND created_at > NOW() - INTERVAL \'7 days\'',
      [userId]
    );
    const scansThisWeek = weekScans.rows[0].count;
    
    // New visitors this week
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
    
    // Last 30 days scans
    let query = `
      SELECT 
        DATE(created_at) as date,
        COUNT(*) as count
      FROM visitors
    `;
    
    if (userId) {
      query += ` WHERE user_id = $1`;
    }
    
    query += ` GROUP BY DATE(created_at) ORDER BY date DESC LIMIT 30`;
    
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

// ============================================================================
// PASTE THIS ENTIRE SECTION INTO YOUR tagme-backend-server.js
// PASTE IT AFTER YOUR EXISTING ENDPOINTS AND BEFORE app.listen()
// ============================================================================

/**
 * GET /api/admin/analytics/visitors
 * Get all visitors across all customers with pagination
 */
app.get('/api/admin/analytics/visitors', authenticateToken, async (req, res) => {
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
        u.username as customer_name
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
app.get('/api/admin/analytics/visitors/by-date/:date', authenticateToken, async (req, res) => {
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
        u.username as customer_name
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
app.get('/api/admin/analytics/new-contacts', authenticateToken, async (req, res) => {
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
        u.username as customer_name
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
app.get('/api/customer/analytics/visitors', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
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
app.get('/api/customer/analytics/visitors/by-date/:date', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
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
app.get('/api/customer/analytics/new-contacts', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
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
app.get('/api/customer/visitors/:visitorId', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
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
