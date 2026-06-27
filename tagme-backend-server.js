const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Log which database we're connecting to
console.log('DATABASE_URL exists:', !!process.env.DATABASE_URL);
console.log('PORT:', port);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection on startup
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('DATABASE CONNECTION FAILED:', err.message);
  } else {
    console.log('DATABASE CONNECTED SUCCESSFULLY at:', res.rows[0].now);
  }
});

const JWT_SECRET = process.env.JWT_SECRET || 'tagme-secret-key';

// Health check
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'TagMe Backend Running', database: 'connected' });
  } catch (err) {
    res.json({ status: 'TagMe Backend Running', database: 'disconnected', error: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('Login attempt for:', email);

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    console.log('Users found:', result.rows.length);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    console.log('User role:', user.role);
    console.log('Password hash exists:', !!user.password);

    const validPassword = await bcrypt.compare(password, user.password);
    console.log('Password valid:', validPassword);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

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
    console.error('LOGIN ERROR:', error.message);
    console.error('FULL ERROR:', error);
    res.status(500).json({ error: error.message });
  }
});

// Verify token middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Admin dashboard
app.get('/api/admin/dashboard', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });

    const customers = await pool.query("SELECT COUNT(*) as count FROM users WHERE role = 'customer'");
    const scans = await pool.query('SELECT COUNT(*) as count FROM visitors');
    const revenue = await pool.query("SELECT SUM(price) as total FROM subscriptions WHERE status = 'active'");
    const monthScans = await pool.query("SELECT COUNT(*) as count FROM visitors WHERE created_at > NOW() - INTERVAL '30 days'");
    const allCustomers = await pool.query(`
      SELECT u.id, u.full_name, u.email, s.tier, s.price, s.status,
        (SELECT COUNT(*) FROM visitors WHERE user_id = u.id) as total_scans
      FROM users u
      LEFT JOIN subscriptions s ON u.id = s.user_id
      WHERE u.role = 'customer'
      ORDER BY u.created_at DESC
    `);

    res.json({
      totalCustomers: customers.rows[0].count,
      totalScans: scans.rows[0].count,
      totalRevenue: revenue.rows[0].total || 0,
      monthRevenue: revenue.rows[0].total || 0,
      monthScans: monthScans.rows[0].count,
      customers: allCustomers.rows
    });
  } catch (error) {
    console.error('ADMIN DASHBOARD ERROR:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Customer dashboard
app.get('/api/customer/dashboard', verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const subscription = await pool.query('SELECT * FROM subscriptions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1', [userId]);
    const scans = await pool.query('SELECT COUNT(*) as count FROM visitors WHERE user_id = $1', [userId]);
    const monthScans = await pool.query("SELECT COUNT(*) as count FROM visitors WHERE user_id = $1 AND created_at > NOW() - INTERVAL '30 days'", [userId]);
    const weekScans = await pool.query("SELECT COUNT(*) as count FROM visitors WHERE user_id = $1 AND created_at > NOW() - INTERVAL '7 days'", [userId]);

    res.json({
      user: user.rows[0],
      subscription: subscription.rows[0] || null,
      stats: {
        totalScans: scans.rows[0].count,
        scansThisMonth: monthScans.rows[0].count,
        scansThisWeek: weekScans.rows[0].count,
        newVisitors: weekScans.rows[0].count
      }
    });
  } catch (error) {
    console.error('CUSTOMER DASHBOARD ERROR:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Analytics
app.get('/api/analytics/visitors', verifyToken, async (req, res) => {
  try {
    const userId = req.user.role === 'admin' ? null : req.user.userId;
    let query = 'SELECT * FROM visitors';
    if (userId) query += ` WHERE user_id = ${userId}`;
    query += ' ORDER BY created_at DESC LIMIT 100';
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('ANALYTICS ERROR:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Visitors
app.get('/api/visitors', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM visitors WHERE user_id = $1 ORDER BY created_at DESC', [req.user.userId]);
    res.json(result.rows);
  } catch (error) {
    console.error('VISITORS ERROR:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/visitors', async (req, res) => {
  try {
    const { userId, name, email, phone, company } = req.body;
    const result = await pool.query(
      'INSERT INTO visitors (user_id, name, email, phone, company) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [userId, name, email, phone, company]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('ADD VISITOR ERROR:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.listen(port, () => {
  console.log(`TagMe Backend running on port ${port}`);
});

module.exports = app;
