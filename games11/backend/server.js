const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());

/* ===== MySQL Pool ===== */
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',                // <-- change if needed
  password: 'Naga12345',   // <-- change to your MySQL password
  database: 'games11',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

/* ===== Helpers ===== */
async function getUserByPhone(phone) {
  const [rows] = await pool.query('SELECT * FROM users WHERE phone = ?', [phone]);
  return rows[0];
}

function makeOTP(len = 6) {
  return [...Array(len)].map(() => Math.floor(Math.random() * 10)).join('');
}

/* ===== Auth: Signup ===== */
app.post('/api/signup', async (req, res) => {
  try {
    const { phone, password, name, email } = req.body;
    if (!phone || !password) return res.status(400).json({ error: 'Phone & password required' });

    const exists = await getUserByPhone(phone);
    if (exists) return res.status(409).json({ error: 'Phone already registered' });

    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (phone, name, email, password_hash) VALUES (?, ?, ?, ?)',
      [phone, name || null, email || null, hash]
    );
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ===== Auth: Login with password ===== */
app.post('/api/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    const user = await getUserByPhone(phone);
    if (!user || !user.password_hash) return res.status(401).json({ error: 'Invalid phone or password' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid phone or password' });

    res.json({
      success: true,
      user: { id: user.id, phone: user.phone, name: user.name, wallet: user.wallet }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ===== OTP: request & verify (mock SMS – OTP is returned in response for demo) ===== */
app.post('/api/request-otp', async (req, res) => {
  try {
    const { phone } = req.body;
    let user = await getUserByPhone(phone);
    if (!user) {
      // auto-create a user shell for OTP-only flow (optional)
      await pool.query('INSERT INTO users (phone) VALUES (?)', [phone]);
      user = await getUserByPhone(phone);
    }
    const otp = makeOTP();
    const expires = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
    await pool.query('UPDATE users SET otp_code=?, otp_expires=? WHERE id=?', [otp, expires, user.id]);

    // In production, send via SMS. For demo we return it.
    res.json({ success: true, otp, message: 'OTP generated (demo returns OTP).' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/verify-otp', async (req, res) => {
  try {
    const { phone, otp } = req.body;
    const user = await getUserByPhone(phone);
    if (!user || !user.otp_code) return res.status(400).json({ error: 'No OTP requested' });

    const notExpired = user.otp_expires && new Date(user.otp_expires) > new Date();
    if (user.otp_code !== otp || !notExpired) return res.status(401).json({ error: 'Invalid or expired OTP' });

    // clear OTP after use
    await pool.query('UPDATE users SET otp_code=NULL, otp_expires=NULL WHERE id=?', [user.id]);
    res.json({
      success: true,
      user: { id: user.id, phone: user.phone, name: user.name, wallet: user.wallet }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ===== Forgot password: set new password ===== */
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { phone, newPassword } = req.body; // demo: set directly
    const user = await getUserByPhone(phone);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash=? WHERE id=?', [hash, user.id]);
    res.json({ success: true, message: 'Password updated' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ===== Wallet demo: add coins ===== */
app.post('/api/wallet/add', async (req, res) => {
  try {
    const { phone, amount } = req.body;
    const user = await getUserByPhone(phone);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const add = parseInt(amount, 10) || 0;
    await pool.query('UPDATE users SET wallet = wallet + ? WHERE id=?', [add, user.id]);
    const [rows] = await pool.query('SELECT wallet FROM users WHERE id=?', [user.id]);
    res.json({ success: true, wallet: rows[0].wallet });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ===== Dev seed (optional): creates a test user phone=9999999999 / password=123456 ===== */
app.post('/api/dev-seed', async (req, res) => {
  try {
    const phone = '9999999999';
    const name = 'Demo User';
    const pwd = '123456';
    const exists = await getUserByPhone(phone);
    if (!exists) {
      const hash = await bcrypt.hash(pwd, 10);
      await pool.query('INSERT INTO users (phone, name, password_hash, wallet) VALUES (?, ?, ?, ?)', [phone, name, hash, 500]);
    }
    res.json({ success: true, phone, password: pwd });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ===== Start ===== */
const PORT = 3000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
