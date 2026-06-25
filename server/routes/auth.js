const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const dayjs = require('dayjs');
const { run, get } = require('../db/database');
const { getJwtSecret } = require('../middleware/authMiddleware');

const router = express.Router();

function signToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    getJwtSecret(),
    { expiresIn: '7d' }
  );
}

router.post('/register', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    if (!username || username.trim().length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }

    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const normalized = username.trim().toLowerCase();
    const exists = await get('SELECT id FROM users WHERE username = ?', [normalized]);
    if (exists) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    const id = uuidv4();
    const passwordHash = await bcrypt.hash(password, 10);
    const now = dayjs().toISOString();

    await run(
      `INSERT INTO users (id, username, password_hash, created_at)
       VALUES (?, ?, ?, ?)`,
      [id, normalized, passwordHash, now]
    );

    await run(
      `INSERT INTO user_profiles (user_id, accent_color, theme, card_style, updated_at)
       VALUES (?, ?, ?, ?, ?)`,
      [id, '#2563eb', 'light', 'rounded', now]
    );

    const token = signToken({ id, username: normalized });

    return res.status(201).json({
      token,
      user: { id, username: normalized }
    });
  } catch (error) {
    return next(error);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const normalized = username.trim().toLowerCase();
    const user = await get('SELECT * FROM users WHERE username = ?', [normalized]);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = signToken(user);

    return res.json({
      token,
      user: { id: user.id, username: user.username }
    });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
