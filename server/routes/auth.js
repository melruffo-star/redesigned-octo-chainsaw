// server/routes/auth.js

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { authenticate } = require('../middleware/auth');

// Shared rate limiter for all auth endpoints (max 15 requests per 15 minutes per IP)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' },
});

router.use(authLimiter);

// Dummy hash used to maintain constant-time behavior when a user is not found,
// preventing username-enumeration via timing differences.
const DUMMY_HASH = '$2a$12$FeW6U0cZkfQH6yKBnbYnEOvxKDxkYVRwqhHJC.1Hk5YCl3dXLdLAe';

// ---------------------------------------------------------------------------
// Register — create a new user account
// ---------------------------------------------------------------------------
router.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }
    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Invalid input.' });
    }
    if (password.length < 8 || password.length > 128) {
        return res.status(400).json({ error: 'Password must be between 8 and 128 characters.' });
    }

    try {
        const existing = await User.findOne({ username: String(username) });
        if (existing) {
            return res.status(409).json({ error: 'Username already taken.' });
        }

        const newUser = new User({ username, password });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully!' });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'User registration failed.' });
    }
});

// ---------------------------------------------------------------------------
// Login — verify credentials and return a signed JWT
// ---------------------------------------------------------------------------
router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }
    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Invalid input.' });
    }

    try {
        const user = await User.findOne({ username: String(username) });

        // Always run a bcrypt comparison to prevent timing-based username enumeration.
        const hashToCompare = user ? user.password : DUMMY_HASH;
        const isMatch = await bcrypt.compare(password, hashToCompare);

        if (!user || !isMatch) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
        );
        res.status(200).json({ token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed.' });
    }
});

// ---------------------------------------------------------------------------
// Logout — stateless JWT: instruct the client to discard the token.
// For stricter revocation, maintain a server-side token blacklist (e.g. Redis).
// ---------------------------------------------------------------------------
router.post('/logout', authenticate, (req, res) => {
    res.status(200).json({ message: 'Logged out successfully.' });
});

// ---------------------------------------------------------------------------
// Current user — return the authenticated user's profile (no password)
// ---------------------------------------------------------------------------
router.get('/current', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }
        // toJSON() strips the password field (see User model)
        res.status(200).json(user);
    } catch (error) {
        console.error('Current user error:', error);
        res.status(500).json({ error: 'Failed to retrieve user.' });
    }
});

module.exports = router;
