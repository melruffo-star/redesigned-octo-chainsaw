// server/routes/auth.js

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { authenticate } = require('../middleware/auth');

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
    if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    try {
        const existing = await User.findOne({ username });
        if (existing) {
            return res.status(409).json({ error: 'Username already taken.' });
        }

        const newUser = new User({ username, password });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully!' });
    } catch (error) {
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

    try {
        const user = await User.findOne({ username });
        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
        );
        res.status(200).json({ token });
    } catch (error) {
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
        res.status(500).json({ error: 'Failed to retrieve user.' });
    }
});

module.exports = router;
