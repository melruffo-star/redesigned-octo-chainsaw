require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');

// Fail fast if required secrets are not configured
if (!process.env.JWT_SECRET) {
    console.error('FATAL: JWT_SECRET environment variable is not set.');
    process.exit(1);
}

const authRoutes = require('./routes/auth');

const app = express();

app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);

// Connect to MongoDB and start the server
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/social-experiments';

mongoose
    .connect(MONGO_URI)
    .then(() => {
        console.log('Connected to MongoDB');
        app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    })
    .catch((err) => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });

module.exports = app;
