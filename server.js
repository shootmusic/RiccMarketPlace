const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ============ SESSION (PASTI INI YANG DIPAKE) ============
app.use(session({
    secret: process.env.SESSION_SECRET || 'rahasia-default',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    },
    name: 'ricc.sid'
}));

app.use(passport.initialize());
app.use(passport.session());

// Database setup
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
[USERS_FILE, PRODUCTS_FILE].forEach(f => {
    if (!fs.existsSync(f)) fs.writeFileSync(f, '[]');
});

// Passport
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    try {
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        const user = users.find(u => u.id === id);
        done(null, user || null);
    } catch (err) {
        done(err, null);
    }
});

passport.use(new LocalStrategy(
    { usernameField: 'email' },
    async (email, password, done) => {
        try {
            const users = JSON.parse(fs.readFileSync(USERS_FILE));
            const user = users.find(u => u.email === email);
            if (!user) return done(null, false, { message: 'Email tidak terdaftar' });
            
            const match = await bcrypt.compare(password, user.password);
            if (!match) return done(null, false, { message: 'Password salah' });
            
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

// ============ API ============
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Semua field harus diisi' });
        }
        
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        if (users.find(u => u.email === email)) {
            return res.status(400).json({ error: 'Email sudah terdaftar' });
        }
        
        const hashed = await bcrypt.hash(password, 10);
        const newUser = {
            id: crypto.randomBytes(16).toString('hex'),
            name, email, password: hashed,
            createdAt: new Date().toISOString()
        };
        
        users.push(newUser);
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        
        req.login(newUser, (err) => {
            if (err) return res.status(500).json({ error: 'Login gagal' });
            const { password, ...user } = newUser;
            res.json({ success: true, user });
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.status(401).json({ error: info?.message });
        
        req.login(user, (err) => {
            if (err) return next(err);
            const { password, ...userData } = user;
            res.json({ success: true, user: userData });
        });
    })(req, res, next);
});

app.post('/api/logout', (req, res) => {
    req.logout(() => {
        req.session.destroy(() => {
            res.clearCookie('ricc.sid');
            res.json({ success: true });
        });
    });
});

app.get('/api/me', (req, res) => {
    if (req.user) {
        const { password, ...user } = req.user;
        res.json({ user });
    } else {
        res.json({ user: null });
    }
});

app.get('/api/products', (req, res) => {
    try {
        res.json(JSON.parse(fs.readFileSync(PRODUCTS_FILE)));
    } catch {
        res.json([]);
    }
});

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
