const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
require('dotenv').config();

const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const slowDown = require('express-slow-down');
const helmet = require('helmet');
const xss = require('xss-clean');
const hpp = require('hpp');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// Key generator
const getClientKey = (req) => {
    return ipKeyGenerator(req.ip || req.connection.remoteAddress || '0.0.0.0');
};

// Rate limiter
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: 'Terlalu banyak request' },
    keyGenerator: getClientKey,
    validate: { keyGeneratorIpFallback: false, delayMs: false }
});

const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    message: { error: 'Terlalu banyak percobaan' },
    keyGenerator: getClientKey,
    validate: { keyGeneratorIpFallback: false }
});

// Middleware
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(xss());
app.use(hpp());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api/', limiter);
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);

// ============ SESSION FIX - TANPA SQLITE3 ============
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
const STORES_FILE = path.join(DATA_DIR, 'stores.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

[DATA_DIR, UPLOADS_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

[USERS_FILE, PRODUCTS_FILE, STORES_FILE].forEach(file => {
    if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify([]));
});

// Passport
passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
    try {
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        const user = users.find(u => u.id === id);
        if (user) {
            const { password, ...userWithoutPassword } = user;
            done(null, userWithoutPassword);
        } else done(null, null);
    } catch (error) {
        done(error, null);
    }
});

passport.use(new LocalStrategy(
    { usernameField: 'email' },
    async (email, password, done) => {
        try {
            const users = JSON.parse(fs.readFileSync(USERS_FILE));
            const user = users.find(u => u.email === email);
            if (!user) return done(null, false, { message: 'Email tidak terdaftar' });
            
            const isValid = await bcrypt.compare(password, user.password);
            if (!isValid) return done(null, false, { message: 'Password salah' });
            
            const { password: _, ...userWithoutPassword } = user;
            return done(null, userWithoutPassword);
        } catch (error) {
            return done(error);
        }
    }
));

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.status(401).json({ error: 'Silakan login dulu' });
}

// API Routes
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;
        if (!name || !email || !password) return res.status(400).json({ error: 'Semua field harus diisi' });
        if (password.length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter' });
        
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        if (users.find(u => u.email === email)) return res.status(400).json({ error: 'Email sudah terdaftar' });
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: crypto.randomBytes(16).toString('hex'),
            name, email, password: hashedPassword, phone: phone || '',
            role: 'user', balance: 0, store: null, createdAt: new Date().toISOString()
        };
        
        users.push(newUser);
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        
        req.login(newUser, (err) => {
            if (err) return res.status(500).json({ error: 'Registrasi berhasil tapi gagal login otomatis' });
            const { password, ...userWithoutPassword } = newUser;
            res.json({ success: true, user: userWithoutPassword });
        });
    } catch (error) {
        res.status(500).json({ error: 'Gagal register' });
    }
});

app.post('/api/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.status(401).json({ error: info?.message || 'Email atau password salah' });
        
        req.login(user, (err) => {
            if (err) return next(err);
            return res.json({ success: true, user });
        });
    })(req, res, next);
});

app.post('/api/logout', (req, res) => {
    req.logout((err) => {
        if (err) return res.status(500).json({ error: 'Gagal logout' });
        req.session.destroy((err) => {
            if (err) return res.status(500).json({ error: 'Gagal destroy session' });
            res.clearCookie('ricc.sid');
            res.json({ success: true });
        });
    });
});

app.get('/api/me', (req, res) => {
    res.json({ user: req.user || null });
});

app.get('/api/products', (req, res) => {
    try {
        const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
        res.json(products);
    } catch (error) {
        res.status(500).json({ error: 'Gagal load products' });
    }
});

app.get('/api/products/store/:storeId', (req, res) => {
    try {
        const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
        res.json(products.filter(p => p.storeId === req.params.storeId));
    } catch (error) {
        res.status(500).json({ error: 'Gagal load products' });
    }
});

app.get('/api/products/:id', (req, res) => {
    try {
        const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
        const product = products.find(p => p.id === req.params.id);
        if (!product) return res.status(404).json({ error: 'Produk tidak ditemukan' });
        
        product.views = (product.views || 0) + 1;
        fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(products, null, 2));
        res.json(product);
    } catch (error) {
        res.status(500).json({ error: 'Gagal load product' });
    }
});

app.post('/api/create-store', isAuthenticated, async (req, res) => {
    try {
        const { storeName, storeDescription } = req.body;
        if (!storeName) return res.status(400).json({ error: 'Nama toko harus diisi' });
        
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        const userIndex = users.findIndex(u => u.id === req.user.id);
        if (users[userIndex].store) return res.status(400).json({ error: 'Anda sudah punya toko' });
        
        const stores = JSON.parse(fs.readFileSync(STORES_FILE));
        if (stores.find(s => s.name.toLowerCase() === storeName.toLowerCase())) {
            return res.status(400).json({ error: 'Nama toko sudah digunakan' });
        }
        
        const newStore = {
            id: crypto.randomBytes(16).toString('hex'),
            ownerId: req.user.id, name: storeName, description: storeDescription || '',
            products: [], balance: 0, createdAt: new Date().toISOString()
        };
        
        stores.push(newStore);
        fs.writeFileSync(STORES_FILE, JSON.stringify(stores, null, 2));
        
        users[userIndex].store = newStore.id;
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        
        res.json({ success: true, store: newStore });
    } catch (error) {
        res.status(500).json({ error: 'Gagal buat toko' });
    }
});

app.get('/api/my-store', isAuthenticated, (req, res) => {
    try {
        const stores = JSON.parse(fs.readFileSync(STORES_FILE));
        const store = stores.find(s => s.ownerId === req.user.id);
        res.json({ store: store || null });
    } catch (error) {
        res.status(500).json({ error: 'Gagal ambil data toko' });
    }
});

app.post('/api/create-manual-payment', (req, res) => {
    try {
        const { productId } = req.body;
        const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
        const product = products.find(p => p.id === productId);
        if (!product) return res.status(404).json({ error: 'Produk tidak ditemukan' });
        
        res.json({
            success: true,
            payment: {
                product: product.title,
                priceRupiah: product.price * 1000000,
                bankTransfer: [
                    { bank: 'BCA', account: '1234567890', name: 'RICC' },
                    { bank: 'Mandiri', account: '0987654321', name: 'RICC' }
                ],
                ewallet: [
                    { name: 'GoPay', number: process.env.GOPAY_NUMBER || '+6281543343778' }
                ]
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Gagal buat pembayaran' });
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'OK', uptime: process.uptime() });
});

app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint tidak ditemukan' });
});

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Terjadi kesalahan internal' });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Ricc Marketing Place running on port ${PORT}`);
    console.log(`🔒 MemoryStore active (no SQLite)`);
});
