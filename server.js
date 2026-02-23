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

// ============ SECURITY PACKAGES ============
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const helmet = require('helmet');
const xss = require('xss-clean');
const hpp = require('hpp');
const ipfilter = require('express-ipfilter').IpFilter;
const winston = require('winston');

const app = express();
const PORT = process.env.PORT || 3000;

// ============ LOGGER SETUP ============
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

// ============ DATABASE SETUP ============
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');
const STORES_FILE = path.join(DATA_DIR, 'stores.json');
const BLOCKED_FILE = path.join(DATA_DIR, 'blocked.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

[DATA_DIR, UPLOADS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

[USERS_FILE, PRODUCTS_FILE, STORES_FILE, BLOCKED_FILE].forEach(file => {
  if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify([]));
});

// ============ IP BLOCKING ============
let blockedIPs = [];
try {
  blockedIPs = JSON.parse(fs.readFileSync(BLOCKED_FILE)).map(b => b.ip);
} catch (e) {
  blockedIPs = [];
}

app.use(ipfilter(blockedIPs, { mode: 'deny', log: false }));

// ============ SECURITY MIDDLEWARE ============
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      imgSrc: ["'self'", "data:", "https://raw.githubusercontent.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Terlalu banyak request, coba lagi 15 menit lagi' }
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { error: 'Terlalu banyak percobaan login, coba 1 jam lagi' }
});

const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 50,
  delayMs: 500
});

app.use(xss());
app.use(hpp());

// ============ CUSTOM SCAN DETECTION ============
const suspiciousPaths = [
  '/wp-admin', '/wp-login', '/.env', '/config.php', 
  '/backup.zip', '/.git', '/admin', '/phpmyadmin', 
  '/xmlrpc.php', '/.well-known', '/server-status',
  '/wp-content', '/wp-includes', '/mysql', '/db'
];

app.use((req, res, next) => {
  if (suspiciousPaths.includes(req.path)) {
    const blocked = JSON.parse(fs.readFileSync(BLOCKED_FILE) || '[]');
    blocked.push({ ip: req.ip, path: req.path, timestamp: Date.now() });
    fs.writeFileSync(BLOCKED_FILE, JSON.stringify(blocked));
    
    logger.warn({ ip: req.ip, path: req.path, action: 'SUSPICIOUS_PATH' });
    return res.status(404).send('Not Found');
  }
  next();
});

// ============ STANDARD MIDDLEWARE ============
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/', limiter);
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use(speedLimiter);

// ============ SESSION ============
app.use(session({
  secret: process.env.SESSION_SECRET || 'rahasia-default',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: 'strict'
  },
  name: 'ricc.sid'
}));

// ============ PASSPORT ============
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(u => u.id === id);
    if (user) {
      const { password, ...userWithoutPassword } = user;
      done(null, userWithoutPassword);
    } else {
      done(null, null);
    }
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

// ============ MIDDLEWARE ============
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Silakan login dulu' });
}

function isProductOwner(req, res, next) {
  const { productId } = req.params;
  const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
  const product = products.find(p => p.id === productId);
  
  if (!product) return res.status(404).json({ error: 'Produk tidak ditemukan' });
  if (product.sellerId !== req.user.id) return res.status(403).json({ error: 'Anda tidak punya akses' });
  
  req.product = product;
  next();
}

// ============ INPUT VALIDATION ============
const dangerous = ['--', ';', '/*', '*/', 'select', 'insert', 'delete', 'drop', 'alter', 'exec'];
function validateInput(value) {
  if (typeof value === 'string') {
    for (const word of dangerous) {
      if (value.toLowerCase().includes(word.toLowerCase())) return false;
    }
  }
  return true;
}

app.use('/api/', (req, res, next) => {
  if (req.body) {
    for (let key in req.body) {
      if (!validateInput(req.body[key])) {
        logger.warn({ ip: req.ip, action: 'INVALID_INPUT', field: key });
        return res.status(400).json({ error: 'Input tidak valid' });
      }
    }
  }
  next();
});

// ============ BRUTE FORCE PROTECTION ============
let failedLogins = {}, failedRegisters = {};

app.post('/api/register', async (req, res) => {
  const ip = req.ip;
  if (!failedRegisters[ip]) failedRegisters[ip] = { count: 0, lastAttempt: Date.now() };
  
  if (Date.now() - failedRegisters[ip].lastAttempt > 3600000) failedRegisters[ip].count = 0;
  if (failedRegisters[ip].count >= 3) {
    return res.status(429).json({ error: 'Terlalu banyak percobaan register. Coba 1 jam lagi.' });
  }
  
  try {
    const { name, email, password, phone } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Semua field harus diisi' });
    if (password.length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter' });
    
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    if (users.find(u => u.email === email)) {
      failedRegisters[ip].count++;
      failedRegisters[ip].lastAttempt = Date.now();
      return res.status(400).json({ error: 'Email sudah terdaftar' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: crypto.randomBytes(16).toString('hex'),
      name, email, password: hashedPassword, phone: phone || '',
      role: 'user', balance: 0, store: null,
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
    };
    
    users.push(newUser);
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    failedRegisters[ip].count = 0;
    
    req.login(newUser, (err) => {
      if (err) return res.status(500).json({ error: 'Login gagal' });
      const { password, ...userWithoutPassword } = newUser;
      res.json({ success: true, user: userWithoutPassword });
    });
  } catch (error) {
    logger.error({ action: 'REGISTER_ERROR', error: error.message });
    res.status(500).json({ error: 'Gagal register' });
  }
});

app.post('/api/login', (req, res, next) => {
  const ip = req.ip;
  if (!failedLogins[ip]) failedLogins[ip] = { count: 0, lastAttempt: Date.now() };
  
  if (Date.now() - failedLogins[ip].lastAttempt > 3600000) failedLogins[ip].count = 0;
  if (failedLogins[ip].count >= 5) {
    return res.status(429).json({ error: 'Terlalu banyak percobaan. Coba 1 jam lagi.' });
  }
  
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      failedLogins[ip].count++;
      failedLogins[ip].lastAttempt = Date.now();
      logger.warn({ ip, action: 'FAILED_LOGIN', attempt: failedLogins[ip].count });
      return res.status(401).json({ error: 'Email atau password salah' });
    }
    
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.login(user, (err) => {
        if (err) return next(err);
        failedLogins[ip].count = 0;
        logger.info({ ip, userId: user.id, action: 'LOGIN_SUCCESS' });
        return res.json({ success: true, user });
      });
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

// ============ STORE & PRODUCT ROUTES ============
app.post('/api/create-store', isAuthenticated, async (req, res) => {
  try {
    const { storeName, storeDescription } = req.body;
    if (!storeName) return res.status(400).json({ error: 'Nama toko harus diisi' });
    
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const userIndex = users.findIndex(u => u.id === req.user.id);
    if (users[userIndex].store) return res.status(400).json({ error: 'Anda sudah punya toko' });
    
    const stores = JSON.parse(fs.readFileSync(STORES_FILE));
    if (stores.find(s => s.name === storeName)) return res.status(400).json({ error: 'Nama toko sudah digunakan' });
    
    const newStore = {
      id: crypto.randomBytes(16).toString('hex'),
      ownerId: req.user.id, name: storeName, description: storeDescription || '',
      products: [], balance: 0,
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
    };
    
    stores.push(newStore);
    fs.writeFileSync(STORES_FILE, JSON.stringify(stores, null, 2));
    
    users[userIndex].store = newStore.id;
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    
    logger.info({ userId: req.user.id, storeId: newStore.id, action: 'STORE_CREATED' });
    res.json({ success: true, store: newStore });
  } catch (error) {
    logger.error({ action: 'CREATE_STORE_ERROR', error: error.message });
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

// ============ FILE UPLOAD ============
const blockedExtensions = ['.php', '.phtml', '.php3', '.php4', '.php5', '.phps', '.cgi', '.pl', '.py', '.asp', '.aspx', '.exe', '.bat', '.sh', '.cmd'];
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userDir = path.join(UPLOADS_DIR, req.user.id);
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    const uniqueSuffix = crypto.randomBytes(16).toString('hex');
    cb(null, uniqueSuffix + '_' + safeName);
  }
});

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  if (blockedExtensions.includes(ext)) {
    logger.warn({ ip: req.ip, user: req.user.id, file: file.originalname });
    return cb(new Error('Ekstensi file tidak diizinkan'), false);
  }
  cb(null, true);
};

const upload = multer({ 
  storage, limits: { fileSize: 100 * 1024 * 1024, files: 10 }, fileFilter 
}).array('files', 10);

app.post('/api/products', isAuthenticated, (req, res) => {
  upload(req, res, async (err) => {
    if (err) return res.status(400).json({ error: 'Upload gagal: ' + err.message });
    
    try {
      const { title, description, price, category, tags } = req.body;
      if (!title || !description || !price) return res.status(400).json({ error: 'Data tidak lengkap' });
      
      const users = JSON.parse(fs.readFileSync(USERS_FILE));
      const user = users.find(u => u.id === req.user.id);
      if (!user.store) return res.status(400).json({ error: 'Buat toko dulu' });
      
      const stores = JSON.parse(fs.readFileSync(STORES_FILE));
      const store = stores.find(s => s.id === user.store);
      const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
      
      const newProduct = {
        id: crypto.randomBytes(16).toString('hex'),
        title, description, price: parseFloat(price), category: category || 'other',
        tags: tags ? tags.split(',').map(t => t.trim()) : [],
        sellerId: req.user.id, storeId: user.store, storeName: store.name,
        files: req.files ? req.files.map(f => ({
          filename: f.filename, originalName: f.originalname,
          size: f.size, mimetype: f.mimetype, path: f.path
        })) : [],
        views: 0, sales: 0,
        createdAt: new Date().toISOString(), updatedAt: new Date().toISOString()
      };
      
      products.push(newProduct);
      fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(products, null, 2));
      
      store.products.push(newProduct.id);
      fs.writeFileSync(STORES_FILE, JSON.stringify(stores, null, 2));
      
      logger.info({ userId: req.user.id, productId: newProduct.id, action: 'PRODUCT_UPLOADED' });
      res.json({ success: true, product: newProduct });
    } catch (error) {
      logger.error({ action: 'UPLOAD_ERROR', error: error.message });
      res.status(500).json({ error: 'Gagal upload' });
    }
  });
});

// ============ PRODUCT ROUTES ============
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

app.put('/api/products/:productId', isAuthenticated, isProductOwner, async (req, res) => {
  try {
    const { title, description, price, category, tags } = req.body;
    const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
    const productIndex = products.findIndex(p => p.id === req.params.productId);
    
    products[productIndex] = {
      ...products[productIndex],
      title: title || products[productIndex].title,
      description: description || products[productIndex].description,
      price: price ? parseFloat(price) : products[productIndex].price,
      category: category || products[productIndex].category,
      tags: tags ? tags.split(',').map(t => t.trim()) : products[productIndex].tags,
      updatedAt: new Date().toISOString()
    };
    
    fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(products, null, 2));
    res.json({ success: true, product: products[productIndex] });
  } catch (error) {
    res.status(500).json({ error: 'Gagal update produk' });
  }
});

app.delete('/api/products/:productId', isAuthenticated, isProductOwner, async (req, res) => {
  try {
    let products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
    products = products.filter(p => p.id !== req.params.productId);
    fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(products, null, 2));
    
    const stores = JSON.parse(fs.readFileSync(STORES_FILE));
    const storeIndex = stores.findIndex(s => s.id === req.product.storeId);
    stores[storeIndex].products = stores[storeIndex].products.filter(id => id !== req.params.productId);
    fs.writeFileSync(STORES_FILE, JSON.stringify(stores, null, 2));
    
    logger.info({ userId: req.user.id, productId: req.params.productId, action: 'PRODUCT_DELETED' });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Gagal hapus produk' });
  }
});

// ============ PAYMENT ============
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
          { name: 'GoPay', number: process.env.GOPAY_NUMBER || '+6281543343778' },
          { name: 'DANA', number: process.env.GOPAY_NUMBER || '+6281543343778' }
        ]
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Gagal buat pembayaran' });
  }
});

// ============ HEALTH CHECK ============
app.get('/health', (req, res) => {
  res.json({ status: 'OK', time: new Date().toISOString(), uptime: process.uptime() });
});

// ============ ERROR HANDLER ============
app.use((err, req, res, next) => {
  logger.error({ ip: req.ip, url: req.url, error: err.message });
  res.status(500).json({ error: 'Terjadi kesalahan internal' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint tidak ditemukan' });
});

// ============ START SERVER ============
app.listen(PORT, () => {
  console.log(`Ricc Marketing Place running on http://localhost:${PORT}`);
  console.log(`Security: Helmet, RateLimit, XSS, HPP, IPFilter, Validation, BruteForce`);
});
