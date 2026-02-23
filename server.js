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
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();

// ============ FIX TRUST PROXY UNTUK RAILWAY ============
app.set('trust proxy', 1);

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

// Ensure directories exist
[DATA_DIR, UPLOADS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Initialize JSON files
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

// ============ RATE LIMITING FIX IPV4/IPV6 ============
const getClientIp = (req) => {
  let clientIp = req.ip;
  
  // Handle IPv6 localhost (::1) and IPv6-mapped IPv4 addresses
  if (clientIp && clientIp.includes(':')) {
    // If it's IPv6 localhost, return '127.0.0.1' for consistency
    if (clientIp === '::1') {
      return '127.0.0.1';
    }
    // If it's IPv6-mapped IPv4 (::ffff:192.168.1.1), extract the IPv4 part
    if (clientIp.startsWith('::ffff:')) {
      return clientIp.substring(7);
    }
  }
  
  return clientIp || req.connection.remoteAddress || '0.0.0.0';
};

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 100, // max 100 request per IP
  message: { error: 'Terlalu banyak request, coba lagi 15 menit lagi' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIp
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 jam
  max: 5, // max 5 percobaan login
  message: { error: 'Terlalu banyak percobaan login, coba 1 jam lagi' },
  keyGenerator: getClientIp
});

const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 50,
  delayMs: 500,
  keyGenerator: getClientIp
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
    try {
      const blocked = JSON.parse(fs.readFileSync(BLOCKED_FILE) || '[]');
      blocked.push({ ip: getClientIp(req), path: req.path, timestamp: Date.now() });
      fs.writeFileSync(BLOCKED_FILE, JSON.stringify(blocked));
      
      logger.warn({ ip: getClientIp(req), path: req.path, action: 'SUSPICIOUS_PATH' });
    } catch (e) {
      // Ignore file write errors
    }
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
  store: new SQLiteStore({ 
    db: 'sessions.db', 
    dir: DATA_DIR,
    concurrentDB: true
  }),
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
        logger.warn({ ip: getClientIp(req), action: 'INVALID_INPUT', field: key });
        return res.status(400).json({ error: 'Input tidak valid' });
      }
    }
  }
  next();
});

// ============ BRUTE FORCE PROTECTION ============
let failedLogins = {};
let failedRegisters = {};

// Clean up old entries every hour
setInterval(() => {
  const oneHourAgo = Date.now() - 3600000;
  for (let ip in failedLogins) {
    if (failedLogins[ip].lastAttempt < oneHourAgo) {
      delete failedLogins[ip];
    }
  }
  for (let ip in failedRegisters) {
    if (failedRegisters[ip].lastAttempt < oneHourAgo) {
      delete failedRegisters[ip];
    }
  }
}, 3600000);

// ============ API ROUTES ============

// Register
app.post('/api/register', async (req, res) => {
  const ip = getClientIp(req);
  
  // Initialize failedRegisters for this IP if not exists
  if (!failedRegisters[ip]) {
    failedRegisters[ip] = { count: 0, lastAttempt: Date.now() };
  }
  
  // Reset count if last attempt was more than 1 hour ago
  if (Date.now() - failedRegisters[ip].lastAttempt > 3600000) {
    failedRegisters[ip].count = 0;
  }
  
  // Check if too many attempts
  if (failedRegisters[ip].count >= 3) {
    return res.status(429).json({ error: 'Terlalu banyak percobaan register. Coba 1 jam lagi.' });
  }
  
  try {
    const { name, email, password, phone } = req.body;
    
    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Semua field harus diisi' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password minimal 6 karakter' });
    }
    
    // Read users file
    let users = [];
    try {
      users = JSON.parse(fs.readFileSync(USERS_FILE));
    } catch (e) {
      users = [];
    }
    
    // Check if email already exists
    if (users.find(u => u.email === email)) {
      failedRegisters[ip].count++;
      failedRegisters[ip].lastAttempt = Date.now();
      return res.status(400).json({ error: 'Email sudah terdaftar' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create new user
    const newUser = {
      id: crypto.randomBytes(16).toString('hex'),
      name,
      email,
      password: hashedPassword,
      phone: phone || '',
      role: 'user',
      balance: 0,
      store: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    users.push(newUser);
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    
    // Reset counter on success
    failedRegisters[ip].count = 0;
    
    // Auto login after register
    req.login(newUser, (err) => {
      if (err) {
        logger.error({ action: 'AUTO_LOGIN_ERROR', error: err.message });
        return res.status(500).json({ error: 'Registrasi berhasil tapi gagal login otomatis' });
      }
      
      const { password, ...userWithoutPassword } = newUser;
      logger.info({ ip, userId: newUser.id, action: 'REGISTER_SUCCESS' });
      res.json({ success: true, user: userWithoutPassword });
    });
    
  } catch (error) {
    logger.error({ action: 'REGISTER_ERROR', error: error.message, stack: error.stack });
    res.status(500).json({ error: 'Gagal register: ' + error.message });
  }
});

// Login
app.post('/api/login', (req, res, next) => {
  const ip = getClientIp(req);
  
  // Initialize failedLogins for this IP if not exists
  if (!failedLogins[ip]) {
    failedLogins[ip] = { count: 0, lastAttempt: Date.now() };
  }
  
  // Reset count if last attempt was more than 1 hour ago
  if (Date.now() - failedLogins[ip].lastAttempt > 3600000) {
    failedLogins[ip].count = 0;
  }
  
  // Check if too many attempts
  if (failedLogins[ip].count >= 5) {
    return res.status(429).json({ error: 'Terlalu banyak percobaan login. Coba 1 jam lagi.' });
  }
  
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      logger.error({ ip, action: 'LOGIN_ERROR', error: err.message });
      return next(err);
    }
    
    if (!user) {
      failedLogins[ip].count++;
      failedLogins[ip].lastAttempt = Date.now();
      
      logger.warn({ ip, action: 'FAILED_LOGIN', attempt: failedLogins[ip].count });
      return res.status(401).json({ error: info?.message || 'Email atau password salah' });
    }
    
    // Regenerate session for security
    req.session.regenerate((err) => {
      if (err) {
        logger.error({ ip, action: 'SESSION_REGENERATE_ERROR', error: err.message });
        return next(err);
      }
      
      req.login(user, (err) => {
        if (err) {
          logger.error({ ip, action: 'LOGIN_AFTER_REGENERATE_ERROR', error: err.message });
          return next(err);
        }
        
        // Reset counter on success
        failedLogins[ip].count = 0;
        
        logger.info({ ip, userId: user.id, action: 'LOGIN_SUCCESS' });
        return res.json({ success: true, user });
      });
    });
  })(req, res, next);
});

// Logout
app.post('/api/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      logger.error({ action: 'LOGOUT_ERROR', error: err.message });
      return res.status(500).json({ error: 'Gagal logout' });
    }
    
    req.session.destroy((err) => {
      if (err) {
        logger.error({ action: 'SESSION_DESTROY_ERROR', error: err.message });
        return res.status(500).json({ error: 'Gagal destroy session' });
      }
      
      res.clearCookie('ricc.sid');
      logger.info({ ip: getClientIp(req), action: 'LOGOUT_SUCCESS' });
      res.json({ success: true });
    });
  });
});

// Get current user
app.get('/api/me', (req, res) => {
  res.json({ user: req.user || null });
});

// Debug endpoint (temporary, remove in production)
app.get('/api/debug/users', (req, res) => {
  try {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    res.json({ 
      count: users.length, 
      users: users.map(u => ({ 
        id: u.id, 
        name: u.name, 
        email: u.email,
        hasStore: !!u.store
      }))
    });
  } catch (e) {
    res.json({ error: e.message });
  }
});

// Create store
app.post('/api/create-store', isAuthenticated, async (req, res) => {
  try {
    const { storeName, storeDescription } = req.body;
    if (!storeName) {
      return res.status(400).json({ error: 'Nama toko harus diisi' });
    }
    
    // Read users
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const userIndex = users.findIndex(u => u.id === req.user.id);
    
    if (users[userIndex].store) {
      return res.status(400).json({ error: 'Anda sudah punya toko' });
    }
    
    // Read stores
    const stores = JSON.parse(fs.readFileSync(STORES_FILE));
    if (stores.find(s => s.name.toLowerCase() === storeName.toLowerCase())) {
      return res.status(400).json({ error: 'Nama toko sudah digunakan' });
    }
    
    // Create new store
    const newStore = {
      id: crypto.randomBytes(16).toString('hex'),
      ownerId: req.user.id,
      name: storeName,
      description: storeDescription || '',
      products: [],
      balance: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    stores.push(newStore);
    fs.writeFileSync(STORES_FILE, JSON.stringify(stores, null, 2));
    
    // Update user with store id
    users[userIndex].store = newStore.id;
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    
    logger.info({ userId: req.user.id, storeId: newStore.id, action: 'STORE_CREATED' });
    res.json({ success: true, store: newStore });
    
  } catch (error) {
    logger.error({ action: 'CREATE_STORE_ERROR', error: error.message });
    res.status(500).json({ error: 'Gagal buat toko' });
  }
});

// Get my store
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
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    // Sanitize filename
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    const uniqueSuffix = crypto.randomBytes(16).toString('hex');
    cb(null, uniqueSuffix + '_' + safeName);
  }
});

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  if (blockedExtensions.includes(ext)) {
    logger.warn({ ip: getClientIp(req), user: req.user?.id, file: file.originalname, action: 'BLOCKED_EXTENSION' });
    return cb(new Error('Ekstensi file tidak diizinkan'), false);
  }
  cb(null, true);
};

const upload = multer({ 
  storage, 
  limits: { 
    fileSize: 100 * 1024 * 1024, // 100MB
    files: 10 
  }, 
  fileFilter 
}).array('files', 10);

// Upload product
app.post('/api/products', isAuthenticated, (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      logger.warn({ userId: req.user?.id, action: 'UPLOAD_ERROR', error: err.message });
      return res.status(400).json({ error: 'Upload gagal: ' + err.message });
    }
    
    try {
      const { title, description, price, category, tags } = req.body;
      
      if (!title || !description || !price) {
        return res.status(400).json({ error: 'Data produk tidak lengkap' });
      }
      
      // Check if user has store
      const users = JSON.parse(fs.readFileSync(USERS_FILE));
      const user = users.find(u => u.id === req.user.id);
      if (!user.store) {
        return res.status(400).json({ error: 'Anda harus buat toko dulu' });
      }
      
      // Get store
      const stores = JSON.parse(fs.readFileSync(STORES_FILE));
      const store = stores.find(s => s.id === user.store);
      if (!store) {
        return res.status(400).json({ error: 'Toko tidak ditemukan' });
      }
      
      // Read products
      const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
      
      // Create new product
      const newProduct = {
        id: crypto.randomBytes(16).toString('hex'),
        title,
        description,
        price: parseFloat(price),
        category: category || 'other',
        tags: tags ? tags.split(',').map(t => t.trim()) : [],
        sellerId: req.user.id,
        storeId: user.store,
        storeName: store.name,
        files: req.files ? req.files.map(f => ({
          filename: f.filename,
          originalName: f.originalname,
          size: f.size,
          mimetype: f.mimetype,
          path: f.path
        })) : [],
        views: 0,
        sales: 0,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      
      products.push(newProduct);
      fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(products, null, 2));
      
      // Update store with product id
      store.products.push(newProduct.id);
      fs.writeFileSync(STORES_FILE, JSON.stringify(stores, null, 2));
      
      logger.info({ 
        userId: req.user.id, 
        storeId: user.store, 
        productId: newProduct.id, 
        action: 'PRODUCT_UPLOADED' 
      });
      
      res.json({ success: true, product: newProduct });
      
    } catch (error) {
      logger.error({ action: 'UPLOAD_PRODUCT_ERROR', error: error.message });
      res.status(500).json({ error: 'Gagal upload produk' });
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
    const storeProducts = products.filter(p => p.storeId === req.params.storeId);
    res.json(storeProducts);
  } catch (error) {
    res.status(500).json({ error: 'Gagal load products' });
  }
});

app.get('/api/products/:id', (req, res) => {
  try {
    const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
    const product = products.find(p => p.id === req.params.id);
    
    if (!product) {
      return res.status(404).json({ error: 'Produk tidak ditemukan' });
    }
    
    // Increment views
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
    // Read products
    let products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
    products = products.filter(p => p.id !== req.params.productId);
    fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(products, null, 2));
    
    // Update store
    const stores = JSON.parse(fs.readFileSync(STORES_FILE));
    const storeIndex = stores.findIndex(s => s.id === req.product.storeId);
    if (storeIndex !== -1) {
      stores[storeIndex].products = stores[storeIndex].products.filter(id => id !== req.params.productId);
      fs.writeFileSync(STORES_FILE, JSON.stringify(stores, null, 2));
    }
    
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
    
    if (!product) {
      return res.status(404).json({ error: 'Produk tidak ditemukan' });
    }
    
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
        ],
        instructions: 'Transfer sesuai total, kirim bukti ke Telegram/Email'
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Gagal buat pembayaran' });
  }
});

// ============ HEALTH CHECK ============
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    time: new Date().toISOString(), 
    uptime: process.uptime(),
    ip: getClientIp(req)
  });
});

// ============ ERROR HANDLER ============
app.use((err, req, res, next) => {
  logger.error({ 
    ip: getClientIp(req), 
    url: req.url, 
    error: err.message, 
    stack: err.stack 
  });
  res.status(500).json({ error: 'Terjadi kesalahan internal' });
});

// ============ 404 HANDLER ============
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint tidak ditemukan' });
});

// ============ START SERVER ============
app.listen(PORT, () => {
  console.log(`Ricc Marketing Place running on http://localhost:${PORT}`);
  console.log(`Server started at: ${new Date().toLocaleString()}`);
  console.log(`Security: Helmet, RateLimit, XSS, HPP, IPFilter, Validation, BruteForce`);
  console.log(`Trust proxy: ENABLED (fix for Railway)`);
  console.log(`Session Store: SQLite (production ready)`);
  console.log(`IP Handler: IPv4/IPv6 compatible`);
});
