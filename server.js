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

const app = express();
const PORT = process.env.PORT || 3000;

// ============ MIDDLEWARE ============
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'rahasia-default',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 hari
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// ============ DATABASE SETUP ============
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');
const STORES_FILE = path.join(DATA_DIR, 'stores.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Ensure directories exist
[DATA_DIR, UPLOADS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Initialize JSON files
[USERS_FILE, PRODUCTS_FILE, STORES_FILE].forEach(file => {
  if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify([]));
});

// ============ AUTHENTICATION ============
// Serialize user
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user
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

// Local strategy
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      const users = JSON.parse(fs.readFileSync(USERS_FILE));
      const user = users.find(u => u.email === email);
      
      if (!user) {
        return done(null, false, { message: 'Email tidak terdaftar' });
      }
      
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return done(null, false, { message: 'Password salah' });
      }
      
      const { password: _, ...userWithoutPassword } = user;
      return done(null, userWithoutPassword);
    } catch (error) {
      return done(error);
    }
  }
));

// Middleware untuk cek login
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: 'Silakan login dulu' });
}

// Middleware untuk cek kepemilikan produk
function isProductOwner(req, res, next) {
  const { productId } = req.params;
  const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
  const product = products.find(p => p.id === productId);
  
  if (!product) {
    return res.status(404).json({ error: 'Produk tidak ditemukan' });
  }
  
  if (product.sellerId !== req.user.id) {
    return res.status(403).json({ error: 'Anda tidak punya akses ke produk ini' });
  }
  
  req.product = product;
  next();
}

// ============ API AUTH ============
// Register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Semua field harus diisi' });
    }
    
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    
    // Cek email udah dipake belum
    if (users.find(u => u.email === email)) {
      return res.status(400).json({ error: 'Email sudah terdaftar' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Buat user baru
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
    
    // Auto login setelah register
    req.login(newUser, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Login gagal setelah register' });
      }
      const { password, ...userWithoutPassword } = newUser;
      res.json({ 
        success: true, 
        user: userWithoutPassword
      });
    });
    
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Gagal register' });
  }
});

// Login
app.post('/api/login', passport.authenticate('local'), (req, res) => {
  res.json({ 
    success: true, 
    user: req.user 
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: 'Gagal logout' });
    }
    res.json({ success: true });
  });
});

// Get current user
app.get('/api/me', (req, res) => {
  if (req.user) {
    res.json({ user: req.user });
  } else {
    res.json({ user: null });
  }
});

// ============ API STORE ============
// Buat toko
app.post('/api/create-store', isAuthenticated, async (req, res) => {
  try {
    const { storeName, storeDescription } = req.body;
    
    if (!storeName) {
      return res.status(400).json({ error: 'Nama toko harus diisi' });
    }
    
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const userIndex = users.findIndex(u => u.id === req.user.id);
    
    if (users[userIndex].store) {
      return res.status(400).json({ error: 'Anda sudah punya toko' });
    }
    
    const stores = JSON.parse(fs.readFileSync(STORES_FILE));
    
    // Cek nama toko udah dipake belum
    if (stores.find(s => s.name === storeName)) {
      return res.status(400).json({ error: 'Nama toko sudah digunakan' });
    }
    
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
    
    // Update user dengan store id
    users[userIndex].store = newStore.id;
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    
    res.json({ 
      success: true, 
      store: newStore 
    });
    
  } catch (error) {
    console.error('Create store error:', error);
    res.status(500).json({ error: 'Gagal buat toko' });
  }
});

// Get store by user
app.get('/api/my-store', isAuthenticated, (req, res) => {
  try {
    const stores = JSON.parse(fs.readFileSync(STORES_FILE));
    const store = stores.find(s => s.ownerId === req.user.id);
    
    if (!store) {
      return res.json({ store: null });
    }
    
    res.json({ store });
    
  } catch (error) {
    console.error('Get store error:', error);
    res.status(500).json({ error: 'Gagal ambil data toko' });
  }
});

// ============ API PRODUCTS ============
// Upload produk (hanya untuk seller yang punya toko)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userDir = path.join(UPLOADS_DIR, req.user.id);
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = crypto.randomBytes(16).toString('hex');
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, true)
}).array('files', 10);

app.post('/api/products', isAuthenticated, (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ error: 'Upload gagal: ' + err.message });
    }
    
    try {
      const { title, description, price, category, tags } = req.body;
      
      if (!title || !description || !price) {
        return res.status(400).json({ error: 'Data produk tidak lengkap' });
      }
      
      // Cek user punya toko
      const users = JSON.parse(fs.readFileSync(USERS_FILE));
      const user = users.find(u => u.id === req.user.id);
      
      if (!user.store) {
        return res.status(400).json({ error: 'Anda harus buat toko dulu' });
      }
      
      const stores = JSON.parse(fs.readFileSync(STORES_FILE));
      const store = stores.find(s => s.id === user.store);
      
      const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
      
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
      
      // Update store dengan product id
      store.products.push(newProduct.id);
      fs.writeFileSync(STORES_FILE, JSON.stringify(stores, null, 2));
      
      res.json({ 
        success: true, 
        product: newProduct 
      });
      
    } catch (error) {
      console.error('Upload product error:', error);
      res.status(500).json({ error: 'Gagal upload produk' });
    }
  });
});

// Get all products (public)
app.get('/api/products', (req, res) => {
  try {
    const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: 'Gagal load products' });
  }
});

// Get products by store
app.get('/api/products/store/:storeId', (req, res) => {
  try {
    const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
    const storeProducts = products.filter(p => p.storeId === req.params.storeId);
    res.json(storeProducts);
  } catch (error) {
    res.status(500).json({ error: 'Gagal load products' });
  }
});

// Get single product (public)
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

// Update product (hanya pemilik)
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
    
    res.json({ 
      success: true, 
      product: products[productIndex] 
    });
    
  } catch (error) {
    console.error('Update product error:', error);
    res.status(500).json({ error: 'Gagal update produk' });
  }
});

// Delete product (hanya pemilik)
app.delete('/api/products/:productId', isAuthenticated, isProductOwner, async (req, res) => {
  try {
    let products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
    products = products.filter(p => p.id !== req.params.productId);
    fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(products, null, 2));
    
    // Hapus dari store
    const stores = JSON.parse(fs.readFileSync(STORES_FILE));
    const storeIndex = stores.findIndex(s => s.id === req.product.storeId);
    stores[storeIndex].products = stores[storeIndex].products.filter(id => id !== req.params.productId);
    fs.writeFileSync(STORES_FILE, JSON.stringify(stores, null, 2));
    
    res.json({ success: true });
    
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json({ error: 'Gagal hapus produk' });
  }
});

// ============ PAYMENT MANUAL ============
app.post('/api/create-manual-payment', (req, res) => {
  try {
    const { productId, paymentMethod } = req.body;
    
    const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
    const product = products.find(p => p.id === productId);
    
    if (!product) {
      return res.status(404).json({ error: 'Produk tidak ditemukan' });
    }
    
    const paymentInfo = {
      product: product.title,
      price: product.price,
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
    };
    
    res.json({ 
      success: true, 
      payment: paymentInfo 
    });
    
  } catch (error) {
    console.error('Payment error:', error);
    res.status(500).json({ error: 'Gagal buat pembayaran' });
  }
});

// ============ START SERVER ============
app.listen(PORT, () => {
  console.log(`Ricc Marketing Place running on http://localhost:${PORT}`);
  console.log(`Server started at: ${new Date().toLocaleString()}`);
});
