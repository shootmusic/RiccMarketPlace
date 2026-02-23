const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const morgan = require('morgan');
const crypto = require('crypto');
const { Web3 } = require('web3');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Database (JSON files)
const DATA_DIR = path.join(__dirname, 'data');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SALES_FILE = path.join(DATA_DIR, 'sales.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Ensure directories exist
[DATA_DIR, UPLOADS_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// Initialize JSON files
[PRODUCTS_FILE, USERS_FILE, SALES_FILE].forEach(file => {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(file, JSON.stringify([]));
    }
});

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(UPLOADS_DIR, req.body.seller || 'anonymous');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = crypto.randomBytes(16).toString('hex');
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
    fileFilter: (req, file, cb) => {
        // Allow all file types
        cb(null, true);
    }
});

// Web3 integration
const web3 = new Web3(process.env.WEB3_PROVIDER || 'http://localhost:8545');

// API Routes

// Get all products
app.get('/api/products', (req, res) => {
    try {
        const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
        res.json(products);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load products' });
    }
});

// Get single product
app.get('/api/products/:id', (req, res) => {
    try {
        const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
        const product = products.find(p => p.id === req.params.id);
        
        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        // Increment views
        product.views = (product.views || 0) + 1;
        fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(products, null, 2));
        
        res.json(product);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load product' });
    }
});

// Upload product
app.post('/api/upload', upload.array('files', 10), (req, res) => {
    try {
        const { title, description, price, category, tags, seller } = req.body;
        const files = req.files;
        
        if (!title || !description || !price || !seller) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
        
        const newProduct = {
            id: crypto.randomBytes(16).toString('hex'),
            title,
            description,
            price: parseFloat(price),
            category,
            tags: tags ? tags.split(',').map(t => t.trim()) : [],
            seller,
            files: files.map(f => ({
                filename: f.filename,
                originalName: f.originalname,
                size: f.size,
                mimetype: f.mimetype,
                path: f.path
            })),
            views: 0,
            sales: 0,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        
        products.push(newProduct);
        fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(products, null, 2));
        
        // Update user stats
        updateUserStats(seller);
        
        res.json({ success: true, product: newProduct });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// Purchase product
app.post('/api/purchase', async (req, res) => {
    try {
        const { productId, buyer, transactionHash } = req.body;
        
        const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
        const productIndex = products.findIndex(p => p.id === productId);
        
        if (productIndex === -1) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        // Record sale
        const sales = JSON.parse(fs.readFileSync(SALES_FILE));
        const sale = {
            id: crypto.randomBytes(16).toString('hex'),
            productId,
            buyer,
            seller: products[productIndex].seller,
            price: products[productIndex].price,
            transactionHash,
            createdAt: new Date().toISOString()
        };
        
        sales.push(sale);
        fs.writeFileSync(SALES_FILE, JSON.stringify(sales, null, 2));
        
        // Update product sales count
        products[productIndex].sales = (products[productIndex].sales || 0) + 1;
        fs.writeFileSync(PRODUCTS_FILE, JSON.stringify(products, null, 2));
        
        // Update seller stats
        updateUserStats(products[productIndex].seller);
        
        res.json({ success: true, sale });
    } catch (error) {
        console.error('Purchase error:', error);
        res.status(500).json({ error: 'Purchase failed' });
    }
});

// Download product
app.get('/api/download/:productId/:fileId', (req, res) => {
    try {
        const { productId, fileId } = req.params;
        const { wallet } = req.query;
        
        const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
        const product = products.find(p => p.id === productId);
        
        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        const file = product.files.find(f => f.filename === fileId);
        if (!file) {
            return res.status(404).json({ error: 'File not found' });
        }
        
        // Verify purchase
        const sales = JSON.parse(fs.readFileSync(SALES_FILE));
        const hasPurchased = sales.some(s => 
            s.productId === productId && s.buyer === wallet
        );
        
        if (!hasPurchased && product.seller !== wallet) {
            return res.status(403).json({ error: 'You must purchase this product first' });
        }
        
        res.download(file.path, file.originalName);
    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({ error: 'Download failed' });
    }
});

// Search products
app.get('/api/search', (req, res) => {
    try {
        const { q } = req.query;
        const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
        
        if (!q) {
            return res.json([]);
        }
        
        const searchTerm = q.toLowerCase();
        const results = products.filter(p => 
            p.title.toLowerCase().includes(searchTerm) ||
            p.description.toLowerCase().includes(searchTerm) ||
            (p.tags && p.tags.some(tag => tag.toLowerCase().includes(searchTerm)))
        );
        
        res.json(results);
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ error: 'Search failed' });
    }
});

// Get stats
app.get('/api/stats', (req, res) => {
    try {
        const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
        const sales = JSON.parse(fs.readFileSync(SALES_FILE));
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        
        const totalProducts = products.length;
        const totalSellers = new Set(products.map(p => p.seller)).size;
        const totalSales = sales.length;
        
        // Calculate earnings
        const earningsBySeller = {};
        sales.forEach(sale => {
            earningsBySeller[sale.seller] = (earningsBySeller[sale.seller] || 0) + sale.price;
        });
        
        const stats = {
            totalProducts,
            totalSellers,
            totalSales,
            earningsBySeller,
            recentSales: sales.slice(-10).reverse()
        };
        
        res.json(stats);
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ error: 'Failed to load stats' });
    }
});

// Get user stats
app.get('/api/user/:wallet/stats', (req, res) => {
    try {
        const { wallet } = req.params;
        const products = JSON.parse(fs.readFileSync(PRODUCTS_FILE));
        const sales = JSON.parse(fs.readFileSync(SALES_FILE));
        
        const userProducts = products.filter(p => p.seller === wallet);
        const userSales = sales.filter(s => s.seller === wallet);
        const userPurchases = sales.filter(s => s.buyer === wallet);
        
        const stats = {
            products: userProducts.length,
            totalDownloads: userSales.length,
            totalEarnings: userSales.reduce((sum, s) => sum + s.price, 0),
            totalViews: userProducts.reduce((sum, p) => sum + (p.views || 0), 0),
            productsList: userProducts,
            salesList: userSales,
            purchasesList: userPurchases
        };
        
        res.json(stats);
    } catch (error) {
        console.error('User stats error:', error);
        res.status(500).json({ error: 'Failed to load user stats' });
    }
});

// Helper function to update user stats
function updateUserStats(wallet) {
    try {
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        let user = users.find(u => u.wallet === wallet);
        
        if (!user) {
            user = {
                wallet,
                joinedAt: new Date().toISOString(),
                lastActive: new Date().toISOString()
            };
            users.push(user);
        } else {
            user.lastActive = new Date().toISOString();
        }
        
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    } catch (error) {
        console.error('Update user stats error:', error);
    }
}

// Serve frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Ricc Marketing Place running on http://localhost:${PORT}`);
    console.log(`Server started at: ${new Date().toLocaleString()}`);
});
