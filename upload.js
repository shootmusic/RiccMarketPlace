const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'uploads', req.body.seller || 'anonymous');
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
    limits: {
        fileSize: 100 * 1024 * 1024, // 100MB max file size
        files: 10 // max 10 files per upload
    },
    fileFilter: (req, file, cb) => {
        // Accept all file types
        cb(null, true);
    }
}).array('files', 10);

// Handle file upload
function handleUpload(req, res) {
    return new Promise((resolve, reject) => {
        upload(req, res, (err) => {
            if (err instanceof multer.MulterError) {
                reject({ error: 'Upload error: ' + err.message });
            } else if (err) {
                reject({ error: 'Unknown error: ' + err.message });
            } else {
                resolve(req.files);
            }
        });
    });
}

// Validate upload request
function validateUpload(req) {
    const { title, description, price, seller } = req.body;
    
    if (!title || title.length < 3) {
        return { valid: false, error: 'Title must be at least 3 characters' };
    }
    
    if (!description || description.length < 10) {
        return { valid: false, error: 'Description must be at least 10 characters' };
    }
    
    if (!price || isNaN(price) || parseFloat(price) <= 0) {
        return { valid: false, error: 'Price must be a positive number' };
    }
    
    if (!seller || seller.length < 10) {
        return { valid: false, error: 'Valid seller wallet required' };
    }
    
    return { valid: true };
}

// Save product data
function saveProduct(productData, files) {
    const productsFile = path.join(__dirname, 'data', 'products.json');
    let products = [];
    
    if (fs.existsSync(productsFile)) {
        products = JSON.parse(fs.readFileSync(productsFile));
    }
    
    const newProduct = {
        id: crypto.randomBytes(16).toString('hex'),
        ...productData,
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
    fs.writeFileSync(productsFile, JSON.stringify(products, null, 2));
    
    return newProduct;
}

module.exports = {
    handleUpload,
    validateUpload,
    saveProduct
};
