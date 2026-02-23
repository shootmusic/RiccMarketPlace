// State Management
let state = {
    products: [],
    cart: [],
    wallet: null,
    currentPage: 1,
    filters: {
        category: 'all',
        sort: 'newest',
        search: ''
    },
    uploads: []
};

// DOM Elements
const cursorGlow = document.getElementById('cursorGlow');
const searchToggle = document.getElementById('searchToggle');
const searchOverlay = document.getElementById('searchOverlay');
const closeSearch = document.getElementById('closeSearch');
const cartToggle = document.getElementById('cartToggle');
const cartSidebar = document.getElementById('cartSidebar');
const closeCart = document.getElementById('closeCart');
const connectWallet = document.getElementById('connectWallet');
const productsGrid = document.getElementById('productsGrid');
const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const browseBtn = document.getElementById('browseBtn');
const uploadForm = document.getElementById('uploadForm');
const submitUpload = document.getElementById('submitUpload');
const cancelUpload = document.getElementById('cancelUpload');
const fileList = document.getElementById('fileList');
const categoryFilter = document.getElementById('categoryFilter');
const sortFilter = document.getElementById('sortFilter');
const productSearch = document.getElementById('productSearch');
const loadMoreBtn = document.getElementById('loadMoreBtn');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initCursor();
    initEventListeners();
    loadProducts();
    loadStats();
    initWeb3();
});

// Cursor Effect
function initCursor() {
    document.addEventListener('mousemove', (e) => {
        cursorGlow.style.left = e.clientX + 'px';
        cursorGlow.style.top = e.clientY + 'px';
    });
    
    document.addEventListener('mouseenter', () => {
        cursorGlow.style.opacity = '1';
    });
    
    document.addEventListener('mouseleave', () => {
        cursorGlow.style.opacity = '0';
    });
}

// Event Listeners
function initEventListeners() {
    // Search
    searchToggle.addEventListener('click', () => {
        searchOverlay.classList.add('active');
        document.getElementById('searchInput').focus();
    });
    
    closeSearch.addEventListener('click', () => {
        searchOverlay.classList.remove('active');
    });
    
    // Cart
    cartToggle.addEventListener('click', () => {
        cartSidebar.classList.add('active');
    });
    
    closeCart.addEventListener('click', () => {
        cartSidebar.classList.remove('active');
    });
    
    // Wallet
    connectWallet.addEventListener('click', connectWalletHandler);
    
    // Upload
    uploadArea.addEventListener('click', () => {
        fileInput.click();
    });
    
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('drag-over');
    });
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('drag-over');
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('drag-over');
        handleFiles(e.dataTransfer.files);
    });
    
    fileInput.addEventListener('change', (e) => {
        handleFiles(e.target.files);
    });
    
    browseBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput.click();
    });
    
    submitUpload.addEventListener('click', uploadProduct);
    cancelUpload.addEventListener('click', cancelUploadHandler);
    
    // Filters
    categoryFilter.addEventListener('change', applyFilters);
    sortFilter.addEventListener('change', applyFilters);
    productSearch.addEventListener('input', debounce(applyFilters, 500));
    
    // Load More
    loadMoreBtn.addEventListener('click', loadMoreProducts);
    
    // Navigation
    document.querySelectorAll('.nav-links a').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('href').substring(1);
            const targetSection = document.getElementById(targetId);
            
            document.querySelectorAll('.nav-links a').forEach(l => l.classList.remove('active'));
            link.classList.add('active');
            
            targetSection.scrollIntoView({ behavior: 'smooth' });
        });
    });
}

// Web3 Integration
async function initWeb3() {
    if (typeof window.ethereum !== 'undefined') {
        try {
            const accounts = await window.ethereum.request({ method: 'eth_accounts' });
            if (accounts.length > 0) {
                state.wallet = accounts[0];
                updateWalletUI();
            }
        } catch (error) {
            console.error('Web3 init error:', error);
        }
        
        window.ethereum.on('accountsChanged', handleAccountsChanged);
    }
}

async function connectWalletHandler() {
    if (typeof window.ethereum !== 'undefined') {
        try {
            const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
            state.wallet = accounts[0];
            updateWalletUI();
            showToast('Wallet connected successfully', 'success');
        } catch (error) {
            showToast('Failed to connect wallet', 'error');
        }
    } else {
        showToast('Please install MetaMask', 'warning');
    }
}

function handleAccountsChanged(accounts) {
    if (accounts.length === 0) {
        state.wallet = null;
        updateWalletUI();
    } else {
        state.wallet = accounts[0];
        updateWalletUI();
    }
}

function updateWalletUI() {
    const walletSpan = connectWallet.querySelector('span');
    if (state.wallet) {
        const shortAddress = state.wallet.substring(0, 6) + '...' + state.wallet.substring(38);
        walletSpan.textContent = shortAddress;
        connectWallet.classList.add('connected');
    } else {
        walletSpan.textContent = 'Connect';
        connectWallet.classList.remove('connected');
    }
}

// File Handling
function handleFiles(files) {
    Array.from(files).forEach(file => {
        const fileItem = {
            name: file.name,
            size: file.size,
            type: file.type,
            file: file
        };
        state.uploads.push(fileItem);
    });
    
    updateFileList();
    uploadForm.classList.add('active');
}

function updateFileList() {
    fileList.innerHTML = '';
    state.uploads.forEach((file, index) => {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        fileItem.innerHTML = `
            <span class="file-name">${file.name}</span>
            <span class="file-size">${formatFileSize(file.size)}</span>
            <span class="remove-file" onclick="removeFile(${index})">
                <i class="fas fa-times"></i>
            </span>
        `;
        fileList.appendChild(fileItem);
    });
}

window.removeFile = (index) => {
    state.uploads.splice(index, 1);
    updateFileList();
    if (state.uploads.length === 0) {
        uploadForm.classList.remove('active');
    }
};

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Product Upload
async function uploadProduct() {
    if (!state.wallet) {
        showToast('Please connect wallet first', 'warning');
        return;
    }
    
    if (state.uploads.length === 0) {
        showToast('Please select files to upload', 'warning');
        return;
    }
    
    const title = document.getElementById('productTitle').value;
    const desc = document.getElementById('productDesc').value;
    const price = document.getElementById('productPrice').value;
    const category = document.getElementById('productCategory').value;
    const tags = document.getElementById('productTags').value;
    
    if (!title || !desc || !price) {
        showToast('Please fill all required fields', 'warning');
        return;
    }
    
    const formData = new FormData();
    formData.append('title', title);
    formData.append('description', desc);
    formData.append('price', price);
    formData.append('category', category);
    formData.append('tags', tags);
    formData.append('seller', state.wallet);
    
    state.uploads.forEach((upload, index) => {
        formData.append('files', upload.file);
    });
    
    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });
        
        if (response.ok) {
            showToast('Product uploaded successfully', 'success');
            resetUploadForm();
            loadProducts();
        } else {
            showToast('Upload failed', 'error');
        }
    } catch (error) {
        showToast('Upload failed', 'error');
    }
}

function resetUploadForm() {
    document.getElementById('productTitle').value = '';
    document.getElementById('productDesc').value = '';
    document.getElementById('productPrice').value = '';
    document.getElementById('productCategory').value = 'pdf';
    document.getElementById('productTags').value = '';
    state.uploads = [];
    fileList.innerHTML = '';
    uploadForm.classList.remove('active');
    fileInput.value = '';
}

function cancelUploadHandler() {
    if (state.uploads.length > 0) {
        if (confirm('Are you sure you want to cancel? All files will be cleared.')) {
            resetUploadForm();
        }
    } else {
        resetUploadForm();
    }
}

// Load Products
async function loadProducts() {
    try {
        const response = await fetch('/api/products');
        const products = await response.json();
        state.products = products;
        renderProducts();
    } catch (error) {
        console.error('Load products error:', error);
    }
}

function renderProducts() {
    let filteredProducts = filterProducts(state.products);
    filteredProducts = sortProducts(filteredProducts);
    
    const start = 0;
    const end = state.currentPage * 12;
    const productsToShow = filteredProducts.slice(start, end);
    
    productsGrid.innerHTML = '';
    productsToShow.forEach(product => {
        const productCard = createProductCard(product);
        productsGrid.appendChild(productCard);
    });
    
    if (end >= filteredProducts.length) {
        loadMoreBtn.style.display = 'none';
    } else {
        loadMoreBtn.style.display = 'block';
    }
}

function createProductCard(product) {
    const card = document.createElement('div');
    card.className = 'product-card';
    card.setAttribute('data-id', product.id);
    
    card.innerHTML = `
        <div class="product-image">
            <span class="product-badge">${product.category}</span>
        </div>
        <div class="product-info">
            <div class="product-category">${product.category}</div>
            <h3 class="product-title">${product.title}</h3>
            <p class="product-desc">${product.description.substring(0, 100)}...</p>
            <div class="product-meta">
                <span class="product-price">${product.price} ETH</span>
                <span class="product-sales">${product.sales || 0} sold</span>
            </div>
            <div class="product-footer">
                <button class="buy-btn" onclick="addToCart('${product.id}')">Buy Now</button>
                <button class="preview-btn" onclick="previewProduct('${product.id}')">Preview</button>
            </div>
        </div>
    `;
    
    return card;
}

function filterProducts(products) {
    let filtered = [...products];
    
    if (state.filters.category !== 'all') {
        filtered = filtered.filter(p => p.category === state.filters.category);
    }
    
    if (state.filters.search) {
        const searchTerm = state.filters.search.toLowerCase();
        filtered = filtered.filter(p => 
            p.title.toLowerCase().includes(searchTerm) ||
            p.description.toLowerCase().includes(searchTerm) ||
            (p.tags && p.tags.some(tag => tag.toLowerCase().includes(searchTerm)))
        );
    }
    
    return filtered;
}

function sortProducts(products) {
    const sorted = [...products];
    
    switch (state.filters.sort) {
        case 'price-low':
            return sorted.sort((a, b) => a.price - b.price);
        case 'price-high':
            return sorted.sort((a, b) => b.price - a.price);
        case 'popular':
            return sorted.sort((a, b) => (b.sales || 0) - (a.sales || 0));
        default:
            return sorted.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    }
}

function applyFilters() {
    state.filters.category = categoryFilter.value;
    state.filters.sort = sortFilter.value;
    state.filters.search = productSearch.value;
    state.currentPage = 1;
    renderProducts();
}

function loadMoreProducts() {
    state.currentPage++;
    renderProducts();
}

// Cart Functions
window.addToCart = (productId) => {
    const product = state.products.find(p => p.id === productId);
    if (product) {
        state.cart.push(product);
        updateCartUI();
        showToast('Product added to cart', 'success');
    }
};

function updateCartUI() {
    const cartCount = document.getElementById('cartCount');
    const cartItems = document.getElementById('cartItems');
    const cartTotal = document.getElementById('cartTotal');
    
    cartCount.textContent = state.cart.length;
    
    if (state.cart.length === 0) {
        cartItems.innerHTML = '<p style="text-align: center; color: var(--text-secondary);">Your cart is empty</p>';
        cartTotal.textContent = '0 ETH';
        return;
    }
    
    let total = 0;
    cartItems.innerHTML = '';
    
    state.cart.forEach((item, index) => {
        total += parseFloat(item.price);
        
        const cartItem = document.createElement('div');
        cartItem.className = 'cart-item';
        cartItem.innerHTML = `
            <div class="cart-item-info">
                <h4>${item.title}</h4>
                <p>${item.price} ETH</p>
            </div>
            <button onclick="removeFromCart(${index})">
                <i class="fas fa-times"></i>
            </button>
        `;
        cartItems.appendChild(cartItem);
    });
    
    cartTotal.textContent = total.toFixed(3) + ' ETH';
}

window.removeFromCart = (index) => {
    state.cart.splice(index, 1);
    updateCartUI();
};

document.getElementById('checkoutBtn').addEventListener('click', async () => {
    if (state.cart.length === 0) {
        showToast('Cart is empty', 'warning');
        return;
    }
    
    if (!state.wallet) {
        showToast('Please connect wallet', 'warning');
        return;
    }
    
    // Process checkout
    showToast('Processing checkout...', 'info');
    
    // Simulate checkout
    setTimeout(() => {
        state.cart = [];
        updateCartUI();
        cartSidebar.classList.remove('active');
        showToast('Purchase successful! Check your email for download links.', 'success');
    }, 2000);
});

// Preview Product
window.previewProduct = (productId) => {
    const product = state.products.find(p => p.id === productId);
    if (product) {
        // Open preview modal
        console.log('Preview product:', product);
    }
};

// Load Stats
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        
        document.getElementById('totalProducts').textContent = stats.totalProducts || 0;
        document.getElementById('totalSellers').textContent = stats.totalSellers || 0;
        document.getElementById('totalSales').textContent = stats.totalSales || 0;
        
        if (state.wallet) {
            document.getElementById('myProductsCount').textContent = stats.myProducts || 0;
            document.getElementById('totalDownloads').textContent = stats.totalDownloads || 0;
            document.getElementById('totalEarnings').textContent = (stats.totalEarnings || 0) + ' ETH';
            document.getElementById('totalViews').textContent = stats.totalViews || 0;
        }
    } catch (error) {
        console.error('Load stats error:', error);
    }
}

// Scroll Functions
window.scrollToProducts = () => {
    document.getElementById('products').scrollIntoView({ behavior: 'smooth' });
};

window.scrollToUpload = () => {
    document.getElementById('upload').scrollIntoView({ behavior: 'smooth' });
};

// Utility Functions
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.classList.add('show');
    }, 100);
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, 3000);
}

// Refresh Dashboard
document.getElementById('refreshDashboard').addEventListener('click', () => {
    loadStats();
    showToast('Dashboard refreshed', 'success');
});

// Search Functionality
document.getElementById('searchInput').addEventListener('input', debounce(async (e) => {
    const searchTerm = e.target.value;
    if (searchTerm.length < 2) {
        document.getElementById('searchResults').innerHTML = '';
        return;
    }
    
    try {
        const response = await fetch(`/api/search?q=${searchTerm}`);
        const results = await response.json();
        displaySearchResults(results);
    } catch (error) {
        console.error('Search error:', error);
    }
}, 500));

function displaySearchResults(results) {
    const searchResults = document.getElementById('searchResults');
    searchResults.innerHTML = '';
    
    if (results.length === 0) {
        searchResults.innerHTML = '<p style="text-align: center; color: var(--text-secondary);">No results found</p>';
        return;
    }
    
    results.forEach(product => {
        const resultItem = document.createElement('div');
        resultItem.className = 'search-result-item';
        resultItem.innerHTML = `
            <h4>${product.title}</h4>
            <p>${product.description.substring(0, 50)}...</p>
            <span>${product.price} ETH</span>
        `;
        resultItem.addEventListener('click', () => {
            searchOverlay.classList.remove('active');
            // Scroll to product
        });
        searchResults.appendChild(resultItem);
    });
}

// Keyboard Shortcuts
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        searchOverlay.classList.remove('active');
        cartSidebar.classList.remove('active');
    }
    
    if (e.ctrlKey && e.key === 'k') {
        e.preventDefault();
        searchOverlay.classList.add('active');
    }
});
