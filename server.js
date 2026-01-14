const express = require('express');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const app = express();
const PORT = 3000;

app.use(express.json());

// --- CONFIGURATION ---
const SECRET_KEY = "comcast-telecom-secret-2026"; 
const MASTER_API_KEY = "telecom-secret-2026";
const ROLES = { ADMIN: 'ADMIN', INTERN: 'INTERN' };
const DB_PATH = './db.json';

// --- HELPERS ---
const getDb = () => JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
const saveDb = (data) => fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));

// --- 1. GLOBAL MIDDLEWARE: API KEY & USAGE TRACKING ---
app.use((req, res, next) => {
    const userApiKey = req.header('x-api-key');
    const db = getDb();

    // Skip tracking for a simple health check or login if desired, 
    // but here we enforce it for all routes as requested.
    if (!userApiKey || userApiKey !== MASTER_API_KEY) {
        return res.status(401).json({ error: "Unauthorized: Invalid or Missing x-api-key" });
    }

    if (!db.usage) db.usage = {};
    if (!db.usage[userApiKey]) db.usage[userApiKey] = 0;

    // Rate Limiting (100 requests per session/key)
    if (db.usage[userApiKey] >= 100) {
        return res.status(429).json({ error: "Rate limit exceeded. Quota: 100 requests." });
    }

    db.usage[userApiKey]++;
    saveDb(db);
    next();
});

// --- 2. AUTHENTICATION: LOGIN (Identity Provider) ---
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // Simulated User Database
    const users = [
        { user: 'telecom_admin', pass: 'p@ssword123', role: ROLES.ADMIN },
        { user: 'telecom_intern', pass: 'intern123', role: ROLES.INTERN }
    ];

    const foundUser = users.find(u => u.user === username && u.pass === password);

    if (!foundUser) {
        return res.status(401).json({ error: "Invalid username or password" });
    }

    // Generate JWT
    const token = jwt.sign(
        { user: foundUser.user, role: foundUser.role }, 
        SECRET_KEY, 
        { expiresIn: '1h' }
    );

    res.json({ message: "Login Successful", token: token });
});

// --- 3. AUTHORIZATION: RBAC MIDDLEWARE ---
const authorize = (allowedRoles = []) => {
    return (req, res, next) => {
        const authHeader = req.header('Authorization');
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: "Access Denied: Bearer Token Required" });
        }

        const token = authHeader.split(' ')[1];

        jwt.verify(token, SECRET_KEY, (err, decoded) => {
            if (err) return res.status(403).json({ error: "Token Expired or Invalid" });

            // Role Check
            if (allowedRoles.length && !allowedRoles.includes(decoded.role)) {
                return res.status(403).json({ error: `Forbidden: Needs ${allowedRoles} role.` });
            }

            req.user = decoded;
            next();
        });
    };
};

// --- 4. API PATHS / ROUTES ---

// A. VIEW USAGE (Admin & Intern)
app.get('/admin/stats', authorize([ROLES.ADMIN, ROLES.INTERN]), (req, res) => {
    const db = getDb();
    res.json({ service: "Telecom Gateway", metrics: db.usage });
});

// B. GET ALL SUBSCRIBERS (Admin & Intern)
app.get('/subscribers', authorize([ROLES.ADMIN, ROLES.INTERN]), (req, res) => {
    const db = getDb();
    let results = db.subscribers;
    if (req.query.status) {
        results = results.filter(s => s.status === req.query.status);
    }
    res.json(results);
});

// C. GET ONE SUBSCRIBER (Admin & Intern)
app.get('/subscribers/:id', authorize([ROLES.ADMIN, ROLES.INTERN]), (req, res) => {
    const db = getDb();
    const sub = db.subscribers.find(s => s.id === req.params.id);
    if (!sub) return res.status(404).json({ error: "Not Found" });
    res.json(sub);
});

// D. CREATE SUBSCRIBER (Admin ONLY)
app.post('/subscribers', authorize([ROLES.ADMIN]), (req, res) => {
    const db = getDb();
    const { id, phoneNumber, name, plan, dataBalanceGB } = req.body;

    if (!id || !phoneNumber || !name) {
        return res.status(400).json({ error: "Missing required fields." });
    }
    if (db.subscribers.find(s => s.id === id)) {
        return res.status(409).json({ error: "ID already exists." });
    }

    const newSub = { id, phoneNumber, name, plan: plan || 'Basic', dataBalanceGB: dataBalanceGB || 0, status: 'Active' };
    db.subscribers.push(newSub);
    saveDb(db);
    res.status(201).json(newSub);
});

// E. UPDATE SUBSCRIBER - PATCH (Admin ONLY)
app.patch('/subscribers/:id', authorize([ROLES.ADMIN]), (req, res) => {
    const db = getDb();
    const index = db.subscribers.findIndex(s => s.id === req.params.id);

    if (index === -1) return res.status(404).json({ error: "Not found" });
    if (req.body.id) return res.status(400).json({ error: "ID cannot be changed" });

    db.subscribers[index] = { ...db.subscribers[index], ...req.body };
    saveDb(db);
    res.json(db.subscribers[index]);
});

// F. DELETE SUBSCRIBER (Admin ONLY)
app.delete('/subscribers/:id', authorize([ROLES.ADMIN]), (req, res) => {
    const db = getDb();
    const originalLength = db.subscribers.length;
    db.subscribers = db.subscribers.filter(s => s.id !== req.params.id);

    if (db.subscribers.length === originalLength) {
        return res.status(404).json({ error: "ID not found" });
    }

    saveDb(db);
    res.status(204).send();
});

app.listen(PORT, () => console.log(`🚀 Telecom API running at http://localhost:${PORT}`));

/* Basic Auth using a username and password 

app.use((req, res, next) => {
    const authHeader = req.header('Authorization');

    // 1. Check if the header exists and starts with 'Basic '
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        // 401 Unauthorized is the standard response for missing credentials
        return res.status(401).json({ error: "Authentication Required" });
    }

    // 2. Extract the Base64 string and decode it
    const base64Credentials = authHeader.split(' ')[1];
    const decoded = Buffer.from(base64Credentials, 'base64').toString('utf-8');
    const [username, password] = decoded.split(':');

    // 3. Validate the credentials
    if (username === 'telecom_admin' && password === 'p@ssword123') {
        next(); // Success! Move to the API routes
    } else {
        res.status(403).json({ error: "Forbidden: Invalid credentials" });
    }
});
*/
