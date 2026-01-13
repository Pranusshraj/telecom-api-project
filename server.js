const express = require('express');
const fs = require('fs');
const app = express();
const PORT = 3000;

app.use(express.json());

// Helper functions for Persistence
const getDb = () => JSON.parse(fs.readFileSync('./db.json', 'utf-8'));
const saveDb = (data) => fs.writeFileSync('./db.json', JSON.stringify(data, null, 2));

// Middleware for API Key Validation AND Usage Tracking
app.use((req, res, next) => {
    const userApiKey = req.header('x-api-key');
    const db = JSON.parse(fs.readFileSync('./db.json', 'utf-8'));

    // 1. Basic Security Check
    if (!userApiKey || userApiKey !== 'telecom-secret-2026') {
        return res.status(401).json({ error: "Unauthorized access" });
    }

    // 2. Usage Tracking Logic
    // We've added a 'usage' object in our db.json to track keys
    if (!db.usage) db.usage = {};
    if (!db.usage[userApiKey]) db.usage[userApiKey] = 0;

    // Increment the counter for this specific key
    db.usage[userApiKey]++;

    // Save the updated count back to the file
    fs.writeFileSync('./db.json', JSON.stringify(db, null, 2));

    console.log(`📊 Usage Tracked: Key [${userApiKey}] has made ${db.usage[userApiKey]} requests.`);
    
    next();
});

// Admin route to check usage stats
app.get('/admin/stats', (req, res) => {
    const db = JSON.parse(fs.readFileSync('./db.json', 'utf-8'));
    res.json({
        service_name: "Telecom Gateway",
        usage_metrics: db.usage
    });
});
// ** Include Rate limiting - The max no. of requests that a user can rise in a session

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
// Basic Auth using a username and password

// --- 1. GET ALL (With Optional Filtering) ---
app.get('/subscribers', (req, res) => {
    const db = getDb();
    let results = db.subscribers;

    // Validation: Check for query params (e.g., ?status=Active)
    if (req.query.status) {
        results = results.filter(s => s.status === req.query.status);
    }
    
    res.json(results);
});

// --- 2. GET ONE (With ID Validation) ---
app.get('/subscribers/:id', (req, res) => {
    const db = getDb();
    const sub = db.subscribers.find(s => s.id === req.params.id);

    if (!sub) {
        return res.status(404).json({ error: `Subscriber with ID ${req.params.id} not found.` });
    }
    res.json(sub);
});

// --- 3. POST (With Structural Validation) ---
app.post('/subscribers', (req, res) => {
    const db = getDb();
    const { id, phoneNumber, name, plan, dataBalanceGB } = req.body;

    // Validation: Check for mandatory fields
    if (!id || !phoneNumber || !name) {
        return res.status(400).json({ error: "Missing required fields: id, phoneNumber, and name are mandatory." });
    }

    // Validation: Prevent duplicate IDs
    if (db.subscribers.find(s => s.id === id)) {
        return res.status(409).json({ error: "Conflict: Subscriber ID already exists." });
    }

    // Validation: Data Types
    if (typeof dataBalanceGB !== 'number') {
        return res.status(400).json({ error: "Invalid Data: dataBalanceGB must be a number." });
    }

    const newSub = { id, phoneNumber, name, plan: plan || 'Basic', dataBalanceGB, status: 'Active' };
    db.subscribers.push(newSub);
    saveDb(db);
    res.status(201).json(newSub);
});

// --- 4. PATCH (With Partial Validation) ---
app.patch('/subscribers/:id', (req, res) => {
    const db = getDb();
    const index = db.subscribers.findIndex(s => s.id === req.params.id);

    if (index === -1) {
        return res.status(404).json({ error: "Subscriber not found." });
    }

    // Validation: Don't allow changing the ID
    if (req.body.id) {
        return res.status(400).json({ error: "ID cannot be changed via PATCH." });
    }

    // Validation: Specific Business Logic (Data Balance cannot be negative)
    if (req.body.dataBalanceGB !== undefined && req.body.dataBalanceGB < 0) {
        return res.status(400).json({ error: "dataBalanceGB cannot be negative." });
    }

    db.subscribers[index] = { ...db.subscribers[index], ...req.body };
    saveDb(db);
    res.json(db.subscribers[index]);
});

// --- 5. DELETE (With ID Validation) ---
app.delete('/subscribers/:id', (req, res) => {
    const db = getDb();
    const originalLength = db.subscribers.length;
    db.subscribers = db.subscribers.filter(s => s.id !== req.params.id);

    if (db.subscribers.length === originalLength) {
        return res.status(404).json({ error: "Cannot delete: Subscriber ID not found." });
    }

    saveDb(db);
    res.status(204).send(); // No content
});

// --- 6. PUT (Full Replacement with Structural Validation) ---
app.put('/subscribers/:id', (req, res) => {
    const db = getDb();
    const index = db.subscribers.findIndex(s => s.id === req.params.id);

    if (index === -1) {
        return res.status(404).json({ error: "Subscriber not found. Use POST to create a new one." });
    }

    const { phoneNumber, name, plan, status, dataBalanceGB } = req.body;

    // Validation: PUT requires the FULL object structure
    if (!phoneNumber || !name || !plan || !status || dataBalanceGB === undefined) {
        return res.status(400).json({ 
            error: "PUT requires all mandatory fields: phoneNumber, name, plan, status, and dataBalanceGB." 
        });
    }

    // Validation: Maintain the ID from the URL path
    const updatedSub = { 
        id: req.params.id, 
        phoneNumber, 
        name, 
        plan, 
        status, 
        dataBalanceGB 
    };

    db.subscribers[index] = updatedSub;
    saveDb(db);
    res.json(updatedSub);
});

app.listen(PORT, () => console.log(`🚀 Telecom API with Validations at http://localhost:3000`));