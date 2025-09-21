const express = require('express')
const mongoose = require('mongoose')
const path = require('path')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const bcryptjs = require('bcryptjs')
require('dotenv').config()
const cors = require('cors')
const { UserSchema } = require('./Schemas/UserSchema')
const { ActivitySchema } = require('./Schemas/ActivitySchema')

const port = process.env.PORT
const URL = process.env.MONGOURL
const app = express()
app.use(express.json())
app.use(cookieParser())
app.use(express.urlencoded({ extended: true }))

/*
app.use(cors({
  origin: 'https://evlens.vercel.app',
  credentials: true,
}));
*/

app.use(cors());

const templatePath = path.join(__dirname, "/templates")
const publicPath = path.join(__dirname, "/public")

app.set('view engine', 'hbs')
app.set('views', templatePath)
app.use(express.static(publicPath))


// Connect to MongoDB
mongoose.connect(URL)
const db = mongoose.connection

db.once('open', () => {
    console.log("Successfully connected to MongoDB Atlas.");
})
db.on('error', (err) => {
    console.error('MongoDB connection error:', err);
})

const Activity = mongoose.model("Activity", ActivitySchema);
const User = mongoose.model("User", UserSchema);

// Middleware to verify JWT token
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Token required' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(403).json({ error: 'Token required' });

    jwt.verify(token, process.env.KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Invalid token' });
        req.user = decoded;
        next();
    });
}

// Signup route
app.post('/api/signup', async (req, res) => {
    try {
        const existingUser = await User.findOne({ name: req.body.name });
        if (existingUser) {
            return res.status(400).json({ error: 'Username not available' });
        }

        const hashedPassword = await hashPassword(req.body.password);
        const token = jwt.sign({ name: req.body.name }, process.env.KEY);

        const data = {
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword,
            RecoveryEmail: req.body.RecoveryEmail || null,
            RecoveryPassword: req.body.RecoveryPassword || null
        };
        await User.create(data);
        res.status(201).json({ message: 'Successfully created account.' });
    }
    catch (err) {
        console.error("Signup error:", err);
        res.status(500).json({ message: `${err} :Server side error.` });
    }
});

// Login route
app.post('/api/login', async (req, res) => {
    console.log("Received login request");
    try {
        const existingUser = await User.findOne({ name: req.body.name });

        if (!existingUser || !(await compare(req.body.password, existingUser.password))) {
            return res.status(401).json({ error: 'Incorrect Username or Password' });
        }

        const token = jwt.sign({ name: existingUser.name }, process.env.KEY);
        return res.json({ status: 'Success', token });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).send('Server side error.');
    }
});

async function hashPassword(password) {
    return await bcryptjs.hash(password, 10);
}

async function compare(userPass, hashPass) {
    return await bcryptjs.compare(userPass, hashPass);
}

// Test route
app.get("/api/test", (req, res) => {
    res.json({ message: "Server is up and running 🚀" });
});

// Add Activity
app.post('/api/addactivity', verifyToken, async (req, res) => {
    const { Name } = req.body;
    try {
        await Activity.create({
            user: req.user.name,
            Game: `${Name}`
        });
        return res.json({ Data: "Successfully added new activity" });
    }
    catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get Activity
app.get('/api/getactivity', verifyToken, async (req, res) => {
    try {
        const activity = await Activity.find({ user: req.user.name }).sort({ timestamp: -1 }).limit(10);
        res.json(activity);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(port, () => {
    console.log(`server started, listening to port ${port}`);
});

