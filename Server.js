const mongoose = require('mongoose');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bcryptjs = require('bcryptjs');
const nodemailer = require('nodemailer');
const path = require('path');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const UserVisit = require('./Schemas/UserVisitSchema');
const { GameSchema } = require('./Schemas/GameSchema');
const { UserSchema } = require('./Schemas/UserSchema');
const { ActivitySchema } = require('./Schemas/ActivitySchema');
const { TempUserSchema } = require('./Schemas/TempUseSchema');

const port = process.env.PORT || 3000;
const URL = process.env.MONGOURL;
const app = express();

// Middlewares
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const templatePath = path.join(__dirname, "/templates");
const publicPath = path.join(__dirname, "/public");

app.set('view engine', 'hbs');
app.set('views', templatePath);
app.use(express.static(publicPath));

// MongoDB connection
mongoose.connect(URL);
const db = mongoose.connection;

db.once('open', () => console.log("✅ Successfully connected to MongoDB Atlas."));
db.on('error', (err) => console.error('❌ MongoDB connection error:', err));

// Models
const Game = mongoose.model("Game", GameSchema);
const Activity = mongoose.model("Activity", ActivitySchema);
const User = mongoose.model("User", UserSchema);
const TempUser = mongoose.model("TempUser", TempUserSchema);

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.MAILID, 
        pass: process.env.MAILPASS
    }
});

// Helper Functions
async function hashPassword(password) {
    return await bcryptjs.hash(password, 10);
}

async function comparePasswords(plain, hashed) {
    return await bcryptjs.compare(plain, hashed);
}

function generateToken(payload) {
    return jwt.sign(payload, process.env.KEY, { expiresIn: '7d' });
}

// JWT Middleware
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: { code: 'TOKEN_MISSING', message: 'Token required' } });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(403).json({ error: { code: 'TOKEN_MISSING', message: 'Token required' } });

    jwt.verify(token, process.env.KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: { code: 'TOKEN_INVALID', message: 'Invalid token' } });
        req.user = decoded;
        next();
    });
}

// -------------------- Routes -------------------- //

app.get("/api/test", (req, res) => {
    res.json({ message: "Server is up and running 🚀" });
});

// -------------------- Game Data Routes -------------------- //

app.get('/api/games', async (req, res) => {
    try {
        const games = await Game.find({});
        res.status(200).json(games);
    } catch (err) {
        console.error("Get games error:", err);
        res.status(500).json({ error: { code: 'SERVER_ERROR', message: "Failed to fetch games" } });
    }
});


// -------------------- Signup with OTP -------------------- //

app.post("/api/send-otp", async (req, res) => {
    try {
        const { name, email, password, RecoveryEmail, RecoveryPassword } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: { code: 'INVALID_INPUT', message: "Name, email, and password are required" } });
        }

        const existingUser = await User.findOne({ name });
        if (existingUser) return res.status(409).json({ error: { code: 'USERNAME_TAKEN', message: "Username already taken" } });

        const hashedPassword = await hashPassword(password);
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Save temporary user
        await TempUser.create({ name, email, password: hashedPassword, RecoveryEmail, RecoveryPassword, otp });

        // Send OTP email
        await transporter.sendMail({
            from: process.env.MAILID,
            to: email,
            subject: "Verify your email",
            text: `Your OTP is ${otp}. It will expire in 5 minutes.`
        });

        res.status(200).json({ message: "OTP sent successfully" });

    } catch (err) {
        console.error("Send OTP error:", err);
        res.status(500).json({ error: { code: 'SERVER_ERROR', message: "Failed to send OTP" } });
    }
});

app.post("/api/verify-otp", async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) return res.status(400).json({ error: { code: 'INVALID_INPUT', message: "Email and OTP are required" } });

        const tempUser = await TempUser.findOne({ email, otp });
        if (!tempUser) return res.status(400).json({ error: { code: 'OTP_INVALID', message: "Invalid or expired OTP" } });

        // Create permanent user
        const user = await User.create({
            name: tempUser.name,
            email: tempUser.email,
            password: tempUser.password,
            RecoveryEmail: tempUser.RecoveryEmail,
            RecoveryPassword: tempUser.RecoveryPassword
        });

        // Remove temporary user
        await TempUser.deleteMany({ email });

        // Generate JWT
        const token = generateToken({ name: user.name });

        res.status(201).json({ message: "Account created successfully!", token });

    } catch (err) {
        console.error("Verify OTP error:", err);
        res.status(500).json({ error: { code: 'SERVER_ERROR', message: "Failed to verify OTP" } });
    }
});

// -------------------- Login -------------------- //

app.post('/api/login', async (req, res) => {
    try {
        const { name, password } = req.body;
        if (!name || !password) return res.status(400).json({ error: { code: 'INVALID_INPUT', message: "Name and password are required" } });

        const user = await User.findOne({ name });
        if (!user || !(await comparePasswords(password, user.password))) {
            return res.status(401).json({ error: { code: 'INVALID_CREDENTIALS', message: "Incorrect Username or Password" } });
        }

        const token = generateToken({ name: user.name });
        res.status(200).json({ message: "Login successful", token });

    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: { code: 'SERVER_ERROR', message: "Login failed" } });
    }
});

// -------------------- Activity -------------------- //

app.post('/api/addactivity', verifyToken, async (req, res) => {
    try {
        const { Name } = req.body;
        if (!Name) return res.status(400).json({ error: { code: 'INVALID_INPUT', message: "Activity Name is required" } });

        await Activity.create({ user: req.user.name, Game: Name });
        res.status(201).json({ message: "Activity added successfully" });

    } catch (err) {
        console.error("Add activity error:", err);
        res.status(500).json({ error: { code: 'SERVER_ERROR', message: err.message } });
    }
});

app.get('/api/getactivity', verifyToken, async (req, res) => {
    try {
        const activities = await Activity.find({ user: req.user.name }).sort({ timestamp: -1 }).limit(10);
        res.status(200).json({ activities });

    } catch (err) {
        console.error("Get activity error:", err);
        res.status(500).json({ error: { code: 'SERVER_ERROR', message: err.message } });
    }
});

// -------------------- User Interactions -------------------- //

// ENDPOINT OF VISITING A GAME WITH 2 MINUTE COOLDOWN
app.post('/api/games/:gameId/visit', verifyToken, async (req, res) => {
    try {
        const { gameId } = req.params;
        const username = req.user.name;
        const twoMinutesAgo = new Date(Date.now() - 2 * 60 * 1000); // 2 minutes in milliseconds

        // Check for a recent visit by this user for this game
        const recentVisit = await UserVisit.findOne({ username, gameId, lastVisited: { $gte: twoMinutesAgo } });

        if (recentVisit) {
            // If a recent visit exists, do nothing and inform the client
            return res.status(200).json({ message: "Cooldown active. Visit not counted." });
        }

        // If no recent visit, proceed to count it
        // Use findOneAndUpdate to increment the visit count atomically
        await Game.findOneAndUpdate(
            { name: new RegExp('^' + gameId.replace(/-/g, ' ') + '$', 'i') },
            { $inc: { visit_count: 1 } },
            { new: true }
        );

        // Update or create the visit record for the user
        await UserVisit.findOneAndUpdate(
            { username, gameId },
            { lastVisited: new Date() },
            { upsert: true } // Creates a new document if one doesn't exist
        );

        res.status(200).json({ message: "Visit counted successfully." });

    } catch (err) {
        console.error("Game visit error:", err);
        res.status(500).json({ error: { code: 'SERVER_ERROR', message: err.message } });
    }
});


// ENDPOINT TO RATE A GAME
app.post('/api/user/rate', verifyToken, async (req, res) => {
    try {
        const { gameId, rating } = req.body;
        if (!gameId || !rating) return res.status(400).json({ error: { code: 'INVALID_INPUT', message: "Game ID and rating are required" } });

        const user = await User.findOne({ name: req.user.name });
        if (!user) return res.status(404).json({ error: { code: 'USER_NOT_FOUND', message: "User not found" } });

        user.ratedGames.set(gameId, rating); // Set or update the rating for the game
        await user.save();

        res.status(200).json({ ratedGames: Object.fromEntries(user.ratedGames) });

    } catch (err) {
        console.error("Rate game error:", err);
        res.status(500).json({ error: { code: 'SERVER_ERROR', message: err.message } });
    }
});


// -------------------- Server -------------------- //
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
