const mongoose = require('mongoose');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bcryptjs = require('bcryptjs');
const nodemailer = require('nodemailer');
const path = require('path');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const { UserSchema } = require('./Schemas/UserSchema');
const { ActivitySchema } = require('./Schemas/ActivitySchema');
const { TempUserSchema } = require('./Schemas/TempUseSchema');
const port = process.env.PORT || 3000;
const URL = process.env.MONGOURL;
const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

// Going to restrict access when frontend is deployed.
app.use(cors());

const templatePath = path.join(__dirname, "/templates");
const publicPath = path.join(__dirname, "/public");

app.set('view engine', 'hbs');
app.set('views', templatePath);
app.use(express.static(publicPath));

// Connect to MongoDB
mongoose.connect(URL);
const db = mongoose.connection;

db.once('open', () => {
    console.log("✅ Successfully connected to MongoDB Atlas.");
});
db.on('error', (err) => {
    console.error('❌ MongoDB connection error:', err);
});

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.MAILID,   // your gmail
        pass: process.env.MAILPASS    // app password
    }
});

const Activity = mongoose.model("Activity", ActivitySchema);
const User = mongoose.model("User", UserSchema);
const TempUser = mongoose.model("TempUser", TempUserSchema);

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

app.post("/api/send-otp", async (req, res) => {
    try {
        const { name, email, password, RecoveryEmail, RecoveryPassword } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: "Name, email, and password are required" });
        }

        const existingUser = await User.findOne({ name });
        if (existingUser) return res.status(400).json({ error: "Username already taken" });

        const hashedPassword = await hashPassword(password);
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Save temporary user with OTP
        await TempUser.create({
            name,
            email,
            password: hashedPassword,
            RecoveryEmail: RecoveryEmail || null,
            RecoveryPassword: RecoveryPassword || null,
            otp
        });

        // Send OTP email
        await transporter.sendMail({
            from: process.env.MAILID,
            to: email,
            subject: "Verify your email",
            text: `Your OTP is ${otp}. It will expire in 5 minutes.`
        });

        res.json({ message: "OTP sent successfully" });

    } catch (err) {
        console.error("Send OTP error:", err);
        res.status(500).json({ error: "Failed to send OTP" });
    }
});


app.post("/api/verify-otp", async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) return res.status(400).json({ error: "Email and OTP are required" });

        const tempUser = await TempUser.findOne({ email, otp });
        if (!tempUser) return res.status(400).json({ error: "Invalid or expired OTP" });

        // Create user in permanent collection
        await User.create({
            name: tempUser.name,
            email: tempUser.email,
            password: tempUser.password,
            RecoveryEmail: tempUser.RecoveryEmail,
            RecoveryPassword: tempUser.RecoveryPassword
        });

        // Remove temporary user
        await TempUser.deleteMany({ email });

        // Generate JWT
        const token = jwt.sign({ name: tempUser.name }, process.env.KEY);

        res.json({ message: "Account created successfully!", token });

    } catch (err) {
        console.error("Verify OTP error:", err);
        res.status(500).json({ error: "Failed to verify OTP" });
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
    console.log(`🚀 Server started, listening on port ${port}`);
});
