import mongoose from "mongoose";

export const TempUserSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String, // hashed already
    RecoveryEmail: String,
    RecoveryPassword: String,
    otp: String,
    createdAt: { type: Date, default: Date.now, expires: 300 } // expires after 5 min
});