import mongoose from "mongoose";
export const ActivitySchema = new mongoose.Schema({
    user: String,
    Game: String, 
    timestamp: {
        type: Date,
        default: Date.now
    }
});