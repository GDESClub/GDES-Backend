import mongoose from "mongoose";
export const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true
    },
    RecoveryEmail:{
        type: String,
        required: false,
    },
    RecoveryPassword:{
        type: String,
        required: false,
    },
        likedGames: {
        type: [String], 
        default: []
    },
    ratedGames: {
        type: Map,
        of: Number,
        default: {}
    }
})