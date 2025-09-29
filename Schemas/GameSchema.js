const mongoose = require('mongoose');

const GameSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "Game name is required"],
        unique: true,
        trim: true
    },
    banner: {
        type: String, // URL to the banner image
        required: [true, "Banner image URL is required"]
    },
    tags: {
        type: [String], // An array of strings
        required: true
    },
    rating: {
        type: Number,
        min: 0,
        max: 5,
        default: 0
    },
    description: {
        type: String,
        required: [true, "Description is required"]
    },
    liked_count: {
        type: Number,
        default: 0
    },
    about: {
        type: String,
        required: [true, "About section is required"]
    }
});

module.exports = { GameSchema };