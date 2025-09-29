const mongoose = require('mongoose');

const UserVisitSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        index: true
    },
    gameId: {
        type: String,
        required: true,
        index: true
    },
    lastVisited: {
        type: Date,
        default: Date.now
    }
});

// Create a compound index for efficient lookups
UserVisitSchema.index({ username: 1, gameId: 1 });

module.exports = mongoose.model("UserVisit", UserVisitSchema);
